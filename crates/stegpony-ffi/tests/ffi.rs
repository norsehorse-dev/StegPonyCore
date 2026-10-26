//! The binding surface, called from Rust the way the generated Kotlin calls it.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use stegpony_ffi::*;
use x25519_dalek::{PublicKey, StaticSecret};

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/../stegpony-core/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn text(t: &str) -> Payload {
    Payload::Text { text: t.into() }
}

fn pass(p: &str) -> HideSecret {
    HideSecret::Passphrase {
        passphrase: p.into(),
    }
}

fn reveal_pass(p: &str) -> RevealSecret {
    RevealSecret::Passphrase {
        passphrase: p.into(),
    }
}

#[test]
fn lossless_round_trip_with_decoy() {
    let cover = Cover::new(fixture("cover_rgb.png")).unwrap();
    assert_eq!(cover.format(), ImageFormat::Png);
    let cap = cover.capacity(ImageMode::Lossless).unwrap();
    assert!(cap.max_text_bytes > 0 && cap.max_payload_bytes == cap.max_text_bytes + 5);
    assert!(cap.low_payload_bytes <= cap.medium_payload_bytes);
    assert!(cap.medium_payload_bytes <= cap.max_payload_bytes);
    assert!(matches!(
        cover.capacity(ImageMode::Jpeg),
        Err(StegError::UnsupportedCover { .. })
    ));

    let real = text("the real one");
    let decoy = text("the decoy");
    let fit = cover
        .fit(
            ImageMode::Lossless,
            text_payload_len("the real one".into()),
            Some(text_payload_len("the decoy".into())),
        )
        .unwrap();
    assert!(fit.fits);
    let out = cover
        .hide(
            ImageMode::Lossless,
            real.clone(),
            pass("one"),
            Some(Decoy {
                payload: decoy.clone(),
                secret: pass("two"),
            }),
            false,
        )
        .unwrap();
    assert_eq!(out.format, ImageFormat::Png);
    assert_eq!(Some(out.detectability), fit.detectability);
    let found = |p: &str| reveal(out.image.clone(), vec![reveal_pass(p)], vec![]).unwrap();
    assert_eq!(found("one"), Some(real));
    assert_eq!(found("two"), Some(decoy));
    assert_eq!(found("three"), None);
}

#[test]
fn fit_matches_capacity() {
    let cover = Cover::new(fixture("jpeg/baseline_420.jpg")).unwrap();
    let cap = cover.capacity(ImageMode::Jpeg).unwrap();
    let fits = |n: u64| cover.fit(ImageMode::Jpeg, n, None).unwrap();
    assert!(fits(cap.max_payload_bytes).fits);
    assert!(!fits(cap.max_payload_bytes + 1).fits);
    assert_eq!(fits(cap.max_payload_bytes + 1).detectability, None);
    if cap.low_payload_bytes > 0 {
        assert_eq!(
            fits(cap.low_payload_bytes).detectability,
            Some(Detectability::Low)
        );
    }
    // The decoy pads both slots to the larger size.
    assert!(
        !cover
            .fit(ImageMode::Jpeg, 1, Some(cap.max_payload_bytes + 1))
            .unwrap()
            .fits
    );
    assert_eq!(
        file_payload_len("a.txt".into(), "text/plain".into(), 100),
        1 + 4 + 2 + 5 + 2 + 10 + 100
    );
}

#[test]
fn not_an_image() {
    assert!(matches!(
        Cover::new(b"GIF89a".to_vec()),
        Err(StegError::UnsupportedCover { .. })
    ));
    assert!(matches!(
        reveal(b"hello".to_vec(), vec![reveal_pass("x")], vec![]),
        Err(StegError::UnsupportedCover { .. })
    ));
}

/// A hardware key stand-in: plain X25519, as an OpenPGP card's PSO:DECIPHER does.
struct Card {
    secret: StaticSecret,
    calls: AtomicUsize,
    answer: fn() -> Option<DeviceError>,
}

impl KeyDevice for Card {
    fn recipient(&self) -> String {
        recipient_from_x25519(PublicKey::from(&self.secret).as_bytes().to_vec()).unwrap()
    }
    fn agree(&self, point: Vec<u8>) -> Result<Vec<u8>, DeviceError> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if let Some(e) = (self.answer)() {
            return Err(e);
        }
        let p: [u8; 32] = point.try_into().unwrap();
        Ok(self
            .secret
            .diffie_hellman(&PublicKey::from(p))
            .as_bytes()
            .to_vec())
    }
}

fn card(seed: u8, answer: fn() -> Option<DeviceError>) -> Arc<Card> {
    Arc::new(Card {
        secret: StaticSecret::from([seed; 32]),
        calls: AtomicUsize::new(0),
        answer,
    })
}

#[test]
fn jpeg_hide_for_a_card_and_reveal_with_it() {
    let good = card(7, || None);
    let cover = Cover::new(fixture("jpeg/baseline_420.jpg")).unwrap();
    let p = text("for the card");
    let out = cover
        .hide(
            ImageMode::Jpeg,
            p.clone(),
            HideSecret::Recipient {
                recipient: good.recipient(),
            },
            None,
            false,
        )
        .unwrap();
    assert_eq!(out.format, ImageFormat::Jpeg);
    assert!(out.image.starts_with(&[0xff, 0xd8, 0xff]));

    let devices: Vec<Arc<dyn KeyDevice>> = vec![good.clone()];
    assert_eq!(reveal(out.image.clone(), vec![], devices).unwrap(), Some(p));
    assert!((1..=2).contains(&good.calls.load(Ordering::SeqCst)));

    // A passphrase is tried before the card, which is still asked when it fails.
    let other = card(8, || None);
    let devices: Vec<Arc<dyn KeyDevice>> = vec![other.clone()];
    assert_eq!(
        reveal(out.image.clone(), vec![reveal_pass("nope")], devices).unwrap(),
        None
    );
    assert_eq!(other.calls.load(Ordering::SeqCst), 2);

    let cancelled = card(7, || Some(DeviceError::Cancelled));
    let devices: Vec<Arc<dyn KeyDevice>> = vec![cancelled];
    assert!(matches!(
        reveal(out.image.clone(), vec![], devices),
        Err(StegError::DeviceCancelled)
    ));
    let removed = card(7, || {
        Some(DeviceError::Failed {
            reason: "tag lost".into(),
        })
    });
    let devices: Vec<Arc<dyn KeyDevice>> = vec![removed];
    match reveal(out.image, vec![], devices) {
        Err(StegError::KeyDevice { detail }) => assert_eq!(detail, "tag lost"),
        other => panic!("{other:?}"),
    }
}

#[test]
fn keys() {
    let k = generate_identity();
    assert!(k.identity.starts_with("AGE-SECRET-KEY-1"));
    assert!(k.recipient.starts_with("age1"));
    let again = identity_key_pair(k.identity.clone()).unwrap();
    assert_eq!(again.recipient, k.recipient);
    assert_eq!(
        parse_recipient(format!(" {} ", k.recipient)).unwrap(),
        k.recipient
    );
    let file = format!(
        "# created: today\n# public key: {}\n{}\n",
        k.recipient, k.identity
    );
    let ids = parse_identity_file(file).unwrap();
    assert_eq!(ids.len(), 1);
    assert_eq!(ids[0].recipient, k.recipient);
    assert!(matches!(
        parse_recipient("age1nope".into()),
        Err(StegError::BadKey { .. })
    ));

    let raw = [9u8; 32];
    let mut prefixed = vec![0x40];
    prefixed.extend_from_slice(&raw);
    assert_eq!(
        recipient_from_x25519(prefixed).unwrap(),
        recipient_from_x25519(raw.to_vec()).unwrap()
    );
    assert!(recipient_from_x25519(vec![1, 2, 3]).is_err());
}

#[test]
fn pgp_keys() {
    let public = pgp_public_key(fixture("pgp/v4_cv25519_public.asc")).unwrap();
    assert_eq!(
        public.subkey_fingerprint,
        "E307B8613923A369799B83BDA826624D510EE185"
    );
    let secret = fixture("pgp/v4_cv25519_secret.asc");
    assert!(matches!(
        pgp_secret_key(secret.clone(), String::new()),
        Err(StegError::WrongPassphrase)
    ));
    let unlocked = pgp_secret_key(secret, "stegpony test".into()).unwrap();
    assert_eq!(unlocked.info, public);
    assert_eq!(
        identity_key_pair(unlocked.identity).unwrap().recipient,
        public.recipient
    );
    assert!(matches!(
        pgp_secret_key(fixture("pgp/v4_cv25519_stub_secret.asc"), String::new()),
        Err(StegError::SecretNotInFile)
    ));
    assert!(matches!(
        pgp_public_key(fixture("pgp/v4_rsa_public.asc")),
        Err(StegError::BadKey { .. })
    ));
}

#[test]
fn versions() {
    assert_eq!(format_version(), 1);
    assert!(!core_version().is_empty());
}

#[test]
fn text_fit_sizes() {
    let words = text_fit(TextMode::Words, text_payload_len("hi".into()), None);
    assert!(words.fits);
    assert_eq!(words.size, 134);
    assert_eq!(words.bucket_payload_bytes, 48);
    let zw = text_fit(TextMode::ZeroWidth, text_payload_len("hi".into()), None);
    assert_eq!(zw.size, 800);
    let decoy = text_fit(TextMode::Words, 10, Some(100));
    assert!(decoy.size > words.size);
    let big = text_fit(TextMode::Words, words.max_payload_bytes + 1, None);
    assert!(!big.fits && big.size == 0);
    assert_eq!(words.max_text_bytes + 5, words.max_payload_bytes);
}

#[test]
fn text_round_trips_with_decoy_and_card() {
    let good = card(9, || None);
    let real = text("the spare key is in the shed");
    let fake = text("pick up milk");
    for mode in [TextMode::Words, TextMode::ZeroWidth] {
        let t = hide_text(
            mode,
            "Are we still on for Saturday?".into(),
            real.clone(),
            HideSecret::Recipient {
                recipient: good.recipient(),
            },
            Some(Decoy {
                payload: fake.clone(),
                secret: pass("decoy"),
            }),
        )
        .unwrap();
        let devices: Vec<Arc<dyn KeyDevice>> = vec![good.clone()];
        let got = reveal_text(t.clone(), vec![], devices).unwrap();
        assert_eq!(
            got,
            TextReveal {
                payload: Some(real.clone()),
                mode
            }
        );
        let got = reveal_text(t.clone(), vec![reveal_pass("decoy")], vec![]).unwrap();
        assert_eq!(got.payload, Some(fake.clone()));
        let got = reveal_text(t, vec![reveal_pass("wrong")], vec![]).unwrap();
        assert_eq!(
            got,
            TextReveal {
                payload: None,
                mode
            }
        );
    }
}

#[test]
fn text_errors() {
    match reveal_text(
        "Hello there, how are you?".into(),
        vec![reveal_pass("x")],
        vec![],
    ) {
        Err(StegError::NotStegText { word }) => assert_eq!(word, "Hello"),
        other => panic!("{other:?}"),
    }
    let t = hide_text(TextMode::Words, String::new(), text("x"), pass("p"), None).unwrap();
    let cut = t.rsplit_once(' ').unwrap().0.to_string();
    assert!(matches!(
        reveal_text(cut, vec![reveal_pass("p")], vec![]),
        Err(StegError::TextIncomplete)
    ));
    assert!(matches!(
        hide_text(
            TextMode::ZeroWidth,
            " \n".into(),
            text("x"),
            pass("p"),
            None
        ),
        Err(StegError::CoverTextEmpty)
    ));
    let cancelled = card(3, || Some(DeviceError::Cancelled));
    let t = hide_text(
        TextMode::Words,
        String::new(),
        text("x"),
        HideSecret::Recipient {
            recipient: cancelled.recipient(),
        },
        None,
    )
    .unwrap();
    let devices: Vec<Arc<dyn KeyDevice>> = vec![cancelled];
    assert!(matches!(
        reveal_text(t, vec![], devices),
        Err(StegError::DeviceCancelled)
    ));
}

#[test]
fn channel_preparation_returns_a_new_cover_for_fit_and_hide() {
    let profiles = channel_profiles();
    assert_eq!(profiles.len(), 1);
    let profile = &profiles[0];
    assert_eq!(profile.channel, Channel::TelegramPhotoV1);
    assert_eq!((profile.max_long_edge, profile.quality), (1280, 72));
    assert!(profile.experimental && profile.last_verified.is_none());
    let source = Cover::new(fixture("cover_rgb.png")).unwrap();
    let source_capacity = source.capacity(ImageMode::Lossless).unwrap();
    let prepared = source.prepare_for_channel(profile.channel).unwrap();
    assert_eq!(prepared.cover.format(), ImageFormat::Jpeg);
    assert_eq!(prepared.report.profile_id, profile.id);
    assert_eq!(prepared.report.profile_revision, profile.revision);
    assert!(prepared.report.output_width <= 1280 && prepared.report.output_height <= 1280);
    assert_eq!(source.format(), ImageFormat::Png);
    assert_eq!(
        source.capacity(ImageMode::Lossless).unwrap(),
        source_capacity
    );
    assert!(source.capacity(ImageMode::Jpeg).is_err());
    let cap = prepared.cover.capacity(ImageMode::Jpeg).unwrap();
    assert!(cap.max_text_bytes > 0);
    let fit = prepared
        .cover
        .fit(
            ImageMode::Jpeg,
            text_payload_len("real".into()),
            Some(text_payload_len("decoy".into())),
        )
        .unwrap();
    assert!(fit.fits);
    let out = prepared
        .cover
        .hide(
            ImageMode::Jpeg,
            text("real"),
            pass("real key"),
            Some(Decoy {
                payload: text("decoy"),
                secret: pass("decoy key"),
            }),
            false,
        )
        .unwrap();
    assert_eq!(out.format, ImageFormat::Jpeg);
    assert_eq!(
        reveal(out.image.clone(), vec![reveal_pass("real key")], vec![]).unwrap(),
        Some(text("real"))
    );
    assert_eq!(
        reveal(out.image, vec![reveal_pass("decoy key")], vec![]).unwrap(),
        Some(text("decoy"))
    );
}

#[test]
fn channel_preparation_reports_unsupported_covers() {
    let cover = Cover::new(fixture("jpeg/cmyk.jpg")).unwrap();
    assert!(matches!(
        cover.prepare_for_channel(Channel::TelegramPhotoV1),
        Err(StegError::UnsupportedCover { .. })
    ));
    let bad = Cover::new(b"\xff\xd8\xfftruncated".to_vec()).unwrap();
    assert!(bad.prepare_for_channel(Channel::TelegramPhotoV1).is_err());
    assert!(matches!(
        StegError::from(stegpony_core::Error::PreparationFailed("limit".into())),
        StegError::PreparationFailed { .. }
    ));
}
