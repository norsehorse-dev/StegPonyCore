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
        Err(StegError::KeyDevice { message }) => assert_eq!(message, "tag lost"),
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
