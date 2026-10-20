//! Reveal with a secret held outside the core, as an OpenPGP card holds it. The stand-in
//! device below uses x25519-dalek's plain X25519, which is what a card computes, so
//! these tests also show the format's torsion-dirty ephemeral points work with
//! ordinary X25519.
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use stegpony_core::jpeg::carrier;
use stegpony_core::{
    lossless, Error, HideKey, Identity, KeyAgreement, Payload, Recipient, RevealKey,
};

struct Device {
    secret: [u8; 32],
    calls: AtomicUsize,
    fail: bool,
}

impl Device {
    fn new(id: &Identity) -> Arc<Self> {
        Arc::new(Device {
            secret: secret_of(id),
            calls: AtomicUsize::new(0),
            fail: false,
        })
    }
}

fn secret_of(id: &Identity) -> [u8; 32] {
    // The core keeps an identity's bytes private; read them back from its age string,
    // as importing the key onto a card would.
    use bech32::primitives::decode::CheckedHrpstring;
    let s = id.to_age_string();
    let c = CheckedHrpstring::new::<bech32::Bech32>(&s).unwrap();
    c.byte_iter().collect::<Vec<u8>>().try_into().unwrap()
}

impl KeyAgreement for Device {
    fn recipient(&self) -> Recipient {
        let s = x25519_dalek::StaticSecret::from(self.secret);
        Recipient::from_bytes(*x25519_dalek::PublicKey::from(&s).as_bytes())
    }
    fn agree(&self, point: &[u8; 32]) -> Result<[u8; 32], String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.fail {
            return Err("PIN entry cancelled".into());
        }
        let s = x25519_dalek::StaticSecret::from(self.secret);
        Ok(*s
            .diffie_hellman(&x25519_dalek::PublicKey::from(*point))
            .as_bytes())
    }
}

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn device_reveals_what_was_hidden_for_its_recipient() {
    let mut rng = ChaCha20Rng::seed_from_u64(71);
    let id = Identity::generate(&mut rng);
    let device = Device::new(&id);
    assert_eq!(device.recipient(), id.recipient());
    for seed in 0..6u64 {
        // Several images, so the ephemeral points cover different low-order components.
        let mut rng = ChaCha20Rng::seed_from_u64(100 + seed);
        let p = Payload::Text(format!("for the card {seed}"));
        let out = carrier::hide(
            &fixture("jpeg/baseline_420.jpg"),
            (&p, &HideKey::Recipient(id.recipient())),
            None,
            false,
            &mut rng,
        )
        .unwrap();
        device.calls.store(0, Ordering::SeqCst);
        let key = RevealKey::External(device.clone());
        assert_eq!(carrier::reveal(&out.jpeg, &[key]).unwrap(), Some(p));
        let calls = device.calls.load(Ordering::SeqCst);
        assert!((1..=2).contains(&calls), "{calls} device operations");
    }
}

#[test]
fn wrong_device_finds_nothing_and_a_failing_device_is_reported() {
    let mut rng = ChaCha20Rng::seed_from_u64(72);
    let id = Identity::generate(&mut rng);
    let other = Identity::generate(&mut rng);
    let p = Payload::Text("png too".into());
    let out = lossless::hide(
        &fixture("cover_rgb.png"),
        (&p, &HideKey::Recipient(id.recipient())),
        None,
        &mut rng,
    )
    .unwrap();
    let wrong = RevealKey::External(Device::new(&other));
    assert_eq!(lossless::reveal(&out.png, &[wrong]).unwrap(), None);
    let right = RevealKey::External(Device::new(&id));
    assert_eq!(lossless::reveal(&out.png, &[right]).unwrap(), Some(p));
    let failing = Arc::new(Device {
        secret: secret_of(&id),
        calls: AtomicUsize::new(0),
        fail: true,
    });
    let e = lossless::reveal(&out.png, &[RevealKey::External(failing)]).unwrap_err();
    assert!(
        matches!(e, Error::KeyDevice(ref m) if m.contains("PIN")),
        "{e}"
    );
}

#[test]
fn text_reveals_with_a_device_and_asks_at_most_once_per_slot() {
    use stegpony_core::text::{self, TextFound, TextMode};
    let mut rng = ChaCha20Rng::seed_from_u64(91);
    let id = Identity::generate(&mut rng);
    let p = Payload::Text("by the old mill".into());
    for mode in [TextMode::Dictionary, TextMode::ZeroWidth] {
        let t = text::hide(
            mode,
            "see you soon",
            (&p, &HideKey::Recipient(id.recipient())),
            None,
            &mut rng,
        )
        .unwrap();
        let dev = Device::new(&id);
        let found = text::reveal(&t, &[RevealKey::External(dev.clone())]).unwrap();
        assert_eq!(found, TextFound::Payload(p.clone(), mode));
        assert!((1..=2).contains(&dev.calls.load(Ordering::SeqCst)));

        let failing = Arc::new(Device {
            secret: secret_of(&id),
            calls: AtomicUsize::new(0),
            fail: true,
        });
        assert!(matches!(
            text::reveal(&t, &[RevealKey::External(failing)]),
            Err(Error::KeyDevice(_))
        ));
    }
}

#[test]
fn text_tries_secrets_in_both_slots_before_a_device() {
    use stegpony_core::text::{self, TextFound, TextMode};
    let id = Identity::generate(&mut ChaCha20Rng::seed_from_u64(5));
    let p = Payload::Text("only the passphrase".into());
    for seed in 0..6 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let t = text::hide(
            TextMode::Dictionary,
            "",
            (
                &p,
                &HideKey::Passphrase(zeroize::Zeroizing::new("pw".into())),
            ),
            None,
            &mut rng,
        )
        .unwrap();
        let dev = Device::new(&id);
        let keys = [
            RevealKey::External(dev.clone()),
            RevealKey::Passphrase(zeroize::Zeroizing::new("pw".into())),
        ];
        assert_eq!(
            text::reveal(&t, &keys).unwrap(),
            TextFound::Payload(p.clone(), TextMode::Dictionary)
        );
        assert_eq!(dev.calls.load(Ordering::SeqCst), 0);
    }
}

#[test]
fn images_try_secrets_in_both_slots_before_a_device() {
    let id = Identity::generate(&mut ChaCha20Rng::seed_from_u64(6));
    let cover = fixture("cover_rgb.png");
    let p = Payload::Text("only the passphrase".into());
    for seed in 0..4 {
        let mut rng = ChaCha20Rng::seed_from_u64(seed);
        let out = lossless::hide(
            &cover,
            (
                &p,
                &HideKey::Passphrase(zeroize::Zeroizing::new("pw".into())),
            ),
            None,
            &mut rng,
        )
        .unwrap();
        let dev = Device::new(&id);
        let keys = [
            RevealKey::External(dev.clone()),
            RevealKey::Passphrase(zeroize::Zeroizing::new("pw".into())),
        ];
        assert_eq!(lossless::reveal(&out.png, &keys).unwrap(), Some(p.clone()));
        assert_eq!(dev.calls.load(Ordering::SeqCst), 0);
    }
}
