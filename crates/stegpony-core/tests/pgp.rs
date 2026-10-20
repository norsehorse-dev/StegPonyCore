//! OpenPGP Curve25519 keys as StegPony keys. Fixtures under tests/fixtures/pgp were made
//! with GnuPG 2.4.4 and are published test keys (passphrase "stegpony test").
use pgp::composed::{
    EncryptionCaps, KeyType, SecretKeyParamsBuilder, SignedPublicKey, SubkeyParamsBuilder,
};
use pgp::types::KeyVersion;
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use stegpony_core::jpeg::carrier;
use stegpony_core::pgp::{identity_from_pgp, recipient_from_pgp};
use stegpony_core::{Error, HideKey, Payload, RevealKey};

const PASS: &str = "stegpony test";
const PRIMARY: &str = "665B7415C9D6DA016DEDD4A1FDCF756153178D05";
const ENCRYPTION_SUBKEY: &str = "E307B8613923A369799B83BDA826624D510EE185";

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

fn message(e: Error) -> String {
    match e {
        Error::BadKey(m) => m,
        other => panic!("expected BadKey, got {other:?}"),
    }
}

#[test]
fn gnupg_v4_public_key_gives_its_cv25519_subkey() {
    let k = recipient_from_pgp(&fixture("pgp/v4_cv25519_public.asc")).unwrap();
    assert_eq!(k.primary_fingerprint, PRIMARY);
    // The cv25519 subkey, not the primary or the ed25519 signing subkey.
    assert_eq!(k.subkey_fingerprint, ENCRYPTION_SUBKEY);
    assert_eq!(k.user_ids, ["StegPony Test <test@example.invalid>"]);
    // A secret key file works as a recipient too.
    let from_secret = recipient_from_pgp(&fixture("pgp/v4_cv25519_secret.asc")).unwrap();
    assert_eq!(from_secret, k);
}

#[test]
fn gnupg_v4_secret_key_unlocks_to_the_matching_identity() {
    let public = recipient_from_pgp(&fixture("pgp/v4_cv25519_public.asc")).unwrap();
    let (id, info) = identity_from_pgp(&fixture("pgp/v4_cv25519_secret.asc"), PASS).unwrap();
    assert_eq!(info, public);
    assert_eq!(id.recipient(), public.recipient);
    let wrong = identity_from_pgp(&fixture("pgp/v4_cv25519_secret.asc"), "nope").unwrap_err();
    assert!(message(wrong).contains("wrong passphrase"));
}

#[test]
fn missing_secret_is_reported_as_such() {
    // The encryption subkey's secret deleted from GnuPG's agent before export: GnuPG
    // writes a gnu-dummy stub in its place, the same shape as a key moved to a
    // hardware token.
    let e = identity_from_pgp(&fixture("pgp/v4_cv25519_stub_secret.asc"), PASS).unwrap_err();
    assert!(message(e).contains("not in the file"));
    // The public half still works as a recipient.
    let r = recipient_from_pgp(&fixture("pgp/v4_cv25519_stub_secret.asc")).unwrap();
    assert_eq!(r.subkey_fingerprint, ENCRYPTION_SUBKEY);
    // Exported with only the signing subkey: the encryption subkey is not in the file
    // at all.
    let e =
        identity_from_pgp(&fixture("pgp/v4_cv25519_no_encryption_secret.asc"), PASS).unwrap_err();
    assert!(message(e).contains("no Curve25519 encryption subkey"));
}

#[test]
fn rsa_and_nist_keys_are_refused() {
    for f in ["pgp/v4_rsa_public.asc", "pgp/v4_p256_public.asc"] {
        let e = recipient_from_pgp(&fixture(f)).unwrap_err();
        assert!(message(e).contains("Curve25519"), "{f}");
    }
    assert!(recipient_from_pgp(b"not a key").is_err());
    assert!(identity_from_pgp(&fixture("pgp/v4_cv25519_public.asc"), PASS).is_err());
}

#[test]
fn v6_x25519_key_round_trip() {
    let mut rng = ChaCha20Rng::seed_from_u64(61);
    let key = SecretKeyParamsBuilder::default()
        .version(KeyVersion::V6)
        .key_type(KeyType::Ed25519)
        .can_certify(true)
        .can_sign(true)
        .primary_user_id("V6 Test <v6@example.invalid>".into())
        .passphrase(Some(PASS.into()))
        .subkey(
            SubkeyParamsBuilder::default()
                .version(KeyVersion::V6)
                .key_type(KeyType::X25519)
                .can_encrypt(EncryptionCaps::All)
                .passphrase(Some(PASS.into()))
                .build()
                .unwrap(),
        )
        .build()
        .unwrap()
        .generate(&mut rng)
        .unwrap();
    let secret = key.to_armored_string(Default::default()).unwrap();
    let public: SignedPublicKey = key.to_public_key();
    let public = public.to_armored_string(Default::default()).unwrap();

    let r = recipient_from_pgp(public.as_bytes()).unwrap();
    let (id, info) = identity_from_pgp(secret.as_bytes(), PASS).unwrap();
    assert_eq!(info, r);
    assert_eq!(id.recipient(), r.recipient);
    assert_eq!(r.subkey_fingerprint.len(), 64); // v6 fingerprints are SHA-256
}

#[test]
fn hide_for_a_pgp_key_and_reveal_with_it() {
    let cover = fixture("jpeg/baseline_420.jpg");
    let r = recipient_from_pgp(&fixture("pgp/v4_cv25519_public.asc")).unwrap();
    let (id, _) = identity_from_pgp(&fixture("pgp/v4_cv25519_secret.asc"), PASS).unwrap();
    let p = Payload::Text("for the PGP key".into());
    let mut rng = ChaCha20Rng::seed_from_u64(62);
    let out = carrier::hide(
        &cover,
        (&p, &HideKey::Recipient(r.recipient)),
        None,
        false,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        carrier::reveal(&out.jpeg, &[RevealKey::Identity(id)]).unwrap(),
        Some(p)
    );
}
