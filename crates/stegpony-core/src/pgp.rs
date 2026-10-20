//! OpenPGP Curve25519 keys as StegPony keys.
//!
//! A Curve25519 OpenPGP encryption subkey (v4 ECDH on Curve25519, or v6 X25519) holds
//! the same kind of X25519 key the envelope uses, so it can serve as a StegPony
//! recipient and, once unlocked, as an identity. Only the key is shared: StegPony's
//! key derivation is its own (FORMAT.md section 3), so the same key used for OpenPGP
//! messages and for StegPony images gives unrelated derived keys.
//!
//! RSA, NIST-curve, X448 and post-quantum composite keys are refused: the hidden key
//! exchange is X25519 only.

use std::io::Cursor;

use pgp::composed::{Deserializable, SignedPublicKey, SignedSecretKey};
use pgp::crypto::ecdh::SecretKey as EcdhSecret;
use pgp::types::{EcdhPublicParams, KeyDetails, Password, PlainSecretParams, PublicParams};

use crate::error::{Error, Result};
use crate::keys::{Identity, Recipient};

/// What was found in an OpenPGP key: the encryption subkey StegPony uses and how to
/// show it to the user.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PgpKey {
    pub recipient: Recipient,
    /// Fingerprint of the primary key, upper-case hex.
    pub primary_fingerprint: String,
    /// Fingerprint of the encryption subkey used, upper-case hex.
    pub subkey_fingerprint: String,
    /// User IDs as written in the key (not verified).
    pub user_ids: Vec<String>,
}

fn bad(msg: &str) -> Error {
    Error::BadKey(msg.into())
}

const NO_CURVE25519: &str = "this key has no Curve25519 encryption subkey; StegPony works with Curve25519 (cv25519 or X25519) keys only, not RSA, NIST curves or post-quantum keys";

/// The X25519 public key of a Curve25519 encryption key, if it is one.
fn x25519_public(params: &PublicParams) -> Option<[u8; 32]> {
    match params {
        PublicParams::ECDH(EcdhPublicParams::Curve25519Legacy { p, .. }) => Some(p.to_bytes()),
        PublicParams::X25519(x) => Some(x.key.to_bytes()),
        _ => None,
    }
}

fn hex(fp: &pgp::types::Fingerprint) -> String {
    fp.as_bytes().iter().map(|b| format!("{b:02X}")).collect()
}

/// A candidate subkey: index into the key's subkeys, its X25519 key, creation time.
struct Candidate {
    index: usize,
    key: [u8; 32],
    created: u32,
}

/// Picks the newest Curve25519 subkey whose newest binding signature allows
/// encryption. Subkeys without key flags are accepted only when no flagged one exists.
fn pick<'a, I>(subkeys: I) -> Result<Candidate>
where
    I: Iterator<
        Item = (
            usize,
            &'a PublicParams,
            u32,
            Vec<&'a pgp::packet::Signature>,
        ),
    >,
{
    let mut flagged: Option<Candidate> = None;
    let mut unflagged: Option<Candidate> = None;
    for (index, params, created, sigs) in subkeys {
        let Some(key) = x25519_public(params) else {
            continue;
        };
        let newest = sigs
            .into_iter()
            .max_by_key(|s| s.created().map(|t| t.as_secs()).unwrap_or(0));
        let flags = newest.map(|s| s.key_flags());
        let encrypts = flags
            .as_ref()
            .is_some_and(|f| f.encrypt_comms() || f.encrypt_storage());
        let slot = if encrypts {
            &mut flagged
        } else if flags.as_ref().is_some_and(|f| f.sign() || f.certify()) {
            continue;
        } else {
            &mut unflagged
        };
        if slot.as_ref().is_none_or(|c| created > c.created) {
            *slot = Some(Candidate {
                index,
                key,
                created,
            });
        }
    }
    flagged.or(unflagged).ok_or_else(|| bad(NO_CURVE25519))
}

fn user_ids(details: &pgp::composed::SignedKeyDetails) -> Vec<String> {
    details
        .users
        .iter()
        .map(|u| String::from_utf8_lossy(u.id.id()).into_owned())
        .collect()
}

fn read_public(bytes: &[u8]) -> Result<SignedPublicKey> {
    if let Ok((k, _)) = SignedPublicKey::from_reader_single(Cursor::new(bytes)) {
        return Ok(k);
    }
    // A secret key works as a recipient too.
    let (k, _) = SignedSecretKey::from_reader_single(Cursor::new(bytes))
        .map_err(|_| bad("not an OpenPGP key"))?;
    Ok(k.to_public_key())
}

/// Reads a recipient from an OpenPGP public (or secret) key, armored or binary.
pub fn recipient_from_pgp(bytes: &[u8]) -> Result<PgpKey> {
    let key = read_public(bytes)?;
    let c = pick(key.public_subkeys.iter().enumerate().map(|(i, s)| {
        (
            i,
            s.key.public_params(),
            s.key.created_at().as_secs(),
            s.signatures.iter().collect(),
        )
    }))?;
    Ok(PgpKey {
        recipient: Recipient::from_bytes(c.key),
        primary_fingerprint: hex(&key.primary_key.fingerprint()),
        subkey_fingerprint: hex(&key.public_subkeys[c.index].key.fingerprint()),
        user_ids: user_ids(&key.details),
    })
}

/// Why a subkey could not be unlocked: its secret is missing from the file (a GnuPG
/// stub, as left by a hardware key or a partial export), or the passphrase is wrong.
fn unlock_error(key: &pgp::packet::SecretSubkey) -> Error {
    use pgp::types::{S2kParams, SecretParams, StringToKey};
    // GnuPG marks a missing secret with the private S2K type 101 ("gnu-dummy" or
    // "gnu-divert-to-card").
    let stub = match key.secret_params() {
        SecretParams::Encrypted(e) => matches!(
            e.string_to_key_params(),
            S2kParams::Cfb {
                s2k: StringToKey::Private { typ: 101, .. },
                ..
            } | S2kParams::MalleableCfb {
                s2k: StringToKey::Private { typ: 101, .. },
                ..
            } | S2kParams::Aead {
                s2k: StringToKey::Private { typ: 101, .. },
                ..
            }
        ),
        SecretParams::Plain(_) => false,
    };
    if stub {
        bad("this key's encryption secret is not in the file (it may live on a hardware key, or the export left it out)")
    } else {
        bad("wrong passphrase for this key")
    }
}

/// Reads an identity from an OpenPGP secret key, armored or binary, unlocking the
/// encryption subkey with `passphrase` (ignored for an unprotected key).
pub fn identity_from_pgp(bytes: &[u8], passphrase: &str) -> Result<(Identity, PgpKey)> {
    let (key, _) = SignedSecretKey::from_reader_single(Cursor::new(bytes))
        .map_err(|_| bad("not an OpenPGP secret key"))?;
    let c = pick(key.secret_subkeys.iter().enumerate().map(|(i, s)| {
        (
            i,
            s.key.public_key().public_params(),
            s.key.public_key().created_at().as_secs(),
            s.signatures.iter().collect(),
        )
    }))?;
    let sub = &key.secret_subkeys[c.index];
    let pw = Password::from(passphrase);
    let secret = sub
        .key
        .unlock(&pw, |_, plain| {
            Ok(match plain {
                PlainSecretParams::ECDH(EcdhSecret::Curve25519Legacy(k)) => Some(*k.as_bytes()),
                PlainSecretParams::X25519(k) => Some(*k.as_bytes()),
                _ => None,
            })
        })
        .map_err(|_| unlock_error(&sub.key))?
        .map_err(|_| unlock_error(&sub.key))?
        .ok_or_else(|| bad(NO_CURVE25519))?;
    let identity = Identity::from_bytes(secret);
    if identity.recipient().as_bytes() != &c.key {
        return Err(bad("the secret does not match its public key"));
    }
    let info = PgpKey {
        recipient: Recipient::from_bytes(c.key),
        primary_fingerprint: hex(&key.primary_key.public_key().fingerprint()),
        subkey_fingerprint: hex(&sub.key.public_key().fingerprint()),
        user_ids: user_ids(&key.details),
    };
    Ok((identity, info))
}
