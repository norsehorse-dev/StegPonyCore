//! The headerless envelope. See FORMAT.md, sections 2 and 3.
//!
//! Every byte this module hands to a carrier is indistinguishable from random without
//! the secret: no magic, no version, no length in the clear, no KDF parameters.

use argon2::{Algorithm, Argon2, Params, Version};
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{ChaCha20Poly1305, Nonce};
use curve25519_elligator2::{MapToPointVariant, MontgomeryPoint, Randomized};
use hkdf::Hkdf;
use rand_core::{CryptoRng, RngCore};
use sha2::Sha256;
use subtle::ConstantTimeEq;
use unicode_normalization::UnicodeNormalization;
use zeroize::{Zeroize, Zeroizing};

use crate::error::{Error, Result};
use crate::keys::{Identity, Recipient};

/// Argon2id parameters for format v1. Fixed, because there is no header to carry them.
///
/// Chosen Oct 2026 from `examples/argon2_bench.rs` run on the slowest test phone: about
/// 0.34 s per derivation there, roughly the cost of the earlier 64 MiB / p = 1 draft with
/// twice the memory. Lanes run on threads through the argon2 crate's `parallel`
/// feature; the output does not depend on whether they do.
pub const ARGON2_M_KIB: u32 = 128 * 1024;
pub const ARGON2_T: u32 = 3;
pub const ARGON2_P: u32 = 4;

const LOCATE_SALT: &[u8] = b"StegPony/v1/locate";
const PK_LOCATE_SALT: &[u8] = b"StegPony/v1/pk-locate";
const INFO_LOCATE: &[u8] = b"StegPony/v1/locate";
const INFO_BODY: &[u8] = b"StegPony/v1/body";
const INFO_PRP: &[u8] = b"StegPony/v1/prp";

pub const SALT_LEN: usize = 16;
pub const REPR_LEN: usize = 32;
pub const MASKED_LEN: usize = 4;
pub const TAG_LEN: usize = 16;

/// Head sizes in bytes.
pub const PASSPHRASE_HEAD_LEN: usize = SALT_LEN + MASKED_LEN;
pub const PUBLIC_KEY_HEAD_LEN: usize = REPR_LEN + MASKED_LEN;

/// Number of entries in the bucket table.
pub const NUM_BUCKETS: usize = 37;

/// Ciphertext body size for bucket `k`: 64, 96, 128, 192, 256, 384, ... 16 MiB.
pub fn bucket_size(k: usize) -> usize {
    let base = 64usize << (k / 2);
    if k % 2 == 1 {
        base + base / 2
    } else {
        base
    }
}

/// What gets hidden.
#[derive(Clone, PartialEq, Eq, Debug)]
pub enum Payload {
    Text(String),
    File {
        name: String,
        mime: String,
        data: Vec<u8>,
    },
}

const KIND_TEXT: u8 = 1;
const KIND_FILE: u8 = 2;

impl Payload {
    /// Bytes of plaintext framing this payload needs (before padding and tag).
    pub fn framed_len(&self) -> usize {
        match self {
            Payload::Text(t) => 1 + 4 + t.len(),
            Payload::File { name, mime, data } => {
                1 + 4 + 2 + name.len() + 2 + mime.len() + data.len()
            }
        }
    }

    fn frame_into(&self, out: &mut Vec<u8>) -> Result<()> {
        match self {
            Payload::Text(t) => {
                out.push(KIND_TEXT);
                out.extend_from_slice(&len_u32(t.len())?.to_le_bytes());
                out.extend_from_slice(t.as_bytes());
            }
            Payload::File { name, mime, data } => {
                out.push(KIND_FILE);
                out.extend_from_slice(&len_u32(data.len())?.to_le_bytes());
                out.extend_from_slice(&len_u16(name.len())?.to_le_bytes());
                out.extend_from_slice(name.as_bytes());
                out.extend_from_slice(&len_u16(mime.len())?.to_le_bytes());
                out.extend_from_slice(mime.as_bytes());
                out.extend_from_slice(data);
            }
        }
        Ok(())
    }

    fn parse(buf: &[u8]) -> Option<Payload> {
        let mut r = Reader { buf, pos: 0 };
        match r.u8()? {
            KIND_TEXT => {
                let n = r.u32()? as usize;
                let text = String::from_utf8(r.take(n)?.to_vec()).ok()?;
                Some(Payload::Text(text))
            }
            KIND_FILE => {
                let n = r.u32()? as usize;
                let nl = r.u16()? as usize;
                let name = String::from_utf8(r.take(nl)?.to_vec()).ok()?;
                let ml = r.u16()? as usize;
                let mime = String::from_utf8(r.take(ml)?.to_vec()).ok()?;
                let data = r.take(n)?.to_vec();
                Some(Payload::File { name, mime, data })
            }
            _ => None,
        }
    }
}

fn len_u32(n: usize) -> Result<u32> {
    u32::try_from(n).map_err(|_| Error::BadPayload("payload too large".into()))
}

fn len_u16(n: usize) -> Result<u16> {
    u16::try_from(n).map_err(|_| Error::BadPayload("file name or type too long".into()))
}

struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let s = self.buf.get(self.pos..end)?;
        self.pos = end;
        Some(s)
    }
    fn u8(&mut self) -> Option<u8> {
        Some(self.take(1)?[0])
    }
    fn u16(&mut self) -> Option<u16> {
        Some(u16::from_le_bytes(self.take(2)?.try_into().ok()?))
    }
    fn u32(&mut self) -> Option<u32> {
        Some(u32::from_le_bytes(self.take(4)?.try_into().ok()?))
    }
}

/// The secret a payload is hidden under.
#[derive(Clone)]
pub enum HideKey {
    Passphrase(Zeroizing<String>),
    Recipient(Recipient),
}

/// A secret to try when revealing.
#[derive(Clone)]
pub enum RevealKey {
    Passphrase(Zeroizing<String>),
    Identity(Identity),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Mode {
    Passphrase,
    PublicKey,
}

impl Mode {
    pub fn head_len(self) -> usize {
        match self {
            Mode::Passphrase => PASSPHRASE_HEAD_LEN,
            Mode::PublicKey => PUBLIC_KEY_HEAD_LEN,
        }
    }
}

/// An envelope ready to be written into one slot.
pub(crate) struct Sealed {
    pub mode: Mode,
    pub locate: Zeroizing<[u8; 32]>,
    pub head: Vec<u8>,
    pub body: Vec<u8>,
}

/// A locate key derived for reveal, before the head has been read.
pub(crate) struct Locator<'k> {
    pub mode: Mode,
    pub locate: Zeroizing<[u8; 32]>,
    pub key: &'k RevealKey,
}

/// Keys recovered from a head.
pub(crate) struct OpenedHead {
    key: Zeroizing<[u8; 32]>,
    pub bucket: usize,
}

pub(crate) fn argon2(password: &[u8], salt: &[u8]) -> Result<Zeroizing<[u8; 32]>> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(32))
        .map_err(|e| Error::Kdf(e.to_string()))?;
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = Zeroizing::new([0u8; 32]);
    a.hash_password_into(password, salt, out.as_mut())
        .map_err(|e| Error::Kdf(e.to_string()))?;
    Ok(out)
}

pub(crate) fn normalized(pass: &str) -> Zeroizing<Vec<u8>> {
    let s: String = pass.nfc().collect();
    let mut s = Zeroizing::new(s);
    let v = Zeroizing::new(s.as_bytes().to_vec());
    s.zeroize();
    v
}

pub(crate) fn passphrase_locate(pass: &str) -> Result<Zeroizing<[u8; 32]>> {
    argon2(&normalized(pass), LOCATE_SALT)
}

pub(crate) fn public_key_locate(recipient: &Recipient) -> Zeroizing<[u8; 32]> {
    let hk = Hkdf::<Sha256>::new(Some(PK_LOCATE_SALT), recipient.as_bytes());
    let mut out = Zeroizing::new([0u8; 32]);
    hk.expand(INFO_LOCATE, out.as_mut())
        .expect("32 bytes is a valid length");
    out
}

/// SipHash key for the position permutation of one slot.
pub(crate) fn prp_key(locate: &[u8; 32], slot: u8) -> [u8; 16] {
    let hk = Hkdf::<Sha256>::from_prk(locate).expect("32-byte prk");
    let mut info = INFO_PRP.to_vec();
    info.push(slot);
    let mut out = [0u8; 16];
    hk.expand(&info, &mut out)
        .expect("16 bytes is a valid length");
    out
}

pub(crate) fn body_okm(prk_ikm: &[u8], salt: Option<&[u8]>) -> Zeroizing<[u8; 36]> {
    let hk = Hkdf::<Sha256>::new(salt, prk_ikm);
    let mut okm = Zeroizing::new([0u8; 36]);
    hk.expand(INFO_BODY, okm.as_mut())
        .expect("36 bytes is a valid length");
    okm
}

fn split_okm(okm: &[u8; 36]) -> (Zeroizing<[u8; 32]>, [u8; 4]) {
    let mut key = Zeroizing::new([0u8; 32]);
    key.copy_from_slice(&okm[..32]);
    let mask: [u8; 4] = okm[32..36].try_into().expect("4 bytes");
    (key, mask)
}

/// Smallest bucket that holds `framed` bytes of plaintext, at or above `min_bucket`.
pub fn bucket_for(framed: usize, min_bucket: usize) -> Result<usize> {
    let need = framed + TAG_LEN;
    (min_bucket..NUM_BUCKETS)
        .find(|&k| bucket_size(k) >= need)
        .ok_or_else(|| Error::BadPayload("payload larger than the largest bucket".into()))
}

/// Seals a payload into a headless envelope for one slot.
pub(crate) fn seal<R: RngCore + CryptoRng>(
    payload: &Payload,
    key: &HideKey,
    bucket: usize,
    rng: &mut R,
) -> Result<Sealed> {
    let size = bucket_size(bucket);
    let mut plain = Zeroizing::new(Vec::with_capacity(size));
    payload.frame_into(&mut plain)?;
    if plain.len() + TAG_LEN > size {
        return Err(Error::BadPayload("bucket too small for payload".into()));
    }
    plain.resize(size - TAG_LEN, 0);

    let (mode, locate, head_prefix, okm) = match key {
        HideKey::Passphrase(pass) => {
            let locate = passphrase_locate(pass)?;
            let mut salt = [0u8; SALT_LEN];
            rng.try_fill_bytes(&mut salt).map_err(|_| Error::Rng)?;
            let content = argon2(&normalized(pass), &salt)?;
            let okm = body_okm(content.as_ref(), None);
            (Mode::Passphrase, locate, salt.to_vec(), okm)
        }
        HideKey::Recipient(recipient) => {
            let locate = public_key_locate(recipient);
            let (repr, shared) = ephemeral_exchange(recipient, rng)?;
            let mut salt = repr.to_vec();
            salt.extend_from_slice(recipient.as_bytes());
            let okm = body_okm(shared.as_ref(), Some(&salt));
            (Mode::PublicKey, locate, repr.to_vec(), okm)
        }
    };

    let (aead_key, mask) = split_okm(&okm);
    let cipher = ChaCha20Poly1305::new_from_slice(aead_key.as_ref()).expect("32-byte key");
    let body = cipher
        .encrypt(&Nonce::default(), plain.as_slice())
        .map_err(|_| Error::Embed("encryption failed".into()))?;
    debug_assert_eq!(body.len(), size);

    let mut head = head_prefix;
    let masked = (bucket as u32).to_le_bytes();
    head.extend(masked.iter().zip(mask.iter()).map(|(a, b)| a ^ b));
    Ok(Sealed {
        mode,
        locate,
        head,
        body,
    })
}

/// Random bytes shaped like a sealed envelope, for a slot that carries nothing.
pub(crate) fn filler<R: RngCore + CryptoRng>(bucket: usize, rng: &mut R) -> Result<Sealed> {
    let mut locate = Zeroizing::new([0u8; 32]);
    rng.try_fill_bytes(locate.as_mut())
        .map_err(|_| Error::Rng)?;
    let mut head = vec![0u8; PASSPHRASE_HEAD_LEN];
    rng.try_fill_bytes(&mut head).map_err(|_| Error::Rng)?;
    let mut body = vec![0u8; bucket_size(bucket)];
    rng.try_fill_bytes(&mut body).map_err(|_| Error::Rng)?;
    Ok(Sealed {
        mode: Mode::Passphrase,
        locate,
        head,
        body,
    })
}

/// X25519 with an Elligator 2 encoded, torsion-dirty ephemeral key.
fn ephemeral_exchange<R: RngCore + CryptoRng>(
    recipient: &Recipient,
    rng: &mut R,
) -> Result<([u8; REPR_LEN], Zeroizing<[u8; 32]>)> {
    for _ in 0..128 {
        let mut eph = Zeroizing::new([0u8; 32]);
        rng.try_fill_bytes(eph.as_mut()).map_err(|_| Error::Rng)?;
        let mut tweak = [0u8; 1];
        rng.try_fill_bytes(&mut tweak).map_err(|_| Error::Rng)?;
        let repr: Option<[u8; 32]> = Randomized::to_representative(&eph, tweak[0]).into();
        if let Some(repr) = repr {
            let shared = MontgomeryPoint(*recipient.as_bytes()).mul_clamped(*eph);
            let shared = Zeroizing::new(shared.to_bytes());
            if bool::from(shared.ct_eq(&[0u8; 32])) {
                return Err(Error::WeakRecipient);
            }
            return Ok((repr, shared));
        }
    }
    Err(Error::Rng)
}

/// Locate keys to try for a set of reveal keys. Passphrase locate keys cost one Argon2id
/// run each, so this is done once per reveal, not once per slot.
pub(crate) fn locators(keys: &[RevealKey]) -> Result<Vec<Locator<'_>>> {
    let mut out = Vec::with_capacity(keys.len());
    for key in keys {
        match key {
            RevealKey::Passphrase(p) => out.push(Locator {
                mode: Mode::Passphrase,
                locate: passphrase_locate(p)?,
                key,
            }),
            RevealKey::Identity(id) => out.push(Locator {
                mode: Mode::PublicKey,
                locate: public_key_locate(&id.recipient()),
                key,
            }),
        }
    }
    Ok(out)
}

/// Derives the body key from a head. Returns `None` when the head cannot belong to this
/// key (bucket index out of range); a wrong key that happens to pass is caught by the tag.
pub(crate) fn open_head(key: &RevealKey, head: &[u8]) -> Result<Option<OpenedHead>> {
    let okm = match key {
        RevealKey::Passphrase(pass) => {
            if head.len() != PASSPHRASE_HEAD_LEN {
                return Ok(None);
            }
            let content = argon2(&normalized(pass), &head[..SALT_LEN])?;
            body_okm(content.as_ref(), None)
        }
        RevealKey::Identity(id) => {
            if head.len() != PUBLIC_KEY_HEAD_LEN {
                return Ok(None);
            }
            let repr: [u8; 32] = head[..REPR_LEN].try_into().expect("32 bytes");
            let point = match MontgomeryPoint::from_representative::<Randomized>(&repr) {
                Some(p) => p,
                None => return Ok(None),
            };
            let shared = Zeroizing::new(point.mul_clamped(id.secret_bytes()).to_bytes());
            if bool::from(shared.ct_eq(&[0u8; 32])) {
                return Ok(None);
            }
            let mut salt = repr.to_vec();
            salt.extend_from_slice(id.recipient().as_bytes());
            body_okm(shared.as_ref(), Some(&salt))
        }
    };
    let (key, mask) = split_okm(&okm);
    let masked = &head[head.len() - MASKED_LEN..];
    let mut idx = [0u8; MASKED_LEN];
    for ((o, a), b) in idx.iter_mut().zip(masked).zip(mask.iter()) {
        *o = a ^ b;
    }
    let bucket = u32::from_le_bytes(idx) as usize;
    if bucket >= NUM_BUCKETS {
        return Ok(None);
    }
    Ok(Some(OpenedHead { key, bucket }))
}

/// Decrypts a body. `None` on any failure.
pub(crate) fn open_body(opened: &OpenedHead, body: &[u8]) -> Option<Payload> {
    let cipher = ChaCha20Poly1305::new_from_slice(opened.key.as_ref()).ok()?;
    let plain = Zeroizing::new(cipher.decrypt(&Nonce::default(), body).ok()?);
    Payload::parse(&plain)
}

#[cfg(test)]
mod tests {
    use super::*;
    use curve25519_elligator2::EdwardsPoint;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;

    fn pass(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn bucket_table() {
        assert_eq!(bucket_size(0), 64);
        assert_eq!(bucket_size(1), 96);
        assert_eq!(bucket_size(2), 128);
        assert_eq!(bucket_size(3), 192);
        assert_eq!(bucket_size(NUM_BUCKETS - 1), 16 * 1024 * 1024);
        for k in 1..NUM_BUCKETS {
            assert!(bucket_size(k) > bucket_size(k - 1));
        }
        assert_eq!(bucket_for(48, 0).unwrap(), 0);
        assert_eq!(bucket_for(49, 0).unwrap(), 1);
        assert_eq!(bucket_for(1, 5).unwrap(), 5);
    }

    #[test]
    fn framing_roundtrip() {
        for p in [
            Payload::Text(String::new()),
            Payload::Text("héllo".into()),
            Payload::File {
                name: "a.age".into(),
                mime: "application/octet-stream".into(),
                data: vec![1, 2, 3],
            },
        ] {
            let mut v = Vec::new();
            p.frame_into(&mut v).unwrap();
            assert_eq!(v.len(), p.framed_len());
            v.extend_from_slice(&[0; 20]);
            assert_eq!(Payload::parse(&v).unwrap(), p);
        }
    }

    fn roundtrip(hide: HideKey, reveal: RevealKey) {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let p = Payload::Text("meet at the usual place".into());
        let k = bucket_for(p.framed_len(), 0).unwrap();
        let sealed = seal(&p, &hide, k, &mut rng).unwrap();
        assert_eq!(sealed.head.len(), sealed.mode.head_len());
        assert_eq!(sealed.body.len(), bucket_size(k));
        let keys = [reveal];
        let locs = locators(&keys).unwrap();
        assert_eq!(*locs[0].locate, *sealed.locate);
        assert_eq!(locs[0].mode, sealed.mode);
        let opened = open_head(&keys[0], &sealed.head).unwrap().unwrap();
        assert_eq!(opened.bucket, k);
        assert_eq!(open_body(&opened, &sealed.body).unwrap(), p);
    }

    #[test]
    fn passphrase_roundtrip() {
        roundtrip(
            HideKey::Passphrase(pass("correct horse")),
            RevealKey::Passphrase(pass("correct horse")),
        );
    }

    #[test]
    fn passphrase_is_nfc_normalized() {
        roundtrip(
            HideKey::Passphrase(pass("caf\u{e9}")),
            RevealKey::Passphrase(pass("cafe\u{301}")),
        );
    }

    #[test]
    fn public_key_roundtrip() {
        let mut rng = ChaCha20Rng::seed_from_u64(2);
        for _ in 0..8 {
            let id = Identity::generate(&mut rng);
            roundtrip(HideKey::Recipient(id.recipient()), RevealKey::Identity(id));
        }
    }

    #[test]
    fn wrong_keys_fail() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let p = Payload::Text("x".into());
        let sealed = seal(&p, &HideKey::Passphrase(pass("one")), 0, &mut rng).unwrap();
        let wrong = RevealKey::Passphrase(pass("two"));
        if let Some(h) = open_head(&wrong, &sealed.head).unwrap() {
            assert!(open_body(&h, &sealed.body).is_none());
        }
        let id = Identity::generate(&mut rng);
        let other = Identity::generate(&mut rng);
        let sealed = seal(&p, &HideKey::Recipient(id.recipient()), 0, &mut rng).unwrap();
        let wrong = RevealKey::Identity(other);
        if let Some(h) = open_head(&wrong, &sealed.head).unwrap() {
            assert!(open_body(&h, &sealed.body).is_none());
        }
    }

    /// Representatives must decode to points of every torsion class, not only the
    /// prime-order subgroup, or they are distinguishable from random strings.
    #[test]
    fn representatives_are_torsion_dirty_and_high_bits_vary() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let id = Identity::generate(&mut rng);
        let mut torsion_free = 0;
        let mut high = [0usize; 4];
        let n = 400;
        for _ in 0..n {
            let (repr, _) = ephemeral_exchange(&id.recipient(), &mut rng).unwrap();
            high[(repr[31] >> 6) as usize] += 1;
            let p: Option<EdwardsPoint> = Randomized::from_representative(&repr).into();
            if p.unwrap().is_torsion_free() {
                torsion_free += 1;
            }
        }
        assert!(
            torsion_free > n / 16 && torsion_free < n / 4,
            "torsion_free = {torsion_free}"
        );
        for h in high {
            assert!(h > n / 8, "high bits {high:?}");
        }
    }

    #[test]
    fn low_order_recipient_rejected() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let zero = Recipient::from_bytes([0u8; 32]);
        let p = Payload::Text("x".into());
        assert!(matches!(
            seal(&p, &HideKey::Recipient(zero), 0, &mut rng),
            Err(Error::WeakRecipient)
        ));
    }
}
