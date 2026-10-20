//! X25519 keys in age's text encoding.
//!
//! StegPony reuses age's key type and Bech32 encoding, so an `age1...` recipient is a
//! StegPony recipient and an `AGE-SECRET-KEY-1...` identity can be imported as is.
//! Only the keys are shared with age; the hidden data is not age format.

use bech32::primitives::decode::CheckedHrpstring;
use bech32::{Bech32, Hrp};
use curve25519_elligator2::MontgomeryPoint;
use rand_core::{CryptoRng, RngCore};
use zeroize::{Zeroize, ZeroizeOnDrop};

use crate::error::{Error, Result};

const RECIPIENT_HRP: &str = "age";
const IDENTITY_HRP: &str = "age-secret-key-";

/// A public key that payloads can be hidden for.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Recipient(pub(crate) [u8; 32]);

/// A secret key that reveals payloads hidden for its recipient.
#[derive(Clone, Zeroize, ZeroizeOnDrop)]
pub struct Identity(pub(crate) [u8; 32]);

impl Recipient {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Recipient(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Parses an `age1...` recipient string.
    pub fn parse(s: &str) -> Result<Self> {
        let bytes = decode_bech32(s.trim(), RECIPIENT_HRP)?;
        Ok(Recipient(bytes))
    }

    /// The `age1...` text form.
    pub fn to_age_string(&self) -> String {
        let hrp = Hrp::parse(RECIPIENT_HRP).expect("static hrp");
        bech32::encode_lower::<Bech32>(hrp, &self.0).expect("32 bytes always encodes")
    }
}

impl core::fmt::Display for Recipient {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.to_age_string())
    }
}

impl Identity {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Identity(bytes)
    }

    pub fn generate<R: RngCore + CryptoRng>(rng: &mut R) -> Self {
        let mut sk = [0u8; 32];
        rng.fill_bytes(&mut sk);
        Identity(sk)
    }

    /// Parses an `AGE-SECRET-KEY-1...` identity string.
    pub fn parse(s: &str) -> Result<Self> {
        let bytes = decode_bech32(s.trim(), IDENTITY_HRP)?;
        Ok(Identity(bytes))
    }

    /// Parses the first identity line in an age identity file (comments and blank lines
    /// are skipped, as age itself does).
    pub fn parse_file(contents: &str) -> Result<Vec<Self>> {
        let mut out = Vec::new();
        for line in contents.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            out.push(Identity::parse(line)?);
        }
        if out.is_empty() {
            return Err(Error::BadKey("no identity found".into()));
        }
        Ok(out)
    }

    /// The `AGE-SECRET-KEY-1...` text form.
    pub fn to_age_string(&self) -> String {
        let hrp = Hrp::parse(IDENTITY_HRP).expect("static hrp");
        bech32::encode_upper::<Bech32>(hrp, &self.0).expect("32 bytes always encodes")
    }

    pub fn recipient(&self) -> Recipient {
        Recipient(MontgomeryPoint::mul_base_clamped(self.0).to_bytes())
    }

    pub(crate) fn secret_bytes(&self) -> [u8; 32] {
        self.0
    }
}

impl core::fmt::Debug for Identity {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Identity({})", self.recipient())
    }
}

fn decode_bech32(s: &str, expected_hrp: &str) -> Result<[u8; 32]> {
    let checked = CheckedHrpstring::new::<Bech32>(s)
        .map_err(|e| Error::BadKey(format!("not an age key: {e}")))?;
    let hrp = checked.hrp().to_lowercase();
    if hrp != expected_hrp {
        return Err(Error::BadKey(format!(
            "expected the \"{expected_hrp}\" prefix, found \"{hrp}\""
        )));
    }
    let bytes: Vec<u8> = checked.byte_iter().collect();
    bytes
        .try_into()
        .map_err(|_| Error::BadKey("wrong key length".into()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::SeedableRng;

    #[test]
    fn roundtrip_and_matches_age() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(7);
        for _ in 0..20 {
            let id = Identity::generate(&mut rng);
            let id_str = id.to_age_string();
            let parsed = Identity::parse(&id_str).unwrap();
            assert_eq!(parsed.secret_bytes(), id.secret_bytes());

            let age_id: age::x25519::Identity = id_str.parse().unwrap();
            assert_eq!(
                age_id.to_public().to_string(),
                id.recipient().to_age_string()
            );

            let r = Recipient::parse(&id.recipient().to_age_string()).unwrap();
            assert_eq!(r, id.recipient());
        }
    }

    #[test]
    fn rejects_wrong_prefix_and_checksum() {
        let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(8);
        let id = Identity::generate(&mut rng);
        assert!(Recipient::parse(&id.to_age_string()).is_err());
        assert!(Identity::parse(&id.recipient().to_age_string()).is_err());
        let mut bad = id.recipient().to_age_string();
        let last = bad.pop().unwrap();
        bad.push(if last == 'q' { 'p' } else { 'q' });
        assert!(Recipient::parse(&bad).is_err());
    }

    #[test]
    fn rejects_bech32m() {
        let hrp = Hrp::parse("age").unwrap();
        let s = bech32::encode_lower::<bech32::Bech32m>(hrp, &[7u8; 32]).unwrap();
        assert!(Recipient::parse(&s).is_err());
    }
}
