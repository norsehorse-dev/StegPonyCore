//! Text carriers: the envelope bytes written as invisible characters inside a cover
//! message ([`zero_width`]) or as a run of words from a fixed list ([`dictionary`]).
//! FORMAT.md section 7.
//!
//! Text has no cover to modify, so there are no positions to find and no locate keys.
//! The two slots are laid end to end, each a fixed-size head area followed by its body;
//! every byte of both is ciphertext or random, so the order needs no secret.

pub mod dictionary;
pub mod zero_width;

use rand_core::{CryptoRng, RngCore};

use crate::envelope::{
    bucket_for, bucket_size, filler, open_body, open_head, seal_unlocated, HideKey, Mode, Payload,
    RevealKey, Sealed, NUM_BUCKETS, PASSPHRASE_HEAD_LEN, PUBLIC_KEY_HEAD_LEN, TAG_LEN,
};
use crate::error::{Error, Result};

/// Bytes reserved for each slot's head, whichever key it was sealed with. A passphrase
/// head (20 bytes) is followed by random fill, so the key kind does not change the
/// length of the text.
pub const HEAD_AREA: usize = PUBLIC_KEY_HEAD_LEN;

/// The largest bucket StegPony writes into text (16 KiB of ciphertext per slot). A
/// writer limit, not a format rule: readers accept any bucket.
pub const MAX_TEXT_BUCKET: usize = 16;

/// Which text carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TextMode {
    /// Invisible characters inside a cover message the user writes.
    ZeroWidth,
    /// Words from the English list.
    Dictionary,
}

/// Envelope bytes for one bucket: two slots of head area plus body.
pub fn stream_len(bucket: usize) -> usize {
    2 * (HEAD_AREA + bucket_size(bucket))
}

/// Visible size of the output for one bucket: invisible characters for zero-width,
/// words for dictionary.
pub fn symbols_for(mode: TextMode, bucket: usize) -> usize {
    match mode {
        TextMode::ZeroWidth => zero_width::chars_for(stream_len(bucket)),
        TextMode::Dictionary => dictionary::words_for(stream_len(bucket)),
    }
}

/// Bucket that holds the payload and the optional decoy (both use the larger one), or
/// an error when it is beyond what StegPony writes into text.
pub fn bucket_for_text(payload_framed: usize, decoy_framed: Option<usize>) -> Result<usize> {
    let mut k = bucket_for(payload_framed, 0)?;
    if let Some(d) = decoy_framed {
        k = bucket_for(d, k)?;
    }
    if k > MAX_TEXT_BUCKET {
        return Err(Error::PayloadTooLarge {
            needed: payload_framed.max(decoy_framed.unwrap_or(0)),
            available: bucket_size(MAX_TEXT_BUCKET) - TAG_LEN,
        });
    }
    Ok(k)
}

/// Largest text message, in UTF-8 bytes, that fits the largest text bucket.
pub fn max_text_bytes() -> usize {
    bucket_size(MAX_TEXT_BUCKET) - TAG_LEN - 5
}

fn slot_bytes<R: RngCore + CryptoRng>(sealed: &Sealed, rng: &mut R) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(HEAD_AREA + sealed.body.len());
    out.extend_from_slice(&sealed.head);
    let mut fill = vec![0u8; HEAD_AREA - sealed.head.len()];
    rng.try_fill_bytes(&mut fill).map_err(|_| Error::Rng)?;
    out.extend_from_slice(&fill);
    out.extend_from_slice(&sealed.body);
    Ok(out)
}

/// The envelope bytes for a text carrier: the payload (and decoy, or filler) sealed in
/// a common bucket, in an order picked by a fair coin.
pub fn hide_stream<R: RngCore + CryptoRng>(
    primary: (&Payload, &HideKey),
    decoy: Option<(&Payload, &HideKey)>,
    rng: &mut R,
) -> Result<Vec<u8>> {
    let bucket = bucket_for_text(primary.0.framed_len(), decoy.map(|(p, _)| p.framed_len()))?;
    let a = seal_unlocated(primary.0, primary.1, bucket, rng)?;
    let b = match decoy {
        Some((p, k)) => seal_unlocated(p, k, bucket, rng)?,
        None => filler(bucket, rng)?,
    };
    let mut coin = [0u8; 1];
    rng.try_fill_bytes(&mut coin).map_err(|_| Error::Rng)?;
    let (first, second) = if coin[0] & 1 == 0 { (a, b) } else { (b, a) };
    let mut out = slot_bytes(&first, rng)?;
    out.extend(slot_bytes(&second, rng)?);
    debug_assert_eq!(out.len(), stream_len(bucket));
    Ok(out)
}

/// The bucket whose stream is exactly `len` bytes.
pub fn bucket_for_stream_len(len: usize) -> Option<usize> {
    (0..NUM_BUCKETS).find(|&k| stream_len(k) == len)
}

/// Opens a stream recovered from text. `Ok(None)` when no key opens either slot, which
/// is also the answer for a stream that was never StegPony's.
pub fn reveal_stream(stream: &[u8], keys: &[RevealKey]) -> Result<Option<Payload>> {
    let Some(bucket) = bucket_for_stream_len(stream.len()) else {
        return Ok(None);
    };
    let slot_len = HEAD_AREA + bucket_size(bucket);
    // Keys held in memory try both slots before any external key is asked, so a
    // hardware key is touched only when nothing else opens the text.
    let external = |k: &&RevealKey| matches!(k, RevealKey::External(_));
    let software: Vec<&RevealKey> = keys.iter().filter(|k| !external(k)).collect();
    let devices: Vec<&RevealKey> = keys.iter().filter(external).collect();
    for group in [software, devices] {
        for slot in stream.chunks_exact(slot_len) {
            let (area, body) = slot.split_at(HEAD_AREA);
            for key in &group {
                let head_len = match key {
                    RevealKey::Passphrase(_) => PASSPHRASE_HEAD_LEN,
                    RevealKey::Identity(_) | RevealKey::External(_) => Mode::PublicKey.head_len(),
                };
                let Some(opened) = open_head(key, &area[..head_len])? else {
                    continue;
                };
                if opened.bucket != bucket {
                    continue;
                }
                if let Some(p) = open_body(&opened, body) {
                    return Ok(Some(p));
                }
            }
        }
    }
    Ok(None)
}

/// Writes the payload into text. `cover` is the visible message for zero-width mode and
/// is ignored for dictionary mode.
pub fn hide<R: RngCore + CryptoRng>(
    mode: TextMode,
    cover: &str,
    primary: (&Payload, &HideKey),
    decoy: Option<(&Payload, &HideKey)>,
    rng: &mut R,
) -> Result<String> {
    let stream = hide_stream(primary, decoy, rng)?;
    match mode {
        TextMode::ZeroWidth => zero_width::encode(cover, &stream),
        TextMode::Dictionary => dictionary::encode(&stream, rng),
    }
}

/// What a pasted text turned out to be.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TextFound {
    /// A key opened it.
    Payload(Payload, TextMode),
    /// It is shaped like StegPony text, but none of the keys open it. Also the answer
    /// for a wrong key.
    Nothing(TextMode),
}

/// Looks for a payload in pasted text. Invisible characters at word starts are read as
/// zero-width text; otherwise every word must be on the list.
///
/// Errors say why the text cannot be StegPony text at all, which the text itself
/// already shows anyone who looks: [`Error::TextUnknownWord`] when it has no hidden
/// characters and a word is not on the list, [`Error::TextLength`] when the hidden
/// characters or the words are not a whole number of slots (some were lost or added).
pub fn reveal(text: &str, keys: &[RevealKey]) -> Result<TextFound> {
    let stream = match zero_width::decode(text) {
        Some(stream) if bucket_for_stream_len(stream.len()).is_some() => {
            return Ok(match reveal_stream(&stream, keys)? {
                Some(p) => TextFound::Payload(p, TextMode::ZeroWidth),
                None => TextFound::Nothing(TextMode::ZeroWidth),
            });
        }
        // Hidden characters, but not a whole stream: either some were lost, or an app
        // slipped a stray one into word text. Words that read as a whole stream win.
        Some(_) => dictionary::decode(text).map_err(|_| Error::TextLength)?,
        None => dictionary::decode(text)?,
    };
    Ok(match reveal_stream(&stream, keys)? {
        Some(p) => TextFound::Payload(p, TextMode::Dictionary),
        None => TextFound::Nothing(TextMode::Dictionary),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::keys::Identity;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use zeroize::Zeroizing;

    fn pass(s: &str) -> Zeroizing<String> {
        Zeroizing::new(s.to_string())
    }

    #[test]
    fn stream_lengths() {
        assert_eq!(stream_len(0), 200);
        assert_eq!(stream_len(1), 264);
        assert_eq!(bucket_for_stream_len(200), Some(0));
        assert_eq!(bucket_for_stream_len(201), None);
        assert_eq!(symbols_for(TextMode::Dictionary, 0), 134);
        assert_eq!(symbols_for(TextMode::ZeroWidth, 0), 800);
    }

    #[test]
    fn streams_round_trip_both_slots_and_both_key_kinds() {
        let mut rng = ChaCha20Rng::seed_from_u64(7);
        let id = Identity::generate(&mut rng);
        let real = Payload::Text("meet at six".into());
        let fake = Payload::Text("groceries: milk".into());
        for seed in 0..6u64 {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let s = hide_stream(
                (&real, &HideKey::Recipient(id.recipient())),
                Some((&fake, &HideKey::Passphrase(pass("decoy pass")))),
                &mut rng,
            )
            .unwrap();
            assert_eq!(s.len(), 200);
            let got = reveal_stream(&s, &[RevealKey::Identity(id.clone())]).unwrap();
            assert_eq!(got, Some(real.clone()));
            let got = reveal_stream(&s, &[RevealKey::Passphrase(pass("decoy pass"))]).unwrap();
            assert_eq!(got, Some(fake.clone()));
            let got = reveal_stream(&s, &[RevealKey::Passphrase(pass("nope"))]).unwrap();
            assert_eq!(got, None);
        }
    }

    #[test]
    fn decoy_sets_the_bucket() {
        let mut rng = ChaCha20Rng::seed_from_u64(1);
        let small = Payload::Text("hi".into());
        let big = Payload::Text("x".repeat(200));
        let s = hide_stream(
            (&small, &HideKey::Passphrase(pass("a"))),
            Some((&big, &HideKey::Passphrase(pass("b")))),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            s.len(),
            stream_len(bucket_for(big.framed_len(), 0).unwrap())
        );
    }

    #[test]
    fn writer_limit() {
        let p = Payload::Text("x".repeat(max_text_bytes()));
        assert!(bucket_for_text(p.framed_len(), None).is_ok());
        let p = Payload::Text("x".repeat(max_text_bytes() + 1));
        assert!(matches!(
            bucket_for_text(p.framed_len(), None),
            Err(Error::PayloadTooLarge { .. })
        ));
    }

    #[test]
    fn text_modes_round_trip() {
        let mut rng = ChaCha20Rng::seed_from_u64(3);
        let p = Payload::Text("the usual place".into());
        let key = HideKey::Passphrase(pass("correct horse"));
        for mode in [TextMode::ZeroWidth, TextMode::Dictionary] {
            let out = hide(
                mode,
                "See you tomorrow, bring the charger!",
                (&p, &key),
                None,
                &mut rng,
            )
            .unwrap();
            let found = reveal(&out, &[RevealKey::Passphrase(pass("correct horse"))]).unwrap();
            assert_eq!(found, TextFound::Payload(p.clone(), mode));
            let found = reveal(&out, &[RevealKey::Passphrase(pass("wrong"))]).unwrap();
            assert_eq!(found, TextFound::Nothing(mode));
        }
    }

    #[test]
    fn a_stray_invisible_character_does_not_hide_word_text() {
        let mut rng = ChaCha20Rng::seed_from_u64(4);
        let p = Payload::Text("still here".into());
        let key = HideKey::Passphrase(pass("pw"));
        let words = hide(TextMode::Dictionary, "", (&p, &key), None, &mut rng).unwrap();
        let (a, b) = words.split_once(' ').unwrap();
        let touched = format!("{a} \u{200B}{b}");
        let found = reveal(&touched, &[RevealKey::Passphrase(pass("pw"))]).unwrap();
        assert_eq!(found, TextFound::Payload(p, TextMode::Dictionary));
        assert!(matches!(
            reveal("hi \u{200B}there", &[]),
            Err(Error::TextLength)
        ));
    }

    #[test]
    fn ordinary_text_is_not_steg_text() {
        assert!(matches!(
            reveal("See you tomorrow, bring the charger!", &[]),
            Err(Error::TextUnknownWord(_))
        ));
    }
}
