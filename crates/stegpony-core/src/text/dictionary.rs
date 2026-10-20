//! Dictionary text: the envelope bytes as a run of words from a fixed list of 4096,
//! twelve bits per word. FORMAT.md section 7.3.
//!
//! Anyone who reads it sees word salad. It keeps ciphertext away from automated filters
//! and casual eyes, not from a person who looks.

use std::collections::HashMap;
use std::sync::OnceLock;

use rand_core::{CryptoRng, RngCore};

use crate::error::{Error, Result};

/// The English list: 4096 lowercase ASCII words, one per line, in index order.
pub const ENGLISH: &str = include_str!("en.txt");

/// SHA-256 of [`ENGLISH`] as stored (lines ending in `\n`). Part of the format.
pub const ENGLISH_SHA256: &str = "6e01295be4982adec0341d5484c17f442424bb20998bcd46d5ee1484f1e5c447";

pub const BITS_PER_WORD: usize = 12;
pub const LIST_LEN: usize = 1 << BITS_PER_WORD;

struct List {
    words: Vec<&'static str>,
    index: HashMap<&'static str, u16>,
}

fn list() -> &'static List {
    static LIST: OnceLock<List> = OnceLock::new();
    LIST.get_or_init(|| {
        let words: Vec<&'static str> = ENGLISH.lines().collect();
        assert_eq!(words.len(), LIST_LEN, "word list must have 4096 words");
        let index = words
            .iter()
            .enumerate()
            .map(|(i, w)| (*w, i as u16))
            .collect();
        List { words, index }
    })
}

/// Words for `len` envelope bytes.
pub fn words_for(len: usize) -> usize {
    (len * 8).div_ceil(BITS_PER_WORD)
}

fn draw<R: RngCore + CryptoRng>(rng: &mut R, below: u32) -> Result<u32> {
    let mut b = [0u8; 4];
    rng.try_fill_bytes(&mut b).map_err(|_| Error::Rng)?;
    Ok(u32::from_le_bytes(b) % below)
}

/// Writes `stream` as words: bits taken least significant first, twelve to a word, the
/// last word's spare bits random. Sentences, commas and paragraph breaks are drawn at
/// random to make the run read less like a list; the reader ignores them.
pub fn encode<R: RngCore + CryptoRng>(stream: &[u8], rng: &mut R) -> Result<String> {
    let list = list();
    let n = words_for(stream.len());
    let mut indices = Vec::with_capacity(n);
    let mut acc: u32 = 0;
    let mut have = 0usize;
    for &b in stream {
        acc |= (b as u32) << have;
        have += 8;
        while have >= BITS_PER_WORD {
            indices.push((acc & 0xFFF) as usize);
            acc >>= BITS_PER_WORD;
            have -= BITS_PER_WORD;
        }
    }
    if have > 0 {
        let spare = draw(rng, 1 << (BITS_PER_WORD - have))?;
        indices.push(((acc | (spare << have)) & 0xFFF) as usize);
    }
    debug_assert_eq!(indices.len(), n);

    let mut out = String::with_capacity(n * 8);
    let mut sentence_left = 0u32;
    let mut sentences_left = 3 + draw(rng, 4)?;
    let mut in_sentence = 0u32;
    for (i, &ix) in indices.iter().enumerate() {
        let word = list.words[ix];
        if sentence_left == 0 {
            if i > 0 {
                out.push('.');
                sentences_left -= 1;
                if sentences_left == 0 {
                    out.push_str("\n\n");
                    sentences_left = 3 + draw(rng, 4)?;
                } else {
                    out.push(' ');
                }
            }
            sentence_left = 6 + draw(rng, 9)?;
            in_sentence = 0;
            let mut cs = word.chars();
            if let Some(f) = cs.next() {
                out.extend(f.to_uppercase());
                out.push_str(cs.as_str());
            }
        } else {
            if in_sentence >= 2 && sentence_left >= 3 && draw(rng, 9)? == 0 {
                out.push(',');
            }
            out.push(' ');
            out.push_str(word);
        }
        sentence_left -= 1;
        in_sentence += 1;
    }
    if !indices.is_empty() {
        out.push('.');
    }
    Ok(out)
}

/// Reads words back into envelope bytes. Words are the runs of ASCII letters, compared
/// ignoring ASCII case; every other character separates them (FORMAT.md 7.3). The word
/// count picks the stream length.
pub fn decode(text: &str) -> Result<Vec<u8>> {
    let list = list();
    let mut indices = Vec::new();
    // A run of ASCII letters never spans whitespace, so going chunk by chunk reads the
    // same words; the chunk is what an error shows, so "café" is reported as written.
    for chunk in text.split_whitespace() {
        for token in chunk
            .split(|c: char| !c.is_ascii_alphabetic())
            .filter(|t| !t.is_empty())
        {
            match list.index.get(token.to_ascii_lowercase().as_str()) {
                Some(&i) => indices.push(i as u32),
                None => return Err(Error::TextUnknownWord(shown(chunk))),
            }
        }
    }
    if indices.is_empty() {
        // No letters at all (emoji, digits, symbols): not word text either.
        return match text.split_whitespace().next() {
            Some(first) => Err(Error::TextUnknownWord(shown(first))),
            None => Err(Error::TextLength),
        };
    }
    let len = (0..crate::envelope::NUM_BUCKETS)
        .map(super::stream_len)
        .find(|&l| words_for(l) == indices.len())
        .ok_or(Error::TextLength)?;
    let mut out = Vec::with_capacity(len);
    let mut acc: u32 = 0;
    let mut have = 0usize;
    for i in indices {
        acc |= i << have;
        have += BITS_PER_WORD;
        while have >= 8 && out.len() < len {
            out.push((acc & 0xFF) as u8);
            acc >>= 8;
            have -= 8;
        }
    }
    debug_assert_eq!(out.len(), len);
    Ok(out)
}

/// At most this many characters of an unknown word are reported.
const SHOWN_CHARS: usize = 40;

fn shown(chunk: &str) -> String {
    let mut out: String = chunk.chars().take(SHOWN_CHARS).collect();
    if chunk.chars().nth(SHOWN_CHARS).is_some() {
        out.push('…');
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::text::stream_len;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use sha2::{Digest, Sha256};

    #[test]
    fn the_list_is_well_formed_and_pinned() {
        let words: Vec<&str> = ENGLISH.lines().collect();
        assert_eq!(words.len(), LIST_LEN);
        let mut seen = std::collections::HashSet::new();
        for w in &words {
            assert!(
                (3..=9).contains(&w.len()) && w.bytes().all(|b| b.is_ascii_lowercase()),
                "{w}"
            );
            assert!(seen.insert(*w), "duplicate {w}");
        }
        assert!(ENGLISH.ends_with('\n'));
        let digest = Sha256::digest(ENGLISH.as_bytes());
        let hex: String = digest.iter().map(|b| format!("{b:02x}")).collect();
        assert_eq!(hex, ENGLISH_SHA256);
    }

    #[test]
    fn round_trip_every_text_size_up_to_the_writer_limit() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for k in 0..=crate::text::MAX_TEXT_BUCKET {
            let len = stream_len(k);
            let mut stream = vec![0u8; len];
            rng.fill_bytes(&mut stream);
            let text = encode(&stream, &mut rng).unwrap();
            assert_eq!(decode(&text).unwrap(), stream, "bucket {k}");
        }
    }

    #[test]
    fn shaping_and_case_are_ignored() {
        let mut rng = ChaCha20Rng::seed_from_u64(5);
        let mut stream = vec![0u8; stream_len(0)];
        rng.fill_bytes(&mut stream);
        let text = encode(&stream, &mut rng).unwrap();
        assert!(text.contains(". "));
        let mangled = text
            .to_uppercase()
            .replace(['.', ','], " ;; ")
            .replace("\n\n", "\r\n");
        assert_eq!(decode(&mangled).unwrap(), stream);
    }

    #[test]
    fn unknown_words_and_wrong_counts_are_reported() {
        let mut rng = ChaCha20Rng::seed_from_u64(6);
        let mut stream = vec![0u8; stream_len(0)];
        rng.fill_bytes(&mut stream);
        let text = encode(&stream, &mut rng).unwrap();
        let first = text.split(' ').next().unwrap().to_string();
        let swapped = text.replacen(&first, "Zzyzx", 1);
        assert!(matches!(decode(&swapped), Err(Error::TextUnknownWord(w)) if w == "Zzyzx"));
        assert!(matches!(decode("12 🐴 !!"), Err(Error::TextUnknownWord(w)) if w == "12"));
        assert!(matches!(decode("the café"), Err(Error::TextUnknownWord(w)) if w == "café"));
        let long = "q".repeat(5000);
        assert!(matches!(decode(&long), Err(Error::TextUnknownWord(w)) if w.chars().count() == 41));
        let dropped = text.replacen(&format!("{first} "), "", 1);
        assert!(matches!(decode(&dropped), Err(Error::TextLength)));
    }
}
