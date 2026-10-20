//! Zero-width text: the envelope bytes as invisible characters placed at the start of
//! words in a cover message the user writes. FORMAT.md section 7.2.
//!
//! Weak by design and labelled so: many apps strip these characters, and any tool that
//! looks for them finds them at once.

use crate::error::{Error, Result};

/// The four carrier characters, by symbol value: ZERO WIDTH SPACE, ZERO WIDTH
/// NON-JOINER, ZERO WIDTH JOINER, WORD JOINER.
pub const ALPHABET: [char; 4] = ['\u{200B}', '\u{200C}', '\u{200D}', '\u{2060}'];

fn symbol(c: char) -> Option<u8> {
    ALPHABET.iter().position(|&a| a == c).map(|i| i as u8)
}

/// Invisible characters for `len` envelope bytes (2 bits each).
pub fn chars_for(len: usize) -> usize {
    len * 4
}

/// The cover with any carrier characters at carrier positions removed, so they cannot
/// be mistaken for hidden data. Carrier characters elsewhere (the joiner inside an
/// emoji sequence, say) are kept.
fn cleaned(cover: &str) -> String {
    let mut out = String::with_capacity(cover.len());
    let mut at_position = true;
    for c in cover.chars() {
        if at_position && symbol(c).is_some() {
            continue;
        }
        out.push(c);
        at_position = c.is_whitespace();
    }
    out
}

/// Hides `stream` in `cover`: the symbols are split as evenly as possible over the
/// starts of the cover's words, in order, each run placed just before its word.
pub fn encode(cover: &str, stream: &[u8]) -> Result<String> {
    let cover = cleaned(cover);
    let mut starts = Vec::new();
    let mut prev_ws = true;
    for (i, c) in cover.char_indices() {
        if prev_ws && !c.is_whitespace() {
            starts.push(i);
        }
        prev_ws = c.is_whitespace();
    }
    if starts.is_empty() {
        return Err(Error::TextCoverEmpty);
    }
    let symbols: Vec<char> = stream
        .iter()
        .flat_map(|&b| (0..4).map(move |j| ALPHABET[((b >> (2 * j)) & 3) as usize]))
        .collect();
    let total = symbols.len();
    let runs = starts.len();
    let mut out = String::with_capacity(cover.len() + total * 3);
    let mut last = 0;
    let mut taken = 0;
    for (r, &at) in starts.iter().enumerate() {
        out.push_str(&cover[last..at]);
        let upto = total * (r + 1) / runs;
        out.extend(&symbols[taken..upto]);
        taken = upto;
        last = at;
    }
    out.push_str(&cover[last..]);
    Ok(out)
}

/// Reads the hidden bytes back. `None` when there are no carrier characters at carrier
/// positions; an empty vector when their count is not a whole number of bytes.
pub fn decode(text: &str) -> Option<Vec<u8>> {
    let mut symbols = Vec::new();
    let mut at_position = true;
    for c in text.chars() {
        if at_position {
            if let Some(s) = symbol(c) {
                symbols.push(s);
                continue;
            }
        }
        at_position = c.is_whitespace();
    }
    if symbols.is_empty() {
        return None;
    }
    if symbols.len() % 4 != 0 {
        return Some(Vec::new());
    }
    Some(
        symbols
            .chunks_exact(4)
            .map(|q| q[0] | (q[1] << 2) | (q[2] << 4) | (q[3] << 6))
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn visible(s: &str) -> String {
        s.chars().filter(|c| symbol(*c).is_none()).collect()
    }

    #[test]
    fn round_trip_keeps_the_visible_text() {
        let stream: Vec<u8> = (0..=255u8).collect();
        let cover = "Running late, see you at the usual place.\nBring snacks 🍿";
        let out = encode(cover, &stream).unwrap();
        assert_eq!(visible(&out), cover);
        assert_eq!(decode(&out).unwrap(), stream);
        assert_eq!(out.chars().count(), cover.chars().count() + chars_for(256));
    }

    #[test]
    fn emoji_joiners_are_not_data() {
        let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
        let cover = format!("{family} dinner at {family} eight");
        assert_eq!(decode(&cover), None);
        let out = encode(&cover, &[1, 2, 3, 4]).unwrap();
        assert_eq!(decode(&out).unwrap(), vec![1, 2, 3, 4]);
        assert_eq!(visible(&out), visible(&cover));
        assert!(out.contains(family));
    }

    #[test]
    fn stray_carrier_characters_in_the_cover_are_dropped() {
        let cover = "\u{200B}hello \u{2060}there";
        let out = encode(cover, &[0xAB]).unwrap();
        assert_eq!(decode(&out).unwrap(), vec![0xAB]);
    }

    #[test]
    fn one_word_cover_and_empty_cover() {
        let out = encode("ok", &[9, 8, 7]).unwrap();
        assert!(out.ends_with("ok"));
        assert_eq!(decode(&out).unwrap(), vec![9, 8, 7]);
        assert!(matches!(encode("  \n ", &[1]), Err(Error::TextCoverEmpty)));
    }

    #[test]
    fn a_lost_character_is_noticed() {
        let out = encode("a b c", &[1, 2]).unwrap();
        let mut chars: Vec<char> = out.chars().collect();
        let i = chars.iter().position(|c| symbol(*c).is_some()).unwrap();
        chars.remove(i);
        let damaged: String = chars.into_iter().collect();
        assert_eq!(decode(&damaged), Some(Vec::new()));
        assert_eq!(decode("plain text"), None);
    }
}
