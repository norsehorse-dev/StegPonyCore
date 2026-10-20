//! Text reveal vectors (FORMAT.md section 7): every text in
//! `tests/vectors/text_vectors.json` must keep revealing exactly what it lists, with only
//! the public API. The texts are reveal inputs, not writer outputs: the writer's shaping
//! and run placement are random.
//!
//! Regenerate (only for a deliberate format change) with
//! `cargo test -p stegpony-core --test text_vectors -- --ignored make_text_vectors`.

use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use stegpony_core::text::{self, TextFound, TextMode};
use stegpony_core::{HideKey, Identity, Payload, RevealKey};
use zeroize::Zeroizing;

const ID_A: &str = "AGE-SECRET-KEY-10CQJUH8Z8EKPC3EUSVDCVLCSX80PG3AACQZJG0PYT47Q6DULRL4QU3R8X4";
const ID_B: &str = "AGE-SECRET-KEY-173T02A38CKUSREPTV0Z93Q35VJK5L30RSGYYN5QT6E7LTH73K42QKMU9Z8";

fn path() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/text_vectors.json")
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn payload_json(p: &Payload) -> Value {
    match p {
        Payload::Text(t) => json!({"kind": "text", "text": t}),
        Payload::File { name, mime, data } => {
            json!({"kind": "file", "name": name, "mime": mime, "data_hex": hex(data)})
        }
    }
}

fn payload(v: &Value) -> Option<Payload> {
    if v.is_null() {
        return None;
    }
    Some(match v["kind"].as_str().unwrap() {
        "text" => Payload::Text(v["text"].as_str().unwrap().into()),
        _ => Payload::File {
            name: v["name"].as_str().unwrap().into(),
            mime: v["mime"].as_str().unwrap().into(),
            data: unhex(v["data_hex"].as_str().unwrap()),
        },
    })
}

fn key(v: &Value) -> RevealKey {
    match v["passphrase"].as_str() {
        Some(p) => RevealKey::Passphrase(Zeroizing::new(p.into())),
        None => RevealKey::Identity(Identity::parse(v["identity"].as_str().unwrap()).unwrap()),
    }
}

fn pass(s: &str) -> HideKey {
    HideKey::Passphrase(Zeroizing::new(s.into()))
}

fn recipient(id: &str) -> HideKey {
    HideKey::Recipient(Identity::parse(id).unwrap().recipient())
}

#[test]
#[ignore]
fn make_text_vectors() {
    let family = "\u{1F468}\u{200D}\u{1F469}\u{200D}\u{1F467}";
    let file = Payload::File {
        name: "list.txt".into(),
        mime: "text/plain".into(),
        data: b"eggs\nflour\nbutter\nsugar\nlemons\n".repeat(3),
    };
    let real = Payload::Text("real: the key is under the blue pot".into());
    let fake = Payload::Text("decoy: remember to water the plants".into());
    let short = Payload::Text("six at the bridge".into());
    let mut cases = Vec::new();
    let mut rng = ChaCha20Rng::seed_from_u64(0x5465_7874);

    let t = text::hide(
        TextMode::Dictionary,
        "",
        (&short, &pass("tuesday")),
        None,
        &mut rng,
    )
    .unwrap();
    cases.push(json!({
        "name": "words, passphrase, no decoy",
        "mode": "words",
        "text": t,
        "checks": [
            {"keys": [{"passphrase": "tuesday"}], "expect": payload_json(&short)},
            {"keys": [{"passphrase": "wednesday"}], "expect": null},
        ],
    }));
    let mangled: String = t
        .to_uppercase()
        .replace(". ", " -- ")
        .replace(", ", "; ")
        .replace("\n\n", "\r\n 12 ");
    cases.push(json!({
        "name": "the same words, recased and repunctuated",
        "mode": "words",
        "text": mangled,
        "checks": [{"keys": [{"passphrase": "tuesday"}], "expect": payload_json(&short)}],
    }));

    let t = text::hide(
        TextMode::Dictionary,
        "",
        (&file, &recipient(ID_A)),
        None,
        &mut rng,
    )
    .unwrap();
    cases.push(json!({
        "name": "words, public key, file in a larger bucket",
        "mode": "words",
        "text": t,
        "checks": [
            {"keys": [{"identity": ID_A}], "expect": payload_json(&file)},
            {"keys": [{"identity": ID_B}], "expect": null},
        ],
    }));

    let cover = format!("Dinner on Sunday {family} at our place?\nBring the good bread.");
    let t = text::hide(
        TextMode::ZeroWidth,
        &cover,
        (&real, &recipient(ID_B)),
        Some((&fake, &pass("garden"))),
        &mut rng,
    )
    .unwrap();
    cases.push(json!({
        "name": "zero-width, public key with a passphrase decoy, emoji joiners in the cover",
        "mode": "zero-width",
        "visible": cover,
        "text": t,
        "checks": [
            {"keys": [{"identity": ID_B}], "expect": payload_json(&real)},
            {"keys": [{"passphrase": "garden"}], "expect": payload_json(&fake)},
            {"keys": [{"passphrase": "nope"}, {"identity": ID_A}], "expect": null},
        ],
    }));

    let cover = "ok";
    let t = text::hide(
        TextMode::ZeroWidth,
        cover,
        (&short, &pass("tuesday")),
        Some((&fake, &pass("garden"))),
        &mut rng,
    )
    .unwrap();
    cases.push(json!({
        "name": "zero-width, one-word cover, passphrase and decoy",
        "mode": "zero-width",
        "visible": cover,
        "text": t,
        "checks": [
            {"keys": [{"passphrase": "tuesday"}], "expect": payload_json(&short)},
            {"keys": [{"passphrase": "garden"}], "expect": payload_json(&fake)},
        ],
    }));

    let t = text::hide(
        TextMode::Dictionary,
        "",
        (&short, &pass("tuesday")),
        None,
        &mut rng,
    )
    .unwrap();
    let w: Vec<&str> = t.split(' ').collect();
    // A stray invisible character after a space, then a non-ASCII dash, a control
    // character and an accented letter in place of spaces.
    let odd = format!(
        "{} {} \u{200B}{}\u{2014}{}\u{1C}{}\u{E9}{} {}",
        w[0],
        w[1],
        w[2],
        w[3],
        w[4],
        w[5],
        w[6..].join(" ")
    );
    cases.push(json!({
        "name": "words with odd separators and a stray invisible character",
        "mode": "words",
        "text": odd,
        "checks": [{"keys": [{"passphrase": "tuesday"}], "expect": payload_json(&short)}],
    }));

    let cover = "Meeting moved\u{3000}to Friday,\u{A0}same room.\u{1C}See you";
    let t = text::hide(
        TextMode::ZeroWidth,
        cover,
        (&short, &pass("tuesday")),
        None,
        &mut rng,
    )
    .unwrap();
    cases.push(json!({
        "name": "zero-width, cover with an ideographic space, a no-break space and a control character",
        "mode": "zero-width",
        "visible": cover,
        "text": t,
        "checks": [{"keys": [{"passphrase": "tuesday"}], "expect": payload_json(&short)}],
    }));

    let doc = json!({
        "about": "StegPony format v1 text reveal vectors (FORMAT.md 7). Each text must reveal \
                  exactly 'expect' with 'keys' (null: nothing). The age keys are published test keys.",
        "wordlist_sha256": stegpony_core::text::dictionary::ENGLISH_SHA256,
        "cases": cases,
    });
    let mut s = serde_json::to_string_pretty(&doc).unwrap();
    s.push('\n');
    std::fs::write(path(), s).unwrap();
}

#[test]
fn text_vectors_reveal() {
    let doc: Value = serde_json::from_slice(&std::fs::read(path()).unwrap()).unwrap();
    assert_eq!(
        doc["wordlist_sha256"].as_str().unwrap(),
        stegpony_core::text::dictionary::ENGLISH_SHA256
    );
    let cases = doc["cases"].as_array().unwrap();
    assert!(cases.len() >= 5);
    for case in cases {
        let t = case["text"].as_str().unwrap();
        let mode = match case["mode"].as_str().unwrap() {
            "words" => TextMode::Dictionary,
            _ => TextMode::ZeroWidth,
        };
        if let Some(v) = case["visible"].as_str() {
            let shown: String = t
                .chars()
                .filter(|c| !text::zero_width::ALPHABET.contains(c))
                .collect();
            let want: String = v
                .chars()
                .filter(|c| !text::zero_width::ALPHABET.contains(c))
                .collect();
            assert_eq!(shown, want);
        }
        for check in case["checks"].as_array().unwrap() {
            let keys: Vec<RevealKey> = check["keys"].as_array().unwrap().iter().map(key).collect();
            let got = match text::reveal(t, &keys).unwrap() {
                TextFound::Payload(p, m) => {
                    assert_eq!(m, mode);
                    Some(p)
                }
                TextFound::Nothing(m) => {
                    assert_eq!(m, mode);
                    None
                }
            };
            assert_eq!(got, payload(&check["expect"]), "{}", case["name"]);
        }
    }
}
