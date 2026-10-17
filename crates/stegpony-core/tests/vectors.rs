//! Lossless reveal vectors (FORMAT.md section 6): every committed stego PNG must keep
//! revealing exactly what `tests/vectors/png_vectors/index.json` says, with only the
//! public API.

use serde_json::Value;
use stegpony_core::lossless;
use stegpony_core::{Identity, Payload, RevealKey};
use zeroize::Zeroizing;

fn dir() -> std::path::PathBuf {
    std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/png_vectors")
}

fn unhex(s: &str) -> Vec<u8> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
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

#[test]
fn png_vectors_reveal() {
    let index: Value =
        serde_json::from_slice(&std::fs::read(dir().join("index.json")).unwrap()).unwrap();
    let cases = index["cases"].as_array().unwrap();
    assert!(cases.len() >= 6);
    let mut checks = 0;
    for case in cases {
        let file = case["file"].as_str().unwrap();
        let image = std::fs::read(dir().join(file)).unwrap();
        for check in case["checks"].as_array().unwrap() {
            let keys: Vec<RevealKey> = check["keys"].as_array().unwrap().iter().map(key).collect();
            let got = lossless::reveal(&image, &keys).unwrap();
            assert_eq!(got, payload(&check["expect"]), "{file}: {check}");
            checks += 1;
        }
    }
    assert!(checks >= 12);
}

#[test]
fn png_vectors_differ_from_covers_only_by_plus_minus_one() {
    let index: Value =
        serde_json::from_slice(&std::fs::read(dir().join("index.json")).unwrap()).unwrap();
    for case in index["cases"].as_array().unwrap() {
        let a = lossless::decode_png(
            &std::fs::read(dir().join(case["cover"].as_str().unwrap())).unwrap(),
        )
        .unwrap();
        let b = lossless::decode_png(
            &std::fs::read(dir().join(case["file"].as_str().unwrap())).unwrap(),
        )
        .unwrap();
        assert_eq!(
            (a.width, a.height, a.channels),
            (b.width, b.height, b.channels)
        );
        assert!(a.data.iter().zip(&b.data).all(|(x, y)| x.abs_diff(*y) <= 1));
    }
}
