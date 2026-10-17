//! Frozen reader vectors. Regeneration is explicit and ignored in normal tests.
use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use serde_json::{json, Value};
use std::path::PathBuf;
use stegpony_core::jpeg::{carrier, Jpeg};
use stegpony_core::{HideKey, Identity, Payload, RevealKey};
use zeroize::Zeroizing;
fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors/jpeg_vectors")
}
fn payload(v: &Value) -> Option<Payload> {
    if v.is_null() {
        return None;
    }
    Some(if v["kind"] == "text" {
        Payload::Text(v["text"].as_str().unwrap().into())
    } else {
        let hex = v["data_hex"].as_str().unwrap();
        Payload::File {
            name: v["name"].as_str().unwrap().into(),
            mime: v["mime"].as_str().unwrap().into(),
            data: (0..hex.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&hex[i..i + 2], 16).unwrap())
                .collect(),
        }
    })
}
fn key(v: &Value) -> RevealKey {
    if let Some(s) = v["passphrase"].as_str() {
        RevealKey::Passphrase(Zeroizing::new(s.into()))
    } else {
        RevealKey::Identity(Identity::parse(v["identity"].as_str().unwrap()).unwrap())
    }
}
#[test]
fn frozen_jpeg_vectors_reveal_and_preserve_coefficients() {
    let index: Value =
        serde_json::from_slice(&std::fs::read(dir().join("index.json")).unwrap()).unwrap();
    assert!(index["cases"].as_array().unwrap().len() >= 4);
    for case in index["cases"].as_array().unwrap() {
        let bytes = std::fs::read(dir().join(case["file"].as_str().unwrap())).unwrap();
        for check in case["checks"].as_array().unwrap() {
            let keys: Vec<_> = check["keys"].as_array().unwrap().iter().map(key).collect();
            assert_eq!(
                carrier::reveal(&bytes, &keys).unwrap(),
                payload(&check["expect"]),
                "{case}"
            );
        }
        let cover =
            Jpeg::parse(&std::fs::read(dir().join(case["cover"].as_str().unwrap())).unwrap())
                .unwrap();
        let stego = Jpeg::parse(&bytes).unwrap();
        for (a, b) in cover.components.iter().zip(&stego.components) {
            assert_eq!(a.quant, b.quant);
            for (i, (x, y)) in a.coefs.iter().zip(&b.coefs).enumerate() {
                assert!(x.abs_diff(*y) <= 1);
                if i % 64 == 0 {
                    assert_eq!(x, y);
                }
            }
        }
    }
}
#[test]
#[ignore]
fn write_jpeg_vectors() {
    std::fs::create_dir_all(dir()).unwrap();
    let mut cases = vec![];
    for (i, source) in [
        "baseline_420.jpg",
        "progressive_turbo.jpg",
        "gray_large.jpg",
        "cmyk.jpg",
    ]
    .iter()
    .enumerate()
    {
        let mut rng = ChaCha20Rng::seed_from_u64(900 + i as u64);
        let id = Identity::generate(&mut rng);
        let wrong = Identity::generate(&mut rng);
        let expected = if i == 1 {
            json!({"kind":"file", "name":"note.bin", "mime":"application/octet-stream", "data_hex":"00ff0102"})
        } else {
            json!({"kind":"text", "text":format!("JPEG vector {i}: café 🐴")})
        };
        let p = payload(&expected).unwrap();
        let secret = "JPEG vector passphrase";
        let hide_key = if i % 2 == 0 {
            HideKey::Passphrase(Zeroizing::new(secret.into()))
        } else {
            HideKey::Recipient(id.recipient())
        };
        let right = if i % 2 == 0 {
            json!({"passphrase":secret})
        } else {
            json!({"identity":id.to_age_string().to_string()})
        };
        let cover = format!("cover_{source}");
        let bytes = std::fs::read(dir().join(&cover)).unwrap_or_else(|_| {
            std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures/jpeg")
                    .join(source),
            )
            .unwrap()
        });
        std::fs::write(dir().join(&cover), &bytes).unwrap();
        let decoy = Payload::Text("a harmless decoy".into());
        let dk = HideKey::Passphrase(Zeroizing::new("JPEG decoy".into()));
        let out = carrier::hide(
            &bytes,
            (&p, &hide_key),
            if i == 0 { Some((&decoy, &dk)) } else { None },
            false,
            &mut rng,
        )
        .unwrap();
        let file = format!("stego_{source}");
        std::fs::write(dir().join(&file), out.jpeg).unwrap();
        let mut checks = vec![
            json!({"keys":[right], "expect":expected}),
            json!({"keys":[{"passphrase":"wrong JPEG key"}], "expect":null}),
            json!({"keys":[{"identity":wrong.to_age_string().to_string()}], "expect":null}),
        ];
        if i == 0 {
            checks.push(json!({"keys":[{"passphrase":"JPEG decoy"}], "expect":{"kind":"text","text":"a harmless decoy"}}));
        }
        cases.push(json!({"file":file,"cover":cover,"checks":checks}));
    }
    std::fs::write(
        dir().join("index.json"),
        serde_json::to_vec_pretty(&json!({"format":1,"cases":cases})).unwrap(),
    )
    .unwrap();
}
