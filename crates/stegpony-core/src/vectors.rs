//! Pinned values and the frozen test-vector files. A change to any of them is a format
//! change and needs a new format version. FORMAT.md section 6.
//!
//! The files under `tests/vectors/` were written once by [`tests::write_vectors`]
//! (`cargo test -p stegpony-core --lib -- --ignored write_vectors`) and are checked here,
//! by `tests/vectors.rs`, and independently by `tools/check_vectors.py`. Regenerating
//! them is never part of a normal change. The envelope vectors must come out identical.
//! The PNG vectors are reveal inputs: their stego images depend on writer choices (costs,
//! embedding, PNG compression), so a writer change would produce different images that
//! are equally valid, and the committed ones must keep revealing.

pub const PRP_ZERO_KEY_1M: [u64; 4] = [354941, 379842, 364614, 325392];

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use chacha20poly1305::aead::{Aead, KeyInit};
    use chacha20poly1305::{ChaCha20Poly1305, Nonce};
    use curve25519_elligator2::MontgomeryPoint;
    use rand_chacha::rand_core::SeedableRng;
    use rand_chacha::ChaCha20Rng;
    use rand_core::{CryptoRng, RngCore};
    use serde_json::{json, Value};
    use zeroize::Zeroizing;

    use crate::envelope::{
        self, bucket_for, bucket_size, locators, open_body, open_head, seal, HideKey, Mode,
        Payload, RevealKey, Sealed, REPR_LEN, SALT_LEN,
    };
    use crate::keys::{Identity, Recipient};
    use crate::lossless::{self, decode_png, encode_png, Raster};

    const ENVELOPE: &str = include_str!("../tests/vectors/envelope_vectors.json");

    fn vectors_dir() -> PathBuf {
        PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/vectors")
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        assert!(s.len().is_multiple_of(2), "odd hex length");
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i + 2], 16).expect("hex"))
            .collect()
    }

    fn s<'a>(v: &'a Value, k: &str) -> &'a str {
        v[k].as_str()
            .unwrap_or_else(|| panic!("missing string {k}"))
    }

    fn payload_json(p: &Payload) -> Value {
        match p {
            Payload::Text(t) => json!({ "kind": "text", "text": t }),
            Payload::File { name, mime, data } => {
                json!({ "kind": "file", "name": name, "mime": mime, "data_hex": hex(data) })
            }
        }
    }

    fn payload_from(v: &Value) -> Payload {
        match s(v, "kind") {
            "text" => Payload::Text(s(v, "text").into()),
            "file" => Payload::File {
                name: s(v, "name").into(),
                mime: s(v, "mime").into(),
                data: unhex(s(v, "data_hex")),
            },
            k => panic!("unknown payload kind {k}"),
        }
    }

    fn pass(p: &str) -> Zeroizing<String> {
        Zeroizing::new(p.into())
    }

    /// Records every random byte a seal draws, so the draw can be replayed exactly.
    struct Recorder {
        inner: ChaCha20Rng,
        log: Vec<u8>,
    }

    impl RngCore for Recorder {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            self.inner.fill_bytes(dest);
            self.log.extend_from_slice(dest);
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for Recorder {}

    /// Hands out recorded random bytes in order and fails if a seal asks for more.
    struct Replay {
        bytes: Vec<u8>,
        pos: usize,
    }

    impl RngCore for Replay {
        fn next_u32(&mut self) -> u32 {
            let mut b = [0u8; 4];
            self.fill_bytes(&mut b);
            u32::from_le_bytes(b)
        }
        fn next_u64(&mut self) -> u64 {
            let mut b = [0u8; 8];
            self.fill_bytes(&mut b);
            u64::from_le_bytes(b)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            let end = self.pos + dest.len();
            assert!(end <= self.bytes.len(), "vector ran out of random bytes");
            dest.copy_from_slice(&self.bytes[self.pos..end]);
            self.pos = end;
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }
    impl CryptoRng for Replay {}

    fn plaintext_of(okm: &[u8; 36], body: &[u8]) -> Vec<u8> {
        ChaCha20Poly1305::new_from_slice(&okm[..32])
            .expect("key")
            .decrypt(&Nonce::default(), body)
            .expect("vector body opens")
    }

    /// What a seal derived, recomputed from its output. For a passphrase this includes the
    /// body key material; for a public key the caller adds it from the ephemeral key.
    fn derive_all(key: &HideKey, sealed: &Sealed) -> (Value, Option<[u8; 36]>) {
        let mut v = json!({
            "locate_hex": hex(sealed.locate.as_ref()),
            "prp_key_slot0_hex": hex(&envelope::prp_key(&sealed.locate, 0)),
            "prp_key_slot1_hex": hex(&envelope::prp_key(&sealed.locate, 1)),
            "head_hex": hex(&sealed.head),
            "body_hex": hex(&sealed.body),
        });
        match key {
            HideKey::Passphrase(p) => {
                let salt = &sealed.head[..SALT_LEN];
                let content = envelope::argon2(&envelope::normalized(p), salt).expect("argon2");
                let okm = envelope::body_okm(content.as_ref(), None);
                v["salt_hex"] = json!(hex(salt));
                v["content_key_hex"] = json!(hex(content.as_ref()));
                v["okm_hex"] = json!(hex(okm.as_ref()));
                (v, Some(*okm))
            }
            HideKey::Recipient(_) => {
                v["repr_hex"] = json!(hex(&sealed.head[..REPR_LEN]));
                (v, None)
            }
        }
    }

    /// Body key material for a public-key seal, from the ephemeral key it used.
    fn public_key_okm(r: &Recipient, eph: [u8; 32], head: &[u8]) -> ([u8; 32], [u8; 36]) {
        let shared = MontgomeryPoint(*r.as_bytes()).mul_clamped(eph).to_bytes();
        let mut salt = head[..REPR_LEN].to_vec();
        salt.extend_from_slice(r.as_bytes());
        (shared, *envelope::body_okm(&shared, Some(&salt)))
    }

    fn envelope_case(
        name: &str,
        key: HideKey,
        reveal: Value,
        payload: Payload,
        bucket: usize,
        seed: u64,
    ) -> Value {
        let mut rec = Recorder {
            inner: ChaCha20Rng::seed_from_u64(seed),
            log: Vec::new(),
        };
        let sealed = seal(&payload, &key, bucket, &mut rec).expect("seal");
        let (mut v, okm) = derive_all(&key, &sealed);
        let okm = match (&key, okm) {
            (_, Some(okm)) => okm,
            (HideKey::Recipient(r), None) => {
                // eph and tweak are the last 33 bytes drawn: earlier attempts, if any, had
                // no representative and were discarded.
                let n = rec.log.len();
                let eph: [u8; 32] = rec.log[n - 33..n - 1].try_into().unwrap();
                let (shared, okm) = public_key_okm(r, eph, &sealed.head);
                v["eph_hex"] = json!(hex(&eph));
                v["tweak"] = json!(rec.log[n - 1]);
                v["attempts"] = json!(n / 33);
                v["shared_hex"] = json!(hex(&shared));
                v["okm_hex"] = json!(hex(&okm));
                okm
            }
            (HideKey::Passphrase(_), None) => unreachable!(),
        };
        v["plaintext_hex"] = json!(hex(&plaintext_of(&okm, &sealed.body)));
        let mut case = json!({
            "name": name,
            "mode": match sealed.mode { Mode::Passphrase => "passphrase", Mode::PublicKey => "public_key" },
            "bucket": bucket,
            "bucket_size": bucket_size(bucket),
            "payload": payload_json(&payload),
            "random_hex": hex(&rec.log),
            "reveal": reveal,
        });
        match &key {
            HideKey::Passphrase(p) => case["passphrase"] = json!(p.as_str()),
            HideKey::Recipient(r) => case["recipient"] = json!(r.to_age_string()),
        }
        case["expected"] = v;
        case
    }

    fn reveal_key(v: &Value) -> RevealKey {
        if let Some(p) = v["passphrase"].as_str() {
            RevealKey::Passphrase(pass(p))
        } else {
            RevealKey::Identity(Identity::parse(s(v, "identity")).expect("identity"))
        }
    }

    fn hide_key(case: &Value) -> HideKey {
        if let Some(p) = case["passphrase"].as_str() {
            HideKey::Passphrase(pass(p))
        } else {
            HideKey::Recipient(Recipient::parse(s(case, "recipient")).expect("recipient"))
        }
    }

    #[test]
    fn envelope_vectors_hold() {
        let doc: Value = serde_json::from_str(ENVELOPE).expect("json");
        let cases = doc["cases"].as_array().expect("cases");
        assert!(cases.len() >= 6);
        for case in cases {
            let name = s(case, "name");
            let key = hide_key(case);
            let payload = payload_from(&case["payload"]);
            let bucket = case["bucket"].as_u64().unwrap() as usize;
            let mut replay = Replay {
                bytes: unhex(s(case, "random_hex")),
                pos: 0,
            };
            let sealed = seal(&payload, &key, bucket, &mut replay).expect("seal");
            assert_eq!(
                replay.pos,
                replay.bytes.len(),
                "{name}: unused random bytes"
            );

            let exp = &case["expected"];
            let (mut got, okm) = derive_all(&key, &sealed);
            let okm = match (&key, okm) {
                (_, Some(okm)) => okm,
                (HideKey::Recipient(r), None) => {
                    let eph: [u8; 32] = unhex(s(exp, "eph_hex")).try_into().unwrap();
                    let (shared, okm) = public_key_okm(r, eph, &sealed.head);
                    got["shared_hex"] = json!(hex(&shared));
                    got["okm_hex"] = json!(hex(&okm));
                    okm
                }
                (HideKey::Passphrase(_), None) => unreachable!(),
            };
            got["plaintext_hex"] = json!(hex(&plaintext_of(&okm, &sealed.body)));
            for field in got.as_object().unwrap().keys() {
                assert_eq!(got[field], exp[field], "{name}: {field}");
            }

            let rk = reveal_key(&case["reveal"]);
            let keys = [rk];
            let locs = locators(&keys).expect("locators");
            assert_eq!(hex(locs[0].locate.as_ref()), s(exp, "locate_hex"), "{name}");
            let opened = open_head(&keys[0], &sealed.head)
                .expect("open head")
                .expect("head belongs to key");
            assert_eq!(opened.bucket, bucket, "{name}");
            assert_eq!(open_body(&opened, &sealed.body), Some(payload), "{name}");
        }
    }

    fn crop(r: &Raster, x0: u32, y0: u32, w: u32, h: u32) -> Raster {
        let ch = r.channels as usize;
        let mut data = Vec::with_capacity((w * h) as usize * ch);
        for y in y0..y0 + h {
            let start = ((y * r.width + x0) as usize) * ch;
            data.extend_from_slice(&r.data[start..start + w as usize * ch]);
        }
        Raster {
            width: w,
            height: h,
            channels: r.channels,
            data,
        }
    }

    fn key_json(k: &RevealKey) -> Value {
        match k {
            RevealKey::Passphrase(p) => json!({ "passphrase": p.as_str() }),
            RevealKey::Identity(id) => json!({ "identity": id.to_age_string() }),
            RevealKey::External(_) => unreachable!("vectors use keys written out in full"),
        }
    }

    fn check(keys: &[RevealKey], expect: Option<&Payload>) -> Value {
        json!({
            "keys": keys.iter().map(key_json).collect::<Vec<_>>(),
            "expect": expect.map_or(Value::Null, payload_json),
        })
    }

    /// Writes `tests/vectors/`. Run only to create the vectors, never to "fix" them.
    #[test]
    #[ignore]
    fn write_vectors() {
        let dir = vectors_dir();
        std::fs::create_dir_all(dir.join("png_vectors")).unwrap();

        // Test-only keys, published on purpose.
        let mut keyrng = ChaCha20Rng::seed_from_u64(0x5374_6567);
        let alice = Identity::generate(&mut keyrng);
        let bob = Identity::generate(&mut keyrng);

        let file = Payload::File {
            name: "notes.age".into(),
            mime: "application/octet-stream".into(),
            data: (0..200u32).map(|i| (i * 7 + 3) as u8).collect(),
        };
        let file_bucket = bucket_for(file.framed_len(), 0).unwrap() + 1;
        let cases = vec![
            envelope_case(
                "passphrase, text",
                HideKey::Passphrase(pass("correct horse battery staple")),
                json!({ "passphrase": "correct horse battery staple" }),
                Payload::Text("meet at noon by the old bridge".into()),
                0,
                1,
            ),
            envelope_case(
                "passphrase, empty text",
                HideKey::Passphrase(pass("x")),
                json!({ "passphrase": "x" }),
                Payload::Text(String::new()),
                0,
                2,
            ),
            envelope_case(
                "passphrase, NFC: hidden composed, revealed decomposed",
                HideKey::Passphrase(pass("caf\u{e9} au lait")),
                json!({ "passphrase": "cafe\u{301} au lait" }),
                Payload::Text("normalized".into()),
                0,
                3,
            ),
            envelope_case(
                "passphrase, file, one bucket above the smallest that fits",
                HideKey::Passphrase(pass("files")),
                json!({ "passphrase": "files" }),
                file.clone(),
                file_bucket,
                4,
            ),
            envelope_case(
                "public key, text",
                HideKey::Recipient(alice.recipient()),
                json!({ "identity": alice.to_age_string() }),
                Payload::Text("for your eyes".into()),
                0,
                5,
            ),
            envelope_case(
                "public key, file",
                HideKey::Recipient(bob.recipient()),
                json!({ "identity": bob.to_age_string() }),
                file.clone(),
                file_bucket,
                6,
            ),
        ];
        let doc = json!({
            "format_version": crate::FORMAT_VERSION,
            "description": "StegPony format v1 envelope vectors. FORMAT.md sections 2, 3 and 4.1. random_hex is every random byte the reference writer drew, in order; for public-key cases eph_hex and tweak are the last 33 of them.",
            "cases": cases,
        });
        std::fs::write(
            dir.join("envelope_vectors.json"),
            serde_json::to_string_pretty(&doc).unwrap() + "\n",
        )
        .unwrap();

        let fx = |n: &str| {
            std::fs::read(
                PathBuf::from(env!("CARGO_MANIFEST_DIR"))
                    .join("tests/fixtures")
                    .join(n),
            )
            .unwrap()
        };
        let covers = [
            (
                "cover_rgb_128.png",
                crop(&decode_png(&fx("cover_rgb.png")).unwrap(), 0, 0, 128, 128),
            ),
            (
                "cover_gray_160.png",
                crop(
                    &decode_png(&fx("cover_gray.png")).unwrap(),
                    80,
                    80,
                    160,
                    160,
                ),
            ),
            (
                "cover_rgba_128.png",
                crop(&decode_png(&fx("cover_rgba.png")).unwrap(), 0, 64, 128, 128),
            ),
        ];
        for (name, r) in &covers {
            std::fs::write(dir.join("png_vectors").join(name), encode_png(r).unwrap()).unwrap();
        }
        let cover = |i: usize| std::fs::read(dir.join("png_vectors").join(covers[i].0)).unwrap();

        let rp = |p: &str| RevealKey::Passphrase(pass(p));
        let ra = RevealKey::Identity(alice.clone());
        let rb = RevealKey::Identity(bob.clone());
        let mut entries = Vec::new();
        let mut add = |file: &str,
                       cover_i: usize,
                       seed: u64,
                       primary: (&Payload, &HideKey),
                       decoy: Option<(&Payload, &HideKey)>,
                       checks: Vec<Value>| {
            let mut rng = ChaCha20Rng::seed_from_u64(seed);
            let out = lossless::hide(&cover(cover_i), primary, decoy, &mut rng).unwrap();
            std::fs::write(dir.join("png_vectors").join(file), &out.png).unwrap();
            entries.push(json!({ "file": file, "cover": covers[cover_i].0, "checks": checks }));
        };

        let text = Payload::Text("the drop is behind the third bench".into());
        add(
            "rgb_passphrase.png",
            0,
            100,
            (&text, &HideKey::Passphrase(pass("tuesday"))),
            None,
            vec![
                check(&[rp("tuesday")], Some(&text)),
                check(&[rp("wednesday")], None),
            ],
        );
        let pk_text = Payload::Text("for your eyes".into());
        add(
            "rgb_public_key.png",
            0,
            101,
            (&pk_text, &HideKey::Recipient(alice.recipient())),
            None,
            vec![
                check(std::slice::from_ref(&ra), Some(&pk_text)),
                check(std::slice::from_ref(&rb), None),
                check(&[rp("nope"), rb.clone(), ra.clone()], Some(&pk_text)),
            ],
        );
        let real = Payload::Text("real: meet at the north gate".into());
        let decoy = Payload::Text("grocery list: eggs, rice".into());
        add(
            "rgb_decoy.png",
            0,
            102,
            (&real, &HideKey::Recipient(bob.recipient())),
            Some((&decoy, &HideKey::Passphrase(pass("grocery list")))),
            vec![
                check(std::slice::from_ref(&rb), Some(&real)),
                check(&[rp("grocery list")], Some(&decoy)),
                check(&[ra.clone(), rp("other")], None),
            ],
        );
        add(
            "gray_file_nfc.png",
            1,
            103,
            (&file, &HideKey::Passphrase(pass("caf\u{e9}"))),
            None,
            vec![
                check(&[rp("cafe\u{301}")], Some(&file)),
                check(&[rp("cafe")], None),
            ],
        );
        let alpha = Payload::Text("alpha stays put".into());
        add(
            "rgba_passphrase.png",
            2,
            104,
            (&alpha, &HideKey::Passphrase(pass("a"))),
            None,
            vec![check(&[rp("a")], Some(&alpha))],
        );
        entries.push(json!({
            "file": "cover_rgb_128.png",
            "cover": "cover_rgb_128.png",
            "checks": [check(&[rp("tuesday"), ra.clone()], None)],
        }));
        let index = json!({
            "format_version": crate::FORMAT_VERSION,
            "description": "StegPony format v1 Lossless reveal vectors. FORMAT.md sections 4 and 5. Each check reveals the file with the listed keys; expect null means nothing is found. Covers are the unmodified images the stego files were made from.",
            "cases": entries,
        });
        std::fs::write(
            dir.join("png_vectors/index.json"),
            serde_json::to_string_pretty(&index).unwrap() + "\n",
        )
        .unwrap();
    }
}
