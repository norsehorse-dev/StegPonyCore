//! Steganalysis harness helper: embeds with the real engine into every JPEG in a
//! directory, once per requested bucket, in native JPEG mode with public-key payloads
//! (no Argon2id, so a batch runs fast; the embedding itself is the same as with a
//! passphrase). Each payload fills its bucket exactly; the second slot gets filler,
//! as it always does.
//!
//!   cargo run --release --example stego_batch -- COVER_DIR OUT_DIR BUCKET [BUCKET ...]
//!
//! Writes OUT_DIR/b<BUCKET>/<name>.jpg and prints each bucket's size and change rate.
use rand_core::{OsRng, RngCore, SeedableRng};
use rayon::prelude::*;
use stegpony_core::envelope::{bucket_size, TAG_LEN};
use stegpony_core::jpeg::carrier;
use stegpony_core::{HideKey, Identity, Payload};

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let (src, out) = (&args[1], &args[2]);
    let buckets: Vec<usize> = args[3..].iter().map(|b| b.parse().unwrap()).collect();
    let mut files: Vec<_> = std::fs::read_dir(src)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().is_some_and(|e| e == "jpg"))
        .collect();
    files.sort();
    let id = Identity::generate(&mut OsRng);
    let key = HideKey::Recipient(id.recipient());
    for &k in &buckets {
        let dir = std::path::Path::new(out).join(format!("b{k}"));
        std::fs::create_dir_all(&dir).unwrap();
        let text_len = bucket_size(k) - TAG_LEN - 5;
        let ratings: Vec<String> = files
            .par_iter()
            .map(|p| {
                let mut rng = rand_chacha::ChaCha20Rng::seed_from_u64(OsRng.next_u64());
                let text: String = (0..text_len)
                    .map(|_| (b'a' + (rng.next_u32() % 26) as u8) as char)
                    .collect();
                let cover = std::fs::read(p).unwrap();
                let out =
                    carrier::hide(&cover, (&Payload::Text(text), &key), None, false, &mut rng)
                        .unwrap_or_else(|e| panic!("{}: {e}", p.display()));
                std::fs::write(dir.join(p.file_name().unwrap()), out.jpeg).unwrap();
                format!("{:?}", out.detectability)
            })
            .collect();
        let cap = carrier::capacity(&std::fs::read(&files[0]).unwrap()).unwrap();
        println!(
            "bucket {k}: {} bytes, {} files, slot elements {:?}, rating {}",
            bucket_size(k),
            files.len(),
            cap.elements,
            ratings[0]
        );
    }
}
