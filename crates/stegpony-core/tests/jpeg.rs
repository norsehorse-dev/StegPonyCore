//! JPEG coefficient codec against frozen libjpeg output. The oracle hashes in
//! tests/fixtures/jpeg/jpeg_oracle.json were computed by libjpeg (through the Python
//! jpeglib package, tools/make_jpeg_fixtures.py); tools/check_jpeg.py runs the wider
//! live comparison.

use sha2::{Digest, Sha256};
use stegpony_core::jpeg::{FrameKind, Jpeg};
use stegpony_core::Error;

fn dir() -> String {
    format!("{}/tests/fixtures/jpeg", env!("CARGO_MANIFEST_DIR"))
}

fn fixtures() -> Vec<(String, Vec<u8>, String)> {
    let oracle: serde_json::Value =
        serde_json::from_slice(&std::fs::read(format!("{}/jpeg_oracle.json", dir())).unwrap())
            .unwrap();
    let mut out = Vec::new();
    for (name, v) in oracle.as_object().unwrap() {
        let bytes = std::fs::read(format!("{}/{name}", dir())).unwrap();
        out.push((
            name.clone(),
            bytes,
            v["coef_sha256"].as_str().unwrap().to_string(),
        ));
    }
    assert!(out.len() >= 9);
    out
}

fn coef_bytes(j: &Jpeg) -> Vec<u8> {
    let mut out = Vec::new();
    for c in &j.components {
        for by in 0..c.height_blocks {
            for bx in 0..c.width_blocks {
                for &v in c.block(bx, by) {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
    }
    out
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn perturb(j: &mut Jpeg, rng: &mut Rng, count: usize) {
    for _ in 0..count {
        let ci = rng.below(j.components.len());
        let c = &mut j.components[ci];
        let (bx, by) = (rng.below(c.width_blocks), rng.below(c.height_blocks));
        let k = 1 + rng.below(63);
        let v = &mut c.block_mut(bx, by)[k];
        *v = if rng.next() & 1 == 1 && *v < 1023 {
            *v + 1
        } else {
            *v - 1
        };
    }
}

#[test]
fn coefficients_match_libjpeg() {
    for (name, bytes, want) in fixtures() {
        let j = Jpeg::parse(&bytes).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_eq!(hex(&Sha256::digest(coef_bytes(&j))), want, "{name}");
    }
}

#[test]
fn unchanged_files_round_trip_exactly() {
    for (name, bytes, _) in fixtures() {
        let j = Jpeg::parse(&bytes).unwrap();
        assert!(j.write().unwrap() == bytes, "{name}");
    }
}

#[test]
fn changed_coefficients_survive_write_and_read() {
    let mut rng = Rng(7);
    for (name, bytes, _) in fixtures() {
        for count in [1, 50, 3000] {
            let mut j = Jpeg::parse(&bytes).unwrap();
            perturb(&mut j, &mut rng, count);
            let out = j.write().unwrap();
            let back = Jpeg::parse(&out).unwrap_or_else(|e| panic!("{name}/{count}: {e}"));
            assert_eq!(coef_bytes(&back), coef_bytes(&j), "{name}/{count}");
            assert_eq!(back.kind, j.kind);
            assert_eq!(back.scan_count(), j.scan_count());
        }
    }
}

#[test]
fn optimized_tables_are_rebuilt_only_when_needed() {
    let bytes = std::fs::read(format!("{}/baseline_422_optimized.jpg", dir())).unwrap();
    let dht = |j: &Jpeg| j.marker_codes().iter().filter(|&&c| c == 0xC4).count();
    let j = Jpeg::parse(&bytes).unwrap();
    let before = dht(&j);
    // Swapping two existing values in a block needs no new symbols.
    let mut same = j.clone();
    let b = same.components[0].block_mut(0, 0);
    b.swap(0, 0);
    assert!(same.write().unwrap() == bytes);
    // A large AC value the optimized table never saw forces new tables, one DHT
    // segment before the single scan, and the result still reads back.
    let mut big = j.clone();
    big.components[0].block_mut(1, 1)[63] = 1000;
    let out = big.write().unwrap();
    let back = Jpeg::parse(&out).unwrap();
    assert_eq!(back.components[0].block(1, 1)[63], 1000);
    assert_eq!(dht(&back), 1);
    assert!(before >= 1);
}

#[test]
fn metadata_strip() {
    let bytes = std::fs::read(format!("{}/cmyk.jpg", dir())).unwrap();
    let mut j = Jpeg::parse(&bytes).unwrap();
    assert!(j.marker_codes().contains(&0xEE));
    let coefs = coef_bytes(&j);
    j.strip_metadata(true);
    assert!(!j.marker_codes().iter().any(|c| (0xE1..=0xEF).contains(c)));
    let back = Jpeg::parse(&j.write().unwrap()).unwrap();
    assert_eq!(coef_bytes(&back), coefs);

    let bytes = std::fs::read(format!("{}/baseline_420.jpg", dir())).unwrap();
    let mut j = Jpeg::parse(&bytes).unwrap();
    j.strip_metadata(true);
    assert_eq!(j.marker_codes()[0], 0xE0);
    j.strip_metadata(false);
    assert!(!j.marker_codes().contains(&0xE0));
}

#[test]
fn frame_kinds_and_geometry() {
    let read = |n: &str| Jpeg::parse(&std::fs::read(format!("{}/{n}", dir())).unwrap()).unwrap();
    let j = read("baseline_420.jpg");
    assert_eq!(j.kind, FrameKind::Baseline);
    assert_eq!((j.width, j.height), (99, 77));
    assert_eq!(
        (j.components[0].width_blocks, j.components[0].height_blocks),
        (13, 10)
    );
    assert_eq!(
        (j.components[1].width_blocks, j.components[1].height_blocks),
        (7, 5)
    );
    assert_eq!(read("progressive_turbo.jpg").kind, FrameKind::Progressive);
    assert_eq!(read("cmyk.jpg").components.len(), 4);
    assert_eq!(read("gray.jpg").components.len(), 1);
}

fn find_marker(bytes: &[u8], code: u8) -> usize {
    bytes
        .windows(2)
        .position(|w| w == [0xFF, code])
        .expect("marker")
}

#[test]
fn refuses_what_it_does_not_handle() {
    let bytes = std::fs::read(format!("{}/baseline_420.jpg", dir())).unwrap();
    let sof = find_marker(&bytes, 0xC0);
    for (code, what) in [
        (0xC9, "arithmetic"),
        (0xC3, "lossless"),
        (0xC5, "hierarchical"),
    ] {
        let mut b = bytes.clone();
        b[sof + 1] = code;
        assert!(
            matches!(Jpeg::parse(&b), Err(Error::UnsupportedCover(_))),
            "{what}"
        );
    }
    let mut b = bytes.clone();
    b[sof + 4] = 12;
    assert!(matches!(Jpeg::parse(&b), Err(Error::UnsupportedCover(_))));
    assert!(Jpeg::parse(b"\x89PNG\r\n\x1a\n").is_err());
    assert!(Jpeg::parse(&bytes[..bytes.len() / 2]).is_err());
}

/// Damaged files must fail cleanly, never panic or hang.
#[test]
fn corrupted_input_never_panics() {
    let mut rng = Rng(99);
    for (_, bytes, _) in fixtures() {
        for _ in 0..300 {
            let mut b = bytes.clone();
            match rng.below(3) {
                0 => {
                    for _ in 0..1 + rng.below(8) {
                        let i = rng.below(b.len());
                        b[i] = rng.next() as u8;
                    }
                }
                1 => b.truncate(rng.below(b.len())),
                _ => {
                    let i = rng.below(b.len());
                    let n = rng.below(64).min(b.len() - i);
                    b.drain(i..i + n);
                }
            }
            if let Ok(j) = Jpeg::parse(&b) {
                let _ = j.write();
            }
        }
    }
}
