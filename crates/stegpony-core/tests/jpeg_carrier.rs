use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use stegpony_core::engine::{self, Cover};
use stegpony_core::jpeg::{
    carrier::{self, JpegCover},
    Jpeg,
};
use stegpony_core::{HideKey, Identity, Payload, RevealKey};
use zeroize::Zeroizing;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/jpeg/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn hp(s: &str) -> HideKey {
    HideKey::Passphrase(Zeroizing::new(s.into()))
}
fn rp(s: &str) -> RevealKey {
    RevealKey::Passphrase(Zeroizing::new(s.into()))
}

#[test]
fn all_ac_geometry_and_invariant_membership() {
    for name in [
        "baseline_420.jpg",
        "sampling_mixed.jpg",
        "cmyk.jpg",
        "gray.jpg",
    ] {
        let j = Jpeg::parse(&fixture(name)).unwrap();
        let mut cover = JpegCover::new(j.clone());
        let mut t = 0;
        let mut counts = [0; 2];
        for c in &j.components {
            for by in 0..c.height_blocks {
                for bx in 0..c.width_blocks {
                    for k in 1..64 {
                        let slot = ((bx + by) & 1) as u8;
                        assert_eq!(cover.slot_of(t), Some(slot));
                        assert_eq!(cover.parity(t), (c.block(bx, by)[k] & 1) as u8);
                        counts[slot as usize] += 1;
                        cover.flip(t, t & 1 == 0);
                        assert_eq!(cover.slot_of(t), Some(slot));
                        assert_ne!(cover.parity(t), (c.block(bx, by)[k] & 1) as u8);
                        t += 1;
                    }
                }
            }
        }
        assert_eq!(cover.domain(), t);
        assert_eq!(cover.slot_counts(), counts);
        assert_eq!(cover.slot_of(t), None);
        for (a, b) in j.components.iter().zip(&cover.jpeg().components) {
            for by in 0..a.height_blocks {
                for bx in 0..a.width_blocks {
                    assert_eq!(a.block(bx, by)[0], b.block(bx, by)[0]);
                }
            }
        }
    }
}

#[test]
fn zero_crossings_and_signed_limits_are_usable() {
    let mut j = Jpeg::parse(&fixture("gray.jpg")).unwrap();
    let values = [0, 1, -1, 1023, -1023, i16::MAX, i16::MIN];
    j.components[0].block_mut(0, 0)[1..8].copy_from_slice(&values);
    for up in [false, true] {
        let mut c = JpegCover::new(j.clone());
        for t in 0..7 {
            c.flip(t, up);
        }
        for (old, new) in values.iter().zip(&c.jpeg().components[0].block(0, 0)[1..8]) {
            assert_eq!(old.abs_diff(*new), 1);
            assert_ne!(old & 1, new & 1);
        }
    }
}

#[test]
fn public_key_payloads_across_codec_matrix() {
    let oracle: serde_json::Value = serde_json::from_slice(&fixture("jpeg_oracle.json")).unwrap();
    for (name, _) in oracle.as_object().unwrap() {
        let bytes = fixture(name);
        let cap = carrier::capacity(&bytes).unwrap();
        if cap.max_bucket.is_none() {
            assert_eq!(name, "gray.jpg");
            let mut rng = ChaCha20Rng::seed_from_u64(1);
            let p = Payload::Text("small".into());
            assert!(carrier::hide(&bytes, (&p, &hp("key")), None, false, &mut rng).is_err());
            continue;
        }
        let mut rng = ChaCha20Rng::seed_from_u64(770);
        let id = Identity::generate(&mut rng);
        let wrong = Identity::generate(&mut rng);
        let p = Payload::File {
            name: "note.bin".into(),
            mime: "application/octet-stream".into(),
            data: vec![0, 255, 1, 2],
        };
        let out = carrier::hide(
            &bytes,
            (&p, &HideKey::Recipient(id.recipient())),
            None,
            false,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            carrier::reveal(&out.jpeg, &[RevealKey::Identity(id)]).unwrap(),
            Some(p)
        );
        assert_eq!(
            carrier::reveal(&out.jpeg, &[RevealKey::Identity(wrong.clone())]).unwrap(),
            None
        );
        assert_eq!(
            carrier::reveal(&bytes, &[RevealKey::Identity(wrong)]).unwrap(),
            None
        );
        let (a, b) = (
            Jpeg::parse(&bytes).unwrap(),
            Jpeg::parse(&out.jpeg).unwrap(),
        );
        assert_eq!(
            (a.width, a.height, a.kind, a.scan_count()),
            (b.width, b.height, b.kind, b.scan_count())
        );
        for (a, b) in a.components.iter().zip(&b.components) {
            assert_eq!((a.h, a.v, a.quant), (b.h, b.v, b.quant));
            for (i, (x, y)) in a.coefs.iter().zip(&b.coefs).enumerate() {
                let block = i / 64;
                let padding = block % a_grid_width(a) >= a.width_blocks
                    || block / a_grid_width(a) >= a.height_blocks;
                if i % 64 == 0 || padding {
                    assert_eq!(x, y);
                } else {
                    assert!(x.abs_diff(*y) <= 1);
                }
            }
        }
        assert_eq!(
            a.marker_codes().contains(&0xee),
            b.marker_codes().contains(&0xee)
        );
        assert_eq!(carrier::capacity(&out.jpeg).unwrap(), cap);
    }
}
fn a_grid_width(c: &stegpony_core::jpeg::Component) -> usize {
    c.coefs.len() / 64 / ((c.height_blocks.div_ceil(c.v as usize)) * c.v as usize)
}

#[test]
fn passphrase_decoy_metadata_and_filler() {
    let mut j = Jpeg::parse(&fixture("baseline_420.jpg")).unwrap();
    j.trailing = b"private trailer".to_vec();
    let mut bytes = j.write().unwrap();
    // Privacy-bearing APP1 segment, independent of the fixture's own markers.
    bytes.splice(
        2..2,
        [0xff, 0xe1, 0x00, 0x0a, b'E', b'x', b'i', b'f', 0, 0, 1, 2],
    );
    let (real, decoy) = (
        Payload::Text("real message".into()),
        Payload::Text("shopping".into()),
    );
    for keep in [false, true] {
        let mut rng = ChaCha20Rng::seed_from_u64(45);
        let out = carrier::hide(
            &bytes,
            (&real, &hp("secret")),
            Some((&decoy, &hp("decoy"))),
            keep,
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            carrier::reveal(&out.jpeg, &[rp("secret")]).unwrap(),
            Some(real.clone())
        );
        assert_eq!(
            carrier::reveal(&out.jpeg, &[rp("decoy")]).unwrap(),
            Some(decoy.clone())
        );
        assert_eq!(carrier::reveal(&out.jpeg, &[rp("wrong")]).unwrap(), None);
        let parsed = Jpeg::parse(&out.jpeg).unwrap();
        assert_eq!(parsed.trailing.is_empty(), !keep);
        assert_eq!(parsed.marker_codes().contains(&0xe1), keep);
    }
    let mut rng = ChaCha20Rng::seed_from_u64(46);
    let out = carrier::hide(&bytes, (&real, &hp("secret")), None, false, &mut rng).unwrap();
    assert_eq!(
        carrier::reveal(&out.jpeg, &[rp("secret")]).unwrap(),
        Some(real)
    );
    assert!(carrier::hide(b"not jpeg", (&decoy, &hp("x")), None, false, &mut rng).is_err());
    let mut tiny = j;
    for c in &mut tiny.components {
        c.width_blocks = 1;
        c.height_blocks = 1;
    }
    assert!(engine::hide(
        &mut JpegCover::new(tiny),
        (&decoy, &hp("x")),
        None,
        &mut rng
    )
    .is_err());
}

#[test]
fn wavelet_costs_prefer_texture_and_are_repeatable() {
    let j = Jpeg::parse(&fixture("gray.jpg")).unwrap();
    let mut flat = j.clone();
    for c in &mut flat.components {
        c.coefs.fill(0);
    }
    let flat = JpegCover::new(flat);
    let busy = JpegCover::new(j.clone());
    let ts: Vec<u64> = (0..busy.domain().min(300)).collect();
    let a = flat.costs(&[&ts]);
    let b = busy.costs(&[&ts]);
    assert!(a[0].iter().sum::<f32>() > b[0].iter().sum::<f32>());
    assert!(b[0].iter().all(|v| v.is_finite() && *v > 0.0));
    // A second request on the same unmodified cover gives the same costs.
    assert_eq!(b, busy.costs(&[&ts]));
}

/// Reference J-UNIWARD costs for gray.jpg, computed with conseal 2025.11
/// (`conseal.juniward._costmap.compute_cost`, `JUNIWARD_FIX_OFF_BY_ONE`, sigma 2^-6) on
/// the unrounded dequantized plane. Element numbers follow FORMAT.md section 6.
#[test]
fn matches_reference_juniward() {
    const REFERENCE: [(u64, f64); 16] = [
        (0, 6.115381e+00),
        (62, 1.195985e+02),
        (8134, 7.476781e+00),
        (7379, 7.482540e+00),
        (817, 2.363337e+02),
        (7918, 6.658799e+01),
        (7041, 1.858767e+01),
        (6681, 5.699593e+01),
        (2701, 2.209245e+01),
        (7402, 2.471450e+01),
        (6665, 3.362011e+01),
        (1248, 5.124863e+01),
        (2726, 5.313391e+00),
        (5984, 2.394098e+01),
        (3685, 2.347736e+01),
        (4568, 6.693064e+00),
    ];
    let cover = JpegCover::new(Jpeg::parse(&fixture("gray.jpg")).unwrap());
    let ts: Vec<u64> = REFERENCE.iter().map(|&(t, _)| t).collect();
    let got = cover.costs(&[&ts]);
    for ((t, want), have) in REFERENCE.iter().zip(&got[0]) {
        assert!(
            ((*have as f64 - want) / want).abs() < 1e-3,
            "element {t}: {have} vs reference {want}"
        );
    }
}

#[test]
fn scrub_follows_scrubpony_policy() {
    // The fixture starts with a plain 14-byte JFIF APP0 (no thumbnail); the segments
    // below are injected in front of it.
    let mut bytes = fixture("baseline_420.jpg");
    let seg = |code: u8, payload: &[u8]| {
        let mut s = vec![0xff, code];
        s.extend_from_slice(&((payload.len() + 2) as u16).to_be_bytes());
        s.extend_from_slice(payload);
        s
    };
    // Little-endian EXIF with a GPS IFD pointer and orientation 6.
    let mut exif = b"Exif\0\0".to_vec();
    exif.extend_from_slice(&[
        b'I', b'I', 42, 0, 8, 0, 0, 0, 2, 0, 0x25, 0x88, 4, 0, 1, 0, 0, 0, 0x26, 0, 0, 0, 0x12,
        0x01, 3, 0, 1, 0, 0, 0, 6, 0, 0, 0, 0, 0, 0, 0,
    ]);
    // JFIF declaring a 1x1 thumbnail (3 bytes of RGB).
    let jfif_thumb = b"JFIF\0\x01\x02\x00\x00\x01\x00\x01\x01\x01\x55\x55\x55";
    let mut extra = Vec::new();
    for s in [
        seg(0xe0, jfif_thumb),
        seg(0xe0, b"JFXX\0\x10thumbnail"),
        seg(0xe1, &exif),
        seg(0xe1, b"http://ns.adobe.com/xap/1.0/\0<x:xmpmeta/>"),
        seg(0xe2, b"ICC_PROFILE\0\x01\x01profile"),
        seg(0xe2, b"MPF\0\x00"),
        seg(0xed, b"Photoshop 3.0\0"),
        seg(0xfe, b"shot on my phone"),
    ] {
        extra.extend(s);
    }
    bytes.splice(2..2, extra);
    bytes.extend_from_slice(b"trailing gain map");

    let mut rng = ChaCha20Rng::seed_from_u64(47);
    let p = Payload::Text("x".into());
    let out = carrier::hide(&bytes, (&p, &hp("k")), None, false, &mut rng).unwrap();
    let parsed = Jpeg::parse(&out.jpeg).unwrap();
    let orientation: &[u8] =
        b"Exif\0\0MM\0\x2a\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0\x06\0\0\0\0\0\0";
    let want: Vec<(u8, &[u8])> = vec![
        (0xe0, b"JFIF\0\x01\x02\x00\x00\x01\x00\x01\x00\x00"),
        (0xe1, orientation),
        (0xe2, b"ICC_PROFILE\0\x01\x01profile"),
        (0xe0, b"JFIF\0\x01\x01\x00\x00\x01\x00\x01\x00\x00"),
    ];
    assert_eq!(parsed.marker_segments(), want);
    assert!(parsed.trailing.is_empty());
    assert_eq!(carrier::reveal(&out.jpeg, &[rp("k")]).unwrap(), Some(p));
}
