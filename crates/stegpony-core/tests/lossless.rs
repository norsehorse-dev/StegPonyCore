use rand_chacha::rand_core::SeedableRng;
use rand_chacha::ChaCha20Rng;
use stegpony_core::lossless::{self, decode_png, SourceFormat};
use stegpony_core::{Error, HideKey, Identity, Payload, RevealKey};
use zeroize::Zeroizing;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
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

fn text(s: &str) -> Payload {
    Payload::Text(s.into())
}

#[test]
fn passphrase_roundtrip_rgb() {
    let cover = fixture("cover_rgb.png");
    let mut rng = ChaCha20Rng::seed_from_u64(100);
    let p = text("the drop is behind the third bench");
    let out = lossless::hide(&cover, (&p, &hp("tuesday")), None, &mut rng).unwrap();
    assert_eq!(out.source, SourceFormat::Png);
    assert_eq!(
        lossless::reveal(&out.png, &[rp("tuesday")]).unwrap(),
        Some(p)
    );
    assert_eq!(
        lossless::reveal(&out.png, &[rp("wednesday")]).unwrap(),
        None
    );
    assert_eq!(lossless::reveal(&cover, &[rp("tuesday")]).unwrap(), None);
}

#[test]
fn changes_are_plus_minus_one_and_sparse() {
    let cover = fixture("cover_rgb.png");
    let mut rng = ChaCha20Rng::seed_from_u64(101);
    let p = text("short");
    let out = lossless::hide(&cover, (&p, &hp("k")), None, &mut rng).unwrap();
    let a = decode_png(&cover).unwrap();
    let b = decode_png(&out.png).unwrap();
    assert_eq!(
        (a.width, a.height, a.channels),
        (b.width, b.height, b.channels)
    );
    let mut changed = 0;
    for (x, y) in a.data.iter().zip(&b.data) {
        let d = (*x as i16 - *y as i16).abs();
        assert!(d <= 1);
        changed += d as usize;
    }
    // Two slots of 64-byte envelopes plus heads: a few hundred changes at most.
    assert!(changed > 0 && changed < 1500, "changed = {changed}");
}

#[test]
fn public_key_roundtrip() {
    let cover = fixture("cover_rgb.png");
    let mut rng = ChaCha20Rng::seed_from_u64(102);
    let id = Identity::generate(&mut rng);
    let other = Identity::generate(&mut rng);
    let p = text("for your eyes");
    let out = lossless::hide(
        &cover,
        (&p, &HideKey::Recipient(id.recipient())),
        None,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        lossless::reveal(&out.png, &[RevealKey::Identity(id.clone())]).unwrap(),
        Some(p.clone())
    );
    assert_eq!(
        lossless::reveal(&out.png, &[RevealKey::Identity(other.clone())]).unwrap(),
        None
    );
    // Mixed key lists: the right key is found among others.
    let keys = [
        rp("nope"),
        RevealKey::Identity(other),
        RevealKey::Identity(id),
    ];
    assert_eq!(lossless::reveal(&out.png, &keys).unwrap(), Some(p));
}

#[test]
fn decoy_reveals_each_payload_with_its_own_key() {
    let cover = fixture("cover_rgb.png");
    for seed in 0..4 {
        let mut rng = ChaCha20Rng::seed_from_u64(200 + seed);
        let real = text("real: the account is 4471");
        let decoy = text("grocery list: eggs, rice");
        let out = lossless::hide(
            &cover,
            (&real, &hp("real pass")),
            Some((&decoy, &hp("decoy pass"))),
            &mut rng,
        )
        .unwrap();
        assert_eq!(
            lossless::reveal(&out.png, &[rp("real pass")]).unwrap(),
            Some(real.clone())
        );
        assert_eq!(
            lossless::reveal(&out.png, &[rp("decoy pass")]).unwrap(),
            Some(decoy.clone())
        );
        assert_eq!(lossless::reveal(&out.png, &[rp("other")]).unwrap(), None);
    }
}

#[test]
fn decoy_with_mixed_key_types() {
    let cover = fixture("cover_rgb.png");
    let mut rng = ChaCha20Rng::seed_from_u64(210);
    let id = Identity::generate(&mut rng);
    let real = text("real");
    let decoy = text("decoy");
    let out = lossless::hide(
        &cover,
        (&real, &HideKey::Recipient(id.recipient())),
        Some((&decoy, &hp("give this up"))),
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        lossless::reveal(&out.png, &[RevealKey::Identity(id)]).unwrap(),
        Some(real)
    );
    assert_eq!(
        lossless::reveal(&out.png, &[rp("give this up")]).unwrap(),
        Some(decoy)
    );
}

#[test]
fn file_payload_roundtrip() {
    let cover = fixture("cover_rgb.png");
    let mut rng = ChaCha20Rng::seed_from_u64(103);
    let data: Vec<u8> = (0..900u32).map(|i| (i * 7 % 256) as u8).collect();
    let p = Payload::File {
        name: "notes.age".into(),
        mime: "application/octet-stream".into(),
        data,
    };
    let out = lossless::hide(&cover, (&p, &hp("files")), None, &mut rng).unwrap();
    assert_eq!(lossless::reveal(&out.png, &[rp("files")]).unwrap(), Some(p));
}

#[test]
fn grayscale_cover() {
    let cover = fixture("cover_gray.png");
    let mut rng = ChaCha20Rng::seed_from_u64(104);
    let p = text("gray");
    let out = lossless::hide(&cover, (&p, &hp("g")), None, &mut rng).unwrap();
    assert_eq!(decode_png(&out.png).unwrap().channels, 1);
    assert_eq!(lossless::reveal(&out.png, &[rp("g")]).unwrap(), Some(p));
}

#[test]
fn rgba_cover_leaves_alpha_and_translucent_pixels_alone() {
    let cover = fixture("cover_rgba.png");
    let mut rng = ChaCha20Rng::seed_from_u64(105);
    let p = text("alpha");
    let out = lossless::hide(&cover, (&p, &hp("a")), None, &mut rng).unwrap();
    let a = decode_png(&cover).unwrap();
    let b = decode_png(&out.png).unwrap();
    assert_eq!(b.channels, 4);
    for (pa, pb) in a.data.chunks(4).zip(b.data.chunks(4)) {
        assert_eq!(pa[3], pb[3]);
        if pa[3] != 255 {
            assert_eq!(pa, pb);
        }
    }
    assert_eq!(lossless::reveal(&out.png, &[rp("a")]).unwrap(), Some(p));
}

#[test]
fn jpeg_cover_becomes_png() {
    let cover = fixture("cover.jpg");
    let mut rng = ChaCha20Rng::seed_from_u64(106);
    let p = text("from a jpeg");
    let out = lossless::hide(&cover, (&p, &hp("j")), None, &mut rng).unwrap();
    assert_eq!(out.source, SourceFormat::Jpeg);
    assert!(out.png.starts_with(b"\x89PNG"));
    assert_eq!(lossless::reveal(&out.png, &[rp("j")]).unwrap(), Some(p));
}

#[test]
fn too_large_and_too_small() {
    let cover = fixture("cover_rgb.png");
    let mut rng = ChaCha20Rng::seed_from_u64(107);
    let cap = lossless::capacity(&cover).unwrap();
    assert!(cap.max_text_bytes > 1000, "{cap:?}");
    let big = text(&"x".repeat(cap.max_text_bytes + 1));
    assert!(matches!(
        lossless::hide(&cover, (&big, &hp("b")), None, &mut rng),
        Err(Error::PayloadTooLarge { .. })
    ));
    let fits = text(&"y".repeat(cap.max_text_bytes));
    let out = lossless::hide(&cover, (&fits, &hp("b")), None, &mut rng).unwrap();
    assert_eq!(lossless::reveal(&out.png, &[rp("b")]).unwrap(), Some(fits));

    let tiny = fixture("cover_tiny.png");
    assert!(lossless::hide(&tiny, (&text("x"), &hp("t")), None, &mut rng).is_err());
    assert_eq!(lossless::reveal(&tiny, &[rp("t")]).unwrap(), None);
}

#[test]
fn palette_png_is_refused() {
    let cover = fixture("cover_palette.png");
    let mut rng = ChaCha20Rng::seed_from_u64(108);
    assert!(matches!(
        lossless::hide(&cover, (&text("x"), &hp("p")), None, &mut rng),
        Err(Error::UnsupportedCover(_))
    ));
}

#[test]
fn deterministic_for_a_seed() {
    let cover = fixture("cover_rgb.png");
    let p = text("same every time");
    let a = lossless::hide(
        &cover,
        (&p, &hp("d")),
        None,
        &mut ChaCha20Rng::seed_from_u64(9),
    )
    .unwrap();
    let b = lossless::hide(
        &cover,
        (&p, &hp("d")),
        None,
        &mut ChaCha20Rng::seed_from_u64(9),
    )
    .unwrap();
    assert_eq!(a.png, b.png);
}

#[test]
fn jpeg_cover_is_made_upright() {
    let jpeg = std::fs::read(format!(
        "{}/tests/fixtures/jpeg/baseline_420.jpg",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap();
    let (stored, _) = lossless::decode_cover(&jpeg).unwrap();
    assert_ne!(stored.width, stored.height);
    // The same file with an EXIF orientation of 6 (rotate 90 clockwise) after SOI.
    let mut rotated = jpeg.clone();
    let exif: &[u8] = b"\xff\xe1\x00\x22Exif\0\0MM\0\x2a\0\0\0\x08\0\x01\x01\x12\0\x03\0\0\0\x01\0\x06\0\0\0\0\0\0";
    rotated.splice(2..2, exif.iter().copied());
    assert_eq!(stegpony_core::jpeg::exif_orientation(&rotated), Some(6));
    let (upright, source) = lossless::decode_cover(&rotated).unwrap();
    assert_eq!(source, SourceFormat::Jpeg);
    assert_eq!(upright, stored.clone().oriented(6));
    assert_eq!(
        (upright.width, upright.height),
        (stored.height, stored.width)
    );
}
