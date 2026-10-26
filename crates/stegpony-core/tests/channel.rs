use rand_chacha::{rand_core::SeedableRng, ChaCha20Rng};
use stegpony_core::{
    channel::{self, Channel},
    jpeg::{self, Jpeg},
    lossless::{self, Raster},
    Error, HideKey, Identity, Payload, RevealKey,
};
use zeroize::Zeroizing;

fn fixture(name: &str) -> Vec<u8> {
    std::fs::read(format!(
        "{}/tests/fixtures/{name}",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}
fn prepare(bytes: &[u8]) -> channel::PreparedCover {
    channel::prepare(bytes, Channel::TelegramPhotoV1).unwrap()
}
fn png(w: u32, h: u32, data: Vec<u8>, channels: u8) -> Vec<u8> {
    lossless::encode_png(&Raster {
        width: w,
        height: h,
        channels,
        data,
    })
    .unwrap()
}

#[test]
fn profile_and_jpeg_structure_are_explicit() {
    let p = &channel::profiles()[0];
    assert_eq!(
        (p.max_long_edge, p.quality, p.sampling),
        (1280, 72, "4:2:0")
    );
    assert!(p.experimental && p.last_verified.is_none());
    let prepared = prepare(&fixture("cover.jpg"));
    let j = Jpeg::parse(&prepared.jpeg).unwrap();
    assert_eq!(j.kind, jpeg::FrameKind::Baseline);
    assert_eq!(
        j.components
            .iter()
            .map(|c| (c.h, c.v, c.tq))
            .collect::<Vec<_>>(),
        vec![(2, 2, 0), (1, 1, 1), (1, 1, 1)]
    );
    assert_eq!(j.components[0].quant, p.quantization[0]);
    assert_eq!(j.components[1].quant, p.quantization[1]);
    assert_eq!(j.components[2].quant, p.quantization[1]);
    assert!(j.trailing.is_empty());
    assert_eq!(
        j.marker_segments()
            .iter()
            .map(|(c, _)| *c)
            .collect::<Vec<_>>(),
        vec![0xe0]
    );
    let rgb = lossless::decode_jpeg(&prepared.jpeg).unwrap();
    assert!(rgb.data.iter().all(|&v| v > 2 && v < 253));
}

#[test]
fn downsizing_no_upscale_and_all_exif_orientations() {
    let bytes = png(1400, 700, vec![100; 1400 * 700 * 3], 3);
    let out = prepare(&bytes);
    assert_eq!(
        (out.report.original_width, out.report.original_height),
        (1400, 700)
    );
    assert_eq!(
        (out.report.output_width, out.report.output_height),
        (1280, 640)
    );
    let bytes = fixture("jpeg/baseline_420.jpg");
    let original = Jpeg::parse(&bytes).unwrap();
    for orientation in 1..=8u8 {
        // Little-endian TIFF with a single SHORT Orientation entry.
        let mut exif = b"Exif\0\0II\x2a\0\x08\0\0\0\x01\0\x12\x01\x03\0\x01\0\0\0".to_vec();
        exif.extend_from_slice(&[orientation, 0, 0, 0, 0, 0, 0, 0]);
        let mut oriented = bytes.clone();
        let mut segment = vec![0xff, 0xe1];
        segment.extend_from_slice(&((exif.len() + 2) as u16).to_be_bytes());
        segment.extend(exif);
        oriented.splice(2..2, segment);
        assert_eq!(jpeg::exif_orientation(&oriented), Some(orientation as u16));
        let prepared = prepare(&oriented);
        let expected = if orientation >= 5 {
            (original.height as u32, original.width as u32)
        } else {
            (original.width as u32, original.height as u32)
        };
        assert_eq!(
            (
                prepared.report.original_width,
                prepared.report.original_height
            ),
            expected
        );
        assert_eq!(
            (prepared.report.output_width, prepared.report.output_height),
            expected
        );
        assert_eq!(jpeg::exif_orientation(&prepared.jpeg), None);
        // Compare the actual transformed content, not only swapped dimensions.
        let upright = lossless::decode_jpeg(&oriented).unwrap();
        let from_upright = prepare(&lossless::encode_png(&upright).unwrap());
        assert_eq!(prepared.jpeg, from_upright.jpeg);
    }
}

#[test]
fn headroom_adjusts_extremes_and_converges() {
    for value in [0, 255] {
        let out = prepare(&png(33, 17, vec![value; 33 * 17 * 3], 3));
        assert!(out.report.headroom_areas > 0 && out.report.headroom_rounds > 0);
        assert!(out.report.headroom_rounds <= 12);
        let pixels = lossless::decode_jpeg(&out.jpeg).unwrap();
        assert!(pixels.data.iter().all(|&v| v > 2 && v < 253));
    }
    let neutral = prepare(&png(32, 32, vec![128; 32 * 32 * 3], 3));
    assert_eq!(
        (
            neutral.report.headroom_areas,
            neutral.report.headroom_rounds
        ),
        (0, 0)
    );
    // Saturated chroma transitions stress subsampling, IDCT and color conversion.
    let data = (0..48 * 48)
        .flat_map(|i| {
            if i % 48 / 4 % 2 == 0 {
                [255, 0, 0]
            } else {
                [0, 0, 255]
            }
        })
        .collect();
    let out = prepare(&png(48, 48, data, 3));
    let pixels = lossless::decode_jpeg(&out.jpeg).unwrap();
    assert!(pixels.data.iter().all(|&v| v > 2 && v < 253));
}

#[test]
fn rejects_bad_images_transparency_and_cmyk() {
    for bytes in [b"invalid".as_slice(), b"\xff\xd8\xff"] {
        assert!(channel::prepare(bytes, Channel::TelegramPhotoV1).is_err());
    }
    assert!(matches!(
        channel::prepare(&fixture("jpeg/cmyk.jpg"), Channel::TelegramPhotoV1),
        Err(Error::UnsupportedCover(_))
    ));
    assert!(matches!(
        channel::prepare(&png(2, 2, vec![0; 16], 4), Channel::TelegramPhotoV1),
        Err(Error::UnsupportedCover(_))
    ));
    let opaque = png(2, 2, [128, 128, 128, 255].repeat(4), 4);
    assert_eq!(prepare(&opaque).report.output_width, 2);
    assert_eq!(prepare(&png(8, 8, vec![128; 64], 1)).report.output_width, 8);
    assert!(channel::prepare(&fixture("cover_palette.png"), Channel::TelegramPhotoV1).is_err());
}

#[test]
fn preparation_is_repeatable_and_both_native_slots_reveal() {
    let bytes = fixture("cover.jpg");
    let out = prepare(&bytes);
    assert_eq!(out.jpeg, prepare(&bytes).jpeg);
    let mut rng = ChaCha20Rng::seed_from_u64(985);
    let id = Identity::generate(&mut rng);
    let real = Payload::Text("prepared Telegram cover".into());
    let decoy = Payload::Text("shopping list".into());
    let pk = HideKey::Recipient(id.recipient());
    let dk = HideKey::Passphrase(Zeroizing::new("decoy".into()));
    let stego = jpeg::carrier::hide(
        &out.jpeg,
        (&real, &pk),
        Some((&decoy, &dk)),
        false,
        &mut rng,
    )
    .unwrap();
    assert_eq!(
        jpeg::carrier::reveal(&stego.jpeg, &[RevealKey::Identity(id)]).unwrap(),
        Some(real)
    );
    assert_eq!(
        jpeg::carrier::reveal(
            &stego.jpeg,
            &[RevealKey::Passphrase(Zeroizing::new("decoy".into()))]
        )
        .unwrap(),
        Some(decoy)
    );
    assert_eq!(
        jpeg::carrier::capacity(&out.jpeg).unwrap(),
        jpeg::carrier::capacity(&stego.jpeg).unwrap()
    );
    // No simulated/real messenger is involved in this test.
}

#[test]
fn progressive_restart_inputs_have_a_sequential_decode_fallback() {
    let bytes = fixture("jpeg/progressive_restart.jpg");
    let source = Jpeg::parse(&bytes).unwrap();
    let prepared = prepare(&bytes);
    assert_eq!(
        (
            prepared.report.original_width,
            prepared.report.original_height
        ),
        (source.width as u32, source.height as u32)
    );
    assert_eq!(
        Jpeg::parse(&prepared.jpeg).unwrap().kind,
        jpeg::FrameKind::Baseline
    );
}
