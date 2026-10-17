//! Metadata policy for native JPEG output, matching ScrubPony's default: keep what a
//! viewer needs to show the picture the right way up and in the right colors, drop
//! everything that identifies the camera, the place, the time or the owner.
//!
//! Kept: JFIF (with any embedded thumbnail removed), ICC profile chunks, Adobe APP14.
//! Rewritten: EXIF becomes ScrubPony's 36-byte orientation-only block when the
//! orientation is 2 to 8, and disappears otherwise. Dropped: every other APPn
//! (XMP, MPF, JFXX thumbnails, maker blocks, Photoshop/IPTC), comments, and anything
//! after EOI.

/// What to do with one APPn or COM segment.
pub(super) enum Action {
    Keep,
    Replace(Vec<u8>),
    Drop,
}

const EXIF_ID: &[u8] = b"Exif\0\0";

/// Decides one segment's fate. `orientation_done` is set once an EXIF block has been
/// considered, so a file with several EXIF blocks gets at most one orientation block.
pub(super) fn action(code: u8, data: &[u8], orientation_done: &mut bool) -> Action {
    match code {
        0xE0 if data.starts_with(b"JFIF\0") && data.len() >= 14 => {
            // Version, units and density stay; the thumbnail size goes to 0x0 and the
            // thumbnail pixels go with it.
            let mut jfif = data[..12].to_vec();
            jfif.extend_from_slice(&[0, 0]);
            Action::Replace(jfif)
        }
        0xE1 if data.starts_with(EXIF_ID) => {
            if std::mem::replace(orientation_done, true) {
                return Action::Drop;
            }
            match exif_orientation(&data[EXIF_ID.len()..]) {
                Some(o @ 2..=8) => Action::Replace(orientation_block(o)),
                _ => Action::Drop,
            }
        }
        0xE2 if data.starts_with(b"ICC_PROFILE\0") => Action::Keep,
        0xEE if data.starts_with(b"Adobe") => Action::Keep,
        _ => Action::Drop,
    }
}

/// ScrubPony's minimal EXIF payload (the APP1 segment without marker and length):
/// big-endian TIFF, IFD0 with the one Orientation entry, no IFD1 and so no thumbnail.
pub(super) fn orientation_block(orientation: u16) -> Vec<u8> {
    let [hi, lo] = orientation.to_be_bytes();
    let mut b = EXIF_ID.to_vec();
    b.extend_from_slice(&[
        b'M', b'M', 0x00, 0x2A, // big-endian TIFF, magic 42
        0x00, 0x00, 0x00, 0x08, // IFD0 starts 8 bytes in
        0x00, 0x01, // one entry
        0x01, 0x12, // Orientation
        0x00, 0x03, // SHORT
        0x00, 0x00, 0x00, 0x01, // count 1
        hi, lo, 0x00, 0x00, // value, left-justified
        0x00, 0x00, 0x00, 0x00, // no next IFD
    ]);
    b
}

/// Reads the Orientation tag from IFD0 of a TIFF block. Every read is bounds-checked;
/// anything malformed reads as no orientation.
pub(super) fn exif_orientation(tiff: &[u8]) -> Option<u16> {
    let big = match tiff.get(..4)? {
        [b'M', b'M', 0, 42] => true,
        [b'I', b'I', 42, 0] => false,
        _ => return None,
    };
    let u16_at = |o: usize| -> Option<u16> {
        let b: [u8; 2] = tiff.get(o..o.checked_add(2)?)?.try_into().ok()?;
        Some(if big {
            u16::from_be_bytes(b)
        } else {
            u16::from_le_bytes(b)
        })
    };
    let u32_at = |o: usize| -> Option<u32> {
        let b: [u8; 4] = tiff.get(o..o.checked_add(4)?)?.try_into().ok()?;
        Some(if big {
            u32::from_be_bytes(b)
        } else {
            u32::from_le_bytes(b)
        })
    };
    let ifd = u32_at(4)? as usize;
    let entries = u16_at(ifd)? as usize;
    for i in 0..entries {
        let e = ifd.checked_add(2)?.checked_add(i.checked_mul(12)?)?;
        if u16_at(e)? == 0x0112 {
            // SHORT, count 1: the value sits in the first two bytes of the value field.
            if u16_at(e + 2)? != 3 || u32_at(e + 4)? != 1 {
                return None;
            }
            return u16_at(e + 8);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn orientation_block_matches_scrubpony_bytes() {
        let b = orientation_block(6);
        // ScrubPony's segment is 36 bytes with marker and length; the payload is 32.
        assert_eq!(b.len(), 32);
        assert_eq!(exif_orientation(&b[6..]), Some(6));
        assert_eq!(
            b[6..],
            [
                b'M', b'M', 0, 42, 0, 0, 0, 8, 0, 1, 0x01, 0x12, 0, 3, 0, 0, 0, 1, 0, 6, 0, 0, 0,
                0, 0, 0
            ]
        );
    }

    #[test]
    fn little_endian_and_malformed_tiff() {
        let le = [
            b'I', b'I', 42, 0, 8, 0, 0, 0, 2, 0, // two entries
            0x0f, 0x01, 2, 0, 4, 0, 0, 0, b'M', b'o', b't', 0, // Make
            0x12, 0x01, 3, 0, 1, 0, 0, 0, 8, 0, 0, 0, // Orientation 8
            0, 0, 0, 0,
        ];
        assert_eq!(exif_orientation(&le), Some(8));
        for cut in 0..le.len() - 4 {
            // Truncations never panic; the tag reads only once it is complete.
            let _ = exif_orientation(&le[..cut]);
        }
        assert_eq!(exif_orientation(b"MM\0\x2a\xff\xff\xff\xff"), None);
        assert_eq!(exif_orientation(b"XX\0\x2a\0\0\0\x08"), None);
    }

    #[test]
    fn segment_policy() {
        let mut done = false;
        let mut jfif = b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x02\x01".to_vec();
        jfif.extend_from_slice(&[7; 6]);
        assert!(matches!(
            action(0xE0, &jfif, &mut done),
            Action::Replace(j) if j == b"JFIF\0\x01\x02\x01\x00\x48\x00\x48\x00\x00"
        ));
        assert!(matches!(
            action(0xE0, b"JFXX\0\x10thumb", &mut done),
            Action::Drop
        ));
        assert!(matches!(
            action(0xE2, b"ICC_PROFILE\0\x01\x01", &mut done),
            Action::Keep
        ));
        assert!(matches!(action(0xE2, b"MPF\0", &mut done), Action::Drop));
        assert!(matches!(
            action(0xEE, b"Adobe\0\x64", &mut done),
            Action::Keep
        ));
        assert!(matches!(action(0xFE, b"comment", &mut done), Action::Drop));
        let exif = orientation_block(3);
        assert!(matches!(
            action(0xE1, &exif, &mut done),
            Action::Replace(b) if b == exif
        ));
        // A second EXIF block never produces a second orientation block.
        assert!(matches!(action(0xE1, &exif, &mut done), Action::Drop));
        let mut fresh = false;
        assert!(matches!(
            action(0xE1, &orientation_block(1), &mut fresh),
            Action::Drop
        ));
        assert!(matches!(
            action(0xE1, b"http://ns.adobe.com/xap/1.0/\0<x/>", &mut fresh),
            Action::Drop
        ));
    }
}
