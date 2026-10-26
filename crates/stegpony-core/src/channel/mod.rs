//! Experimental channel cover preparation, before ordinary native JPEG embedding.
//! Profile observations are scoped lab evidence, not guarantees of delivery.
//! Preparation destroys existing hidden payloads; never run it after embedding.
mod profiles;
mod resize;
pub use profiles::{ChannelProfile, Headroom};

use crate::jpeg::{self, encode};
use crate::lossless::{self, Raster, SourceFormat};
use crate::{Error, Result};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Channel {
    TelegramPhotoV1,
}

pub fn profiles() -> &'static [ChannelProfile] {
    &profiles::PROFILES
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PreparationReport {
    pub channel: Channel,
    pub profile_id: &'static str,
    pub profile_revision: u32,
    /// Display dimensions, after applying JPEG EXIF orientation.
    pub original_width: u32,
    pub original_height: u32,
    pub output_width: u32,
    pub output_height: u32,
    /// Distinct 16x16 areas adjusted at least once.
    pub headroom_areas: u32,
    /// Number of adjustment passes, excluding the final successful check.
    pub headroom_rounds: u8,
}

pub struct PreparedCover {
    /// Fresh JPEG for capacity/fit and native embedding, not a stego image.
    pub jpeg: Vec<u8>,
    pub report: PreparationReport,
}

/// Decode JPEG or opaque 8-bit PNG, apply JPEG orientation, downsize without
/// enlargement, and encode a metadata-free baseline 4:2:0 cover. RGB is not ICC
/// color-managed. Partial transparency and CMYK/YCCK JPEGs are refused.
pub fn prepare(image: &[u8], channel: Channel) -> Result<PreparedCover> {
    let profile = profiles().iter().find(|p| p.channel == channel).unwrap();
    let raster = match lossless::sniff(image) {
        Some(SourceFormat::Jpeg) => {
            // Reject CMYK before a decoder can convert it ambiguously to RGB.
            let parsed = jpeg::Jpeg::parse(image)?;
            if !matches!(parsed.components.len(), 1 | 3) {
                return Err(Error::UnsupportedCover(
                    "channel preparation requires gray or three-component JPEG".into(),
                ));
            }
            match lossless::decode_jpeg(image) {
                Ok(raster) => raster,
                // Some valid progressive/restart layouts are refused by zune.
                // The coefficient codec has already validated the file: normalize
                // its scans without requantization, retaining EXIF/color markers.
                Err(_) => lossless::decode_jpeg(&parsed.into_sequential()?)?,
            }
        }
        Some(SourceFormat::Png) => lossless::decode_png(image)?,
        None => return Err(Error::UnsupportedCover("not a PNG or JPEG image".into())),
    };
    let rgb = opaque_rgb(raster)?;
    let (original_width, original_height) = (rgb.width, rgb.height);
    let resized = resize::downsize(rgb, profile.max_long_edge);
    let (jpeg, areas, rounds) = headroom(resized, profile)?;
    let parsed = jpeg::Jpeg::parse(&jpeg)?;
    Ok(PreparedCover {
        jpeg,
        report: PreparationReport {
            channel,
            profile_id: profile.id,
            profile_revision: profile.revision,
            original_width,
            original_height,
            output_width: parsed.width as u32,
            output_height: parsed.height as u32,
            headroom_areas: areas,
            headroom_rounds: rounds,
        },
    })
}

fn opaque_rgb(r: Raster) -> Result<Raster> {
    if r.width == 0
        || r.height == 0
        || !(1..=4).contains(&r.channels)
        || r.data.len() as u64 != r.width as u64 * r.height as u64 * r.channels as u64
    {
        return Err(Error::BadCover("invalid decoded raster".into()));
    }
    if r.channels == 3 {
        return Ok(r);
    }
    let mut data = Vec::with_capacity(r.width as usize * r.height as usize * 3);
    for p in r.data.chunks_exact(r.channels as usize) {
        let alpha = match r.channels {
            2 => Some(p[1]),
            4 => Some(p[3]),
            _ => None,
        };
        if alpha.is_some_and(|a| a != 255) {
            return Err(Error::UnsupportedCover(
                "channel preparation requires fully opaque pixels".into(),
            ));
        }
        if r.channels <= 2 {
            data.extend_from_slice(&[p[0]; 3]);
        } else {
            data.extend_from_slice(&p[..3]);
        }
    }
    Ok(Raster {
        width: r.width,
        height: r.height,
        channels: 3,
        data,
    })
}

/// Adjust only areas whose encoded/decoded pixels hit the profile's clipping
/// threshold. Every adjustment is followed by a check, including the last pass.
fn headroom(mut rgb: Raster, profile: &ChannelProfile) -> Result<(Vec<u8>, u32, u8)> {
    let (w, h) = (rgb.width as usize, rgb.height as usize);
    let (cols, rows) = (w.div_ceil(16), h.div_ceil(16));
    let mut touched = vec![false; cols * rows];
    for round in 0..=profile.headroom.max_rounds {
        let encoded = encode::baseline_420(&rgb, &profile.quantization)?;
        let decoded = lossless::decode_jpeg(&encoded)?;
        if decoded.channels != 3 || decoded.width != rgb.width || decoded.height != rgb.height {
            return Err(Error::PreparationFailed(
                "unexpected JPEG round-trip raster".into(),
            ));
        }
        let parsed = jpeg::Jpeg::parse(&encoded)?;
        let mut bad = jpeg::headroom::clipping_areas(
            &parsed,
            profile.headroom.low,
            profile.headroom.high,
            profile.headroom.decoder_guard,
        );
        for (i, p) in decoded.data.chunks_exact(3).enumerate() {
            if p.iter()
                .any(|&v| v <= profile.headroom.low || v >= profile.headroom.high)
            {
                bad[(i / w / 16) * cols + (i % w / 16)] = true;
            }
        }
        if !bad.iter().any(|&b| b) {
            return Ok((
                encoded,
                touched.iter().filter(|&&b| b).count() as u32,
                round,
            ));
        }
        if round == profile.headroom.max_rounds {
            break;
        }
        for (area, &is_bad) in bad.iter().enumerate() {
            if !is_bad {
                continue;
            }
            touched[area] = true;
            let (x0, y0) = (area % cols * 16, area / cols * 16);
            let (x1, y1) = ((x0 + 16).min(w), (y0 + 16).min(h));
            let n = ((x1 - x0) * (y1 - y0)) as i64;
            let mut sum = [0i64; 3];
            for y in y0..y1 {
                for x in x0..x1 {
                    for (c, s) in sum.iter_mut().enumerate() {
                        *s += rgb.data[(y * w + x) * 3 + c] as i64;
                    }
                }
            }
            // Exact rational arithmetic, Python-style ties-to-even rounding.
            let means = sum.map(|s| s.clamp(40 * n, 215 * n));
            let f = profile.headroom.contraction_percent as i64;
            for y in y0..y1 {
                for x in x0..x1 {
                    for (c, &mean) in means.iter().enumerate() {
                        let p = &mut rgb.data[(y * w + x) * 3 + c];
                        *p = round_even(mean * (100 - f) + *p as i64 * n * f, n * 100) as u8;
                    }
                }
            }
        }
    }
    Err(Error::PreparationFailed(format!(
        "still clipping after {} headroom rounds",
        profile.headroom.max_rounds
    )))
}

fn round_even(n: i64, d: i64) -> i64 {
    let (q, r) = (n / d, n % d);
    q + i64::from(r * 2 > d || (r * 2 == d && q % 2 != 0))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn nonconvergence_is_an_explicit_error() {
        let mut profile = profiles()[0];
        profile.headroom.max_rounds = 0;
        let r = Raster {
            width: 16,
            height: 16,
            channels: 3,
            data: vec![0; 16 * 16 * 3],
        };
        assert!(matches!(
            headroom(r, &profile),
            Err(Error::PreparationFailed(_))
        ));
    }
    #[test]
    fn final_adjustment_is_checked_before_failing() {
        let mut profile = profiles()[0];
        profile.headroom.max_rounds = 1;
        profile.headroom.decoder_guard = 0;
        let r = Raster {
            width: 16,
            height: 16,
            channels: 3,
            data: vec![0; 16 * 16 * 3],
        };
        let (_, areas, rounds) = headroom(r, &profile).unwrap();
        assert_eq!((areas, rounds), (1, 1));
    }

    #[test]
    fn ties_round_to_even() {
        assert_eq!((round_even(25, 10), round_even(35, 10)), (2, 4));
    }
}
