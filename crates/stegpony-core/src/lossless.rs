//! Lossless mode: spatial-domain ±1 embedding into 8-bit samples, written out as PNG.
//! FORMAT.md section 5.
//!
//! Elements are the color samples of fully opaque pixels. Slot membership is a
//! checkerboard of 8x8 pixel blocks. Costs are HILL (Li, Wang, Huang, Ni 2014): a
//! high-pass residual, a 3x3 average of its magnitude, the reciprocal, then a 15x15
//! average, so changes land in texture and stay out of flat areas.

use std::io::Cursor;

use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

use crate::engine::{self, Capacity, Cover, Detectability};
use crate::envelope::{bucket_for, HideKey, Payload, RevealKey};
use crate::error::{Error, Result};

/// Decoded 8-bit raster.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Raster {
    pub width: u32,
    pub height: u32,
    /// Samples per pixel: 1 gray, 2 gray+alpha, 3 RGB, 4 RGBA.
    pub channels: u8,
    pub data: Vec<u8>,
}

impl Raster {
    fn has_alpha(&self) -> bool {
        self.channels == 2 || self.channels == 4
    }

    fn color_channels(&self) -> u8 {
        if self.has_alpha() {
            self.channels - 1
        } else {
            self.channels
        }
    }

    fn pixels(&self) -> u64 {
        self.width as u64 * self.height as u64
    }

    fn opaque(&self, p: u64) -> bool {
        !self.has_alpha()
            || self.data[(p * self.channels as u64 + self.color_channels() as u64) as usize] == 255
    }

    fn pixel_slot(&self, p: u64) -> u8 {
        let x = (p % self.width as u64) as u32;
        let y = (p / self.width as u64) as u32;
        (((x >> 3) + (y >> 3)) & 1) as u8
    }

    fn sample_index(&self, t: u64) -> usize {
        let cc = self.color_channels() as u64;
        let p = t / cc;
        let c = t % cc;
        (p * self.channels as u64 + c) as usize
    }
}

/// What a cover file was.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SourceFormat {
    Png,
    /// A JPEG cover is decoded to pixels and the result is a PNG. The UI should warn
    /// that a camera photo saved as PNG is unusual in itself.
    Jpeg,
}

const PNG_MAGIC: &[u8] = b"\x89PNG\r\n\x1a\n";

pub fn sniff(bytes: &[u8]) -> Option<SourceFormat> {
    if bytes.starts_with(PNG_MAGIC) {
        Some(SourceFormat::Png)
    } else if bytes.starts_with(&[0xff, 0xd8, 0xff]) {
        Some(SourceFormat::Jpeg)
    } else {
        None
    }
}

/// Decodes a PNG exactly as stored. Palette, 16-bit, sub-byte and animated PNGs are
/// refused rather than converted, because conversion would change what reveal reads.
pub fn decode_png(bytes: &[u8]) -> Result<Raster> {
    let mut decoder = png::Decoder::new(Cursor::new(bytes));
    decoder.set_transformations(png::Transformations::IDENTITY);
    let mut reader = decoder
        .read_info()
        .map_err(|e| Error::BadCover(e.to_string()))?;
    let info = reader.info();
    if info.animation_control.is_some() {
        return Err(Error::UnsupportedCover("animated PNG".into()));
    }
    if info.bit_depth != png::BitDepth::Eight {
        return Err(Error::UnsupportedCover(format!(
            "{:?}-bit PNG",
            info.bit_depth
        )));
    }
    let channels = match info.color_type {
        png::ColorType::Grayscale => 1,
        png::ColorType::GrayscaleAlpha => 2,
        png::ColorType::Rgb => 3,
        png::ColorType::Rgba => 4,
        png::ColorType::Indexed => return Err(Error::UnsupportedCover("palette PNG".into())),
    };
    let size = reader
        .output_buffer_size()
        .ok_or_else(|| Error::BadCover("image too large".into()))?;
    let mut data = vec![0u8; size];
    let out = reader
        .next_frame(&mut data)
        .map_err(|e| Error::BadCover(e.to_string()))?;
    data.truncate(out.buffer_size());
    let r = Raster {
        width: out.width,
        height: out.height,
        channels,
        data,
    };
    if r.data.len() as u64 != r.pixels() * channels as u64 {
        return Err(Error::BadCover("unexpected PNG row layout".into()));
    }
    Ok(r)
}

/// Decodes a JPEG cover to 8-bit pixels.
pub fn decode_jpeg(bytes: &[u8]) -> Result<Raster> {
    let mut dec = zune_jpeg::JpegDecoder::new(bytes);
    let data = dec
        .decode()
        .map_err(|e| Error::BadCover(format!("{e:?}")))?;
    let info = dec
        .info()
        .ok_or_else(|| Error::BadCover("no JPEG header".into()))?;
    let (w, h) = (info.width as u32, info.height as u32);
    let px = w as usize * h as usize;
    if px == 0 || data.len() % px != 0 {
        return Err(Error::BadCover("unexpected JPEG output".into()));
    }
    let channels = (data.len() / px) as u8;
    if !(1..=4).contains(&channels) {
        return Err(Error::UnsupportedCover(format!("{channels}-channel JPEG")));
    }
    Ok(Raster {
        width: w,
        height: h,
        channels,
        data,
    })
}

pub fn decode_cover(bytes: &[u8]) -> Result<(Raster, SourceFormat)> {
    match sniff(bytes) {
        Some(SourceFormat::Png) => Ok((decode_png(bytes)?, SourceFormat::Png)),
        Some(SourceFormat::Jpeg) => Ok((decode_jpeg(bytes)?, SourceFormat::Jpeg)),
        None => Err(Error::UnsupportedCover("not a PNG or JPEG file".into())),
    }
}

/// Encodes a raster as a PNG with no ancillary chunks.
pub fn encode_png(r: &Raster) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    {
        let mut enc = png::Encoder::new(&mut out, r.width, r.height);
        enc.set_color(match r.channels {
            1 => png::ColorType::Grayscale,
            2 => png::ColorType::GrayscaleAlpha,
            3 => png::ColorType::Rgb,
            _ => png::ColorType::Rgba,
        });
        enc.set_depth(png::BitDepth::Eight);
        enc.set_compression(png::Compression::Balanced);
        let mut w = enc
            .write_header()
            .map_err(|e| Error::Output(e.to_string()))?;
        w.write_image_data(&r.data)
            .map_err(|e| Error::Output(e.to_string()))?;
        w.finish().map_err(|e| Error::Output(e.to_string()))?;
    }
    Ok(out)
}

/// A raster seen as an engine cover.
pub struct LosslessCover {
    pub raster: Raster,
    counts: [u64; 2],
}

impl LosslessCover {
    pub fn new(raster: Raster) -> Self {
        let mut counts = [0u64; 2];
        let cc = raster.color_channels() as u64;
        for p in 0..raster.pixels() {
            if raster.opaque(p) {
                counts[raster.pixel_slot(p) as usize] += cc;
            }
        }
        LosslessCover { raster, counts }
    }
}

impl Cover for LosslessCover {
    fn domain(&self) -> u64 {
        self.raster.pixels() * self.raster.color_channels() as u64
    }

    fn slot_of(&self, t: u64) -> Option<u8> {
        let p = t / self.raster.color_channels() as u64;
        if self.raster.opaque(p) {
            Some(self.raster.pixel_slot(p))
        } else {
            None
        }
    }

    fn slot_counts(&self) -> [u64; 2] {
        self.counts
    }

    fn parity(&self, t: u64) -> u8 {
        self.raster.data[self.raster.sample_index(t)] & 1
    }

    /// One HILL plane per color channel, built once for all sets and dropped before the
    /// next channel's, so memory holds a single plane at a time.
    fn costs(&self, sets: &[&[u64]]) -> Vec<Vec<f32>> {
        let cc = self.raster.color_channels() as u64;
        let mut out: Vec<Vec<f32>> = sets.iter().map(|ts| vec![0f32; ts.len()]).collect();
        for c in 0..cc {
            if !sets.iter().any(|ts| ts.iter().any(|t| t % cc == c)) {
                continue;
            }
            let plane = hill_costs(&self.raster, c as usize);
            for (o, ts) in out.iter_mut().zip(sets) {
                o.par_iter_mut().zip(ts.par_iter()).for_each(|(o, &t)| {
                    if t % cc == c {
                        *o = plane[(t / cc) as usize];
                    }
                });
            }
        }
        out
    }

    fn flip(&mut self, t: u64, up: bool) {
        let i = self.raster.sample_index(t);
        let v = self.raster.data[i];
        self.raster.data[i] = match v {
            255 => 254,
            0 => 1,
            _ if up => v + 1,
            _ => v - 1,
        };
    }
}

/// Symmetric index into `0..n` (edge sample repeated, as MATLAB's 'symmetric').
fn sym(i: isize, n: usize) -> usize {
    let n = n as isize;
    let mut i = i;
    loop {
        if i < 0 {
            i = -i - 1;
        } else if i >= n {
            i = 2 * n - i - 1;
        } else {
            return i as usize;
        }
    }
}

/// Rows per parallel band in the vertical pass of [`box_mean`].
const BOX_BAND: usize = 64;

/// Separable box mean of size `k` (odd) with symmetric borders.
///
/// Rows run in parallel, and the vertical pass restarts its running sum at the top of
/// each band of rows. That gives the same floats as one sliding sum from the top: the
/// inputs here are 8-bit residuals and HILL reciprocals, whose sums of up to 16 terms are
/// exact in f64, so the order of additions cannot change a result.
fn box_mean(src: &[f32], w: usize, h: usize, k: usize) -> Vec<f32> {
    let r = (k / 2) as isize;
    let mut tmp = vec![0f32; w * h];
    tmp.par_chunks_mut(w)
        .zip(src.par_chunks(w))
        .for_each(|(trow, row)| {
            let mut acc: f64 = (-r..=r).map(|d| row[sym(d, w)] as f64).sum();
            for (x, t) in trow.iter_mut().enumerate() {
                *t = (acc / k as f64) as f32;
                acc += row[sym(x as isize + r + 1, w)] as f64 - row[sym(x as isize - r, w)] as f64;
            }
        });
    let mut out = vec![0f32; w * h];
    out.par_chunks_mut(w * BOX_BAND)
        .enumerate()
        .for_each(|(band, chunk)| {
            let y0 = (band * BOX_BAND) as isize;
            let mut acc: Vec<f64> = (0..w)
                .map(|x| (-r..=r).map(|d| tmp[sym(y0 + d, h) * w + x] as f64).sum())
                .collect();
            for (dy, orow) in chunk.chunks_mut(w).enumerate() {
                let y = y0 + dy as isize;
                let (add, sub) = (sym(y + r + 1, h) * w, sym(y - r, h) * w);
                for (x, (o, a)) in orow.iter_mut().zip(acc.iter_mut()).enumerate() {
                    *o = (*a / k as f64) as f32;
                    *a += tmp[add + x] as f64 - tmp[sub + x] as f64;
                }
            }
        });
    out
}

const HILL_EPS: f32 = 0.01;

/// HILL cost plane for one color channel.
fn hill_costs(r: &Raster, c: usize) -> Vec<f32> {
    let (w, h) = (r.width as usize, r.height as usize);
    let ch = r.channels as usize;
    let at = |x: isize, y: isize| -> f32 { r.data[(sym(y, h) * w + sym(x, w)) * ch + c] as f32 };
    const KB: [[f32; 3]; 3] = [[-1.0, 2.0, -1.0], [2.0, -4.0, 2.0], [-1.0, 2.0, -1.0]];
    let mut res = vec![0f32; w * h];
    res.par_chunks_mut(w).enumerate().for_each(|(y, row)| {
        let y = y as isize;
        for (x, out) in row.iter_mut().enumerate() {
            let x = x as isize;
            let mut s = 0f32;
            for (dy, krow) in KB.iter().enumerate() {
                for (dx, k) in krow.iter().enumerate() {
                    s += k * at(x + dx as isize - 1, y + dy as isize - 1);
                }
            }
            *out = s.abs();
        }
    });
    let mut xi = box_mean(&res, w, h, 3);
    drop(res);
    xi.par_iter_mut().for_each(|v| *v = 1.0 / (*v + HILL_EPS));
    box_mean(&xi, w, h, 15)
}

/// Result of a hide: the stego PNG and what the cover was.
pub struct Hidden {
    pub png: Vec<u8>,
    pub source: SourceFormat,
    pub detectability: Detectability,
}

/// Hides a payload (and optional decoy) in a PNG or JPEG cover; output is always PNG.
pub fn hide<R: RngCore + CryptoRng>(
    cover: &[u8],
    primary: (&Payload, &HideKey),
    decoy: Option<(&Payload, &HideKey)>,
    rng: &mut R,
) -> Result<Hidden> {
    let (raster, source) = decode_cover(cover)?;
    let mut lc = LosslessCover::new(raster);
    let mut bucket = bucket_for(primary.0.framed_len(), 0)?;
    if let Some((p, _)) = decoy {
        bucket = bucket_for(p.framed_len(), bucket)?;
    }
    engine::hide(&mut lc, primary, decoy, rng)?;
    let detectability = engine::detectability(&lc, bucket);
    Ok(Hidden {
        png: encode_png(&lc.raster)?,
        source,
        detectability,
    })
}

/// Looks for a payload in a PNG.
pub fn reveal(image: &[u8], keys: &[RevealKey]) -> Result<Option<Payload>> {
    if sniff(image) != Some(SourceFormat::Png) {
        return Ok(None);
    }
    let lc = LosslessCover::new(decode_png(image)?);
    engine::reveal(&lc, keys)
}

/// How much a cover can hold in lossless mode.
pub fn capacity(cover: &[u8]) -> Result<Capacity> {
    let (raster, _) = decode_cover(cover)?;
    Ok(engine::capacity(&LosslessCover::new(raster)))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sym_indexing() {
        assert_eq!(sym(-1, 5), 0);
        assert_eq!(sym(-2, 5), 1);
        assert_eq!(sym(5, 5), 4);
        assert_eq!(sym(6, 5), 3);
        assert_eq!(sym(2, 5), 2);
    }

    #[test]
    fn box_mean_of_constant_is_constant() {
        let src = vec![3.0f32; 20 * 7];
        for v in box_mean(&src, 20, 7, 15) {
            assert!((v - 3.0).abs() < 1e-4);
        }
    }

    #[test]
    fn hill_prefers_texture() {
        let (w, h) = (64u32, 64u32);
        let mut data = vec![128u8; (w * h) as usize];
        for y in 0..h {
            for x in 32..w {
                data[(y * w + x) as usize] = ((x * 37 + y * 91) % 251) as u8;
            }
        }
        let r = Raster {
            width: w,
            height: h,
            channels: 1,
            data,
        };
        let c = hill_costs(&r, 0);
        let flat = c[(32 * w + 4) as usize];
        let busy = c[(32 * w + 56) as usize];
        assert!(flat > busy * 100.0, "flat {flat} busy {busy}");
    }

    #[test]
    fn checkerboard_slots() {
        let r = Raster {
            width: 16,
            height: 16,
            channels: 3,
            data: vec![0; 16 * 16 * 3],
        };
        assert_eq!(r.pixel_slot(0), 0);
        assert_eq!(r.pixel_slot(8), 1);
        assert_eq!(r.pixel_slot(16 * 8), 1);
        assert_eq!(r.pixel_slot(16 * 8 + 8), 0);
        let lc = LosslessCover::new(r);
        assert_eq!(lc.slot_counts(), [384, 384]);
    }
}
