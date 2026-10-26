//! Pixel-to-coefficient baseline 4:2:0 encoder for channel preparation.
//! Fixed-point color conversion and orthonormal DCT; existing entropy writer.
use super::{Component, FrameKind, Geometry, Jpeg, ScanComp, ScanHeader, Segment, ZIGZAG};
use crate::lossless::Raster;
use crate::{Error, Result};
use rayon::prelude::*;

// Orthonormal DCT-II basis, Q14. Constants keep transform rounding platform-independent.
pub(super) const BASIS: [[i64; 8]; 8] = [
    [5793, 5793, 5793, 5793, 5793, 5793, 5793, 5793],
    [8035, 6811, 4551, 1598, -1598, -4551, -6811, -8035],
    [7568, 3135, -3135, -7568, -7568, -3135, 3135, 7568],
    [6811, -1598, -8035, -4551, 4551, 8035, 1598, -6811],
    [5793, -5793, -5793, 5793, 5793, -5793, -5793, 5793],
    [4551, -8035, 1598, 6811, -6811, -1598, 8035, -4551],
    [3135, -7568, 7568, -3135, -3135, 7568, -7568, 3135],
    [1598, -4551, 6811, -8035, 8035, -6811, 4551, -1598],
];

pub(super) fn rounded(n: i64, d: i64) -> i64 {
    if n >= 0 {
        (n + d / 2) / d
    } else {
        -((-n + d / 2) / d)
    }
}

fn transform(samples: &[i32; 64], quant: &[u16; 64]) -> [i16; 64] {
    let mut horizontal = [[0i64; 8]; 8];
    for y in 0..8 {
        for (u, basis) in BASIS.iter().enumerate() {
            horizontal[y][u] = (0..8)
                .map(|x| (samples[y * 8 + x] - 128) as i64 * basis[x])
                .sum();
        }
    }
    std::array::from_fn(|k| {
        let (v, u) = (k / 8, k % 8);
        let sum: i64 = (0..8).map(|y| horizontal[y][u] * BASIS[v][y]).sum();
        rounded(sum, (1i64 << 28) * quant[k] as i64) as i16
    })
}

/// Encodes RGB pixels, replicating right/bottom samples at partial MCU edges.
/// Does not accept arbitrary/malformed public Raster values.
pub(crate) fn baseline_420(rgb: &Raster, quant: &[[u16; 64]; 2]) -> Result<Vec<u8>> {
    let (w, h) = (rgb.width as usize, rgb.height as usize);
    if w == 0
        || h == 0
        || w > 1280
        || h > 1280
        || rgb.channels != 3
        || rgb.data.len() != w * h * 3
        || quant.iter().flatten().any(|&q| q == 0 || q > 255)
    {
        return Err(Error::Output(
            "invalid RGB raster or quantization tables for channel JPEG".into(),
        ));
    }
    let geo = Geometry {
        mcu_cols: w.div_ceil(16),
        mcu_rows: h.div_ceil(16),
    };
    // Full-resolution YCbCr, with integer conversion coefficients summing exactly
    // to unity (Y) and zero (chroma). Chroma is 2x2 box sampled before the DCT.
    let planes: Vec<[i32; 3]> = rgb
        .data
        .par_chunks_exact(3)
        .map(|p| {
            let (r, g, b) = (p[0] as i32, p[1] as i32, p[2] as i32);
            [
                (19595 * r + 38470 * g + 7471 * b + 32768) >> 16,
                (-11059 * r - 21709 * g + 32768 * b + 8421375) >> 16,
                (32768 * r - 27439 * g - 5329 * b + 8421375) >> 16,
            ]
        })
        .collect();
    let mut components = Vec::new();
    for ci in [0, 1, 2] {
        let sampling = if ci == 0 { 2 } else { 1 };
        let div = if ci == 0 { 1 } else { 2 };
        let grid_w = geo.mcu_cols * sampling;
        let grid_h = geo.mcu_rows * sampling;
        let table = if ci == 0 { 0 } else { 1 };
        let mut coefs = vec![0i16; grid_w * grid_h * 64];
        coefs
            .par_chunks_mut(64)
            .enumerate()
            .for_each(|(block, out)| {
                let (bx, by) = (block % grid_w, block / grid_w);
                let samples = std::array::from_fn(|k| {
                    let (x, y) = ((bx * 8 + k % 8) * div, (by * 8 + k / 8) * div);
                    let mut sum = 0;
                    for dy in 0..div {
                        for dx in 0..div {
                            sum += planes[(y + dy).min(h - 1) * w + (x + dx).min(w - 1)][ci];
                        }
                    }
                    (sum + (div * div / 2) as i32) / (div * div) as i32
                });
                out.copy_from_slice(&transform(&samples, &quant[table]));
            });
        components.push(Component {
            id: (ci + 1) as u8,
            h: sampling as u8,
            v: sampling as u8,
            tq: table as u8,
            quant: quant[table],
            width_blocks: w.div_ceil(div).div_ceil(8),
            height_blocks: h.div_ceil(div).div_ceil(8),
            grid_w,
            grid_h,
            coefs,
        });
    }
    let mut dqt = Vec::new();
    for (id, q) in quant.iter().enumerate() {
        dqt.push(id as u8);
        dqt.extend(ZIGZAG.iter().map(|&k| q[k] as u8));
    }
    let mut sof = vec![8];
    sof.extend_from_slice(&(h as u16).to_be_bytes());
    sof.extend_from_slice(&(w as u16).to_be_bytes());
    sof.extend_from_slice(&[3, 1, 0x22, 0, 2, 0x11, 1, 3, 0x11, 1]);
    let header = ScanHeader {
        comps: (0..3)
            .map(|i| ScanComp {
                index: i,
                td: if i == 0 { 0 } else { 1 },
                ta: if i == 0 { 0 } else { 1 },
            })
            .collect(),
        ss: 0,
        se: 63,
        ah: 0,
        al: 0,
    };
    let jpeg = Jpeg {
        kind: FrameKind::Baseline,
        width: w as u16,
        height: h as u16,
        components,
        geo,
        segments: vec![
            Segment::Marker {
                code: 0xe0,
                data: b"JFIF\0\x01\x01\0\0\x01\0\x01\0\0".to_vec(),
            },
            Segment::Marker {
                code: 0xdb,
                data: dqt,
            },
            Segment::Marker {
                code: 0xc0,
                data: sof,
            },
            // No input DHT: write() builds optimal tables for this scan.
            Segment::Scan {
                header,
                data: vec![3, 1, 0, 2, 0x11, 3, 0x11, 0, 63, 0],
                restart: 0,
            },
        ],
        trailing: Vec::new(),
    };
    jpeg.write()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn transform_matches_independent_float_dct() {
        let samples = std::array::from_fn(|k| ((k * 37 + k / 8 * 19) % 256) as i32);
        let q = std::array::from_fn(|k| (k % 30 + 1) as u16);
        let actual = transform(&samples, &q);
        for k in 0..64 {
            let (u, v) = (k % 8, k / 8);
            let a = |f: usize| if f == 0 { 1.0 / 8.0_f64.sqrt() } else { 0.5 };
            let mut sum = 0.0;
            for y in 0..8 {
                for x in 0..8 {
                    sum += (samples[y * 8 + x] - 128) as f64
                        * a(u)
                        * a(v)
                        * (std::f64::consts::PI * u as f64 * (2 * x + 1) as f64 / 16.0).cos()
                        * (std::f64::consts::PI * v as f64 * (2 * y + 1) as f64 / 16.0).cos();
                }
            }
            assert!((actual[k] as f64 - (sum / q[k] as f64).round()).abs() <= 1.0);
        }
        assert_eq!(transform(&[128; 64], &[1; 64]), [0; 64]);
    }
    #[test]
    fn odd_edges_and_coefficients_round_trip() {
        for (w, h) in [(1, 1), (17, 9), (31, 33), (1280, 1)] {
            let r = Raster {
                width: w,
                height: h,
                channels: 3,
                data: vec![128; (w * h * 3) as usize],
            };
            let bytes = baseline_420(&r, &[[1; 64]; 2]).unwrap();
            let j = Jpeg::parse(&bytes).unwrap();
            assert_eq!((j.width, j.height), (w as u16, h as u16));
            assert!(j.components.iter().all(|c| c.coefs.iter().all(|&v| v == 0)));
            assert_eq!(j.write().unwrap(), bytes);
        }
    }
}
