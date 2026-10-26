//! Conservative clipping check for newly encoded baseline 4:2:0 preparation covers.
//! zune and libjpeg differ in IDCT/color rounding and chroma interpolation. Bound
//! RGB through several common interpolation choices instead of trusting one
//! decoder's pixels. It is not a channel simulator or a guarantee for every decoder.
use super::{encode::BASIS, Jpeg};
use rayon::prelude::*;

fn plane(c: &super::Component) -> Vec<i32> {
    let w = c.grid_w * 8;
    let mut out = vec![0; w * c.grid_h * 8];
    out.par_chunks_mut(w * 8)
        .enumerate()
        .for_each(|(by, band)| {
            for bx in 0..c.grid_w {
                let block = c.block(bx, by);
                let horizontal: [[i64; 8]; 8] = std::array::from_fn(|v| {
                    std::array::from_fn(|x| {
                        (0..8)
                            .map(|u| {
                                block[v * 8 + u] as i64 * c.quant[v * 8 + u] as i64 * BASIS[u][x]
                            })
                            .sum()
                    })
                });
                for y in 0..8 {
                    for x in 0..8 {
                        let sum: i64 = (0..8).map(|v| horizontal[v][x] * BASIS[v][y]).sum();
                        // Keep the estimate un-clamped until bounds are applied below.
                        band[y * w + bx * 8 + x] =
                            (super::encode::rounded(sum, 1 << 28) + 128) as i32;
                    }
                }
            }
        });
    out
}

/// JPEG must be the three-component 4:2:0 image just produced by our encoder.
/// Check nearest, horizontal/vertical and bilinear 3:1 chroma interpolation, with
/// a final RGB tolerance for differences between fixed/integer IDCT implementations.
pub(crate) fn clipping_areas(j: &Jpeg, low: u8, high: u8, guard: u8) -> Vec<bool> {
    let (w, h) = (j.width as usize, j.height as usize);
    let cols = w.div_ceil(16);
    let planes: Vec<_> = j.components.iter().map(plane).collect();
    let strides: Vec<_> = j.components.iter().map(|c| c.grid_w * 8).collect();
    let (cw, ch) = (w.div_ceil(2), h.div_ceil(2));
    let chroma = |ci: usize, x: usize, y: usize| {
        let nx = if x.is_multiple_of(2) {
            (x / 2).saturating_sub(1)
        } else {
            (x / 2 + 1).min(cw - 1)
        };
        let ny = if y.is_multiple_of(2) {
            (y / 2).saturating_sub(1)
        } else {
            (y / 2 + 1).min(ch - 1)
        };
        let sample = |sx: usize, sy: usize| planes[ci][sy * strides[ci] + sx].clamp(0, 255) - 128;
        let (a, b, c, d) = (
            sample(x / 2, y / 2),
            sample(nx, y / 2),
            sample(x / 2, ny),
            sample(nx, ny),
        );
        // Q4 chroma samples, sharing the same weights for Cb and Cr. Keeping
        // their correlation avoids impossible combinations at saturated edges.
        [
            16 * a,
            12 * a + 4 * b,
            12 * a + 4 * c,
            9 * a + 3 * b + 3 * c + d,
        ]
    };
    let mut bad = vec![false; cols * h.div_ceil(16)];
    let scale = 65536 * 16;
    for y in 0..h {
        for x in 0..w {
            let yv = planes[0][y * strides[0] + x].clamp(0, 255) * scale;
            let cb = chroma(1, x, y);
            let cr = chroma(2, x, y);
            for i in 0..4 {
                let rgb = [
                    yv + 91881 * cr[i],
                    yv - 22554 * cb[i] - 46802 * cr[i],
                    yv + 116130 * cb[i],
                ];
                if rgb.iter().any(|&v| {
                    v <= (low as i32 + guard as i32) * scale
                        || v >= (high as i32 - guard as i32) * scale
                }) {
                    bad[y / 16 * cols + x / 16] = true;
                    break;
                }
            }
        }
    }
    bad
}
