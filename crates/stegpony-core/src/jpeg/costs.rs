//! J-UNIWARD additive wavelet distortion (Holub, Fridrich, Denemark).
//! https://dde.binghamton.edu/vholub/pdf/acmih2013_digital_image_steganography_using_universal_distortion.pdf
//! This is a writer cost choice, not a format primitive. No rounded/clipped pixel
//! decoder or color conversion enters the coefficient write path.
//!
//! The filters are applied as correlations, as in the reference implementation, with
//! the corrected cover-residual alignment (Butora et al., arXiv 2305.19776). Costs
//! agree with conseal's `JUNIWARD_FIX_OFF_BY_ONE` to float precision; the
//! `matches_reference_juniward` test pins values computed with it.
use super::Component;
use rayon::prelude::*;
use std::sync::OnceLock;

const HIGH: [f64; 16] = [
    -0.0544158422,
    0.3128715909,
    -0.6756307363,
    0.5853546837,
    0.0158291053,
    -0.2840155430,
    -0.0004724846,
    0.1287474266,
    0.0173693010,
    -0.0440882539,
    -0.0139810279,
    0.0087460940,
    0.0048703530,
    -0.0003917404,
    -0.0006754494,
    -0.0001174768,
];
const SUPPORT: usize = 23; // 8 + 16 - 1, full convolution
const SIGMA: f64 = 1.0 / 64.0;

fn basis() -> [[f64; 8]; 8] {
    std::array::from_fn(|k| {
        std::array::from_fn(|x| {
            let scale = if k == 0 { (1.0_f64 / 8.0).sqrt() } else { 0.5 };
            scale * (std::f64::consts::PI * k as f64 * (2 * x + 1) as f64 / 16.0).cos()
        })
    })
}
fn low() -> [f64; 16] {
    std::array::from_fn(|i| HIGH[15 - i] * if i & 1 == 0 { 1.0 } else { -1.0 })
}
/// Low- and high-pass decomposition filters, reversed: a full convolution with these
/// is the reference implementation's full correlation with the originals.
fn correlation_filters() -> [[f64; 16]; 2] {
    [low(), HIGH].map(|f| std::array::from_fn(|i| f[15 - i]))
}
fn sym(i: isize, n: usize) -> usize {
    let j = i.rem_euclid(2 * n as isize) as usize;
    if j < n {
        j
    } else {
        2 * n - 1 - j
    }
}
// Separable 1-D basis/filter responses make each 2-D impact an outer product. Only
// magnitudes enter the cost, so they are stored as absolute values.
type Impacts = [[[f64; SUPPORT]; 8]; 2];
fn impacts_f32() -> &'static [[[f32; SUPPORT]; 8]; 2] {
    static CACHE: OnceLock<[[[f32; SUPPORT]; 8]; 2]> = OnceLock::new();
    CACHE.get_or_init(|| impacts().map(|f| f.map(|k| k.map(|v| v as f32))))
}
fn impacts() -> &'static Impacts {
    static CACHE: OnceLock<Impacts> = OnceLock::new();
    CACHE.get_or_init(|| {
        let b = basis();
        let filters = correlation_filters();
        std::array::from_fn(|f| {
            std::array::from_fn(|k| {
                std::array::from_fn(|x| {
                    (0..8)
                        .filter(|&i| x >= i && x - i < 16)
                        .map(|i| b[k][i] * filters[f][x - i])
                        .sum::<f64>()
                        .abs()
                })
            })
        })
    })
}

pub(super) struct Model {
    width: usize,
    /// 1 / (|residual| + sigma) for LH, HL and HH, over the full-convolution extent.
    inverse: [Vec<f32>; 3],
}

/// (vertical, horizontal) filter for LH, HL and HH; 0 is low-pass, 1 is high-pass.
const SUBBANDS: [(usize, usize); 3] = [(0, 1), (1, 0), (1, 1)];

impl Model {
    /// Builds the three reciprocal residual maps for one component. Peak memory is the
    /// f64 dequantized plane plus two f32 horizontal passes, then the passes plus three
    /// f32 maps: about 13 bytes per sample, so roughly 160 MB for a 12-megapixel luma.
    pub fn new(c: &Component) -> Self {
        let (w, h) = (c.width_blocks * 8, c.height_blocks * 8);
        let b = basis();
        let mut plane = vec![0.0f64; w * h];
        plane
            .par_chunks_mut(w * 8)
            .enumerate()
            .for_each(|(by, band)| {
                for bx in 0..c.width_blocks {
                    let block = c.block(bx, by);
                    let mut tmp = [[0.0; 8]; 8];
                    for v in 0..8 {
                        for x in 0..8 {
                            tmp[v][x] = (0..8)
                                .map(|u| {
                                    block[v * 8 + u] as f64 * c.quant[v * 8 + u] as f64 * b[u][x]
                                })
                                .sum();
                        }
                    }
                    for y in 0..8 {
                        for x in 0..8 {
                            band[y * w + bx * 8 + x] = (0..8).map(|v| b[v][y] * tmp[v][x]).sum();
                        }
                    }
                }
            });
        // R(x,y) = sum F(dy,dx) * X(x-dx,y-dy) with the reversed filters, over every
        // output a unit change can reach (the full 23x23 impact window). The two
        // horizontal passes are shared by the three subbands.
        let (rw, rh) = (w + 15, h + 15);
        let filters = correlation_filters();
        let horizontal: [Vec<f32>; 2] = std::array::from_fn(|fx| {
            let mut out = vec![0.0f32; rw * h];
            out.par_chunks_mut(rw).enumerate().for_each(|(y, row)| {
                for (x, value) in row.iter_mut().enumerate() {
                    *value = (0..16)
                        .map(|d| filters[fx][d] * plane[y * w + sym(x as isize - d as isize, w)])
                        .sum::<f64>() as f32;
                }
            });
            out
        });
        drop(plane);
        let inverse = SUBBANDS.map(|(fy, fx)| {
            let src = &horizontal[fx];
            let mut inv = vec![0.0f32; rw * rh];
            inv.par_chunks_mut(rw).enumerate().for_each(|(y, row)| {
                for (x, value) in row.iter_mut().enumerate() {
                    let res: f64 = (0..16)
                        .map(|d| {
                            filters[fy][d] * src[sym(y as isize - d as isize, h) * rw + x] as f64
                        })
                        .sum();
                    *value = (1.0 / (res.abs() + SIGMA)) as f32;
                }
            });
            inv
        });
        Self { width: rw, inverse }
    }

    /// Costs of all 64 coefficients of block `(bx, by)`, each scaled by its
    /// quantization step (index 0, DC, is computed but never used). The impact of a
    /// unit change is separable, so each subband's 23x23 window is summed in two
    /// passes shared by the whole block: first along rows for each horizontal
    /// frequency, then down the columns for each vertical one. Same result as
    /// [`Model::cost`] for every coefficient, about six times fewer operations.
    pub fn block_costs(&self, bx: usize, by: usize, quant: &[u16; 64]) -> [f32; 64] {
        let impact = impacts_f32();
        let mut rho = [0f32; 64];
        for (f, (fy, fx)) in SUBBANDS.into_iter().enumerate() {
            let inverse = &self.inverse[f];
            let mut rows = [[0f32; 8]; SUPPORT];
            for (y, row) in rows.iter_mut().enumerate() {
                let start = (by * 8 + y) * self.width + bx * 8;
                let line = &inverse[start..start + SUPPORT];
                for (u, out) in row.iter_mut().enumerate() {
                    *out = impact[fx][u].iter().zip(line).map(|(a, b)| a * b).sum();
                }
            }
            for v in 0..8 {
                let iy = &impact[fy][v];
                for u in 0..8 {
                    rho[v * 8 + u] += iy.iter().zip(&rows).map(|(a, r)| a * r[u]).sum::<f32>();
                }
            }
        }
        for (r, &q) in rho.iter_mut().zip(quant) {
            *r = (*r as f64 * q as f64).clamp(1e-6, 1e8) as f32;
        }
        rho
    }

    /// One coefficient's cost, computed directly. Kept as the reference that
    /// [`Model::block_costs`] is tested against.
    #[cfg(test)]
    pub fn cost(&self, bx: usize, by: usize, k: usize, quant: u16) -> f32 {
        let impact = impacts();
        let mut rho = 0.0f64;
        for (f, (fy, fx)) in SUBBANDS.into_iter().enumerate() {
            let inverse = &self.inverse[f];
            for y in 0..SUPPORT {
                let iy = impact[fy][k / 8][y];
                let row = (by * 8 + y) * self.width + bx * 8;
                let line = &inverse[row..row + SUPPORT];
                let mut acc = 0.0f64;
                for (ix, inv) in impact[fx][k % 8].iter().zip(line) {
                    acc += ix * *inv as f64;
                }
                rho += iy * acc;
            }
        }
        (rho * quant as f64).clamp(1e-6, 1e8) as f32
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dct_is_orthonormal() {
        let b = basis();
        for i in 0..8 {
            for j in 0..8 {
                let dot: f64 = (0..8).map(|x| b[i][x] * b[j][x]).sum();
                assert!((dot - if i == j { 1.0 } else { 0.0 }).abs() < 1e-12);
            }
        }
    }
    #[test]
    fn block_costs_match_per_coefficient_costs() {
        let bytes = std::fs::read(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/tests/fixtures/jpeg/baseline_420.jpg"
        ))
        .unwrap();
        let j = super::super::Jpeg::parse(&bytes).unwrap();
        for c in &j.components {
            let m = Model::new(c);
            for (bx, by) in [(0, 0), (c.width_blocks - 1, c.height_blocks - 1), (1, 2)] {
                let all = m.block_costs(bx, by, &c.quant);
                for (k, &a) in all.iter().enumerate().skip(1) {
                    let one = m.cost(bx, by, k, c.quant[k]);
                    assert!(
                        ((a - one) / one).abs() < 1e-4,
                        "{bx},{by},{k}: {a} vs {one}"
                    );
                }
            }
        }
    }

    #[test]
    fn symmetric_edges() {
        assert_eq!((sym(-1, 8), sym(8, 8), sym(-17, 8)), (0, 7, 0));
    }
}
