//! Separable area resampling with exact integer overlap weights. This deliberately
//! avoids platform image APIs and floating-point filter/coordinate differences.
//! The lab used Pillow Lanczos; Rust-prepared photos need fresh delivery testing.
use crate::lossless::Raster;
use rayon::prelude::*;

/// Weights are overlaps in a coordinate system scaled by the destination length;
/// their sum for each output is exactly the source length.
fn weights(source: usize, target: usize) -> Vec<Vec<(usize, u64)>> {
    (0..target)
        .map(|i| {
            let (start, end) = (i * source, (i + 1) * source);
            (start / target..end.div_ceil(target))
                .map(|j| {
                    (
                        j,
                        (end.min((j + 1) * target) - start.max(j * target)) as u64,
                    )
                })
                .collect()
        })
        .collect()
}

pub(super) fn downsize(r: Raster, max_edge: u32) -> Raster {
    let longest = r.width.max(r.height);
    if longest <= max_edge {
        return r;
    }
    // Nearest integer dimension, minimum 1. Preserve the exact limiting long edge.
    let scaled = |v: u32| {
        ((v as u64 * max_edge as u64 + longest as u64 / 2) / longest as u64).max(1) as usize
    };
    let (ow, oh) = (scaled(r.width), scaled(r.height));
    let (w, h) = (r.width as usize, r.height as usize);
    let xw = weights(w, ow);
    let yw = weights(h, oh);
    let mut tmp = vec![0u8; ow * h * 3];
    tmp.par_chunks_mut(ow * 3).enumerate().for_each(|(y, row)| {
        for (x, ws) in xw.iter().enumerate() {
            for c in 0..3 {
                let sum: u64 = ws
                    .iter()
                    .map(|&(i, weight)| r.data[(y * w + i) * 3 + c] as u64 * weight)
                    .sum();
                row[x * 3 + c] = ((sum + w as u64 / 2) / w as u64) as u8;
            }
        }
    });
    let mut data = vec![0u8; ow * oh * 3];
    data.par_chunks_mut(ow * 3)
        .enumerate()
        .for_each(|(y, row)| {
            for (i, p) in row.iter_mut().enumerate() {
                let sum: u64 = yw[y]
                    .iter()
                    .map(|&(j, weight)| tmp[j * ow * 3 + i] as u64 * weight)
                    .sum();
                *p = ((sum + h as u64 / 2) / h as u64) as u8;
            }
        });
    Raster {
        width: ow as u32,
        height: oh as u32,
        channels: 3,
        data,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn weights_cover_every_pixel_and_constant_is_preserved() {
        for (src, dst) in [(33, 17), (17, 1), (4096, 1280)] {
            for ws in weights(src, dst) {
                assert_eq!(ws.iter().map(|(_, w)| w).sum::<u64>(), src as u64);
            }
        }
        let r = Raster {
            width: 2000,
            height: 1000,
            channels: 3,
            data: vec![123; 2000 * 1000 * 3],
        };
        let resized = downsize(r, 1280);
        assert_eq!((resized.width, resized.height), (1280, 640));
        assert!(resized.data.iter().all(|&v| v == 123));
    }
    #[test]
    fn area_average_and_no_upscale() {
        let r = Raster {
            width: 2,
            height: 2,
            channels: 3,
            data: vec![0, 0, 0, 100, 100, 100, 100, 100, 100, 200, 200, 200],
        };
        assert_eq!(downsize(r.clone(), 1).data, vec![100; 3]);
        assert_eq!(downsize(r.clone(), 1280), r);
    }
}
