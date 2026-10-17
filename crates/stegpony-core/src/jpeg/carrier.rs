//! Native JPEG carrier; FORMAT.md section 6. All content-block AC coefficients,
//! including zeros, participate, so embedding cannot change enumeration.
use super::{costs, Jpeg};
use crate::engine::{self, Capacity, Cover, Detectability};
use crate::envelope::{bucket_for, HideKey, Payload, RevealKey};
use crate::error::Result;
use rand_core::{CryptoRng, RngCore};

pub struct JpegCover {
    jpeg: Jpeg,
    offsets: Vec<u64>,
    counts: [u64; 2],
}

impl JpegCover {
    pub fn new(jpeg: Jpeg) -> Self {
        let mut offsets = vec![0];
        let mut counts = [0; 2];
        for c in &jpeg.components {
            let blocks = (c.width_blocks * c.height_blocks) as u64;
            let odd = blocks / 2;
            let even = blocks - odd;
            // A rectangular checkerboard has one extra even block iff both sides are odd.
            counts[0] += even * 63;
            counts[1] += odd * 63;
            offsets.push(offsets.last().unwrap() + blocks * 63);
        }
        Self {
            jpeg,
            offsets,
            counts,
        }
    }

    pub fn jpeg(&self) -> &Jpeg {
        &self.jpeg
    }
    pub fn into_jpeg(self) -> Jpeg {
        self.jpeg
    }

    fn address(&self, t: u64) -> (usize, usize, usize, usize) {
        let ci = self.offsets.partition_point(|&o| o <= t) - 1;
        let local = (t - self.offsets[ci]) as usize;
        let b = local / 63;
        let c = &self.jpeg.components[ci];
        (ci, b % c.width_blocks, b / c.width_blocks, local % 63 + 1)
    }
}

impl Cover for JpegCover {
    fn domain(&self) -> u64 {
        *self.offsets.last().unwrap()
    }
    fn slot_of(&self, t: u64) -> Option<u8> {
        if t >= self.domain() {
            return None;
        }
        let (_, bx, by, _) = self.address(t);
        Some(((bx + by) & 1) as u8)
    }
    fn slot_counts(&self) -> [u64; 2] {
        self.counts
    }
    fn parity(&self, t: u64) -> u8 {
        let (ci, bx, by, k) = self.address(t);
        (self.jpeg.components[ci].block(bx, by)[k] & 1) as u8
    }
    fn costs(&self, sets: &[&[u64]]) -> Vec<Vec<f32>> {
        use rayon::prelude::*;
        let mut out: Vec<Vec<f32>> = sets.iter().map(|s| vec![0.0; s.len()]).collect();
        // One component's maps at a time, and only for components with requested
        // elements, so memory holds a single cost model.
        for (ci, c) in self.jpeg.components.iter().enumerate() {
            let (lo, hi) = (self.offsets[ci], self.offsets[ci + 1]);
            if !sets
                .iter()
                .any(|ts| ts.iter().any(|&t| (lo..hi).contains(&t)))
            {
                continue;
            }
            let model = costs::Model::new(c);
            for (values, ts) in out.iter_mut().zip(sets) {
                values
                    .par_iter_mut()
                    .zip(ts.par_iter())
                    .for_each(|(v, &t)| {
                        let (component, bx, by, k) = self.address(t);
                        if component == ci {
                            *v = model.cost(bx, by, k, c.quant[k]);
                        }
                    });
            }
        }
        out
    }
    fn flip(&mut self, t: u64, up: bool) {
        let (ci, bx, by, k) = self.address(t);
        let v = &mut self.jpeg.components[ci].block_mut(bx, by)[k];
        *v += if *v >= 1023 {
            -1
        } else if *v <= -1023 || up {
            1
        } else {
            -1
        };
    }
}

pub struct Hidden {
    pub jpeg: Vec<u8>,
    /// Provisional payload-rate rating, pending steganalysis calibration.
    pub detectability: Detectability,
}

/// Hides in native coefficients. Privacy metadata is stripped unless explicitly kept.
pub fn hide<R: RngCore + CryptoRng>(
    bytes: &[u8],
    primary: (&Payload, &HideKey),
    decoy: Option<(&Payload, &HideKey)>,
    keep_metadata: bool,
    rng: &mut R,
) -> Result<Hidden> {
    let mut cover = JpegCover::new(Jpeg::parse(bytes)?);
    let mut bucket = bucket_for(primary.0.framed_len(), 0)?;
    if let Some((p, _)) = decoy {
        bucket = bucket_for(p.framed_len(), bucket)?;
    }
    engine::hide(&mut cover, primary, decoy, rng)?;
    let detectability = engine::detectability(&cover, bucket);
    let mut jpeg = cover.into_jpeg();
    if !keep_metadata {
        jpeg.strip_private_metadata();
    }
    Ok(Hidden {
        jpeg: jpeg.write()?,
        detectability,
    })
}

pub fn reveal(bytes: &[u8], keys: &[RevealKey]) -> Result<Option<Payload>> {
    engine::reveal(&JpegCover::new(Jpeg::parse(bytes)?), keys)
}

pub fn capacity(bytes: &[u8]) -> Result<Capacity> {
    Ok(engine::capacity(&JpegCover::new(Jpeg::parse(bytes)?)))
}
