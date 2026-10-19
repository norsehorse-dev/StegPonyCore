//! Native JPEG carrier; FORMAT.md section 6. All content-block AC coefficients,
//! including zeros, participate, so embedding cannot change enumeration. An element's
//! symbol is its coefficient modulo 3.
use super::{costs, Jpeg};
use crate::engine::{self, Capacity, Cover, Detectability};
use crate::envelope::{bucket_for, bucket_size, HideKey, Payload, RevealKey};
use crate::error::Result;
use rand_core::{CryptoRng, RngCore};

/// Largest AC magnitude an 8-bit JPEG can code; a change never moves a coefficient
/// past it.
const MAX_COEF: i16 = 1023;

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

    fn value(&self, t: u64) -> i16 {
        let (ci, bx, by, k) = self.address(t);
        self.jpeg.components[ci].block(bx, by)[k]
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
    fn symbol(&self, t: u64) -> u8 {
        (self.value(t) as i32).rem_euclid(3) as u8
    }
    fn directions(&self, t: u64) -> (bool, bool) {
        let v = self.value(t);
        (v < MAX_COEF, v > -MAX_COEF)
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
    fn step(&mut self, t: u64, up: bool) {
        let (ci, bx, by, k) = self.address(t);
        let v = &mut self.jpeg.components[ci].block_mut(bx, by)[k];
        *v += if up { 1 } else { -1 };
    }
}

pub struct Hidden {
    pub jpeg: Vec<u8>,
    /// Rating from [`rating`], computed on the cover before embedding.
    pub detectability: Detectability,
}

/// Upper bounds, in payload bits per nonzero AC coefficient, for the Low and Medium
/// ratings. Calibrated Oct 2026 with color DCTR and an FLD ensemble on 792 tiles
/// (512x512) cut from 66 quality-95 phone photos (tools/steganalysis): 0.10 bpnzac
/// gave P_E 0.445, 0.19 gave 0.398, 0.39 gave 0.232, 0.78 gave 0.031. The bounds sit
/// below the measured points on purpose, because larger training sets, deep-learning
/// detectors and full-size photos all detect more than this baseline does.
pub const LOW_MAX_BPNZAC: f64 = 0.15;
pub const MEDIUM_MAX_BPNZAC: f64 = 0.30;

/// How detectable a payload of `bucket` would be in this cover: both slots' bits
/// (the second slot is always filled) per nonzero AC coefficient among the elements
/// the engine uses.
pub fn rating(cover: &JpegCover, bucket: usize) -> Detectability {
    let counts = cover.slot_counts();
    let total = counts[0] + counts[1];
    let used: u64 = counts
        .iter()
        .map(|&n| n.min(engine::MAX_ELEMENTS_PER_SLOT))
        .sum();
    let nonzero: u64 = cover
        .jpeg
        .components
        .iter()
        .map(|c| {
            let mut n = 0u64;
            for by in 0..c.height_blocks {
                for bx in 0..c.width_blocks {
                    n += c.block(bx, by)[1..].iter().filter(|&&v| v != 0).count() as u64;
                }
            }
            n
        })
        .sum();
    // Slot positions are a keyed random sample, so the used elements carry the same
    // share of nonzero coefficients as the whole cover.
    let nonzero_used = nonzero as f64 * used as f64 / total.max(1) as f64;
    let bits = (2 * bucket_size(bucket) * 8) as f64;
    let bpnzac = bits / nonzero_used.max(1.0);
    if bpnzac <= LOW_MAX_BPNZAC {
        Detectability::Low
    } else if bpnzac <= MEDIUM_MAX_BPNZAC {
        Detectability::Medium
    } else {
        Detectability::High
    }
}

/// The rating a payload of `framed_len` bytes would get in this cover, for a live
/// capacity meter before hiding.
pub fn detectability(bytes: &[u8], framed_len: usize) -> Result<Detectability> {
    let cover = JpegCover::new(Jpeg::parse(bytes)?);
    Ok(rating(&cover, bucket_for(framed_len, 0)?))
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
    let detectability = rating(&cover, bucket);
    engine::hide(&mut cover, primary, decoy, rng)?;
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
