//! Carrier-independent embedding: two slots, keyed positions, head and body regions.
//! FORMAT.md section 4.

use rand_core::{CryptoRng, RngCore};
use rayon::prelude::*;

use crate::envelope::{
    self, bucket_for, bucket_size, filler, locators, open_body, open_head, seal, HideKey, Mode,
    Payload, RevealKey, Sealed, PUBLIC_KEY_HEAD_LEN, TAG_LEN,
};
use crate::error::{Error, Result};
use crate::prp::Prp;
use crate::stc::{self, bits_to_bytes, bytes_to_bits};

/// At most this many elements of a slot are used. Bounds Viterbi memory (16 bytes per
/// element) to about 32 MiB per slot on a phone.
pub const MAX_ELEMENTS_PER_SLOT: u64 = 2_000_000;

/// The body never carries more than one message bit per this many elements.
pub const MIN_ELEMENTS_PER_BIT: usize = 2;

/// A cover medium the engine can write into. Elements are numbered `0..domain()`; each
/// belongs to slot 0, slot 1, or neither. Slot membership and usability must not depend
/// on anything embedding changes, so reveal sees exactly the same elements.
///
/// `Sync` because the engine reads a cover from several threads at once.
pub trait Cover: Sync {
    fn domain(&self) -> u64;
    fn slot_of(&self, t: u64) -> Option<u8>;
    fn slot_counts(&self) -> [u64; 2];
    fn parity(&self, t: u64) -> u8;
    /// Cost of changing each element's parity, computed on the unmodified cover: one
    /// list per set of elements, in the same order. Every slot's elements come in one
    /// call, so a carrier can build whatever cost maps it needs once.
    fn costs(&self, sets: &[&[u64]]) -> Vec<Vec<f32>>;
    /// Changes the element's parity by ±1. `up` is a fair coin for when both directions
    /// are allowed.
    fn flip(&mut self, t: u64, up: bool);
}

/// The two regions of a slot's element sequence.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Layout {
    pub head: usize,
    pub body: usize,
}

/// Head region size: one sixteenth of the slot, but never more than one head bit per
/// eight elements.
pub fn layout(n: usize, mode: Mode) -> Option<Layout> {
    let head_bits = mode.head_len() * 8;
    let head = (n / 16).max(head_bits * 8);
    if n < head * 2 {
        return None;
    }
    Some(Layout {
        head,
        body: n - head,
    })
}

fn slot_len<C: Cover>(cover: &C, slot: u8) -> usize {
    cover.slot_counts()[slot as usize].min(MAX_ELEMENTS_PER_SLOT) as usize
}

/// Permutation inputs evaluated per parallel round in [`positions`].
const POSITION_BLOCK: u64 = 1 << 18;

/// The first `n` elements of `slot` in the order given by the slot's permutation.
///
/// Inputs are permuted a block at a time across threads and kept in input order, so the
/// result is the same sequence a single thread walking `0, 1, 2, ...` would produce.
fn positions<C: Cover>(cover: &C, key: &[u8; 16], slot: u8, n: usize) -> Vec<u64> {
    let domain = cover.domain();
    let prp = Prp::new(key, domain);
    let mut out = Vec::with_capacity(n);
    let mut start = 0u64;
    while out.len() < n && start < domain {
        let end = start.saturating_add(POSITION_BLOCK).min(domain);
        let found: Vec<u64> = (start..end)
            .into_par_iter()
            .map(|i| prp.permute(i))
            .filter(|&t| cover.slot_of(t) == Some(slot))
            .collect();
        let need = n - out.len();
        out.extend(found.into_iter().take(need));
        start = end;
    }
    out
}

/// How much fits, in plaintext bytes per slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capacity {
    /// Largest bucket index usable in both slots.
    pub max_bucket: Option<usize>,
    /// Largest text message, in UTF-8 bytes, that fits.
    pub max_text_bytes: usize,
    /// Elements per slot that the engine will use.
    pub elements: [usize; 2],
}

/// How noticeable the changes are likely to be. Native JPEG rates with thresholds
/// calibrated by steganalysis (`jpeg::carrier::rating`); [`detectability`] below is
/// still provisional and serves Lossless mode until PNG covers get their own baseline.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detectability {
    Low,
    Medium,
    High,
}

fn body_bits_available(n: usize) -> usize {
    layout(n, Mode::PublicKey).map_or(0, |l| l.body / MIN_ELEMENTS_PER_BIT)
}

pub fn capacity<C: Cover>(cover: &C) -> Capacity {
    let elements = [slot_len(cover, 0), slot_len(cover, 1)];
    let bits = body_bits_available(elements[0]).min(body_bits_available(elements[1]));
    let max_bucket = (0..envelope::NUM_BUCKETS)
        .rev()
        .find(|&k| bucket_size(k) * 8 <= bits);
    let max_text_bytes = max_bucket.map_or(0, |k| bucket_size(k) - TAG_LEN - 5);
    Capacity {
        max_bucket,
        max_text_bytes,
        elements,
    }
}

/// Provisional rate-based rating (bucket bits per body element), used by Lossless mode.
pub fn detectability<C: Cover>(cover: &C, bucket: usize) -> Detectability {
    let n = slot_len(cover, 0).min(slot_len(cover, 1));
    let body = layout(n, Mode::PublicKey).map_or(1, |l| l.body.max(1));
    let rate = (bucket_size(bucket) * 8) as f64 / body as f64;
    if rate < 0.05 {
        Detectability::Low
    } else if rate < 0.2 {
        Detectability::Medium
    } else {
        Detectability::High
    }
}

struct Plan {
    positions: Vec<u64>,
    layout: Layout,
    sealed: Sealed,
}

/// Hides `primary` (and `decoy`, if given) in the two slots of `cover`. Without a decoy
/// the second slot gets random filler of the same size, so the two cases look alike.
pub fn hide<C: Cover, R: RngCore + CryptoRng>(
    cover: &mut C,
    primary: (&Payload, &HideKey),
    decoy: Option<(&Payload, &HideKey)>,
    rng: &mut R,
) -> Result<()> {
    let mut bucket = bucket_for(primary.0.framed_len(), 0)?;
    if let Some((p, _)) = decoy {
        bucket = bucket_for(p.framed_len(), bucket)?;
    }
    let cap = capacity(cover);
    if cap.max_bucket.is_none_or(|k| k < bucket) {
        return Err(Error::PayloadTooLarge {
            needed: primary
                .0
                .framed_len()
                .max(decoy.map_or(0, |d| d.0.framed_len())),
            available: cap.max_text_bytes,
        });
    }

    let a = seal(primary.0, primary.1, bucket, rng)?;
    let b = match decoy {
        Some((p, k)) => seal(p, k, bucket, rng)?,
        None => filler(bucket, rng)?,
    };
    let mut coin = [0u8; 1];
    rng.try_fill_bytes(&mut coin).map_err(|_| Error::Rng)?;
    let ordered = if coin[0] & 1 == 0 { [a, b] } else { [b, a] };

    let mut plans = Vec::with_capacity(2);
    for (slot, sealed) in ordered.into_iter().enumerate() {
        let slot = slot as u8;
        let n = slot_len(cover, slot);
        let layout = layout(n, sealed.mode).ok_or(Error::CoverTooSmall)?;
        if bucket_size(bucket) * 8 > layout.body / MIN_ELEMENTS_PER_BIT {
            return Err(Error::PayloadTooLarge {
                needed: primary.0.framed_len(),
                available: cap.max_text_bytes,
            });
        }
        let key = envelope::prp_key(&sealed.locate, slot);
        let positions = positions(cover, &key, slot, n);
        if positions.len() != n {
            return Err(Error::Embed("slot enumeration came up short".into()));
        }
        plans.push(Plan {
            positions,
            layout,
            sealed,
        });
    }

    // All costs and parities come from the unmodified cover before anything changes. The
    // four codes (head and body of each slot) are independent and run in parallel; the
    // flips are then applied in slot order, so the random directions are drawn in the
    // same order whatever the thread count.
    let view: &C = cover;
    let sets: Vec<&[u64]> = plans.iter().map(|p| p.positions.as_slice()).collect();
    let costs = view.costs(&sets);
    let per_slot: Vec<Result<Vec<u64>>> = plans
        .par_iter()
        .zip(costs.par_iter())
        .map(|(plan, costs)| {
            let x: Vec<u8> = plan.positions.iter().map(|&t| view.parity(t)).collect();
            let (hx, bx) = x.split_at(plan.layout.head);
            let (hc, bc) = costs.split_at(plan.layout.head);
            let (hy, by) = rayon::join(
                || stc::embed(hx, hc, &bytes_to_bits(&plan.sealed.head)),
                || stc::embed(bx, bc, &bytes_to_bits(&plan.sealed.body)),
            );
            let (hy, by) = (hy?, by?);
            Ok(x.iter()
                .zip(hy.iter().chain(by.iter()))
                .zip(&plan.positions)
                .filter(|((old, new), _)| old != new)
                .map(|(_, &t)| t)
                .collect())
        })
        .collect();
    let mut flips: Vec<u64> = Vec::new();
    for slot_flips in per_slot {
        flips.extend(slot_flips?);
    }
    for t in flips {
        let mut c = [0u8; 1];
        rng.try_fill_bytes(&mut c).map_err(|_| Error::Rng)?;
        cover.flip(t, c[0] & 1 == 1);
    }
    Ok(())
}

/// Looks for a payload any of `keys` opens. `Ok(None)` means nothing was found, which is
/// also the answer for a wrong key: the two cases are indistinguishable by design.
pub fn reveal<C: Cover>(cover: &C, keys: &[RevealKey]) -> Result<Option<Payload>> {
    let locs = locators(keys)?;
    for slot in 0..2u8 {
        let n = slot_len(cover, slot);
        for loc in &locs {
            let Some(layout) = layout(n, loc.mode) else {
                continue;
            };
            let key = envelope::prp_key(&loc.locate, slot);
            let positions = positions(cover, &key, slot, n);
            if positions.len() != n {
                continue;
            }
            let y: Vec<u8> = positions.iter().map(|&t| cover.parity(t)).collect();
            let (hy, by) = y.split_at(layout.head);
            let head = bits_to_bytes(&stc::extract(hy, loc.mode.head_len() * 8)?);
            let Some(opened) = open_head(loc.key, &head)? else {
                continue;
            };
            let bits = bucket_size(opened.bucket) * 8;
            if bits > layout.body / MIN_ELEMENTS_PER_BIT {
                continue;
            }
            let body = bits_to_bytes(&stc::extract(by, bits)?);
            if let Some(p) = open_body(&opened, &body) {
                return Ok(Some(p));
            }
        }
    }
    Ok(None)
}

/// Head region element count for the larger head, exposed for capacity reporting.
pub fn min_slot_elements() -> usize {
    PUBLIC_KEY_HEAD_LEN * 8 * 8 * 2
}
