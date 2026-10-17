//! Binary syndrome-trellis codes (Filler, Judas, Fridrich 2011). FORMAT.md section 4.3.
//!
//! Embeds `m` message bits into the parities of `n` cover elements so that the stego
//! parities `y` satisfy `H·y = message`, choosing `y` with a Viterbi search that
//! minimizes the total cost of the elements whose parity changes.
//!
//! `H` is built from an `h x w` submatrix placed down the diagonal, one block of columns
//! per message bit; block `i` covers elements `floor(i·n/m) .. floor((i+1)·n/m)`.

use crate::error::{Error, Result};

/// Constraint height. 2^H Viterbi states.
pub const H: u32 = 7;
const STATES: usize = 1 << H;
const SEED: u64 = 0x5374_6567_506f_6e79; // "StegPony"

/// Cost of an element that must not change. Large but finite so a path always exists;
/// a solution whose total reaches this is reported as a failure.
pub const WET: f32 = 1.0e10;

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Columns of the submatrix for a code whose widest block is `wmax`. Every column has
/// its first and last row set.
fn columns(wmax: usize) -> Vec<u32> {
    let mut st = SEED ^ wmax as u64;
    (0..wmax)
        .map(|_| {
            let v = splitmix64(&mut st) as u32;
            (v & ((1 << H) - 1)) | 1 | (1 << (H - 1))
        })
        .collect()
}

fn block_start(i: usize, n: usize, m: usize) -> usize {
    ((i as u128 * n as u128) / m as u128) as usize
}

fn row_mask(i: usize, m: usize) -> u32 {
    let left = m - i;
    if left >= H as usize {
        (1 << H) - 1
    } else {
        (1u32 << left) - 1
    }
}

fn check_dims(n: usize, m: usize) -> Result<()> {
    if m == 0 || m > n {
        return Err(Error::Embed(format!(
            "cannot place {m} bits in {n} elements"
        )));
    }
    Ok(())
}

/// Chooses stego parities. `x` and the result hold one bit (0 or 1) per element; `cost`
/// is the price of flipping that element's parity.
pub fn embed(x: &[u8], cost: &[f32], msg: &[u8]) -> Result<Vec<u8>> {
    let n = x.len();
    let m = msg.len();
    assert_eq!(cost.len(), n);
    check_dims(n, m)?;
    let wmax = n.div_ceil(m);
    let cols = columns(wmax);

    let mut w = vec![f32::INFINITY; STATES];
    let mut nw = vec![f32::INFINITY; STATES];
    w[0] = 0.0;
    let mut dec = vec![0u128; n];

    for (i, &msg_bit) in msg.iter().enumerate() {
        let mask = row_mask(i, m);
        let (b0, b1) = (block_start(i, n, m), block_start(i + 1, n, m));
        for j in b0..b1 {
            let c = (cols[j - b0] & mask) as usize;
            let (c0, c1) = if x[j] == 0 {
                (0.0, cost[j])
            } else {
                (cost[j], 0.0)
            };
            let mut d: u128 = 0;
            for s in 0..STATES {
                let a = w[s] + c0;
                let b = w[s ^ c] + c1;
                if b < a {
                    nw[s] = b;
                    d |= 1u128 << s;
                } else {
                    nw[s] = a;
                }
            }
            dec[j] = d;
            std::mem::swap(&mut w, &mut nw);
        }
        let bit = (msg_bit & 1) as usize;
        for (s, v) in nw.iter_mut().enumerate() {
            *v = if s < STATES / 2 {
                w[(s << 1) | bit]
            } else {
                f32::INFINITY
            };
        }
        std::mem::swap(&mut w, &mut nw);
    }

    if w[0] >= WET {
        return Err(Error::Embed(
            "no embedding avoids the fixed elements".into(),
        ));
    }

    let mut y = vec![0u8; n];
    let mut s = 0usize;
    for i in (0..m).rev() {
        s = (s << 1) | (msg[i] & 1) as usize;
        let mask = row_mask(i, m);
        let (b0, b1) = (block_start(i, n, m), block_start(i + 1, n, m));
        for j in (b0..b1).rev() {
            if (dec[j] >> s) & 1 == 1 {
                y[j] = 1;
                s ^= (cols[j - b0] & mask) as usize;
            }
        }
    }
    debug_assert_eq!(s, 0);
    Ok(y)
}

/// Reads `m` message bits back from stego parities.
pub fn extract(y: &[u8], m: usize) -> Result<Vec<u8>> {
    let n = y.len();
    check_dims(n, m)?;
    let wmax = n.div_ceil(m);
    let cols = columns(wmax);
    let mut out = vec![0u8; m];
    let mut s = 0u32;
    for (i, o) in out.iter_mut().enumerate() {
        let mask = row_mask(i, m);
        let (b0, b1) = (block_start(i, n, m), block_start(i + 1, n, m));
        for j in b0..b1 {
            if y[j] & 1 == 1 {
                s ^= cols[j - b0] & mask;
            }
        }
        *o = (s & 1) as u8;
        s >>= 1;
    }
    Ok(out)
}

/// Bytes to bits, least significant bit of each byte first.
pub fn bytes_to_bits(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len() * 8);
    for b in bytes {
        for k in 0..8 {
            out.push((b >> k) & 1);
        }
    }
    out
}

/// Inverse of [`bytes_to_bits`]. `bits.len()` must be a multiple of 8.
pub fn bits_to_bytes(bits: &[u8]) -> Vec<u8> {
    bits.chunks(8)
        .map(|c| {
            c.iter()
                .enumerate()
                .fold(0u8, |acc, (k, b)| acc | ((b & 1) << k))
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand_chacha::rand_core::{RngCore, SeedableRng};
    use rand_chacha::ChaCha20Rng;

    fn random_bits(rng: &mut ChaCha20Rng, n: usize) -> Vec<u8> {
        (0..n).map(|_| (rng.next_u32() & 1) as u8).collect()
    }

    #[test]
    fn roundtrip_various_rates() {
        let mut rng = ChaCha20Rng::seed_from_u64(11);
        for (n, m) in [
            (10, 10),
            (100, 7),
            (1000, 333),
            (5000, 100),
            (20_000, 2_000),
            (777, 1),
        ] {
            let x = random_bits(&mut rng, n);
            let msg = random_bits(&mut rng, m);
            let cost: Vec<f32> = (0..n)
                .map(|_| 1.0 + (rng.next_u32() % 100) as f32)
                .collect();
            let y = embed(&x, &cost, &msg).unwrap();
            assert_eq!(extract(&y, m).unwrap(), msg, "n={n} m={m}");
        }
    }

    #[test]
    fn change_rate_beats_naive() {
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let n = 40_000;
        let m = 4_000;
        let x = random_bits(&mut rng, n);
        let msg = random_bits(&mut rng, m);
        let cost = vec![1.0f32; n];
        let y = embed(&x, &cost, &msg).unwrap();
        let changes = x.iter().zip(&y).filter(|(a, b)| a != b).count();
        // Naive LSB replacement into m elements changes about m/2. STC at rate 0.1
        // should need well under that.
        assert!(changes < m / 4, "changes = {changes}");
    }

    #[test]
    fn wet_elements_never_change() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let n = 8_000;
        let m = 1_000;
        let x = random_bits(&mut rng, n);
        let msg = random_bits(&mut rng, m);
        let cost: Vec<f32> = (0..n).map(|j| if j % 3 == 0 { WET } else { 1.0 }).collect();
        let y = embed(&x, &cost, &msg).unwrap();
        for j in (0..n).step_by(3) {
            assert_eq!(x[j], y[j]);
        }
        assert_eq!(extract(&y, m).unwrap(), msg);
    }

    #[test]
    fn bits_bytes() {
        let b = vec![0x00, 0xff, 0xa5, 0x01];
        assert_eq!(bits_to_bytes(&bytes_to_bits(&b)), b);
        assert_eq!(bytes_to_bits(&[0x01])[0], 1);
    }

    #[test]
    fn rejects_bad_dims() {
        assert!(embed(&[0, 1], &[1.0, 1.0], &[1, 0, 1]).is_err());
        assert!(extract(&[0, 1], 0).is_err());
    }
}
