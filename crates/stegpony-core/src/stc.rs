//! Ternary syndrome-trellis codes (Filler, Judas, Fridrich 2011, the q-ary form with
//! q = 3). FORMAT.md section 4.3.
//!
//! Every element carries a symbol in {0, 1, 2}: its value modulo 3. A change of +1 or
//! -1 moves the symbol to a different one, so both directions carry information, and a
//! message needs fewer changes than with parity (binary) embedding.
//!
//! `m` message trits go into `n` symbols so that the stego symbols `y` satisfy
//! `H·y = message` over GF(3), where `H` is an `h x w` submatrix placed down the
//! diagonal, one block of columns per message trit; block `i` covers elements
//! `floor(i·n/m) .. floor((i+1)·n/m)`. A Viterbi search picks the `y` that minimizes the
//! total cost of the changes.
//!
//! States and columns are `h`-trit vectors stored as base-3 integers, trit `k` (row `k`)
//! worth `3^k`.

use std::sync::OnceLock;

use crate::error::{Error, Result};

/// Constraint height in trits. 3^H Viterbi states.
pub const H: u32 = 4;
const STATES: usize = pow3(H);
const WORDS: usize = (2 * STATES).div_ceil(64);
const SEED: u64 = 0x5374_6567_5465_726e; // "StegTern"

/// Bits per packing group and trits per group: 2^11 = 2048 <= 3^7 = 2187.
pub const GROUP_BITS: usize = 11;
pub const GROUP_TRITS: usize = 7;

fn splitmix64(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9E37_79B9_7F4A_7C15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

const fn pow3(k: u32) -> usize {
    let mut p = 1;
    let mut i = 0;
    while i < k {
        p *= 3;
        i += 1;
    }
    p
}

/// Columns of the submatrix for a code whose widest block is `wmax`: one SplitMix64 draw
/// per column, whose base-3 digits 0..H are the column's trits; a zero in the first or
/// last trit becomes 1, so every column touches the current and the last row.
fn columns(wmax: usize) -> Vec<u16> {
    let mut st = SEED ^ wmax as u64;
    (0..wmax)
        .map(|_| {
            let mut v = splitmix64(&mut st);
            let mut c = 0usize;
            for k in 0..H {
                let mut d = (v % 3) as usize;
                v /= 3;
                if d == 0 && (k == 0 || k == H - 1) {
                    d = 1;
                }
                c += d * pow3(k);
            }
            c as u16
        })
        .collect()
}

/// `table[(c * 3 + y) * STATES + s]` is the state `s ⊖ y·c` (trit-wise, mod 3).
fn sub_table() -> &'static [u16] {
    static TABLE: OnceLock<Vec<u16>> = OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = vec![0u16; STATES * 3 * STATES];
        for c in 0..STATES {
            for y in 0..3 {
                for s in 0..STATES {
                    let (mut cc, mut ss, mut out) = (c, s, 0usize);
                    for k in 0..H {
                        let d = (ss % 3 + 3 * 3 - (y * (cc % 3)) % 3) % 3;
                        out += d * pow3(k);
                        cc /= 3;
                        ss /= 3;
                    }
                    t[(c * 3 + y) * STATES + s] = out as u16;
                }
            }
        }
        t
    })
}

fn sub(c: usize, y: usize) -> &'static [u16] {
    let i = (c * 3 + y) * STATES;
    &sub_table()[i..i + STATES]
}

fn block_start(i: usize, n: usize, m: usize) -> usize {
    ((i as u128 * n as u128) / m as u128) as usize
}

/// Column modulus for block `i`: rows past the end of the message do not exist.
fn row_modulus(i: usize, m: usize) -> usize {
    pow3((m - i).min(H as usize) as u32)
}

fn check_dims(n: usize, m: usize) -> Result<()> {
    if m == 0 || m > n {
        return Err(Error::Embed(format!(
            "cannot place {m} trits in {n} elements"
        )));
    }
    Ok(())
}

/// Chooses stego symbols. `x` holds each element's symbol (0, 1 or 2); `up` and `down`
/// are the costs of changing it by +1 and -1 (infinite when that change is not
/// allowed). The result holds the chosen symbols: `x` (no change), `x + 1` or `x - 1`
/// modulo 3.
pub fn embed(x: &[u8], up: &[f32], down: &[f32], msg: &[u8]) -> Result<Vec<u8>> {
    let n = x.len();
    let m = msg.len();
    assert!(up.len() == n && down.len() == n);
    check_dims(n, m)?;
    let cols = columns(n.div_ceil(m));

    let mut w = vec![f64::INFINITY; STATES];
    let mut nw = vec![f64::INFINITY; STATES];
    w[0] = 0.0;
    // Two bits per state: the symbol chosen on the best path into that state.
    let mut dec = vec![0u64; n * WORDS];

    for (i, &t) in msg.iter().enumerate() {
        let modulus = row_modulus(i, m);
        let (b0, b1) = (block_start(i, n, m), block_start(i + 1, n, m));
        for j in b0..b1 {
            let c = cols[j - b0] as usize % modulus;
            let xs = x[j] as usize % 3;
            let mut cost = [0f64; 3];
            cost[(xs + 1) % 3] = up[j] as f64;
            cost[(xs + 2) % 3] = down[j] as f64;
            let p = [sub(c, 0), sub(c, 1), sub(c, 2)];
            for s in 0..STATES {
                let mut best = w[p[0][s] as usize] + cost[0];
                let mut by = 0u64;
                for y in 1..3 {
                    let v = w[p[y][s] as usize] + cost[y];
                    if v < best {
                        best = v;
                        by = y as u64;
                    }
                }
                nw[s] = best;
                dec[j * WORDS + (2 * s) / 64] |= by << ((2 * s) % 64);
            }
            std::mem::swap(&mut w, &mut nw);
        }
        let t = (t % 3) as usize;
        for (s, v) in nw.iter_mut().enumerate() {
            *v = if s < STATES / 3 {
                w[s * 3 + t]
            } else {
                f64::INFINITY
            };
        }
        std::mem::swap(&mut w, &mut nw);
    }

    if !w[0].is_finite() {
        return Err(Error::Embed(
            "no embedding avoids the fixed elements".into(),
        ));
    }

    let mut y = vec![0u8; n];
    let mut s = 0usize;
    for i in (0..m).rev() {
        s = s * 3 + (msg[i] % 3) as usize;
        let modulus = row_modulus(i, m);
        let (b0, b1) = (block_start(i, n, m), block_start(i + 1, n, m));
        for j in (b0..b1).rev() {
            let c = cols[j - b0] as usize % modulus;
            let sym = ((dec[j * WORDS + (2 * s) / 64] >> ((2 * s) % 64)) & 3) as usize;
            y[j] = sym as u8;
            s = sub(c, sym)[s] as usize;
        }
    }
    debug_assert_eq!(s, 0);
    Ok(y)
}

/// Reads `m` message trits back from stego symbols.
pub fn extract(y: &[u8], m: usize) -> Result<Vec<u8>> {
    let n = y.len();
    check_dims(n, m)?;
    let cols = columns(n.div_ceil(m));
    let mut out = vec![0u8; m];
    let mut s = 0usize;
    for (i, o) in out.iter_mut().enumerate() {
        let modulus = row_modulus(i, m);
        let (b0, b1) = (block_start(i, n, m), block_start(i + 1, n, m));
        for j in b0..b1 {
            let c = cols[j - b0] as usize % modulus;
            // s ⊕ y·c is s ⊖ (3 - y)·c.
            s = sub(c, (3 - (y[j] % 3) as usize) % 3)[s] as usize;
        }
        *o = (s % 3) as u8;
        s /= 3;
    }
    Ok(out)
}

/// Trits needed for `bits` bits: 7 per started group of 11.
pub fn trits_for_bits(bits: usize) -> usize {
    GROUP_TRITS * bits.div_ceil(GROUP_BITS)
}

/// Bytes to trits: bits least significant first, in groups of 11 (the last padded
/// with zeros), each group's value written as 7 base-3 digits, least significant first.
pub fn bytes_to_trits(bytes: &[u8]) -> Vec<u8> {
    let bits = bytes_to_bits(bytes);
    let mut out = Vec::with_capacity(trits_for_bits(bits.len()));
    for g in bits.chunks(GROUP_BITS) {
        let mut v = g
            .iter()
            .enumerate()
            .fold(0usize, |acc, (k, &b)| acc | ((b as usize) << k));
        for _ in 0..GROUP_TRITS {
            out.push((v % 3) as u8);
            v /= 3;
        }
    }
    out
}

/// Inverse of [`bytes_to_trits`] for `len` bytes. A group whose value is 2048 or more
/// (possible only when reading with the wrong key) keeps its low 11 bits.
pub fn trits_to_bytes(trits: &[u8], len: usize) -> Vec<u8> {
    let mut bits = Vec::with_capacity(trits.len() / GROUP_TRITS * GROUP_BITS);
    for g in trits.chunks(GROUP_TRITS) {
        let v = g
            .iter()
            .rev()
            .fold(0usize, |acc, &t| acc * 3 + (t % 3) as usize);
        for k in 0..GROUP_BITS {
            bits.push(((v >> k) & 1) as u8);
        }
    }
    bits.truncate(len * 8);
    bits_to_bytes(&bits)
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

    fn random_trits(rng: &mut ChaCha20Rng, n: usize) -> Vec<u8> {
        (0..n).map(|_| (rng.next_u32() % 3) as u8).collect()
    }

    fn costs(rng: &mut ChaCha20Rng, n: usize) -> Vec<f32> {
        (0..n)
            .map(|_| 1.0 + (rng.next_u32() % 100) as f32)
            .collect()
    }

    #[test]
    fn columns_touch_first_and_last_row() {
        for wmax in [1, 2, 7, 100] {
            for c in columns(wmax) {
                assert!((c as usize) < STATES);
                assert_ne!(c % 3, 0);
                assert_ne!(c as usize / pow3(H - 1), 0);
            }
        }
    }

    #[test]
    fn table_is_trit_wise_subtraction() {
        // 2·(1,2,0,1) = (2,1,0,2); (0,0,0,0) - that = (1,2,0,1).
        let c = 1 + 2 * 3 + 27;
        assert_eq!(sub(c, 2)[0] as usize, 1 + 2 * 3 + 27);
        for c in 0..STATES {
            for s in 0..STATES {
                assert_eq!(sub(c, 0)[s] as usize, s);
                // Subtracting three times gets back to the start.
                let once = sub(c, 1)[s] as usize;
                let twice = sub(c, 1)[once] as usize;
                assert_eq!(sub(c, 1)[twice] as usize, s);
                assert_eq!(sub(c, 2)[s] as usize, twice);
            }
        }
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
            (3000, 3),
        ] {
            let x = random_trits(&mut rng, n);
            let msg = random_trits(&mut rng, m);
            let (up, down) = (costs(&mut rng, n), costs(&mut rng, n));
            let y = embed(&x, &up, &down, &msg).unwrap();
            assert_eq!(extract(&y, m).unwrap(), msg, "n={n} m={m}");
            for (a, b) in x.iter().zip(&y) {
                assert!(*b < 3 && (*a == *b || (a + 1) % 3 == *b || (a + 2) % 3 == *b));
            }
        }
    }

    /// Distortion of an ideal coder: `ways` = 1 for binary (one way to change an
    /// element), 2 for ternary (+1 or -1), at the payload-limited optimum.
    fn bound(costs: &[f64], bits: f64, ways: f64) -> f64 {
        let at = |l: f64| {
            let (mut h, mut d) = (0.0, 0.0);
            for &r in costs {
                let e = (-l * r).exp();
                let (p, p0) = (e / (1.0 + ways * e), 1.0 / (1.0 + ways * e));
                h -= p0 * p0.log2() + if p > 0.0 { ways * p * p.log2() } else { 0.0 };
                d += ways * p * r;
            }
            (h, d)
        };
        let (mut lo, mut hi) = (1e-9f64, 1e4f64);
        for _ in 0..200 {
            let mid = (lo * hi).sqrt();
            if at(mid).0 > bits {
                lo = mid
            } else {
                hi = mid
            }
        }
        at(lo).1
    }

    #[test]
    fn distortion_near_the_ternary_bound() {
        // Heavy-tailed costs, a 2,000-byte message in 100,000 elements. On real
        // J-UNIWARD cost maps height 4 lands at about 1.3x the ternary bound, which is
        // below what an ideal binary code could reach.
        let mut rng = ChaCha20Rng::seed_from_u64(12);
        let n = 100_000;
        let bytes: Vec<u8> = (0..2000).map(|_| rng.next_u32() as u8).collect();
        let msg = bytes_to_trits(&bytes);
        let x = random_trits(&mut rng, n);
        let c: Vec<f32> = (0..n)
            .map(|_| 1.0 / ((rng.next_u32() % 10_000) as f32 / 10_000.0 + 0.01))
            .collect();
        let y = embed(&x, &c, &c, &msg).unwrap();
        let d: f64 = (0..n).filter(|&j| x[j] != y[j]).map(|j| c[j] as f64).sum();
        let cd: Vec<f64> = c.iter().map(|&v| v as f64).collect();
        let bits = (bytes.len() * 8) as f64;
        let tern = bound(&cd, bits, 2.0);
        assert!(d < tern * 1.4, "distortion {d:.0}, ternary bound {tern:.0}");
        // Sanity check of the bound itself: binary needs more.
        assert!(bound(&cd, bits, 1.0) > tern);
    }

    #[test]
    fn forbidden_directions_are_respected() {
        let mut rng = ChaCha20Rng::seed_from_u64(13);
        let n = 9_000;
        let m = 1_000;
        let x = random_trits(&mut rng, n);
        let msg = random_trits(&mut rng, m);
        let inf = f32::INFINITY;
        // Every third element is fixed; of the rest, alternate ones may only go up or
        // only go down.
        let up: Vec<f32> = (0..n)
            .map(|j| if j % 3 == 0 || j % 3 == 2 { inf } else { 1.0 })
            .collect();
        let down: Vec<f32> = (0..n)
            .map(|j| if j % 3 == 0 || j % 3 == 1 { inf } else { 1.0 })
            .collect();
        let y = embed(&x, &up, &down, &msg).unwrap();
        for j in 0..n {
            match j % 3 {
                0 => assert_eq!(x[j], y[j]),
                1 => assert!(y[j] == x[j] || y[j] == (x[j] + 1) % 3),
                _ => assert!(y[j] == x[j] || y[j] == (x[j] + 2) % 3),
            }
        }
        assert_eq!(extract(&y, m).unwrap(), msg);
    }

    #[test]
    fn all_fixed_fails_cleanly() {
        let inf = vec![f32::INFINITY; 30];
        let x = vec![0u8; 30];
        assert!(embed(&x, &inf, &inf, &[1, 2, 0]).is_err());
    }

    #[test]
    fn trit_packing() {
        for len in [0usize, 1, 2, 20, 36, 37, 256] {
            let bytes: Vec<u8> = (0..len).map(|i| (i * 37 + 11) as u8).collect();
            let t = bytes_to_trits(&bytes);
            assert_eq!(t.len(), trits_for_bits(len * 8));
            assert!(t.iter().all(|&v| v < 3));
            assert_eq!(trits_to_bytes(&t, len), bytes);
        }
        assert_eq!(trits_for_bits(160), 105);
        assert_eq!(trits_for_bits(288), 189);
        // 0x7ff (all ones) is 2047 = 2210211 in base 3, least significant digit first.
        assert_eq!(&bytes_to_trits(&[0xff, 0x07])[..7], &[1, 1, 2, 0, 1, 2, 2]);
    }

    #[test]
    fn bits_bytes() {
        let b = vec![0x00, 0xff, 0xa5, 0x01];
        assert_eq!(bits_to_bytes(&bytes_to_bits(&b)), b);
        assert_eq!(bytes_to_bits(&[0x01])[0], 1);
    }

    #[test]
    fn rejects_bad_dims() {
        assert!(embed(&[0, 1], &[1.0, 1.0], &[1.0, 1.0], &[1, 0, 1]).is_err());
        assert!(extract(&[0, 1], 0).is_err());
    }
}
