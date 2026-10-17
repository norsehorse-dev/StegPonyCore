//! Keyed pseudo-random permutation of `0..n`. FORMAT.md section 4.1.
//!
//! A 4-round balanced Feistel network over the smallest even bit width that covers `n`,
//! with SipHash-2-4 as the round function, and cycle walking to stay inside `0..n`.
//! Lets a carrier visit its elements in a secret order without materializing an index
//! array the size of the image.

use siphasher::sip::SipHasher24;

pub struct Prp {
    hasher: SipHasher24,
    n: u64,
    half: u32,
    mask: u64,
}

impl Prp {
    pub fn new(key: &[u8; 16], n: u64) -> Self {
        assert!(n > 0, "empty domain");
        let bits = 64 - (n - 1).leading_zeros();
        let bits = bits.max(2);
        let bits = bits + (bits & 1);
        let half = bits / 2;
        Prp {
            hasher: SipHasher24::new_with_key(key),
            n,
            half,
            mask: (1u64 << half) - 1,
        }
    }

    fn round(&self, r: u8, x: u64) -> u64 {
        let mut msg = [0u8; 9];
        msg[0] = r;
        msg[1..].copy_from_slice(&x.to_le_bytes());
        self.hasher.hash(&msg) & self.mask
    }

    fn feistel(&self, x: u64) -> u64 {
        let mut l = x >> self.half;
        let mut r = x & self.mask;
        for round in 0..4u8 {
            let f = self.round(round, r);
            let nl = r;
            r = l ^ f;
            l = nl;
        }
        (l << self.half) | r
    }

    /// The image of `i` under the permutation. `i` must be below `n`.
    pub fn permute(&self, i: u64) -> u64 {
        debug_assert!(i < self.n);
        let mut y = self.feistel(i);
        while y >= self.n {
            y = self.feistel(y);
        }
        y
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_a_permutation() {
        for n in [1u64, 2, 3, 5, 16, 17, 1000, 4097] {
            let p = Prp::new(&[9u8; 16], n);
            let mut seen = vec![false; n as usize];
            for i in 0..n {
                let y = p.permute(i) as usize;
                assert!(!seen[y]);
                seen[y] = true;
            }
        }
    }

    #[test]
    fn key_changes_order() {
        let a = Prp::new(&[1u8; 16], 10_000);
        let b = Prp::new(&[2u8; 16], 10_000);
        let same = (0..10_000)
            .filter(|&i| a.permute(i) == b.permute(i))
            .count();
        assert!(same < 20);
    }

    #[test]
    fn fixed_vector() {
        let p = Prp::new(&[0u8; 16], 1_000_000);
        let first: Vec<u64> = (0..4).map(|i| p.permute(i)).collect();
        assert_eq!(first, crate::vectors::PRP_ZERO_KEY_1M);
    }
}
