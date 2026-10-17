//! Huffman tables, bit-level I/O and optimal table generation for JPEG entropy coding
//! (ITU-T T.81 Annex C, F.2.2 and K.2).

use crate::error::{Error, Result};

/// A Huffman table as stored in a DHT segment: code counts per length and the symbols
/// in code order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HuffSpec {
    /// `counts[l]` is the number of codes of length `l + 1`.
    pub counts: [u8; 16],
    pub symbols: Vec<u8>,
}

fn bad(msg: &str) -> Error {
    Error::BadCover(format!("JPEG: {msg}"))
}

impl HuffSpec {
    /// Code length and code for every symbol, in symbol order of the table.
    fn codes(&self) -> Result<Vec<(u8, u16)>> {
        let mut out = Vec::with_capacity(self.symbols.len());
        let mut code: u32 = 0;
        for (i, &n) in self.counts.iter().enumerate() {
            let len = i as u32 + 1;
            for _ in 0..n {
                // Same check as libjpeg: a code may not overflow its length. (Writers
                // should also avoid the all-ones code, and ours does, but readers
                // accept it.)
                if code >= (1 << len) {
                    return Err(bad("Huffman table overflows its code space"));
                }
                out.push((len as u8, code as u16));
                code += 1;
            }
            code <<= 1;
        }
        Ok(out)
    }

    /// Parses every table in a DHT segment payload as `(class, id, table)`.
    pub fn parse_dht(mut data: &[u8]) -> Result<Vec<(u8, u8, HuffSpec)>> {
        let mut out = Vec::new();
        while !data.is_empty() {
            if data.len() < 17 {
                return Err(bad("short DHT segment"));
            }
            let tc = data[0] >> 4;
            let th = data[0] & 15;
            if tc > 1 || th > 3 {
                return Err(bad("bad DHT table class or id"));
            }
            let mut counts = [0u8; 16];
            counts.copy_from_slice(&data[1..17]);
            let n: usize = counts.iter().map(|&c| c as usize).sum();
            if n > 256 || data.len() < 17 + n {
                return Err(bad("bad DHT symbol count"));
            }
            let spec = HuffSpec {
                counts,
                symbols: data[17..17 + n].to_vec(),
            };
            spec.codes()?;
            out.push((tc, th, spec));
            data = &data[17 + n..];
        }
        Ok(out)
    }

    pub fn write_dht(&self, class: u8, id: u8, out: &mut Vec<u8>) {
        out.push((class << 4) | id);
        out.extend_from_slice(&self.counts);
        out.extend_from_slice(&self.symbols);
    }

    /// Builds the optimal length-limited table for these symbol frequencies, with the
    /// same procedure as libjpeg's `jpeg_gen_optimal_table` (T.81 K.2).
    pub fn optimal(freq: &[u64; 256]) -> HuffSpec {
        const MAX_LEN: usize = 64;
        let mut f = [0u64; 257];
        f[..256].copy_from_slice(freq);
        // A pseudo-symbol that takes the all-ones code, so no real code is all ones.
        f[256] = 1;
        let mut codesize = [0usize; 257];
        let mut others = [-1i32; 257];
        loop {
            let mut c1: i32 = -1;
            let mut v = u64::MAX;
            for (i, &x) in f.iter().enumerate() {
                if x != 0 && x <= v {
                    v = x;
                    c1 = i as i32;
                }
            }
            let mut c2: i32 = -1;
            v = u64::MAX;
            for (i, &x) in f.iter().enumerate() {
                if x != 0 && x <= v && i as i32 != c1 {
                    v = x;
                    c2 = i as i32;
                }
            }
            if c2 < 0 {
                break;
            }
            let (mut a, mut b) = (c1 as usize, c2 as usize);
            f[a] += f[b];
            f[b] = 0;
            codesize[a] += 1;
            while others[a] >= 0 {
                a = others[a] as usize;
                codesize[a] += 1;
            }
            others[a] = b as i32;
            codesize[b] += 1;
            while others[b] >= 0 {
                b = others[b] as usize;
                codesize[b] += 1;
            }
        }
        let mut bits = [0u32; MAX_LEN + 1];
        for &cs in codesize.iter() {
            if cs > 0 {
                bits[cs.min(MAX_LEN)] += 1;
            }
        }
        // Limit code lengths to 16 bits (K.2, Figure K.3).
        for i in (17..=MAX_LEN).rev() {
            while bits[i] > 0 {
                let mut j = i - 2;
                while bits[j] == 0 {
                    j -= 1;
                }
                bits[i] -= 2;
                bits[i - 1] += 1;
                bits[j + 1] += 2;
                bits[j] -= 1;
            }
        }
        // Drop the pseudo-symbol's code, which is the longest.
        let mut i = 16;
        while i > 0 && bits[i] == 0 {
            i -= 1;
        }
        if i > 0 {
            bits[i] -= 1;
        }
        let mut counts = [0u8; 16];
        for l in 1..=16 {
            counts[l - 1] = bits[l] as u8;
        }
        let mut symbols = Vec::new();
        for len in 1..=MAX_LEN {
            for (sym, &cs) in codesize[..256].iter().enumerate() {
                if cs == len {
                    symbols.push(sym as u8);
                }
            }
        }
        if symbols.is_empty() {
            // A table nothing uses still has to be valid: one 1-bit code for symbol 0.
            counts = [0; 16];
            counts[0] = 1;
            symbols.push(0);
        }
        HuffSpec { counts, symbols }
    }
}

/// Decoding form of a table.
pub struct DecTable {
    /// Indexed by the next `LOOKUP_BITS` bits: `(length << 8) | symbol`, or 0 when the
    /// code is longer.
    lookup: Vec<u16>,
    maxcode: [i32; 18],
    valoffset: [i32; 17],
    symbols: Vec<u8>,
}

const LOOKUP_BITS: u32 = 9;

impl DecTable {
    pub fn new(spec: &HuffSpec) -> Result<DecTable> {
        let codes = spec.codes()?;
        let mut lookup = vec![0u16; 1 << LOOKUP_BITS];
        for (k, &(len, code)) in codes.iter().enumerate() {
            let len = len as u32;
            if len <= LOOKUP_BITS {
                let shift = LOOKUP_BITS - len;
                let base = (code as usize) << shift;
                for e in &mut lookup[base..base + (1 << shift)] {
                    *e = ((len as u16) << 8) | spec.symbols[k] as u16;
                }
            }
        }
        let mut maxcode = [-1i32; 18];
        let mut valoffset = [0i32; 17];
        let mut k = 0usize;
        for l in 1..=16usize {
            let n = spec.counts[l - 1] as usize;
            if n > 0 {
                valoffset[l] = k as i32 - codes[k].1 as i32;
                k += n;
                maxcode[l] = codes[k - 1].1 as i32;
            }
        }
        maxcode[17] = i32::MAX;
        Ok(DecTable {
            lookup,
            maxcode,
            valoffset,
            symbols: spec.symbols.clone(),
        })
    }
}

/// Encoding form of a table: `(length, code)` per symbol, length 0 for absent symbols.
#[derive(Clone)]
pub struct EncTable {
    pub codes: [(u8, u16); 256],
}

impl EncTable {
    pub fn new(spec: &HuffSpec) -> Result<EncTable> {
        let mut codes = [(0u8, 0u16); 256];
        for (k, c) in spec.codes()?.into_iter().enumerate() {
            codes[spec.symbols[k] as usize] = c;
        }
        Ok(EncTable { codes })
    }

    pub fn covers(&self, freq: &[u64; 256]) -> bool {
        freq.iter()
            .zip(self.codes.iter())
            .all(|(&f, &(len, _))| f == 0 || len > 0)
    }
}

/// Reads entropy-coded data, removing byte stuffing. At a marker (or the end of the
/// input) it supplies zero bits and remembers how many, so a scan that reads past its
/// own data is detected.
pub struct BitReader<'a> {
    data: &'a [u8],
    pub pos: usize,
    acc: u64,
    nbits: u32,
    fake_bits: u32,
    at_marker: bool,
}

impl<'a> BitReader<'a> {
    pub fn new(data: &'a [u8], pos: usize) -> BitReader<'a> {
        BitReader {
            data,
            pos,
            acc: 0,
            nbits: 0,
            fake_bits: 0,
            at_marker: false,
        }
    }

    #[inline]
    fn fill(&mut self) {
        while self.nbits <= 56 {
            let byte = if self.at_marker {
                self.fake_bits += 8;
                0
            } else if self.pos >= self.data.len() {
                self.at_marker = true;
                continue;
            } else {
                let b = self.data[self.pos];
                if b == 0xFF {
                    match self.data.get(self.pos + 1) {
                        Some(0) => {
                            self.pos += 2;
                            0xFF
                        }
                        _ => {
                            self.at_marker = true;
                            continue;
                        }
                    }
                } else {
                    self.pos += 1;
                    b
                }
            };
            self.acc |= (byte as u64) << (56 - self.nbits);
            self.nbits += 8;
        }
    }

    #[inline]
    pub fn bits(&mut self, n: u32) -> u32 {
        if n == 0 {
            return 0;
        }
        if self.nbits < n {
            self.fill();
        }
        let v = (self.acc >> (64 - n)) as u32;
        self.acc <<= n;
        self.nbits -= n;
        v
    }

    #[inline]
    pub fn bit(&mut self) -> u32 {
        self.bits(1)
    }

    /// Reads `n` bits as a signed value in the JPEG magnitude-category coding (F.2.2.1).
    #[inline]
    pub fn receive_extend(&mut self, n: u32) -> i32 {
        if n == 0 {
            return 0;
        }
        let v = self.bits(n) as i32;
        if v < (1 << (n - 1)) {
            v - (1 << n) + 1
        } else {
            v
        }
    }

    #[inline]
    pub fn decode(&mut self, t: &DecTable) -> Result<u8> {
        if self.nbits < 16 {
            self.fill();
        }
        let peek = (self.acc >> (64 - LOOKUP_BITS)) as usize;
        let e = t.lookup[peek];
        if e != 0 {
            let len = (e >> 8) as u32;
            self.acc <<= len;
            self.nbits -= len;
            return Ok(e as u8);
        }
        let mut code = 0i32;
        for l in 1..=16usize {
            code = (code << 1) | ((self.acc >> (63 - (l - 1))) & 1) as i32;
            if code <= t.maxcode[l] {
                self.acc <<= l;
                self.nbits -= l as u32;
                let idx = (code + t.valoffset[l]) as usize;
                return t
                    .symbols
                    .get(idx)
                    .copied()
                    .ok_or_else(|| bad("bad Huffman code"));
            }
        }
        Err(bad("bad Huffman code"))
    }

    /// True when the scan so far consumed only real bits.
    pub fn ok(&self) -> bool {
        self.nbits >= self.fake_bits
    }

    /// Drops buffered bits and moves to the next marker, returning its code. Fill bytes
    /// (0xFF runs) before a marker are skipped.
    pub fn next_marker(&mut self) -> Result<u8> {
        if !self.ok() {
            return Err(bad("entropy-coded data ends early"));
        }
        self.acc = 0;
        self.nbits = 0;
        self.fake_bits = 0;
        self.at_marker = false;
        let d = self.data;
        let mut p = self.pos;
        loop {
            if p + 1 >= d.len() {
                return Err(bad("missing marker after scan"));
            }
            if d[p] == 0xFF && d[p + 1] != 0 && d[p + 1] != 0xFF {
                self.pos = p + 2;
                return Ok(d[p + 1]);
            }
            p += 1;
        }
    }
}

/// Writes entropy-coded data with byte stuffing.
pub struct BitWriter {
    pub out: Vec<u8>,
    acc: u64,
    nbits: u32,
}

impl BitWriter {
    pub fn new(out: Vec<u8>) -> BitWriter {
        BitWriter {
            out,
            acc: 0,
            nbits: 0,
        }
    }

    #[inline]
    pub fn put(&mut self, v: u32, n: u32) {
        if n == 0 {
            return;
        }
        let v = (v as u64) & ((1u64 << n) - 1);
        self.acc = (self.acc << n) | v;
        self.nbits += n;
        while self.nbits >= 8 {
            let b = (self.acc >> (self.nbits - 8)) as u8;
            self.out.push(b);
            if b == 0xFF {
                self.out.push(0);
            }
            self.nbits -= 8;
        }
        self.acc &= (1u64 << self.nbits) - 1;
    }

    /// Pads the last byte with one bits.
    pub fn flush(&mut self) {
        if self.nbits > 0 {
            let pad = 8 - self.nbits;
            self.put((1 << pad) - 1, pad);
        }
    }

    pub fn marker(&mut self, m: u8) {
        self.flush();
        self.out.push(0xFF);
        self.out.push(m);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Luminance DC table from T.81 Table K.3.
    fn std_dc() -> HuffSpec {
        HuffSpec {
            counts: [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
            symbols: (0..12).collect(),
        }
    }

    #[test]
    fn decode_encode_round_trip() {
        let spec = std_dc();
        let enc = EncTable::new(&spec).unwrap();
        let dec = DecTable::new(&spec).unwrap();
        let mut w = BitWriter::new(Vec::new());
        let syms: Vec<u8> = (0..12).chain((0..12).rev()).collect();
        for &s in &syms {
            let (l, c) = enc.codes[s as usize];
            w.put(c as u32, l as u32);
        }
        w.flush();
        w.out.extend_from_slice(&[0xFF, 0xD9]);
        let mut r = BitReader::new(&w.out, 0);
        for &s in &syms {
            assert_eq!(r.decode(&dec).unwrap(), s);
        }
        assert_eq!(r.next_marker().unwrap(), 0xD9);
    }

    #[test]
    fn optimal_table_is_valid_and_limited() {
        let mut freq = [0u64; 256];
        // Fibonacci frequencies force very long codes before limiting.
        let (mut a, mut b) = (1u64, 1u64);
        for f in freq.iter_mut().take(40) {
            *f = a;
            (a, b) = (b, a + b);
        }
        let spec = HuffSpec::optimal(&freq);
        let enc = EncTable::new(&spec).unwrap();
        assert!(enc.covers(&freq));
        assert_eq!(spec.symbols.len(), 40);
        assert!(DecTable::new(&spec).is_ok());
    }

    #[test]
    fn single_symbol_table() {
        let mut freq = [0u64; 256];
        freq[0] = 1000;
        let spec = HuffSpec::optimal(&freq);
        assert_eq!(spec.symbols, vec![0]);
        assert_eq!(spec.counts[0], 1);
        assert!(EncTable::new(&spec).is_ok());
    }
}
