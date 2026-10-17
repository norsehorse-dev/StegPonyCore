//! Entropy decoding and encoding of one scan, sequential or progressive (T.81 F.2, G.1
//! and G.2). The encoder follows libjpeg's decisions (EOB runs, ZRL placement,
//! correction-bit buffering), so a libjpeg-written file comes back byte for byte when
//! nothing changed.

use super::huffman::{BitReader, BitWriter, DecTable, EncTable};
use super::{Component, Geometry, ScanHeader};
use crate::error::{Error, Result};

/// Zigzag position to natural (row-major) position in an 8x8 block.
pub const ZIGZAG: [usize; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

fn bad(msg: &str) -> Error {
    Error::BadCover(format!("JPEG: {msg}"))
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Sequential,
    DcFirst,
    DcRefine,
    AcFirst,
    AcRefine,
}

fn kind(scan: &ScanHeader, progressive: bool) -> Kind {
    if !progressive {
        Kind::Sequential
    } else if scan.ss == 0 {
        if scan.ah == 0 {
            Kind::DcFirst
        } else {
            Kind::DcRefine
        }
    } else if scan.ah == 0 {
        Kind::AcFirst
    } else {
        Kind::AcRefine
    }
}

/// Block offsets (into each component's coefficient array) of every MCU in the scan, in
/// coding order, with the index of the scan component each belongs to.
fn mcus(geo: &Geometry, comps: &[Component], scan: &ScanHeader) -> (usize, Vec<(u8, usize)>) {
    let mut units = Vec::new();
    if scan.comps.len() == 1 {
        let c = &comps[scan.comps[0].index];
        for by in 0..c.height_blocks {
            for bx in 0..c.width_blocks {
                units.push((0u8, (by * c.grid_w + bx) * 64));
            }
        }
        (1, units)
    } else {
        let per: usize = scan
            .comps
            .iter()
            .map(|s| comps[s.index].h as usize * comps[s.index].v as usize)
            .sum();
        for my in 0..geo.mcu_rows {
            for mx in 0..geo.mcu_cols {
                for (si, s) in scan.comps.iter().enumerate() {
                    let c = &comps[s.index];
                    for v in 0..c.v as usize {
                        for h in 0..c.h as usize {
                            let by = my * c.v as usize + v;
                            let bx = mx * c.h as usize + h;
                            units.push((si as u8, (by * c.grid_w + bx) * 64));
                        }
                    }
                }
            }
        }
        (per, units)
    }
}

fn store(v: i32) -> Result<i16> {
    i16::try_from(v).map_err(|_| bad("coefficient out of range"))
}

pub struct Tables<'a> {
    pub dc: &'a [Option<DecTable>; 4],
    pub ac: &'a [Option<DecTable>; 4],
}

/// Decodes one scan whose entropy-coded data starts at `r.pos`. Returns the marker
/// that follows the scan.
pub fn decode(
    r: &mut BitReader,
    geo: &Geometry,
    comps: &mut [Component],
    scan: &ScanHeader,
    restart: u16,
    tables: &Tables,
    progressive: bool,
) -> Result<u8> {
    let kind = kind(scan, progressive);
    let mut dc: Vec<Option<&DecTable>> = Vec::new();
    let mut ac: Vec<Option<&DecTable>> = Vec::new();
    for s in &scan.comps {
        let need_dc = matches!(kind, Kind::Sequential | Kind::DcFirst);
        let need_ac = matches!(kind, Kind::Sequential | Kind::AcFirst | Kind::AcRefine);
        let d = tables.dc[s.td as usize].as_ref();
        let a = tables.ac[s.ta as usize].as_ref();
        if (need_dc && d.is_none()) || (need_ac && a.is_none()) {
            return Err(bad("scan uses an undefined Huffman table"));
        }
        dc.push(d);
        ac.push(a);
    }
    let (per, units) = mcus(geo, comps, scan);
    let mut pred = vec![0i32; scan.comps.len()];
    let mut eobrun: u32 = 0;
    let (ss, se, al) = (scan.ss as usize, scan.se as usize, scan.al as u32);
    let nmcu = units.len() / per;
    let mut rst = 0u32;
    for m in 0..nmcu {
        if restart > 0 && m > 0 && m % restart as usize == 0 {
            let mk = r.next_marker()?;
            if mk != 0xD0 + (rst & 7) as u8 {
                return Err(bad("restart marker out of sequence"));
            }
            rst += 1;
            pred.iter_mut().for_each(|p| *p = 0);
            eobrun = 0;
        }
        for &(si, off) in &units[m * per..(m + 1) * per] {
            let si = si as usize;
            let c = &mut comps[scan.comps[si].index];
            let b = &mut c.coefs[off..off + 64];
            match kind {
                Kind::Sequential => {
                    let t = r.decode(dc[si].unwrap())? as u32;
                    if t > 15 {
                        return Err(bad("bad DC category"));
                    }
                    pred[si] += r.receive_extend(t);
                    b[0] = store(pred[si])?;
                    let a = ac[si].unwrap();
                    let mut k = 1;
                    while k < 64 {
                        let rs = r.decode(a)?;
                        let (run, s) = ((rs >> 4) as usize, (rs & 15) as u32);
                        if s != 0 {
                            k += run;
                            if k > 63 {
                                return Err(bad("AC run past end of block"));
                            }
                            b[ZIGZAG[k]] = store(r.receive_extend(s))?;
                            k += 1;
                        } else if run == 15 {
                            k += 16;
                        } else {
                            break;
                        }
                    }
                }
                Kind::DcFirst => {
                    let t = r.decode(dc[si].unwrap())? as u32;
                    if t > 15 {
                        return Err(bad("bad DC category"));
                    }
                    pred[si] += r.receive_extend(t);
                    b[0] = store(pred[si] << al)?;
                }
                Kind::DcRefine => {
                    if r.bit() != 0 {
                        b[0] |= 1 << al;
                    }
                }
                Kind::AcFirst => {
                    if eobrun > 0 {
                        eobrun -= 1;
                        continue;
                    }
                    let a = ac[si].unwrap();
                    let mut k = ss;
                    while k <= se {
                        let rs = r.decode(a)?;
                        let (run, s) = ((rs >> 4) as u32, (rs & 15) as u32);
                        if s != 0 {
                            k += run as usize;
                            if k > se {
                                return Err(bad("AC run past end of band"));
                            }
                            b[ZIGZAG[k]] = store(r.receive_extend(s) << al)?;
                            k += 1;
                        } else if run == 15 {
                            k += 16;
                        } else {
                            eobrun = 1 << run;
                            if run > 0 {
                                eobrun += r.bits(run);
                            }
                            eobrun -= 1;
                            break;
                        }
                    }
                }
                Kind::AcRefine => {
                    let p1: i16 = 1 << al;
                    let m1: i16 = -1 << al;
                    let mut k = ss;
                    let refine = |r: &mut BitReader, c: &mut i16| -> Result<()> {
                        if r.bit() != 0 && (*c & p1) == 0 {
                            *c = c
                                .checked_add(if *c >= 0 { p1 } else { m1 })
                                .ok_or_else(|| bad("coefficient out of range"))?;
                        }
                        Ok(())
                    };
                    if eobrun == 0 {
                        let a = ac[si].unwrap();
                        while k <= se {
                            let rs = r.decode(a)?;
                            let mut run = (rs >> 4) as i32;
                            let s = rs & 15;
                            let mut val = 0i16;
                            if s != 0 {
                                if s != 1 {
                                    return Err(bad("bad refinement symbol"));
                                }
                                val = if r.bit() != 0 { p1 } else { m1 };
                            } else if run != 15 {
                                eobrun = 1 << run;
                                if run > 0 {
                                    eobrun += r.bits(run as u32);
                                }
                                break;
                            }
                            while k <= se {
                                let z = ZIGZAG[k];
                                if b[z] != 0 {
                                    refine(r, &mut b[z])?;
                                } else {
                                    run -= 1;
                                    if run < 0 {
                                        break;
                                    }
                                }
                                k += 1;
                            }
                            if val != 0 {
                                if k > se {
                                    return Err(bad("refinement past end of band"));
                                }
                                b[ZIGZAG[k]] = val;
                            }
                            k += 1;
                        }
                    }
                    if eobrun > 0 {
                        while k <= se {
                            let z = ZIGZAG[k];
                            if b[z] != 0 {
                                refine(r, &mut b[z])?;
                            }
                            k += 1;
                        }
                        eobrun -= 1;
                    }
                }
            }
        }
    }
    r.next_marker()
}

/// Receives the output of the encoder: symbols for counting or writing, raw bits, and
/// restart points.
pub trait Sink {
    /// `table` is `class * 4 + id`.
    fn sym(&mut self, table: usize, s: u8) -> Result<()>;
    fn raw(&mut self, v: u32, n: u32);
    fn restart(&mut self, index: u32);
}

/// Counts symbol frequencies per table.
pub struct Counter {
    pub freq: Vec<[u64; 256]>,
}

impl Counter {
    pub fn new() -> Counter {
        Counter {
            freq: vec![[0u64; 256]; 8],
        }
    }
}

impl Sink for Counter {
    fn sym(&mut self, table: usize, s: u8) -> Result<()> {
        self.freq[table][s as usize] += 1;
        Ok(())
    }
    fn raw(&mut self, _: u32, _: u32) {}
    fn restart(&mut self, _: u32) {}
}

/// Writes entropy-coded data with the given tables.
pub struct Writer<'a> {
    pub bits: BitWriter,
    pub tables: [Option<&'a EncTable>; 8],
}

impl Sink for Writer<'_> {
    fn sym(&mut self, table: usize, s: u8) -> Result<()> {
        let (len, code) = self
            .tables
            .get(table)
            .copied()
            .flatten()
            .map(|t| t.codes[s as usize])
            .unwrap_or((0, 0));
        if len == 0 {
            return Err(Error::Output(
                "JPEG writer: symbol missing from Huffman table".into(),
            ));
        }
        self.bits.put(code as u32, len as u32);
        Ok(())
    }
    fn raw(&mut self, v: u32, n: u32) {
        self.bits.put(v, n);
    }
    fn restart(&mut self, index: u32) {
        self.bits.marker(0xD0 + (index & 7) as u8);
    }
}

/// Magnitude category and the low bits that encode `v` (F.1.2.1).
fn category(v: i32) -> Result<(u32, u32)> {
    let a = v.unsigned_abs();
    let n = 32 - a.leading_zeros();
    if n > 15 {
        return Err(Error::Output("JPEG writer: coefficient too large".into()));
    }
    let bits = if v < 0 { (v - 1) as u32 } else { v as u32 };
    Ok((n, bits & ((1u32 << n) - 1)))
}

fn nbits(v: u32) -> u32 {
    32 - v.leading_zeros()
}

const MAX_CORR_BITS: usize = 1000;

struct Progress {
    eobrun: u32,
    /// Correction bits waiting for the pending EOB run (refinement scans).
    pending: Vec<u8>,
}

impl Progress {
    fn emit_eobrun<S: Sink>(&mut self, sink: &mut S, table: usize) -> Result<()> {
        if self.eobrun > 0 {
            let n = nbits(self.eobrun) - 1;
            sink.sym(table, (n << 4) as u8)?;
            if n > 0 {
                sink.raw(self.eobrun, n);
            }
            self.eobrun = 0;
            for &b in &self.pending {
                sink.raw(b as u32, 1);
            }
            self.pending.clear();
        }
        Ok(())
    }
}

/// Encodes one scan into `sink`.
pub fn encode<S: Sink>(
    sink: &mut S,
    geo: &Geometry,
    comps: &[Component],
    scan: &ScanHeader,
    restart: u16,
    progressive: bool,
) -> Result<()> {
    let kind = kind(scan, progressive);
    let (per, units) = mcus(geo, comps, scan);
    let dct: Vec<usize> = scan.comps.iter().map(|s| s.td as usize).collect();
    let act: Vec<usize> = scan.comps.iter().map(|s| 4 + s.ta as usize).collect();
    let mut pred = vec![0i32; scan.comps.len()];
    let mut prog = Progress {
        eobrun: 0,
        pending: Vec::new(),
    };
    let (ss, se, al) = (scan.ss as usize, scan.se as usize, scan.al as u32);
    let nmcu = units.len() / per;
    let mut rst = 0u32;
    let mut block_bits: Vec<u8> = Vec::new();
    let mut absv = [0u32; 64];
    for m in 0..nmcu {
        if restart > 0 && m > 0 && m % restart as usize == 0 {
            if matches!(kind, Kind::AcFirst | Kind::AcRefine) {
                prog.emit_eobrun(sink, act[0])?;
            }
            sink.restart(rst);
            rst += 1;
            pred.iter_mut().for_each(|p| *p = 0);
        }
        for &(si, off) in &units[m * per..(m + 1) * per] {
            let si = si as usize;
            let b = &comps[scan.comps[si].index].coefs[off..off + 64];
            match kind {
                Kind::Sequential => {
                    let v = b[0] as i32;
                    let (t, bits) = category(v - pred[si])?;
                    pred[si] = v;
                    sink.sym(dct[si], t as u8)?;
                    sink.raw(bits, t);
                    let mut run = 0u32;
                    for &z in &ZIGZAG[1..] {
                        let v = b[z] as i32;
                        if v == 0 {
                            run += 1;
                            continue;
                        }
                        while run > 15 {
                            sink.sym(act[si], 0xF0)?;
                            run -= 16;
                        }
                        let (t, bits) = category(v)?;
                        sink.sym(act[si], ((run << 4) | t) as u8)?;
                        sink.raw(bits, t);
                        run = 0;
                    }
                    if run > 0 {
                        sink.sym(act[si], 0)?;
                    }
                }
                Kind::DcFirst => {
                    let v = (b[0] as i32) >> al;
                    let (t, bits) = category(v - pred[si])?;
                    pred[si] = v;
                    sink.sym(dct[si], t as u8)?;
                    sink.raw(bits, t);
                }
                Kind::DcRefine => {
                    sink.raw(((b[0] as i32 >> al) & 1) as u32, 1);
                }
                Kind::AcFirst => {
                    let mut run = 0u32;
                    for &z in &ZIGZAG[ss..=se] {
                        let c = b[z] as i32;
                        let a = c.unsigned_abs() >> al;
                        if a == 0 {
                            run += 1;
                            continue;
                        }
                        prog.emit_eobrun(sink, act[si])?;
                        while run > 15 {
                            sink.sym(act[si], 0xF0)?;
                            run -= 16;
                        }
                        let t = nbits(a);
                        if t > 14 {
                            return Err(Error::Output("JPEG writer: coefficient too large".into()));
                        }
                        let bits = (if c < 0 { !a } else { a }) & ((1 << t) - 1);
                        sink.sym(act[si], ((run << 4) | t) as u8)?;
                        sink.raw(bits, t);
                        run = 0;
                    }
                    if run > 0 {
                        prog.eobrun += 1;
                        if prog.eobrun == 0x7FFF {
                            prog.emit_eobrun(sink, act[si])?;
                        }
                    }
                }
                Kind::AcRefine => {
                    let mut eob = 0usize;
                    for k in ss..=se {
                        let a = (b[ZIGZAG[k]] as i32).unsigned_abs() >> al;
                        absv[k] = a;
                        if a == 1 {
                            eob = k;
                        }
                    }
                    let mut run = 0u32;
                    block_bits.clear();
                    for k in ss..=se {
                        let a = absv[k];
                        if a == 0 {
                            run += 1;
                            continue;
                        }
                        while run > 15 && k <= eob {
                            prog.emit_eobrun(sink, act[si])?;
                            sink.sym(act[si], 0xF0)?;
                            run -= 16;
                            for &bit in &block_bits {
                                sink.raw(bit as u32, 1);
                            }
                            block_bits.clear();
                        }
                        if a > 1 {
                            block_bits.push((a & 1) as u8);
                            continue;
                        }
                        prog.emit_eobrun(sink, act[si])?;
                        sink.sym(act[si], ((run << 4) | 1) as u8)?;
                        sink.raw(if b[ZIGZAG[k]] < 0 { 0 } else { 1 }, 1);
                        for &bit in &block_bits {
                            sink.raw(bit as u32, 1);
                        }
                        block_bits.clear();
                        run = 0;
                    }
                    if run > 0 || !block_bits.is_empty() {
                        prog.eobrun += 1;
                        prog.pending.extend_from_slice(&block_bits);
                        if prog.eobrun == 0x7FFF || prog.pending.len() > MAX_CORR_BITS - 64 + 1 {
                            prog.emit_eobrun(sink, act[si])?;
                        }
                    }
                }
            }
        }
    }
    if matches!(kind, Kind::AcFirst | Kind::AcRefine) {
        prog.emit_eobrun(sink, act[0])?;
    }
    Ok(())
}
