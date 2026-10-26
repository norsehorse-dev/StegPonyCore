//! JPEG coefficient I/O in pure Rust: reads a JPEG's quantized DCT coefficients and
//! writes them back without ever going through pixels.
//!
//! Coefficient I/O handles the entropy layer (T.81 Annex F and G) without pixels.
//! Separate internal encoding/headroom helpers support channel cover preparation.
//! Everything else in the file (APPn, COM, DQT, DRI, the frame header) is kept byte for byte. When every symbol the new coefficients need exists in
//! the file's own Huffman tables, those tables are kept and a file whose coefficients
//! did not change comes back identical. When embedding needs a symbol the tables lack
//! (an optimized table only lists the symbols its image used), every scan gets fresh
//! optimal tables instead, written in a DHT segment just before its SOS.
//!
//! Supported: 8-bit baseline and extended sequential Huffman (SOF0, SOF1) and
//! progressive Huffman (SOF2), 1 to 4 components, any sampling factors, restart
//! intervals. Refused: arithmetic coding, lossless, hierarchical, 12-bit, DNL.

pub mod carrier;
mod costs;
pub(crate) mod encode;
pub(crate) mod headroom;
mod huffman;
mod metadata;
mod scan;

use huffman::{BitReader, BitWriter, DecTable, EncTable, HuffSpec};

use crate::error::{Error, Result};

pub use scan::ZIGZAG;

fn bad(msg: &str) -> Error {
    Error::BadCover(format!("JPEG: {msg}"))
}

fn unsupported(msg: &str) -> Error {
    Error::UnsupportedCover(format!("JPEG: {msg}"))
}

/// How the frame is coded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FrameKind {
    /// SOF0.
    Baseline,
    /// SOF1, 8-bit.
    ExtendedSequential,
    /// SOF2.
    Progressive,
}

/// The EXIF orientation (TIFF values 1 to 8) recorded in a JPEG file, read from its
/// marker segments without decoding. `None` when there is none or it is unreadable.
pub fn exif_orientation(bytes: &[u8]) -> Option<u16> {
    metadata::file_orientation(bytes)
}

/// One color component and its quantized coefficients.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Component {
    pub id: u8,
    pub h: u8,
    pub v: u8,
    /// Quantization table id.
    pub tq: u8,
    /// Quantization table in natural (row-major) order, as in effect when the
    /// component's first scan began.
    pub quant: [u16; 64],
    /// Blocks that carry image content.
    pub width_blocks: usize,
    pub height_blocks: usize,
    /// Allocated grid, padded out to whole MCUs. Blocks past `width_blocks` /
    /// `height_blocks` are the padding an interleaved scan codes; they are kept as read
    /// so an unchanged file round-trips exactly.
    pub(crate) grid_w: usize,
    pub(crate) grid_h: usize,
    /// `grid_w * grid_h` blocks of 64 coefficients, natural order within a block.
    pub coefs: Vec<i16>,
}

impl Component {
    pub fn block(&self, bx: usize, by: usize) -> &[i16] {
        let o = (by * self.grid_w + bx) * 64;
        &self.coefs[o..o + 64]
    }

    pub fn block_mut(&mut self, bx: usize, by: usize) -> &mut [i16] {
        let o = (by * self.grid_w + bx) * 64;
        &mut self.coefs[o..o + 64]
    }

    /// Index into `coefs` of coefficient `k` (natural order) of block `(bx, by)`.
    pub fn index(&self, bx: usize, by: usize, k: usize) -> usize {
        (by * self.grid_w + bx) * 64 + k
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Geometry {
    pub mcu_cols: usize,
    pub mcu_rows: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScanComp {
    /// Index into the frame's components.
    pub index: usize,
    pub td: u8,
    pub ta: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct ScanHeader {
    pub comps: Vec<ScanComp>,
    pub ss: u8,
    pub se: u8,
    pub ah: u8,
    pub al: u8,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum Segment {
    /// A marker segment kept as read (marker code and payload without the length).
    Marker { code: u8, data: Vec<u8> },
    /// SOS: the header as read; entropy-coded data is regenerated on write.
    Scan {
        header: ScanHeader,
        data: Vec<u8>,
        restart: u16,
    },
}

/// A parsed JPEG: its coefficients plus everything needed to write it back.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Jpeg {
    pub kind: FrameKind,
    pub width: u16,
    pub height: u16,
    pub components: Vec<Component>,
    geo: Geometry,
    segments: Vec<Segment>,
    /// Bytes after EOI (for example an Ultra HDR gain map). Written back as is.
    pub trailing: Vec<u8>,
}

const SOI: u8 = 0xD8;
const EOI: u8 = 0xD9;
const SOS: u8 = 0xDA;
const DHT: u8 = 0xC4;
const DQT: u8 = 0xDB;
const DRI: u8 = 0xDD;

fn u16be(d: &[u8], i: usize) -> u16 {
    u16::from_be_bytes([d[i], d[i + 1]])
}

impl Jpeg {
    pub fn parse(bytes: &[u8]) -> Result<Jpeg> {
        if bytes.len() < 4 || bytes[0] != 0xFF || bytes[1] != SOI {
            return Err(bad("not a JPEG"));
        }
        let mut pos = 2usize;
        let mut segments = Vec::new();
        let mut frame: Option<(FrameKind, u16, u16, Vec<Component>, Geometry)> = None;
        let mut quant: [Option<[u16; 64]>; 4] = [None; 4];
        let mut quant_bound = [false; 4];
        let mut dc: [Option<DecTable>; 4] = [None, None, None, None];
        let mut ac: [Option<DecTable>; 4] = [None, None, None, None];
        let mut restart = 0u16;
        let mut pending: Option<u8> = None;
        let mut scans = 0usize;
        loop {
            let code = match pending.take() {
                Some(c) => c,
                None => {
                    if pos >= bytes.len() || bytes[pos] != 0xFF {
                        return Err(bad("expected a marker"));
                    }
                    while pos < bytes.len() && bytes[pos] == 0xFF {
                        pos += 1;
                    }
                    let c = *bytes.get(pos).ok_or_else(|| bad("truncated"))?;
                    pos += 1;
                    c
                }
            };
            if code == EOI {
                break;
            }
            let standalone = matches!(code, 0x01 | 0xD0..=0xD7 | SOI);
            if standalone {
                return Err(bad("unexpected marker"));
            }
            if pos + 2 > bytes.len() {
                return Err(bad("truncated segment"));
            }
            let len = u16be(bytes, pos) as usize;
            if len < 2 || pos + len > bytes.len() {
                return Err(bad("bad segment length"));
            }
            let data = &bytes[pos + 2..pos + len];
            pos += len;
            match code {
                0xE0..=0xEF | 0xFE => {}
                DQT => {
                    let mut d = data;
                    while !d.is_empty() {
                        let pq = d[0] >> 4;
                        let tq = (d[0] & 15) as usize;
                        let n = if pq == 0 { 64 } else { 128 };
                        if pq > 1 || tq > 3 || d.len() < 1 + n {
                            return Err(bad("bad DQT segment"));
                        }
                        let mut t = [0u16; 64];
                        for (k, &z) in ZIGZAG.iter().enumerate() {
                            t[z] = if pq == 0 {
                                d[1 + k] as u16
                            } else {
                                u16be(d, 1 + 2 * k)
                            };
                        }
                        quant[tq] = Some(t);
                        d = &d[1 + n..];
                    }
                }
                DHT => {
                    for (class, id, spec) in HuffSpec::parse_dht(data)? {
                        let t = DecTable::new(&spec)?;
                        if class == 0 {
                            dc[id as usize] = Some(t);
                        } else {
                            ac[id as usize] = Some(t);
                        }
                    }
                }
                DRI => {
                    if data.len() != 2 {
                        return Err(bad("bad DRI segment"));
                    }
                    restart = u16be(data, 0);
                }
                0xC0..=0xC2 => {
                    if frame.is_some() {
                        return Err(bad("more than one frame"));
                    }
                    frame = Some(parse_frame(code, data)?);
                }
                0xC3 | 0xC5..=0xC7 => return Err(unsupported("lossless or hierarchical")),
                0xC9..=0xCF => return Err(unsupported("arithmetic coding")),
                0xDC => return Err(unsupported("DNL marker")),
                SOS => {
                    let (kind, _, _, comps, geo) =
                        frame.as_mut().ok_or_else(|| bad("scan before frame"))?;
                    let header = parse_scan(data, comps, *kind)?;
                    for s in &header.comps {
                        let c = &mut comps[s.index];
                        let tq = c.tq as usize;
                        if !quant_bound[s.index] {
                            c.quant = quant[tq].ok_or_else(|| bad("missing quantization table"))?;
                            quant_bound[s.index] = true;
                        }
                    }
                    let mut r = BitReader::new(bytes, pos);
                    let next = scan::decode(
                        &mut r,
                        geo,
                        comps,
                        &header,
                        restart,
                        &scan::Tables { dc: &dc, ac: &ac },
                        *kind == FrameKind::Progressive,
                    )?;
                    pos = r.pos;
                    pending = Some(next);
                    scans += 1;
                    segments.push(Segment::Scan {
                        header,
                        data: data.to_vec(),
                        restart,
                    });
                    continue;
                }
                _ => return Err(unsupported("unknown marker")),
            }
            segments.push(Segment::Marker {
                code,
                data: data.to_vec(),
            });
        }
        let (kind, height, width, components, geo) = frame.ok_or_else(|| bad("no frame"))?;
        if scans == 0 {
            return Err(bad("no scans"));
        }
        if quant_bound.iter().take(components.len()).any(|&b| !b) {
            return Err(bad("a component never appears in a scan"));
        }
        Ok(Jpeg {
            kind,
            width,
            height,
            components,
            geo,
            segments,
            trailing: bytes[pos..].to_vec(),
        })
    }

    /// Normalizes supported coefficients to one sequential scan for pixel decoders
    /// that cannot handle a particular progressive/restart scan arrangement.
    /// Keeps color/EXIF markers for the decoding step; this is not stego output.
    pub(crate) fn into_sequential(mut self) -> Result<Vec<u8>> {
        let mut dqt = Vec::new();
        for (i, c) in self.components.iter_mut().enumerate() {
            c.tq = i as u8;
            let wide = c.quant.iter().any(|&q| q > 255);
            dqt.push((if wide { 0x10 } else { 0 }) | c.tq);
            for &k in &ZIGZAG {
                if wide {
                    dqt.extend_from_slice(&c.quant[k].to_be_bytes());
                } else {
                    dqt.push(c.quant[k] as u8);
                }
            }
        }
        let wide = self
            .components
            .iter()
            .any(|c| c.quant.iter().any(|&q| q > 255));
        self.kind = if wide {
            FrameKind::ExtendedSequential
        } else {
            FrameKind::Baseline
        };
        let mut sof = vec![8];
        sof.extend_from_slice(&self.height.to_be_bytes());
        sof.extend_from_slice(&self.width.to_be_bytes());
        sof.push(self.components.len() as u8);
        let mut sos = vec![self.components.len() as u8];
        let mut comps = Vec::new();
        for (i, c) in self.components.iter().enumerate() {
            sof.extend_from_slice(&[c.id, (c.h << 4) | c.v, c.tq]);
            let table = if i == 0 { 0 } else { 1 };
            sos.extend_from_slice(&[c.id, (table << 4) | table]);
            comps.push(ScanComp {
                index: i,
                td: table,
                ta: table,
            });
        }
        sos.extend_from_slice(&[0, 63, 0]);
        self.segments.retain(|s| {
            matches!(
                s,
                Segment::Marker {
                    code: 0xe0..=0xef | 0xfe,
                    ..
                }
            )
        });
        self.segments.extend([
            Segment::Marker {
                code: DQT,
                data: dqt,
            },
            Segment::Marker {
                code: if wide { 0xc1 } else { 0xc0 },
                data: sof,
            },
            Segment::Scan {
                header: ScanHeader {
                    comps,
                    ss: 0,
                    se: 63,
                    ah: 0,
                    al: 0,
                },
                data: sos,
                restart: 0,
            },
        ]);
        self.trailing.clear();
        self.write()
    }

    /// Writes the file back, re-encoding every scan from the current coefficients.
    pub fn write(&self) -> Result<Vec<u8>> {
        let progressive = self.kind == FrameKind::Progressive;
        // Count the symbols every scan needs.
        let mut freqs = Vec::new();
        for seg in &self.segments {
            if let Segment::Scan {
                header, restart, ..
            } = seg
            {
                let mut c = scan::Counter::new();
                scan::encode(
                    &mut c,
                    &self.geo,
                    &self.components,
                    header,
                    *restart,
                    progressive,
                )?;
                freqs.push(c.freq);
            }
        }
        let keep = self.tables_cover(&freqs)?;

        let mut out = vec![0xFF, SOI];
        let mut tables: [Option<EncTable>; 8] = Default::default();
        let mut si = 0usize;
        for seg in &self.segments {
            match seg {
                Segment::Marker { code, data } => {
                    if *code == DHT {
                        if !keep {
                            continue;
                        }
                        for (class, id, spec) in HuffSpec::parse_dht(data)? {
                            tables[class as usize * 4 + id as usize] = Some(EncTable::new(&spec)?);
                        }
                    }
                    put_segment(&mut out, *code, data)?;
                }
                Segment::Scan {
                    header,
                    data,
                    restart,
                } => {
                    let freq = &freqs[si];
                    si += 1;
                    if !keep {
                        tables = Default::default();
                        let mut dht = Vec::new();
                        for t in used_tables(header, progressive) {
                            let spec = HuffSpec::optimal(&freq[t]);
                            spec.write_dht((t / 4) as u8, (t % 4) as u8, &mut dht);
                            tables[t] = Some(EncTable::new(&spec)?);
                        }
                        put_segment(&mut out, DHT, &dht)?;
                    }
                    put_segment(&mut out, SOS, data)?;
                    let mut w = scan::Writer {
                        bits: BitWriter::new(out),
                        tables: std::array::from_fn(|i| tables[i].as_ref()),
                    };
                    scan::encode(
                        &mut w,
                        &self.geo,
                        &self.components,
                        header,
                        *restart,
                        progressive,
                    )?;
                    w.bits.flush();
                    out = w.bits.out;
                }
            }
        }
        out.extend_from_slice(&[0xFF, EOI]);
        out.extend_from_slice(&self.trailing);
        Ok(out)
    }

    /// True when the file's own tables hold every symbol every scan needs.
    fn tables_cover(&self, freqs: &[Vec<[u64; 256]>]) -> Result<bool> {
        let progressive = self.kind == FrameKind::Progressive;
        let mut tables: [Option<EncTable>; 8] = Default::default();
        let mut si = 0usize;
        for seg in &self.segments {
            match seg {
                Segment::Marker { code: DHT, data } => {
                    for (class, id, spec) in HuffSpec::parse_dht(data)? {
                        tables[class as usize * 4 + id as usize] = Some(EncTable::new(&spec)?);
                    }
                }
                Segment::Marker { .. } => {}
                Segment::Scan { header, .. } => {
                    let freq = &freqs[si];
                    si += 1;
                    for t in used_tables(header, progressive) {
                        match &tables[t] {
                            Some(e) if e.covers(&freq[t]) => {}
                            _ => return Ok(false),
                        }
                    }
                }
            }
        }
        Ok(true)
    }

    /// Drops APPn and COM segments (EXIF, XMP, ICC, maker data, comments) and anything
    /// after EOI. JFIF (APP0 starting `JFIF\0`) is kept when `keep_jfif` is set.
    pub fn strip_metadata(&mut self, keep_jfif: bool) {
        self.segments.retain(|s| match s {
            Segment::Marker { code: 0xE0, data } => keep_jfif && data.starts_with(b"JFIF\0"),
            Segment::Marker {
                code: 0xE1..=0xEF | 0xFE,
                ..
            } => false,
            _ => true,
        });
        self.trailing.clear();
    }

    /// Privacy scrub with ScrubPony's default policy (see [`metadata`]): keeps JFIF
    /// without its thumbnail, ICC profile chunks and Adobe APP14, reduces EXIF to an
    /// orientation-only block (or nothing when the image is upright), and drops every
    /// other APPn, comments and anything after EOI.
    pub fn strip_private_metadata(&mut self) {
        let mut orientation_done = false;
        let segments = std::mem::take(&mut self.segments);
        for s in segments {
            match s {
                Segment::Marker { code, data } if matches!(code, 0xE0..=0xEF | 0xFE) => {
                    match metadata::action(code, &data, &mut orientation_done) {
                        metadata::Action::Keep => {
                            self.segments.push(Segment::Marker { code, data })
                        }
                        metadata::Action::Replace(data) => {
                            self.segments.push(Segment::Marker { code, data })
                        }
                        metadata::Action::Drop => {}
                    }
                }
                other => self.segments.push(other),
            }
        }
        self.trailing.clear();
    }

    /// APPn and COM segments as (marker code, payload), in order, for inspection and tests.
    pub fn marker_segments(&self) -> Vec<(u8, &[u8])> {
        self.segments
            .iter()
            .filter_map(|s| match s {
                Segment::Marker { code, data } if matches!(code, 0xE0..=0xEF | 0xFE) => {
                    Some((*code, data.as_slice()))
                }
                _ => None,
            })
            .collect()
    }

    /// Marker codes of the kept segments, in order, for inspection and tests.
    pub fn marker_codes(&self) -> Vec<u8> {
        self.segments
            .iter()
            .map(|s| match s {
                Segment::Marker { code, .. } => *code,
                Segment::Scan { .. } => SOS,
            })
            .collect()
    }

    pub fn scan_count(&self) -> usize {
        self.segments
            .iter()
            .filter(|s| matches!(s, Segment::Scan { .. }))
            .count()
    }
}

fn used_tables(scan: &ScanHeader, progressive: bool) -> Vec<usize> {
    let mut v = Vec::new();
    let dc = !progressive || (scan.ss == 0 && scan.ah == 0);
    let ac = !progressive || scan.ss > 0;
    for c in &scan.comps {
        if dc {
            v.push(c.td as usize);
        }
        if ac {
            v.push(4 + c.ta as usize);
        }
    }
    v.sort_unstable();
    v.dedup();
    v
}

fn put_segment(out: &mut Vec<u8>, code: u8, data: &[u8]) -> Result<()> {
    let len =
        u16::try_from(data.len() + 2).map_err(|_| Error::Output("JPEG segment too long".into()))?;
    out.extend_from_slice(&[0xFF, code]);
    out.extend_from_slice(&len.to_be_bytes());
    out.extend_from_slice(data);
    Ok(())
}

fn parse_frame(code: u8, d: &[u8]) -> Result<(FrameKind, u16, u16, Vec<Component>, Geometry)> {
    let kind = match code {
        0xC0 => FrameKind::Baseline,
        0xC1 => FrameKind::ExtendedSequential,
        _ => FrameKind::Progressive,
    };
    if d.len() < 6 {
        return Err(bad("short frame header"));
    }
    if d[0] != 8 {
        return Err(unsupported("only 8-bit samples"));
    }
    let height = u16be(d, 1);
    let width = u16be(d, 3);
    let n = d[5] as usize;
    if height == 0 {
        return Err(unsupported("DNL marker"));
    }
    if width == 0 || n == 0 || n > 4 || d.len() != 6 + 3 * n {
        return Err(bad("bad frame header"));
    }
    let mut comps = Vec::with_capacity(n);
    for i in 0..n {
        let id = d[6 + 3 * i];
        let h = d[7 + 3 * i] >> 4;
        let v = d[7 + 3 * i] & 15;
        let tq = d[8 + 3 * i];
        if !(1..=4).contains(&h) || !(1..=4).contains(&v) || tq > 3 {
            return Err(bad("bad component in frame header"));
        }
        if comps.iter().any(|c: &Component| c.id == id) {
            return Err(bad("duplicate component id"));
        }
        comps.push(Component {
            id,
            h,
            v,
            tq,
            quant: [0; 64],
            width_blocks: 0,
            height_blocks: 0,
            grid_w: 0,
            grid_h: 0,
            coefs: Vec::new(),
        });
    }
    let hmax = comps.iter().map(|c| c.h).max().unwrap() as usize;
    let vmax = comps.iter().map(|c| c.v).max().unwrap() as usize;
    let (w, h) = (width as usize, height as usize);
    let geo = Geometry {
        mcu_cols: w.div_ceil(8 * hmax),
        mcu_rows: h.div_ceil(8 * vmax),
    };
    let blocks: usize = comps
        .iter()
        .map(|c| geo.mcu_cols * c.h as usize * geo.mcu_rows * c.v as usize)
        .sum();
    // 128 bytes of coefficients per block; refuse anything over 512 MiB of them (a
    // 108 MP 4:2:0 photo needs about 330 MiB).
    if blocks > (1 << 29) / 128 {
        return Err(unsupported("image too large"));
    }
    for c in &mut comps {
        let cw = (w * c.h as usize).div_ceil(hmax);
        let ch = (h * c.v as usize).div_ceil(vmax);
        c.width_blocks = cw.div_ceil(8);
        c.height_blocks = ch.div_ceil(8);
        if n == 1 {
            c.grid_w = c.width_blocks;
            c.grid_h = c.height_blocks;
        } else {
            c.grid_w = geo.mcu_cols * c.h as usize;
            c.grid_h = geo.mcu_rows * c.v as usize;
        }
        c.coefs = vec![0i16; c.grid_w * c.grid_h * 64];
    }
    Ok((kind, height, width, comps, geo))
}

fn parse_scan(d: &[u8], comps: &[Component], kind: FrameKind) -> Result<ScanHeader> {
    if d.is_empty() {
        return Err(bad("short scan header"));
    }
    let n = d[0] as usize;
    if n == 0 || n > 4 || d.len() != 1 + 2 * n + 3 {
        return Err(bad("bad scan header"));
    }
    let mut sc = Vec::with_capacity(n);
    for i in 0..n {
        let id = d[1 + 2 * i];
        let index = comps
            .iter()
            .position(|c| c.id == id)
            .ok_or_else(|| bad("scan names an unknown component"))?;
        if sc.iter().any(|s: &ScanComp| s.index == index) {
            return Err(bad("component twice in one scan"));
        }
        let td = d[2 + 2 * i] >> 4;
        let ta = d[2 + 2 * i] & 15;
        let max = if kind == FrameKind::Baseline { 1 } else { 3 };
        if td > max || ta > max {
            return Err(bad("bad Huffman table id in scan"));
        }
        sc.push(ScanComp { index, td, ta });
    }
    let ss = d[1 + 2 * n];
    let se = d[2 + 2 * n];
    let ah = d[3 + 2 * n] >> 4;
    let al = d[3 + 2 * n] & 15;
    if kind == FrameKind::Progressive {
        let ok = if ss == 0 {
            se == 0
        } else {
            se >= ss && se <= 63 && n == 1
        } && al <= 13
            && (ah == 0 || ah == al + 1);
        if !ok {
            return Err(bad("bad progressive scan parameters"));
        }
    } else if ss != 0 || se != 63 || ah != 0 || al != 0 {
        return Err(bad("bad sequential scan parameters"));
    }
    if n > 1 {
        let blocks: usize = sc
            .iter()
            .map(|s| comps[s.index].h as usize * comps[s.index].v as usize)
            .sum();
        if blocks > 10 {
            return Err(bad("too many blocks per MCU"));
        }
    }
    Ok(ScanHeader {
        comps: sc,
        ss,
        se,
        ah,
        al,
    })
}

#[cfg(test)]
mod sequential_tests {
    use super::*;
    #[test]
    fn normalization_preserves_content_coefficients_tables_and_color_markers() {
        for name in [
            "progressive_restart.jpg",
            "progressive_mozjpeg.jpg",
            "sampling_mixed.jpg",
            "gray.jpg",
            "cmyk.jpg",
        ] {
            let bytes = std::fs::read(format!(
                "{}/tests/fixtures/jpeg/{name}",
                env!("CARGO_MANIFEST_DIR")
            ))
            .unwrap();
            let j = Jpeg::parse(&bytes).unwrap();
            let normalized = j.clone().into_sequential().unwrap();
            let back = Jpeg::parse(&normalized).unwrap();
            assert_eq!((j.width, j.height), (back.width, back.height));
            assert_eq!(j.marker_segments(), back.marker_segments());
            for (a, b) in j.components.iter().zip(&back.components) {
                assert_eq!((a.id, a.h, a.v, a.quant), (b.id, b.h, b.v, b.quant));
                for by in 0..a.height_blocks {
                    for bx in 0..a.width_blocks {
                        assert_eq!(a.block(bx, by), b.block(bx, by), "{name}/{bx}/{by}");
                    }
                }
            }
        }
    }
}
