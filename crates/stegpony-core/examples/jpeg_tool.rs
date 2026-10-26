//! Test helper for the JPEG coefficient codec, driven by tools/check_jpeg.py.
//!
//!   jpeg_tool info <in.jpg>
//!   jpeg_tool roundtrip <in.jpg> <out.jpg>      parse and write back unchanged
//!   jpeg_tool dump <in.jpg> <out.bin>           coefficients, see coef_bytes()
//!   jpeg_tool perturb <in.jpg> <out.jpg> <seed> <count>
//!       changes <count> AC coefficients of real blocks by ±1 (zeros included), so the
//!       writer usually has to rebuild its Huffman tables, then writes the result
//!
//! Dump layout: for each component in frame order, every real block in raster order,
//! 64 coefficients in natural order, i16 little-endian.

use std::env;
use std::fs;
use std::process::ExitCode;

use stegpony_core::jpeg::Jpeg;

fn coef_bytes(j: &Jpeg) -> Vec<u8> {
    let mut out = Vec::new();
    for c in &j.components {
        for by in 0..c.height_blocks {
            for bx in 0..c.width_blocks {
                for &v in c.block(bx, by) {
                    out.extend_from_slice(&v.to_le_bytes());
                }
            }
        }
    }
    out
}

fn splitmix(state: &mut u64) -> u64 {
    *state = state.wrapping_add(0x9e37_79b9_7f4a_7c15);
    let mut z = *state;
    z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
    z ^ (z >> 31)
}

fn run(args: &[String]) -> Result<(), String> {
    let read = |p: &str| -> Result<Jpeg, String> {
        let b = fs::read(p).map_err(|e| format!("{p}: {e}"))?;
        Jpeg::parse(&b).map_err(|e| format!("{p}: {e}"))
    };
    match args.first().map(String::as_str) {
        Some("prepare-telegram") if args.len() == 3 => {
            let bytes = fs::read(&args[1]).map_err(|e| e.to_string())?;
            let prepared = stegpony_core::channel::prepare(
                &bytes,
                stegpony_core::channel::Channel::TelegramPhotoV1,
            )
            .map_err(|e| e.to_string())?;
            let mut file = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&args[2])
                .map_err(|e| format!("new output {}: {e}", args[2]))?;
            std::io::Write::write_all(&mut file, &prepared.jpeg).map_err(|e| e.to_string())?;
            println!("{:?}", prepared.report);
        }
        Some("info") if args.len() == 2 => {
            let j = read(&args[1])?;
            println!(
                "{:?} {}x{} scans={} markers={:02x?} trailing={}",
                j.kind,
                j.width,
                j.height,
                j.scan_count(),
                j.marker_codes(),
                j.trailing.len()
            );
            for c in &j.components {
                println!(
                    "  id={} {}x{} tq={} blocks={}x{} q0={}",
                    c.id, c.h, c.v, c.tq, c.width_blocks, c.height_blocks, c.quant[0]
                );
            }
        }
        Some("roundtrip") if args.len() == 3 => {
            let original = fs::read(&args[1]).map_err(|e| e.to_string())?;
            let j = Jpeg::parse(&original).map_err(|e| e.to_string())?;
            let out = j.write().map_err(|e| e.to_string())?;
            fs::write(&args[2], &out).map_err(|e| e.to_string())?;
            println!(
                "{}",
                if out == original {
                    "identical"
                } else {
                    "different"
                }
            );
        }
        Some("dump") if args.len() == 3 => {
            let j = read(&args[1])?;
            fs::write(&args[2], coef_bytes(&j)).map_err(|e| e.to_string())?;
        }
        Some("perturb") if args.len() == 5 => {
            let mut j = read(&args[1])?;
            let mut state: u64 = args[3].parse().map_err(|_| "bad seed")?;
            let count: usize = args[4].parse().map_err(|_| "bad count")?;
            for _ in 0..count {
                let ci = (splitmix(&mut state) % j.components.len() as u64) as usize;
                let c = &mut j.components[ci];
                let bx = (splitmix(&mut state) % c.width_blocks as u64) as usize;
                let by = (splitmix(&mut state) % c.height_blocks as u64) as usize;
                let k = 1 + (splitmix(&mut state) % 63) as usize;
                let up = splitmix(&mut state) & 1 == 1;
                let v = &mut c.block_mut(bx, by)[k];
                *v = if (*v >= 1023 || !up) && *v > -1023 {
                    *v - 1
                } else {
                    *v + 1
                };
            }
            let out = j.write().map_err(|e| e.to_string())?;
            fs::write(&args[2], &out).map_err(|e| e.to_string())?;
            let back = Jpeg::parse(&out).map_err(|e| format!("re-read: {e}"))?;
            if coef_bytes(&back) != coef_bytes(&j) {
                return Err("re-read coefficients differ from what was written".into());
            }
        }
        _ => {
            return Err("usage: jpeg_tool info|roundtrip|dump|perturb|prepare-telegram ...".into())
        }
    }
    Ok(())
}

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("{e}");
            ExitCode::FAILURE
        }
    }
}
