//! Argon2id timing grid for choosing format v1's fixed parameters (planning Q2).
//!
//! Build it for a phone and run it there, since the slowest supported device is what
//! the parameters have to suit:
//!
//!     cargo ndk -t arm64-v8a build --release -p stegpony-core --example argon2_bench
//!     adb push target/aarch64-linux-android/release/examples/argon2_bench /data/local/tmp/
//!     adb shell /data/local/tmp/argon2_bench [cap_seconds] [p]
//!
//! Each cell is the median of three derivations after one warm-up. Cells whose first
//! run takes longer than the cap (default 6 s) are reported once and not repeated.
//!
//! `p` (default 1) is the Argon2id lane count. stegpony-core enables the argon2 crate's
//! `parallel` feature, so lanes run on separate threads.
//!
//! The derivation counts in the summary follow `envelope.rs` and `engine.rs`:
//! a passphrase hide runs Argon2id twice (locate key, content key), plus twice more for
//! a passphrase decoy; a reveal with one passphrase runs it once for the locate key and
//! once per slot whose head it opens, so 3 for a wrong passphrase, an image without a
//! payload, or a payload in the second slot, and 2 for a payload in the first.

use std::time::{Duration, Instant};

use argon2::{Algorithm, Argon2, Params, Version};
use stegpony_core::envelope::{ARGON2_M_KIB, ARGON2_P, ARGON2_T};

const MIB: &[u32] = &[16, 32, 64, 96, 128, 192, 256];
const PASSES: &[u32] = &[1, 2, 3, 4];

fn derive(m_kib: u32, t: u32, p: u32, salt: &[u8]) -> Duration {
    let params = Params::new(m_kib, t, p, Some(32)).expect("valid parameters");
    let a = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
    let mut out = [0u8; 32];
    let start = Instant::now();
    a.hash_password_into(b"correct horse battery staple", salt, &mut out)
        .expect("argon2id");
    let d = start.elapsed();
    std::hint::black_box(out);
    d
}

fn median(mut v: Vec<Duration>) -> Duration {
    v.sort();
    v[v.len() / 2]
}

fn secs(d: Duration) -> f64 {
    d.as_secs_f64()
}

fn main() {
    let mut args = std::env::args().skip(1);
    let cap: f64 = args.next().and_then(|a| a.parse().ok()).unwrap_or(6.0);
    let p: u32 = args.next().and_then(|a| a.parse().ok()).unwrap_or(1).max(1);
    let salt = *b"StegPony/v1/bench";
    let cores = std::thread::available_parallelism().map_or(0, |n| n.get());

    println!(
        "Argon2id, p = {p}, 32-byte output, {cores} cores visible. Current v1: m = {} MiB, t = {}, p = {}.",
        ARGON2_M_KIB / 1024,
        ARGON2_T,
        ARGON2_P
    );
    println!("Seconds per derivation (median of 3; * = single run, over the {cap} s cap).");
    println!();
    print!("{:>8}", "m \\ t");
    for t in PASSES {
        print!("{t:>9}");
    }
    println!();

    derive(16 * 1024, 1, p, &salt);

    let mut current = None;
    for &m in MIB {
        print!("{:>4} MiB", m);
        let mut over = false;
        for &t in PASSES {
            if over {
                print!("{:>9}", "-");
                continue;
            }
            let first = derive(m * 1024, t, p, &salt);
            let (d, mark) = if secs(first) > cap {
                over = true;
                (first, '*')
            } else {
                let runs = vec![
                    first,
                    derive(m * 1024, t, p, &salt),
                    derive(m * 1024, t, p, &salt),
                ];
                (median(runs), ' ')
            };
            if m * 1024 == ARGON2_M_KIB && t == ARGON2_T && p == ARGON2_P {
                current = Some(d);
            }
            print!("{:>8.2}{mark}", secs(d));
        }
        println!();
    }

    if let Some(d) = current {
        let one = secs(d);
        println!();
        println!("At the current v1 parameters ({one:.2} s per derivation), Argon2id alone costs:");
        for (what, runs) in [
            ("hide with a passphrase", 2.0),
            ("hide with a passphrase and a passphrase decoy", 4.0),
            ("reveal, payload in the first slot", 2.0),
            ("reveal, second slot, wrong key, or nothing", 3.0),
        ] {
            println!("  {what:<47}{:>6.2} s", runs * one);
        }
        println!("Image work (positions, costs, embedding) comes on top of these.");
    }
}
