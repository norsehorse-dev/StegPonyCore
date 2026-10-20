//! StegPony core: hides encrypted payloads in images so that, without the secret,
//! there is nothing to find. See FORMAT.md for the byte-level specification.
//!
//! Phase A covers the envelope (passphrase and age X25519 public keys), the two-slot
//! layout with decoy, syndrome-trellis embedding, and Lossless (PNG) mode. Phase B adds
//! the pure-Rust JPEG coefficient codec and native carrier in [`jpeg::carrier`].

pub mod engine;
pub mod envelope;
pub mod error;
pub mod jpeg;
pub mod keys;
pub mod lossless;
pub mod pgp;
pub mod prp;
pub mod stc;

#[cfg(test)]
mod vectors;

pub use engine::{Capacity, Detectability};
pub use envelope::{HideKey, Payload, RevealKey};
pub use error::{Error, Result};
pub use keys::{Identity, Recipient};

/// Format version this build writes and reads.
pub const FORMAT_VERSION: u32 = 1;
