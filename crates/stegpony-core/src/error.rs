use thiserror::Error;

/// Everything that can go wrong in the core. Reveal never reports *why* nothing was
/// found: a wrong secret and an image without a payload are the same answer.
#[derive(Debug, Error)]
pub enum Error {
    #[error("the cover image could not be read: {0}")]
    BadCover(String),

    #[error("this kind of image can't be used as a cover yet: {0}")]
    UnsupportedCover(String),

    #[error("the cover is too small for anything to be hidden in it")]
    CoverTooSmall,

    #[error(
        "the payload does not fit in this cover (needs {needed} bytes of room, has {available})"
    )]
    PayloadTooLarge { needed: usize, available: usize },

    #[error("not a valid age recipient or identity: {0}")]
    BadKey(String),

    #[error("the recipient key is unusable (low-order point)")]
    WeakRecipient,

    #[error("the payload is invalid: {0}")]
    BadPayload(String),

    #[error("embedding failed: {0}")]
    Embed(String),

    #[error("writing the output image failed: {0}")]
    Output(String),

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("random number generator failure")]
    Rng,
}

pub type Result<T> = core::result::Result<T, Error>;
