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

    #[error("key not usable: {0}")]
    BadKey(String),

    /// The passphrase does not unlock this key. Also the answer for an empty passphrase
    /// on a protected key, so callers can try without one first.
    #[error("wrong passphrase for this key")]
    WrongPassphrase,

    /// The key file holds the public half of the encryption key but not its secret: a
    /// GnuPG stub, as left by a key moved to a hardware token or a partial export.
    #[error("this key's encryption secret is not in the file (it may live on a hardware key, or the export left it out)")]
    SecretNotInFile,

    #[error("the recipient key is unusable (low-order point)")]
    WeakRecipient,

    #[error("the payload is invalid: {0}")]
    BadPayload(String),

    #[error("embedding failed: {0}")]
    Embed(String),

    #[error("writing the output image failed: {0}")]
    Output(String),

    /// Pasted text with no hidden characters has a word that is not on the word list,
    /// so it cannot be StegPony word text. Carries the first such word, as written.
    #[error("\"{0}\" is not on StegPony's word list")]
    TextUnknownWord(String),

    /// The text has StegPony's hidden characters or words, but not as many as any
    /// StegPony text has: some were lost or added on the way.
    #[error("the hidden text is incomplete: characters or words were lost or added")]
    TextLength,

    /// Zero-width text needs a visible message with at least one word to sit in.
    #[error("the cover message needs at least one word")]
    TextCoverEmpty,

    #[error("key derivation failed: {0}")]
    Kdf(String),

    #[error("random number generator failure")]
    Rng,

    /// A key held elsewhere (for example on a hardware key) could not do its part:
    /// the device was removed, the PIN was refused or cancelled, or it reported an
    /// error. Unlike a failed reveal, this is reported, since nothing was tried.
    #[error("the key device failed: {0}")]
    KeyDevice(String),
}

pub type Result<T> = core::result::Result<T, Error>;
