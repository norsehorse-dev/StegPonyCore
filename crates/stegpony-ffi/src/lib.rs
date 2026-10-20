//! UniFFI surface over stegpony-core for the StegPony apps.
//!
//! The apps hand over file bytes, never decoded bitmaps: platform decoders apply color
//! management and resampling that destroy the low-order bits the format lives in.
//! Every call here is blocking and some take seconds (a 12-megapixel hide takes
//! several), so callers run them off the main thread.
//!
//! Text carriers ([`hide_text`], [`reveal_text`]) take and return strings: StegPony
//! words, or invisible characters inside a message the user writes.
//!
//! Hardware keys come in through [`KeyDevice`], a foreign trait the app implements
//! over its OpenPGP card layer; the core asks it for one X25519 operation per slot it
//! tries and never sees the secret.
//!
//! Generate bindings with:
//! `cargo run -p stegpony-ffi --features cli --bin uniffi-bindgen -- generate --library target/debug/libstegpony_ffi.so --language kotlin --out-dir bindings-out`

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};

use rand_core::OsRng;
use stegpony_core::envelope::{bucket_for, bucket_size, NUM_BUCKETS, TAG_LEN};
use stegpony_core::jpeg::{carrier, Jpeg};
use stegpony_core::lossless::{self, LosslessCover, SourceFormat};
use stegpony_core::{engine, pgp, text, HideKey, Identity, KeyAgreement, Recipient, RevealKey};
use zeroize::Zeroizing;

uniffi::setup_scaffolding!();

/// Everything that can go wrong. Reveal never fails for a wrong secret: finding
/// nothing is `None`, the same answer as an image with nothing in it.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum StegError {
    /// The image could not be read.
    #[error("{detail}")]
    BadCover { detail: String },
    /// The image is readable but this kind can't be used (or not in this mode).
    #[error("{detail}")]
    UnsupportedCover { detail: String },
    #[error("the cover is too small for anything to be hidden in it")]
    CoverTooSmall,
    #[error("the message does not fit in this cover")]
    PayloadTooLarge,
    /// A key string or key file could not be used; `detail` says why.
    #[error("{detail}")]
    BadKey { detail: String },
    /// The passphrase does not unlock this OpenPGP key (also the answer for an empty
    /// passphrase on a protected key).
    #[error("wrong passphrase for this key")]
    WrongPassphrase,
    /// The OpenPGP file has the encryption key's public half only (a GnuPG stub, as
    /// for a key on a hardware token).
    #[error("this key's secret is not in the file; it may live on a hardware key")]
    SecretNotInFile,
    #[error("this recipient key can't be used")]
    WeakRecipient,
    /// The user cancelled a hardware-key operation (PIN prompt, tap).
    #[error("the hardware key operation was cancelled")]
    DeviceCancelled,
    /// A hardware key failed: removed, PIN refused, or an error from the card.
    #[error("{detail}")]
    KeyDevice { detail: String },
    /// Pasted text with no hidden characters has a word that is not on StegPony's word
    /// list, so it is not StegPony text. `word` is the first such word, as written
    /// (autocorrect may have changed it).
    #[error("\"{word}\" is not on StegPony's word list")]
    NotStegText { word: String },
    /// The text has StegPony's hidden characters or words, but some were lost or added
    /// on the way (an app stripped characters, or words were edited).
    #[error("the hidden text is incomplete")]
    TextIncomplete,
    /// Zero-width text needs a visible message with at least one word.
    #[error("the cover message needs at least one word")]
    CoverTextEmpty,
    /// Anything else (a payload too odd to frame, an output encoding failure).
    #[error("{detail}")]
    Failed { detail: String },
}

impl From<stegpony_core::Error> for StegError {
    fn from(e: stegpony_core::Error) -> Self {
        use stegpony_core::Error as E;
        let detail = e.to_string();
        match e {
            E::BadCover(_) => StegError::BadCover { detail },
            E::UnsupportedCover(_) => StegError::UnsupportedCover { detail },
            E::CoverTooSmall => StegError::CoverTooSmall,
            E::PayloadTooLarge { .. } => StegError::PayloadTooLarge,
            E::BadKey(_) => StegError::BadKey { detail },
            E::WrongPassphrase => StegError::WrongPassphrase,
            E::SecretNotInFile => StegError::SecretNotInFile,
            E::WeakRecipient => StegError::WeakRecipient,
            E::KeyDevice(m) => StegError::KeyDevice { detail: m },
            E::TextUnknownWord(word) => StegError::NotStegText { word },
            E::TextLength => StegError::TextIncomplete,
            E::TextCoverEmpty => StegError::CoverTextEmpty,
            _ => StegError::Failed { detail },
        }
    }
}

type Result<T> = std::result::Result<T, StegError>;

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImageFormat {
    Png,
    Jpeg,
}

/// How to hide. Lossless takes a PNG or JPEG cover and always writes a PNG; Jpeg
/// takes a JPEG cover and writes a JPEG with the camera's own compression intact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum ImageMode {
    Lossless,
    Jpeg,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Detectability {
    Low,
    Medium,
    High,
}

impl From<stegpony_core::Detectability> for Detectability {
    fn from(d: stegpony_core::Detectability) -> Self {
        match d {
            stegpony_core::Detectability::Low => Detectability::Low,
            stegpony_core::Detectability::Medium => Detectability::Medium,
            stegpony_core::Detectability::High => Detectability::High,
        }
    }
}

/// What gets hidden.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum Payload {
    Text {
        text: String,
    },
    File {
        name: String,
        mime: String,
        data: Vec<u8>,
    },
}

impl From<Payload> for stegpony_core::Payload {
    fn from(p: Payload) -> Self {
        match p {
            Payload::Text { text } => stegpony_core::Payload::Text(text),
            Payload::File { name, mime, data } => stegpony_core::Payload::File { name, mime, data },
        }
    }
}

impl From<stegpony_core::Payload> for Payload {
    fn from(p: stegpony_core::Payload) -> Self {
        match p {
            stegpony_core::Payload::Text(text) => Payload::Text { text },
            stegpony_core::Payload::File { name, mime, data } => Payload::File { name, mime, data },
        }
    }
}

/// The secret a payload is hidden under: a passphrase, or a recipient's `age1...`
/// public key (OpenPGP keys arrive as one through [`pgp_public_key`]).
#[derive(Clone, uniffi::Enum)]
pub enum HideSecret {
    Passphrase { passphrase: String },
    Recipient { recipient: String },
}

impl HideSecret {
    fn into_core(self) -> Result<HideKey> {
        Ok(match self {
            HideSecret::Passphrase { passphrase } => {
                let p = Zeroizing::new(passphrase);
                if p.is_empty() {
                    return Err(StegError::BadKey {
                        detail: "the passphrase is empty".into(),
                    });
                }
                HideKey::Passphrase(p)
            }
            HideSecret::Recipient { recipient } => {
                HideKey::Recipient(Recipient::parse(&recipient)?)
            }
        })
    }
}

/// A secret to try when revealing: a passphrase, or an `AGE-SECRET-KEY-1...` identity
/// (OpenPGP secret keys arrive as one through [`pgp_secret_key`]).
#[derive(Clone, uniffi::Enum)]
pub enum RevealSecret {
    Passphrase { passphrase: String },
    Identity { identity: String },
}

impl RevealSecret {
    fn into_core(self) -> Result<RevealKey> {
        Ok(match self {
            RevealSecret::Passphrase { passphrase } => {
                RevealKey::Passphrase(Zeroizing::new(passphrase))
            }
            RevealSecret::Identity { identity } => {
                let identity = Zeroizing::new(identity);
                RevealKey::Identity(Identity::parse(&identity)?)
            }
        })
    }
}

/// A second payload for the second slot, revealed by its own secret.
#[derive(Clone, uniffi::Record)]
pub struct Decoy {
    pub payload: Payload,
    pub secret: HideSecret,
}

#[derive(Clone, uniffi::Record)]
pub struct HideOutput {
    /// The image to share, byte for byte. Any re-encoding destroys the payload.
    pub image: Vec<u8>,
    pub format: ImageFormat,
    pub detectability: Detectability,
}

/// How much a cover holds in one mode, in payload bytes (see [`text_payload_len`]
/// and [`file_payload_len`]). All zero when nothing fits.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct CoverCapacity {
    /// Largest payload that fits.
    pub max_payload_bytes: u64,
    /// Largest text message that fits, in UTF-8 bytes.
    pub max_text_bytes: u64,
    /// Largest payload still rated Low, and Medium; 0 if none is.
    pub low_payload_bytes: u64,
    pub medium_payload_bytes: u64,
}

/// Whether a payload (and decoy) of the given sizes fits, and how it would rate.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct Fit {
    pub fits: bool,
    /// None when it doesn't fit.
    pub detectability: Option<Detectability>,
}

/// Capacity and the rating of every bucket, for one cover in one mode.
struct Analysis {
    max_bucket: Option<usize>,
    max_text_bytes: usize,
    ratings: Vec<Detectability>,
}

impl Analysis {
    fn largest_rated(&self, at_most: Detectability) -> u64 {
        let rank = |d: Detectability| d as u8;
        self.max_bucket
            .and_then(|m| {
                (0..=m)
                    .rev()
                    .find(|&k| rank(self.ratings[k]) <= rank(at_most))
            })
            .map_or(0, |k| (bucket_size(k) - TAG_LEN) as u64)
    }
}

/// A cover image, read once. Capacity and ratings are worked out on first use per
/// mode and kept, so a capacity meter can ask on every keystroke.
#[derive(uniffi::Object)]
pub struct Cover {
    bytes: Vec<u8>,
    format: ImageFormat,
    analyses: Mutex<[Option<Arc<Analysis>>; 2]>,
}

impl Cover {
    fn analysis(&self, mode: ImageMode) -> Result<Arc<Analysis>> {
        let slot = mode as usize;
        if let Some(a) = &self.analyses.lock().unwrap()[slot] {
            return Ok(a.clone());
        }
        let (capacity, ratings) = match mode {
            ImageMode::Jpeg => {
                self.require_jpeg()?;
                let cover = carrier::JpegCover::new(Jpeg::parse(&self.bytes)?);
                let ratings = carrier::ratings(&cover)
                    .into_iter()
                    .map(Into::into)
                    .collect();
                (engine::capacity(&cover), ratings)
            }
            ImageMode::Lossless => {
                let (raster, _) = lossless::decode_cover(&self.bytes)?;
                let cover = LosslessCover::new(raster);
                let ratings = (0..NUM_BUCKETS)
                    .map(|k| engine::detectability(&cover, k).into())
                    .collect();
                (engine::capacity(&cover), ratings)
            }
        };
        let a = Arc::new(Analysis {
            max_bucket: capacity.max_bucket,
            max_text_bytes: capacity.max_text_bytes,
            ratings,
        });
        self.analyses.lock().unwrap()[slot] = Some(a.clone());
        Ok(a)
    }

    fn require_jpeg(&self) -> Result<()> {
        if self.format != ImageFormat::Jpeg {
            return Err(StegError::UnsupportedCover {
                detail: "JPEG mode needs a JPEG cover; use Lossless for a PNG".into(),
            });
        }
        Ok(())
    }
}

#[uniffi::export]
impl Cover {
    /// Takes the cover file's bytes. Fails for anything but PNG and JPEG; the image
    /// itself is read when first needed.
    #[uniffi::constructor]
    pub fn new(bytes: Vec<u8>) -> Result<Arc<Self>> {
        let format = match lossless::sniff(&bytes) {
            Some(SourceFormat::Png) => ImageFormat::Png,
            Some(SourceFormat::Jpeg) => ImageFormat::Jpeg,
            None => {
                return Err(StegError::UnsupportedCover {
                    detail: "not a PNG or JPEG image".into(),
                })
            }
        };
        Ok(Arc::new(Cover {
            bytes,
            format,
            analyses: Mutex::new([None, None]),
        }))
    }

    pub fn format(&self) -> ImageFormat {
        self.format
    }

    pub fn capacity(&self, mode: ImageMode) -> Result<CoverCapacity> {
        let a = self.analysis(mode)?;
        Ok(CoverCapacity {
            max_payload_bytes: a
                .max_bucket
                .map_or(0, |k| (bucket_size(k) - TAG_LEN) as u64),
            max_text_bytes: a.max_text_bytes as u64,
            low_payload_bytes: a.largest_rated(Detectability::Low),
            medium_payload_bytes: a.largest_rated(Detectability::Medium),
        })
    }

    /// Payload sizes come from [`text_payload_len`] and [`file_payload_len`]. Both
    /// slots are padded to the larger one's size.
    pub fn fit(&self, mode: ImageMode, payload_len: u64, decoy_len: Option<u64>) -> Result<Fit> {
        let a = self.analysis(mode)?;
        let bucket = bucket_for(payload_len as usize, 0)
            .and_then(|b| decoy_len.map_or(Ok(b), |d| bucket_for(d as usize, b)));
        Ok(match (bucket, a.max_bucket) {
            (Ok(b), Some(m)) if b <= m => Fit {
                fits: true,
                detectability: Some(a.ratings[b]),
            },
            _ => Fit {
                fits: false,
                detectability: None,
            },
        })
    }

    /// Hides `payload` under `secret`, and `decoy` under its own secret if given
    /// (otherwise the second slot gets random filler). In Jpeg mode, location and
    /// other private metadata are removed unless `keep_metadata` is set; Lossless
    /// output never carries metadata and ignores it.
    pub fn hide(
        &self,
        mode: ImageMode,
        payload: Payload,
        secret: HideSecret,
        decoy: Option<Decoy>,
        keep_metadata: bool,
    ) -> Result<HideOutput> {
        let payload: stegpony_core::Payload = payload.into();
        let key = secret.into_core()?;
        let decoy = match decoy {
            Some(d) => Some((
                stegpony_core::Payload::from(d.payload),
                d.secret.into_core()?,
            )),
            None => None,
        };
        let decoy = decoy.as_ref().map(|(p, k)| (p, k));
        Ok(match mode {
            ImageMode::Jpeg => {
                self.require_jpeg()?;
                let out = carrier::hide(
                    &self.bytes,
                    (&payload, &key),
                    decoy,
                    keep_metadata,
                    &mut OsRng,
                )?;
                HideOutput {
                    image: out.jpeg,
                    format: ImageFormat::Jpeg,
                    detectability: out.detectability.into(),
                }
            }
            ImageMode::Lossless => {
                let out = lossless::hide(&self.bytes, (&payload, &key), decoy, &mut OsRng)?;
                HideOutput {
                    image: out.png,
                    format: ImageFormat::Png,
                    detectability: out.detectability.into(),
                }
            }
        })
    }
}

/// Size of a text payload, for [`Cover::fit`] and [`text_fit`].
#[uniffi::export]
pub fn text_payload_len(text: String) -> u64 {
    stegpony_core::Payload::Text(text).framed_len() as u64
}

/// Size of a file payload of `size` bytes, for [`Cover::fit`] and [`text_fit`], without handing the
/// file over.
#[uniffi::export]
pub fn file_payload_len(name: String, mime: String, size: u64) -> u64 {
    let framing = stegpony_core::Payload::File {
        name,
        mime,
        data: Vec::new(),
    }
    .framed_len() as u64;
    framing + size
}

/// Why a hardware key could not do its part.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum DeviceError {
    /// The user backed out (PIN prompt dismissed, tap abandoned).
    #[error("cancelled")]
    Cancelled,
    #[error("{reason}")]
    Failed { reason: String },
}

impl From<uniffi::UnexpectedUniFFICallbackError> for DeviceError {
    fn from(e: uniffi::UnexpectedUniFFICallbackError) -> Self {
        DeviceError::Failed { reason: e.reason }
    }
}

/// A Curve25519 key whose secret lives on a hardware key, implemented by the app over
/// its OpenPGP card layer. A reveal calls [`KeyDevice::agree`] at most twice per
/// device (once per slot), on the thread that called [`reveal`].
#[uniffi::export(with_foreign)]
pub trait KeyDevice: Send + Sync {
    /// The device key's recipient as an `age1...` string (from [`recipient_from_x25519`]
    /// for a key read off a card).
    fn recipient(&self) -> String;

    /// X25519 of the device's secret with `point`, a 32-byte little-endian Montgomery
    /// u-coordinate: on an OpenPGP card, PSO:DECIPHER with the point in the cipher DO.
    /// Returns the 32-byte shared secret.
    fn agree(&self, point: Vec<u8>) -> std::result::Result<Vec<u8>, DeviceError>;
}

struct DeviceAdapter {
    device: Arc<dyn KeyDevice>,
    recipient: Recipient,
    cancelled: Arc<AtomicBool>,
}

impl KeyAgreement for DeviceAdapter {
    fn recipient(&self) -> Recipient {
        self.recipient
    }

    fn agree(&self, point: &[u8; 32]) -> std::result::Result<[u8; 32], String> {
        match self.device.agree(point.to_vec()) {
            Ok(shared) => {
                let shared = Zeroizing::new(shared);
                <[u8; 32]>::try_from(shared.as_slice())
                    .map_err(|_| "the key returned a shared secret of the wrong length".into())
            }
            Err(DeviceError::Cancelled) => {
                self.cancelled.store(true, Ordering::SeqCst);
                Err("cancelled".into())
            }
            Err(DeviceError::Failed { reason }) => Err(reason),
        }
    }
}

/// The core keys for a reveal: secrets first, then devices. The flag is set when the
/// user cancels a device operation, so the error can say so.
fn reveal_keys(
    secrets: Vec<RevealSecret>,
    devices: Vec<Arc<dyn KeyDevice>>,
) -> Result<(Vec<RevealKey>, Arc<AtomicBool>)> {
    let cancelled = Arc::new(AtomicBool::new(false));
    let mut keys = Vec::with_capacity(secrets.len() + devices.len());
    for s in secrets {
        keys.push(s.into_core()?);
    }
    for device in devices {
        let recipient = Recipient::parse(&device.recipient())?;
        keys.push(RevealKey::External(Arc::new(DeviceAdapter {
            device,
            recipient,
            cancelled: cancelled.clone(),
        })));
    }
    Ok((keys, cancelled))
}

fn device_error(e: stegpony_core::Error, cancelled: &AtomicBool) -> StegError {
    match e {
        stegpony_core::Error::KeyDevice(_) if cancelled.load(Ordering::SeqCst) => {
            StegError::DeviceCancelled
        }
        e => e.into(),
    }
}

/// Looks for a payload in a PNG or JPEG that any of the secrets or devices opens.
/// Secrets are tried in both slots first, then devices, so a hardware key is only
/// asked when nothing else worked. `None` means nothing was found.
#[uniffi::export]
pub fn reveal(
    image: Vec<u8>,
    secrets: Vec<RevealSecret>,
    devices: Vec<Arc<dyn KeyDevice>>,
) -> Result<Option<Payload>> {
    let (keys, cancelled) = reveal_keys(secrets, devices)?;
    let found = match lossless::sniff(&image) {
        Some(SourceFormat::Png) => lossless::reveal(&image, &keys),
        Some(SourceFormat::Jpeg) => carrier::reveal(&image, &keys),
        None => {
            return Err(StegError::UnsupportedCover {
                detail: "not a PNG or JPEG image".into(),
            })
        }
    };
    found
        .map(|p| p.map(Into::into))
        .map_err(|e| device_error(e, &cancelled))
}

/// Which text carrier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Enum)]
pub enum TextMode {
    /// A run of words from StegPony's English list. Reads as word salad.
    Words,
    /// Invisible characters inside a message the user writes. Weak: many apps strip
    /// them, and any tool that looks finds them.
    ZeroWidth,
}

impl From<TextMode> for text::TextMode {
    fn from(m: TextMode) -> Self {
        match m {
            TextMode::Words => text::TextMode::Dictionary,
            TextMode::ZeroWidth => text::TextMode::ZeroWidth,
        }
    }
}

impl From<text::TextMode> for TextMode {
    fn from(m: text::TextMode) -> Self {
        match m {
            text::TextMode::Dictionary => TextMode::Words,
            text::TextMode::ZeroWidth => TextMode::ZeroWidth,
        }
    }
}

/// How big the hidden text will be for a payload (and decoy) of the given sizes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TextFit {
    /// False when the payload is over the text limit ([`TextFit::max_payload_bytes`]).
    pub fits: bool,
    /// Words (Words mode) or invisible characters (ZeroWidth mode); 0 when it doesn't
    /// fit.
    pub size: u64,
    /// Largest payload StegPony writes into text, and the largest text message.
    pub max_payload_bytes: u64,
    pub max_text_bytes: u64,
    /// Largest payload that keeps the output at its current size, for "N more bytes
    /// before it grows"; 0 when it doesn't fit.
    pub bucket_payload_bytes: u64,
}

/// Payload sizes come from [`text_payload_len`] and [`file_payload_len`].
#[uniffi::export]
pub fn text_fit(mode: TextMode, payload_len: u64, decoy_len: Option<u64>) -> TextFit {
    let max_payload_bytes = (bucket_size(text::MAX_TEXT_BUCKET) - TAG_LEN) as u64;
    let max_text_bytes = text::max_text_bytes() as u64;
    let payload_len = usize::try_from(payload_len).unwrap_or(usize::MAX);
    let decoy_len = decoy_len.map(|d| usize::try_from(d).unwrap_or(usize::MAX));
    match text::bucket_for_text(payload_len, decoy_len) {
        Ok(k) => TextFit {
            fits: true,
            size: text::symbols_for(mode.into(), k) as u64,
            max_payload_bytes,
            max_text_bytes,
            bucket_payload_bytes: (bucket_size(k) - TAG_LEN) as u64,
        },
        Err(_) => TextFit {
            fits: false,
            size: 0,
            max_payload_bytes,
            max_text_bytes,
            bucket_payload_bytes: 0,
        },
    }
}

/// Hides `payload` in text: StegPony words, or invisible characters inside `cover`
/// (ignored in Words mode). The decoy works as for images.
#[uniffi::export]
pub fn hide_text(
    mode: TextMode,
    cover: String,
    payload: Payload,
    secret: HideSecret,
    decoy: Option<Decoy>,
) -> Result<String> {
    let payload: stegpony_core::Payload = payload.into();
    let key = secret.into_core()?;
    let decoy = match decoy {
        Some(d) => Some((
            stegpony_core::Payload::from(d.payload),
            d.secret.into_core()?,
        )),
        None => None,
    };
    let decoy = decoy.as_ref().map(|(p, k)| (p, k));
    Ok(text::hide(
        mode.into(),
        &cover,
        (&payload, &key),
        decoy,
        &mut OsRng,
    )?)
}

/// What [`reveal_text`] found. `mode` says what kind of StegPony text it was, also
/// when no secret opened it.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct TextReveal {
    pub payload: Option<Payload>,
    pub mode: TextMode,
}

/// Looks for a payload in pasted text, with secrets tried before devices as in
/// [`reveal`]. Text that cannot be StegPony text at all is an error
/// ([`StegError::NotStegText`], [`StegError::TextIncomplete`]); StegPony text that no
/// secret opens has no payload.
#[uniffi::export]
pub fn reveal_text(
    text: String,
    secrets: Vec<RevealSecret>,
    devices: Vec<Arc<dyn KeyDevice>>,
) -> Result<TextReveal> {
    let (keys, cancelled) = reveal_keys(secrets, devices)?;
    match text::reveal(&text, &keys) {
        Ok(text::TextFound::Payload(p, m)) => Ok(TextReveal {
            payload: Some(p.into()),
            mode: m.into(),
        }),
        Ok(text::TextFound::Nothing(m)) => Ok(TextReveal {
            payload: None,
            mode: m.into(),
        }),
        Err(e) => Err(device_error(e, &cancelled)),
    }
}

/// An identity (secret key) and its recipient (public key), as age strings.
#[derive(Clone, uniffi::Record)]
pub struct KeyPair {
    /// `AGE-SECRET-KEY-1...`; store it encrypted.
    pub identity: String,
    /// `age1...`; share it.
    pub recipient: String,
}

fn key_pair(id: &Identity) -> KeyPair {
    KeyPair {
        identity: id.to_age_string(),
        recipient: id.recipient().to_age_string(),
    }
}

/// A new identity, compatible with age's X25519 keys.
#[uniffi::export]
pub fn generate_identity() -> KeyPair {
    key_pair(&Identity::generate(&mut OsRng))
}

/// Checks an `AGE-SECRET-KEY-1...` string and gives its recipient.
#[uniffi::export]
pub fn identity_key_pair(identity: String) -> Result<KeyPair> {
    let identity = Zeroizing::new(identity);
    Ok(key_pair(&Identity::parse(&identity)?))
}

/// Every identity in an age identity file (comments and blank lines skipped).
#[uniffi::export]
pub fn parse_identity_file(contents: String) -> Result<Vec<KeyPair>> {
    let contents = Zeroizing::new(contents);
    Ok(Identity::parse_file(&contents)?
        .iter()
        .map(key_pair)
        .collect())
}

/// Checks an `age1...` recipient string and gives it back in canonical form.
#[uniffi::export]
pub fn parse_recipient(recipient: String) -> Result<String> {
    Ok(Recipient::parse(&recipient)?.to_age_string())
}

/// The `age1...` recipient of a raw X25519 public key, such as the encryption key
/// read off an OpenPGP card: 32 bytes, or 33 with OpenPGP's 0x40 prefix.
#[uniffi::export]
pub fn recipient_from_x25519(public_key: Vec<u8>) -> Result<String> {
    let raw = match public_key.as_slice() {
        [0x40, rest @ ..] if rest.len() == 32 => rest,
        other => other,
    };
    let bytes: [u8; 32] = raw.try_into().map_err(|_| StegError::BadKey {
        detail: "an X25519 public key is 32 bytes".into(),
    })?;
    Ok(Recipient::from_bytes(bytes).to_age_string())
}

/// What was found in an OpenPGP key.
#[derive(Clone, Debug, PartialEq, Eq, uniffi::Record)]
pub struct PgpKeyInfo {
    /// The Curve25519 encryption subkey as an `age1...` recipient.
    pub recipient: String,
    /// Upper-case hex, for showing to the user.
    pub primary_fingerprint: String,
    pub subkey_fingerprint: String,
    /// As written in the key, not verified.
    pub user_ids: Vec<String>,
}

impl From<pgp::PgpKey> for PgpKeyInfo {
    fn from(k: pgp::PgpKey) -> Self {
        PgpKeyInfo {
            recipient: k.recipient.to_age_string(),
            primary_fingerprint: k.primary_fingerprint,
            subkey_fingerprint: k.subkey_fingerprint,
            user_ids: k.user_ids,
        }
    }
}

#[derive(Clone, uniffi::Record)]
pub struct PgpSecretKey {
    /// The encryption subkey's secret as an `AGE-SECRET-KEY-1...` identity; store it
    /// encrypted.
    pub identity: String,
    pub info: PgpKeyInfo,
}

/// Reads a Curve25519 OpenPGP public key (or the public half of a secret key),
/// armored or binary.
#[uniffi::export]
pub fn pgp_public_key(key: Vec<u8>) -> Result<PgpKeyInfo> {
    Ok(pgp::recipient_from_pgp(&key)?.into())
}

/// Unlocks a Curve25519 OpenPGP secret key. Try an empty passphrase first: an
/// unprotected key opens with it, and a protected one answers
/// [`StegError::WrongPassphrase`].
#[uniffi::export]
pub fn pgp_secret_key(key: Vec<u8>, passphrase: String) -> Result<PgpSecretKey> {
    let key = Zeroizing::new(key);
    let passphrase = Zeroizing::new(passphrase);
    let (id, info) = pgp::identity_from_pgp(&key, &passphrase)?;
    Ok(PgpSecretKey {
        identity: id.to_age_string(),
        info: info.into(),
    })
}

/// The image format version this build reads and writes.
#[uniffi::export]
pub fn format_version() -> u32 {
    stegpony_core::FORMAT_VERSION
}

/// This core's version.
#[uniffi::export]
pub fn core_version() -> String {
    env!("CARGO_PKG_VERSION").into()
}
