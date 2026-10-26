//! Versioned writer settings, not part of the hidden-message format.
use super::Channel;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Headroom {
    pub low: u8,
    pub high: u8,
    pub max_rounds: u8,
    pub contraction_percent: u8,
    /// RGB tolerance used by the additional IDCT/chroma clipping check.
    pub decoder_guard: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ChannelProfile {
    pub channel: Channel,
    pub id: &'static str,
    pub revision: u32,
    pub max_long_edge: u32,
    /// Descriptive quality only; quantization tables below are authoritative.
    pub quality: u8,
    pub sampling: &'static str,
    /// Luma and chroma, natural row-major order, explicit 8-bit JPEG steps.
    pub quantization: [[u16; 64]; 2],
    pub headroom: Headroom,
    pub experimental: bool,
    /// Date of lab observations, not a production verification date.
    pub last_observed: &'static str,
    pub last_verified: Option<&'static str>,
    pub observed_scope: &'static str,
}

// Exact IJG quality-72 scaling of the Annex K tables: (base * 56 + 50) / 100.
// Store the resulting tables rather than inferring a channel from a quality label.
const TELEGRAM_QUANTIZATION: [[u16; 64]; 2] = [
    [
        9, 6, 6, 9, 13, 22, 29, 34, 7, 7, 8, 11, 15, 32, 34, 31, 8, 7, 9, 13, 22, 32, 39, 31, 8,
        10, 12, 16, 29, 49, 45, 35, 10, 12, 21, 31, 38, 61, 58, 43, 13, 20, 31, 36, 45, 58, 63, 52,
        27, 36, 44, 49, 58, 68, 67, 57, 40, 52, 53, 55, 63, 56, 58, 55,
    ],
    [
        10, 10, 13, 26, 55, 55, 55, 55, 10, 12, 15, 37, 55, 55, 55, 55, 13, 15, 31, 55, 55, 55, 55,
        55, 26, 37, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55,
        55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55, 55,
    ],
];

pub(super) const PROFILES: [ChannelProfile; 1] = [ChannelProfile {
    channel: Channel::TelegramPhotoV1,
    id: "telegram-photo-v1",
    revision: 1,
    max_long_edge: 1280,
    quality: 72,
    sampling: "4:2:0",
    quantization: TELEGRAM_QUANTIZATION,
    headroom: Headroom { low: 2, high: 253, max_rounds: 12, contraction_percent: 85, decoder_guard: 4 },
    experimental: true,
    last_observed: "2026-10-26",
    last_verified: None,
    observed_scope: "Telegram compressed photo, default settings, iPhone to Mac; Pillow/libjpeg lab preparation. Rust preparation and Android paths need delivery tests.",
}];
