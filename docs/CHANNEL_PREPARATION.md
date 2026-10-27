# Experimental Telegram cover preparation

`stegpony_core::channel` prepares a fresh cover before native JPEG embedding. The
hidden-message format, native carrier and reveal API are unchanged. This operation
re-encodes pixels, so it must happen **before hiding**, never on a stego image.

## API

```rust
use stegpony_core::channel::{self, Channel};

let prepared = channel::prepare(&input_bytes, Channel::TelegramPhotoV1)?;
let capacity = stegpony_core::jpeg::carrier::capacity(&prepared.jpeg)?;
// Pass prepared.jpeg to the existing native JPEG hide API.
```

`channel::profiles()` returns the core-owned profiles. Their implementation lives
in `crates/stegpony-core/src/channel/profiles.rs`; applications choose an enum value
rather than supplying their own JPEG quality, tables or headroom parameters.
`PreparedCover` contains the JPEG bytes and a `PreparationReport`: profile ID and
revision, upright source dimensions, output dimensions, distinct 16x16 areas
adjusted, and adjustment rounds.

The UniFFI surface exports `channel_profiles()` and
`Cover::prepare_for_channel(Channel::TelegramPhotoV1)`. Its result contains a new
`Cover` object plus the report. The source object and its capacity/fit caches are
unchanged. In Kotlin the call is `source.prepareForChannel(Channel.TELEGRAM_PHOTO_V1)`;
use `result.cover.capacity(ImageMode.JPEG)`, `fit`, and `hide` on the returned object.
All image work is blocking and must run off the main thread.

`PreparationFailed` is an explicit core/binding error when the bounded headroom
procedure cannot meet its criterion. A prepared cover can still be too small for
embedding; the existing capacity/fit/hide APIs decide that separately.

## Profile and pipeline

The initial `telegram-photo-v1`, revision 1 profile specifies:

- 1280 maximum long edge, preserved aspect ratio, no enlargement or MCU crop.
- Baseline JPEG, 4:2:0, explicit natural-order IJG q72 luma/chroma tables.
- EXIF orientation applied to JPEG pixels before resizing. JPEG color/EXIF markers
  are retained only during decoding; output carries JFIF without private metadata.
- JPEG and opaque 8-bit PNG input, including gray and fully opaque alpha channels.
  Palette/16-bit/animated PNG, transparent pixels and CMYK/YCCK JPEG are refused.
  RGB values are not ICC color-managed; use ordinary SDR/sRGB phone covers.
- Separable integer area resampling, fixed-point RGB-to-YCbCr conversion, 2x2 box
  chroma sampling, Q14 orthonormal DCT, and the existing entropy writer. No new
  dependency, C library or platform image API is used. Partial MCU edges replicate
  their last sample. Output uses optimized Huffman tables, not the camera's tables.
- For a JPEG the coefficient parser accepts but zune cannot decode directly (such
  as the progressive/restart fixture), a coefficient-preserving sequential rewrite
  is decoded instead. Original color and orientation markers survive this step.

Headroom follows the lab's local adjustment strategy: find 16x16 areas with decoded
samples at or below 2 or at or above 253; pull the input RGB pixels 15% toward their
per-channel area means, clamped to 40..215; re-encode and check again. At most 12
adjustments are allowed, and the last adjustment is checked before returning an
error. The returned bytes are the exact encoding that passed the final checks.

A zune-only clipping check missed clipping visible in independent libjpeg tests.
The Rust profile therefore also checks a fixed-point IDCT reconstruction with
nearest and 3:1 horizontal, vertical and bilinear chroma interpolation, plus a
four-level RGB rounding margin. Correlated Cb/Cr samples are retained. This can
adjust more areas than the Python lab and is not a model of every possible decoder.
Only flagged areas are changed; counts are reported for later visual/timing review.

## Evidence and limits

The profile is experimental. `last_observed` is 2026-10-26. `last_verified` is absent.
Its scope is a Telegram compressed photo **sent from an iPhone, picked from Telegram's
photo gallery**, in standard quality, downloaded on a Mac. On that path the Pillow lab
covers and one Rust-prepared cover made by StegPony Android came back with every AC
coefficient intact.

Two paths do not work and no preparation can fix them:

- **Attach > File** (and likely sharing into Telegram from another app): the image is
  re-encoded at IJG q87 with an sRGB ICC profile, so every coefficient is rescaled.
- **Android as the sender**: Android Telegram re-encodes even gallery photos at IJG q87.
  Covers pre-matched to those tables still lost 8 to 10% of luma AC coefficients to
  evenly signed plus or minus 1 errors (a pixel round trip with added noise).

Android senders, like WhatsApp and Signal, need an error-tolerant mode. More scenes,
larger payloads and a repeat after an app update are still required before
`last_verified` is set.

A successful preparation means the local cover passed its clipping checks. It does
not mean it will survive Telegram, that a stego image cannot introduce clipping,
or that a particular payload is sufficiently inconspicuous. Existing native JPEG
ratings are not a measured Telegram-path rating. WhatsApp and Signal remain outside
this preparation profile; they require error-tolerant embedding.

## Checks and lab use

```
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace --release
cargo build --locked --release --example jpeg_tool
python3 tools/check_channel_prep.py
```

The independent checker needs Pillow, NumPy and jpeglib, as does the existing JPEG
oracle. It compares Rust-prepared covers with Pillow's complete IJG q72 tables,
checks dimensions and sampling, inspects clipping with libjpeg, and verifies that
libjpeg and the Rust reader see identical coefficients. CI runs this checker.
Extra camera JPEG paths can be supplied for additional local validation.

To prepare a photo with the Rust path for the next real-channel experiment:

```
cargo run --locked --release --example jpeg_tool -- prepare-telegram INPUT.jpg PREPARED.jpg
```

The example writes an unembedded cover to a new file and prints its preparation
report; it refuses to overwrite an existing file. Embed
both slots with the existing JPEG mode, send through the recorded Telegram photo
path, then compare coefficients and reveal both secrets from the actual download.
Collect reports across scenes, payload sizes and sender/receiver devices before
promoting a profile or offering a survival claim. Preparation itself uses no keys.
