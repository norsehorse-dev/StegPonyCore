# StegPony format, version 1

This is the byte-level specification for what StegPony writes into a carrier. Any implementation that follows it must produce output that the reference implementation in `crates/stegpony-core` reveals, and the other way round. Status: draft (envelope, slot layout, Lossless and native JPEG carriers). Survive-messenger and text carriers get their own sections as they land.

Design rule: every bit written into a carrier is indistinguishable from random without the secret. There is no magic number, no version field, no length in the clear and no KDF parameters in the clear. Format versions are found by trial, newest first.

Notation: `||` is concatenation, integers are little-endian, `HKDF` is HKDF-SHA256 (RFC 5869), `Argon2id` is Argon2 version 0x13 (RFC 9106) with a 32-byte output, strings are ASCII byte strings without a terminator.

## 1. Constants

| Name | Value |
|---|---|
| Argon2id memory | 131072 KiB |
| Argon2id iterations | 3 |
| Argon2id parallelism | 4 |
| `LOCATE_SALT` | `StegPony/v1/locate` |
| `PK_LOCATE_SALT` | `StegPony/v1/pk-locate` |
| `INFO_LOCATE` | `StegPony/v1/locate` |
| `INFO_BODY` | `StegPony/v1/body` |
| `INFO_PRP` | `StegPony/v1/prp` |
| AEAD | ChaCha20-Poly1305 (RFC 8439), 12-byte all-zero nonce, empty associated data |

The all-zero nonce is safe because every body key is used exactly once: it is derived from a fresh random salt (passphrase) or a fresh ephemeral key (public key).

## 2. Payload framing and buckets

The plaintext inside the AEAD is:

```
kind      u8      1 = text, 2 = file
data_len  u32
if kind == 2:
  name_len  u16
  name      name_len bytes, UTF-8
  mime_len  u16
  mime      mime_len bytes, UTF-8
data      data_len bytes (UTF-8 for text)
padding   zero bytes up to bucket_size - 16
```

The ciphertext body (plaintext plus the 16-byte tag) is exactly `bucket_size(k)` bytes for a bucket index `k` in `0..37`:

```
bucket_size(k) = (64 << (k / 2)) * (k odd ? 3/2 : 1)
             = 64, 96, 128, 192, 256, 384, ... 16 MiB
```

A writer picks the smallest bucket that holds the framed payload. With a decoy, both payloads use the larger of their two buckets.

Passphrases are normalized to Unicode NFC and encoded as UTF-8 before use.

## 3. Envelope

Each envelope has a locate key (used only to find positions), a head, and a body.

### 3.1 Passphrase

```
locate   = Argon2id(passphrase, LOCATE_SALT)
salt     = 16 random bytes
content  = Argon2id(passphrase, salt)
okm      = HKDF(salt = none, ikm = content, info = INFO_BODY, length = 36)
key      = okm[0..32]
mask     = okm[32..36]
head     = salt || (u32(k) XOR mask)                      20 bytes
body     = ChaCha20-Poly1305(key, nonce = 0, padded plaintext)
```

### 3.2 Public key

Keys are X25519 and use age's encodings: a recipient is Bech32 (not Bech32m) with HRP `age`, an identity is Bech32 with HRP `age-secret-key-`, 32 data bytes each.

```
locate   = HKDF(salt = PK_LOCATE_SALT, ikm = recipient, info = INFO_LOCATE, length = 32)
eph      = 32 random bytes, retried until it has a representative
repr     = Elligator2 representative of the torsion-dirty point for eph
shared   = X25519(eph, recipient)                   reject if all zero
okm      = HKDF(salt = repr || recipient, ikm = shared, info = INFO_BODY, length = 36)
head     = repr || (u32(k) XOR okm[32..36])                36 bytes
body     = ChaCha20-Poly1305(okm[0..32], nonce = 0, padded plaintext)
```

The representative follows the `Randomized` variant of the Tor Project's `curve25519-elligator2` crate: the public point is `clamp(eph)·B + T`, with `T` a low-order point selected by the three low bits of `eph[0]` (which clamping clears, so the recipient's clamped scalar removes `T` again), mapped through the inverse of Elligator 2 with the least-square-root convention, and the two top bits of the representative filled from a random tweak byte. A reader maps the representative back with those two bits masked off, and computes `shared = X25519(identity, point)`.

Without the torsion component every decoded point would lie in the prime-order subgroup, which random strings do only one time in eight. Without the tweak the top two bits would always be zero.

### 3.3 Filler

A slot with nothing in it carries a filler: a random 32-byte locate key, a random 20-byte head, and a random body the size of the bucket in use. It is written exactly like a passphrase envelope and is indistinguishable from one.

## 4. Slots and embedding

A carrier exposes elements numbered `0..T`. Each element belongs to slot 0, slot 1, or neither, and has a parity bit that the writer can flip at some cost. Membership and usability must not depend on anything embedding changes.

Every image carries two envelopes, one per slot: the payload and a decoy, or the payload and a filler. Which slot gets which is a fair coin.

### 4.1 Positions

For slot `s` and locate key `L`:

```
prp_key = HKDF-Expand(prk = L, info = INFO_PRP || u8(s), length = 16)
```

The permutation of `0..T` is a 4-round balanced Feistel network:

- `bits` = the bit length of `T - 1`, at least 2, rounded up to even; `half = bits / 2`, `mask = 2^half - 1`.
- On input `x`: `l = x >> half`, `r = x & mask`. For round `i` in 0..4: `f = SipHash-2-4(prp_key, u8(i) || u64(r)) & mask`, then `(l, r) = (r, l XOR f)`. Output `(l << half) | r`.
- Cycle walking: apply the network repeatedly until the result is below `T`.

The slot's element sequence is `π(0), π(1), ...` filtered to the elements of slot `s`, truncated to `n = min(count(s), 2,000,000)` elements.

### 4.2 Head and body regions

```
head_bits   = 8 * head length (160 passphrase, 288 public key)
head_region = max(n / 16, 8 * head_bits)
body_region = n - head_region
```

The first `head_region` elements carry the head, the rest carry the body. A slot needs `n >= 2 * head_region`. A body of bucket `k` needs `8 * bucket_size(k) <= body_region / 2`.

A reader tries each slot with each of its keys: derive the positions, read the head, derive the body key, unmask `k` (reject if `k >= 37` or the body does not fit), read the body, open the AEAD. A wrong key and an empty slot both end in a failed tag.

### 4.3 Syndrome-trellis code

Bits are taken from bytes least significant bit first. To place `m` bits in `n` elements:

- Constraint height `h = 7`.
- `wmax = ceil(n / m)`. The submatrix columns are `c_j` for `j` in `0..wmax`: draw `v` from SplitMix64 seeded with `0x5374_6567_506f_6e79 XOR wmax` (one draw per column, low 32 bits), `c_j = (v & 0x7f) | 0x01 | 0x40`.
- Block `i` (message bit `i`) covers elements `floor(i·n/m) .. floor((i+1)·n/m)`; element `j` of the slice uses column `c_(j - start)`, masked to the rows that exist: `(1 << min(h, m - i)) - 1`.
- Extraction: `s = 0`; for each block, XOR in the masked column of every element whose parity is 1; message bit `i` is `s & 1`; then `s >>= 1`.

Writers choose stego parities with the Viterbi algorithm to minimize total cost; any choice whose extraction gives the message is valid. Each element whose parity changes is moved by ±1 (see the carrier for direction).

## 5. Lossless carrier (PNG)

Input: PNG, 8-bit gray, gray+alpha, RGB or RGBA. Palette, 16-bit, sub-byte and animated PNGs are refused. A JPEG cover is decoded to 8-bit pixels, turned upright by its EXIF orientation (the PNG carries no metadata to do it), and written out as PNG.

- Elements are the color samples (not alpha) of pixels whose alpha is 255 (every pixel, without alpha), numbered `t = pixel_index · color_channels + channel`, pixels in row-major order.
- Slot of a pixel at `(x, y)`: `((x >> 3) + (y >> 3)) & 1`.
- Parity is the sample's low bit. A change moves the sample by ±1: 255 always goes to 254, 0 to 1, otherwise a fair coin picks the direction.
- Output is a PNG with the same dimensions, color type and bit depth, carrying only IHDR, IDAT and IEND.

Writers in the reference implementation use HILL costs (high-pass residual with the KB kernel, 3x3 mean of its magnitude, reciprocal with epsilon 0.01, 15x15 mean, symmetric borders), computed per channel on the unmodified cover. Costs are a writer choice and not part of the format.

## 6. Native JPEG carrier

Input: the 8-bit Huffman JPEG variants the coefficient codec supports: baseline, extended sequential and progressive, with one to four components. The cover is never decoded to pixels and re-encoded: quantization tables, dimensions, sampling and scan structure are kept. Recompression, cropping and resizing destroy the payload.

- Every AC coefficient in every component is an element, **including zero and ±1**. DC coefficients and MCU padding blocks are excluded. Eligibility never depends on a coefficient's value, so changes through zero do not change positions or capacity.
- Components are concatenated in frame-header order. Within each component, content blocks are row-major over `width_blocks * height_blocks`, excluding MCU padding. Within each block, natural row-major frequency indices `1..64` give the 63 AC elements (not zigzag order). The element number is the component's offset plus `63 * (by * width_blocks + bx) + (k - 1)`.
- The slot is `(bx + by) & 1` in that component's own block coordinates. Sampling factors do not rescale this checkerboard. Every AC element of a block shares its slot.
- Parity is `coefficient & 1`, also for negative coefficients (equivalently the absolute value modulo two). A flip changes the signed value by one: at or above 1023 it decrements, at or below -1023 it increments, otherwise a fair coin chooses +1 or -1. Existing values outside that range stay eligible and move toward zero.
- Output is JPEG. Missing Huffman symbols trigger the codec's table rebuild. Metadata handling is a writer choice and does not affect element enumeration.

The reference writer strips metadata by default with ScrubPony's default policy, and keeps everything only when asked: JFIF is kept with any embedded thumbnail removed, ICC profile chunks and Adobe APP14 are kept so colors are interpreted as before, and EXIF is replaced by ScrubPony's orientation-only block (one IFD0 entry, no thumbnail) when the orientation is 2 to 8, or dropped when the image is upright. Every other APPn (XMP, MPF, JFXX, maker blocks, Photoshop/IPTC), comments and data after EOI are removed.

The reference writer uses J-UNIWARD costs. It reconstructs each component's unrounded, unclipped dequantized spatial plane only to measure texture, correlates it with the three Daubechies-8 high-frequency filter pairs (LH, HL, HH) under symmetric borders, and sums the absolute wavelet impact of a unit change in the coefficient, scaled by its quantization step, divided by `abs(residual) + 2^-6`. The residual alignment is the corrected one (Butora et al., arXiv 2305.19776); costs agree with conseal's `JUNIWARD_FIX_OFF_BY_ONE` to float precision. Planes use complete content blocks, including edge-block samples. Costs are computed before any embedding and are a writer choice, not a format rule; floating-point costs need not be bit-exact across platforms, while extraction and coefficient I/O are integer operations. Detectability ratings stay provisional until the Phase B steganalysis baseline.

## 7. Test vectors

Everything here is fixed for format v1. A change to any of it is a format change.

- `crates/stegpony-core/src/vectors.rs` pins the permutation: the first four outputs with an all-zero key over `T = 1,000,000` are `354941, 379842, 364614, 325392`.
- `crates/stegpony-core/tests/vectors/envelope_vectors.json`: six envelopes (passphrase text, empty text, an NFC pair, a file in a larger bucket, public-key text, public-key file). Each gives the inputs, every random byte the writer drew (`random_hex`; for public-key cases the last 33 are `eph || tweak`, and one case needed four attempts), and every derived value: locate key, both slots' PRP keys, Argon2id output or shared secret, HKDF output, padded plaintext, head and body. A writer fed the same random bytes must produce the same head and body.
- `crates/stegpony-core/tests/vectors/jpeg_vectors/`: baseline RGB, progressive RGB, gray and CMYK native JPEG reader vectors, including a decoy and a public-key file. `index.json` lists the keys and expected payloads. The independent checker reads their coefficients through libjpeg (`jpeglib`), rather than the Rust codec.
- `crates/stegpony-core/tests/vectors/png_vectors/`: Lossless stego images (RGB, gray, RGBA) with their unmodified covers and `index.json`, which lists keys to try on each image and the payload each must reveal, or `null` for nothing. A reader must reveal exactly that. The images are reveal inputs, not writer outputs: a writer with different costs makes different images that are equally valid.

The age keys in the vectors are test keys and are published on purpose.

`tools/check_vectors.py` checks all of it independently of the Rust code: it rebuilds every passphrase envelope, checks public-key envelopes from both the sender's and the reader's side (the reader's through the Elligator 2 map), and reveals every PNG and JPEG vector from scratch. It needs `argon2-cffi`, `cryptography`, `Pillow`, `numpy` and `jpeglib`.
