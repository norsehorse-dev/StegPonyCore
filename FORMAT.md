# StegPony format, version 1

This is the byte-level specification for what StegPony writes into a carrier. Any implementation that follows it must produce output that the reference implementation in `crates/stegpony-core` reveals, and the other way round. Status: draft (envelope, slot layout, Lossless and native JPEG carriers, text carriers). Survive-messenger gets its own section when it lands.

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

A Curve25519 OpenPGP encryption subkey is the same kind of key and may be used in place of an age key; the image does not record which kind was used. The recipient is the subkey's 32-byte X25519 public value (for a v4 ECDH key on Curve25519 the MPI is `0x40` followed by those 32 bytes; for a v6 X25519 key it is the key material itself). The identity is the X25519 secret: for v4 ECDH keys the MPI holds it byte-reversed and must be reversed back, for v6 X25519 keys it is stored as is. StegPony's derivations above are its own, so reusing an OpenPGP key here does not interact with OpenPGP's ECDH key derivation.

### 3.3 Filler

A slot with nothing in it carries a filler: a random 32-byte locate key, a random 20-byte head, and a random body the size of the bucket in use. It is written exactly like a passphrase envelope and is indistinguishable from one.

## 4. Slots and embedding

A carrier exposes elements numbered `0..T`. Each element belongs to slot 0, slot 1, or neither, and has an integer value that the writer can move by +1 or -1 at some cost. Its symbol is the value modulo 3 (0, 1 or 2, also for negative values), so either change moves it to a different symbol. Membership and usability must not depend on anything embedding changes.

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

Bytes become trits (section 4.3) at 7 trits per started group of 11 bits:

```
trits(bits) = 7 * ceil(bits / 11)
head_trits  = trits(8 * head length)      105 passphrase, 189 public key
head_region = max(n / 16, 8 * head_trits)
body_region = n - head_region
```

The first `head_region` elements carry the head, the rest carry the body. A slot needs `n >= 2 * head_region`. A body of bucket `k` needs `3 * trits(8 * bucket_size(k)) <= body_region`.

A reader tries each slot with each of its keys: derive the positions, read the head, derive the body key, unmask `k` (reject if `k >= 37` or the body does not fit), read the body, open the AEAD. A wrong key and an empty slot both end in a failed tag.

### 4.3 Syndrome-trellis code

The code is ternary: it works on element symbols and message trits over GF(3).

Bytes to trits: bits are taken from bytes least significant bit first and grouped by 11, the last group padded with zero bits. A group's value `v = sum(bit_k * 2^k)` (below 2048) is written as 7 base-3 digits, least significant first. Reading reverses this: a group of 7 trits gives `v = sum(trit_k * 3^k)`, whose low 11 bits are the group's bits (a value of 2048 or more only comes from reading with the wrong key). Extra bits past the byte length are dropped.

To place `m` trits in `n` elements:

- Constraint height `h = 4`. States and columns are vectors of `h` trits; row 0 is the current message trit.
- `wmax = ceil(n / m)`. The submatrix columns are `c_j` for `j` in `0..wmax`: draw `v` from SplitMix64 seeded with `0x5374_6567_5465_726e XOR wmax` (one 64-bit draw per column); trit `k` of the column is `floor(v / 3^k) mod 3` for `k` in `0..h`, except that a 0 in trit 0 or trit `h - 1` becomes 1.
- Block `i` (message trit `i`) covers elements `floor(i·n/m) .. floor((i+1)·n/m)`; element `j` of the slice uses column `c_(j - start)`, of which only rows `0 .. min(h, m - i)` exist.
- Extraction: `s = (0, ..., 0)`; for each element of block `i` with symbol `y`, add `y · c` to `s` trit by trit modulo 3, over the rows that exist; message trit `i` is `s[0]`; then shift `s` down one row (`s[k] = s[k + 1]`, the top row becomes 0).

Writers choose stego symbols with the Viterbi algorithm to minimize the total cost of the changes; any choice whose extraction gives the message is valid. A change moves an element by +1 or -1, and the direction is part of the code's answer: +1 gives symbol `x + 1`, -1 gives `x - 1` (modulo 3).

## 5. Lossless carrier (PNG)

Input: PNG, 8-bit gray, gray+alpha, RGB or RGBA. Palette, 16-bit, sub-byte and animated PNGs are refused. A JPEG cover is decoded to 8-bit pixels, turned upright by its EXIF orientation (the PNG carries no metadata to do it), and written out as PNG.

- Elements are the color samples (not alpha) of pixels whose alpha is 255 (every pixel, without alpha), numbered `t = pixel_index · color_channels + channel`, pixels in row-major order.
- Slot of a pixel at `(x, y)`: `((x >> 3) + (y >> 3)) & 1`.
- The symbol is the sample value modulo 3. A change moves the sample by ±1 within 0..255: 255 can only go down and 0 only up.
- Output is a PNG with the same dimensions, color type and bit depth, carrying only IHDR, IDAT and IEND.

Writers in the reference implementation use HILL costs (high-pass residual with the KB kernel, 3x3 mean of its magnitude, reciprocal with epsilon 0.01, 15x15 mean, symmetric borders), computed per channel on the unmodified cover. Costs are a writer choice and not part of the format.

## 6. Native JPEG carrier

Input: the 8-bit Huffman JPEG variants the coefficient codec supports: baseline, extended sequential and progressive, with one to four components. The cover is never decoded to pixels and re-encoded: quantization tables, dimensions, sampling and scan structure are kept. Recompression, cropping and resizing destroy the payload.

- Every AC coefficient in every component is an element, **including zero and ±1**. DC coefficients and MCU padding blocks are excluded. Eligibility never depends on a coefficient's value, so changes through zero do not change positions or capacity.
- Components are concatenated in frame-header order. Within each component, content blocks are row-major over `width_blocks * height_blocks`, excluding MCU padding. Within each block, natural row-major frequency indices `1..64` give the 63 AC elements (not zigzag order). The element number is the component's offset plus `63 * (by * width_blocks + bx) + (k - 1)`.
- The slot is `(bx + by) & 1` in that component's own block coordinates. Sampling factors do not rescale this checkerboard. Every AC element of a block shares its slot.
- The symbol is the coefficient modulo 3, taken as non-negative (`-1` is symbol 2). A change moves the coefficient by ±1, never past ±1023: at 1023 or above it can only go down, at -1023 or below only up.
- Output is JPEG. Missing Huffman symbols trigger the codec's table rebuild. Metadata handling is a writer choice and does not affect element enumeration.

The reference writer strips metadata by default with ScrubPony's default policy, and keeps everything only when asked: JFIF is kept with any embedded thumbnail removed, ICC profile chunks and Adobe APP14 are kept so colors are interpreted as before, and EXIF is replaced by ScrubPony's orientation-only block (one IFD0 entry, no thumbnail) when the orientation is 2 to 8, or dropped when the image is upright. Every other APPn (XMP, MPF, JFXX, maker blocks, Photoshop/IPTC), comments and data after EOI are removed.

The reference writer uses J-UNIWARD costs. It reconstructs each component's unrounded, unclipped dequantized spatial plane only to measure texture, correlates it with the three Daubechies-8 high-frequency filter pairs (LH, HL, HH) under symmetric borders, and sums the absolute wavelet impact of a unit change in the coefficient, scaled by its quantization step, divided by `abs(residual) + 2^-6`. The residual alignment is the corrected one (Butora et al., arXiv 2305.19776); costs agree with conseal's `JUNIWARD_FIX_OFF_BY_ONE` to float precision. Planes use complete content blocks, including edge-block samples. Costs are computed before any embedding and are a writer choice, not a format rule; floating-point costs need not be bit-exact across platforms, while extraction and coefficient I/O are integer operations. The writer's Low / Medium / High rating counts both slots' bits per nonzero AC coefficient among the elements used, with thresholds from the steganalysis baseline in `tools/steganalysis/`; it is advice to the user, not part of the format.

## 7. Text carriers

Text carries the envelope bytes directly: there is no cover to modify, so there are no elements, positions, locate keys or syndrome-trellis code. Every byte written is a head, random fill or ciphertext, so the layout needs no secret.

### 7.1 Stream

```
HEAD_AREA      = 36
slot           = head || fill || body          HEAD_AREA + bucket_size(k) bytes
stream         = slot_a || slot_b              2 * (36 + bucket_size(k)) bytes
```

`head` is the envelope head of section 3 (20 bytes for a passphrase, 36 for a public key) and `fill` is random bytes up to 36, so the key kind does not change the length. A slot with nothing in it is 36 random bytes followed by a random body (section 3.3). Both slots use the same bucket; which slot gets the payload is a fair coin, as for images. The smallest stream (`k = 0`) is 200 bytes.

A reader finds `k` from the stream length (no other bucket gives the same length), then tries each slot with each key: the first 20 bytes of the slot as a passphrase head or the first 36 as a public-key head, the masked bucket index must equal `k`, and the body opens the AEAD. Section 3's derivations are unchanged, except that the locate key is never derived.

Writers in the reference implementation use buckets up to 16 KiB (`k <= 16`); this is a writer limit, and readers accept any bucket.

### 7.2 Zero-width characters

Symbols are 2 bits, taken from each byte least significant first (four symbols per byte), written as:

| Symbol | Character |
|---|---|
| 0 | U+200B ZERO WIDTH SPACE |
| 1 | U+200C ZERO WIDTH NON-JOINER |
| 2 | U+200D ZERO WIDTH JOINER |
| 3 | U+2060 WORD JOINER |

A **carrier position** is the start of the text or the point right after a whitespace character. Whitespace here is exactly Unicode's `White_Space` set: U+0009 to U+000D, U+0020, U+0085, U+00A0, U+1680, U+2000 to U+200A, U+2028, U+2029, U+202F, U+205F and U+3000 (not U+200B, U+FEFF or U+001C to U+001F). Reading: walk the text; while at a carrier position, each carrier character is a symbol and the position stays a carrier position; any other character ends it, and a whitespace character starts a new one. Carrier characters anywhere else (such as the joiner inside an emoji sequence) are not symbols. With no symbols the text has no zero-width payload. A symbol count that is not a multiple of 4, or bytes that are not a stream length from 7.1, mean characters were lost or added, unless the whole text also reads as dictionary words (7.3), in which case it is read as words: apps sometimes insert a stray invisible character.

The reference writer first removes carrier characters at carrier positions from the cover, then splits the symbols as evenly as possible over the starts of the cover's words (a non-whitespace character at a carrier position), in order, each run placed just before its word. A cover needs at least one word. A writer may place the symbols any other way that reads back the same.

### 7.3 Dictionary words

The English list is `crates/stegpony-core/src/text/en.txt`: 4096 lowercase ASCII words, one per line, each line ending in `\n`, index = line number from 0. Its SHA-256 is `6e01295be4982adec0341d5484c17f442424bb20998bcd46d5ee1484f1e5c447`. `tools/wordlist/` records how it was chosen.

Bits are taken from the stream bytes least significant first and grouped by 12; a group's value `v = sum(bit_k * 2^k)` is the index of its word. The last group's missing bits are random. A stream of `L` bytes gives `ceil(8L / 12)` words; the smallest stream is 134 words.

Reading: the words are the maximal runs of ASCII letters (A to Z, a to z); every other character (spaces, punctuation, digits, line breaks, any non-ASCII character) separates them. Each word, with ASCII letters lowercased, must be on the list. The word count selects the stream length `L` from 7.1 (no two lengths give the same count), and the first `L` bytes of the bits, in the same order, are the stream.

The reference writer capitalizes the first word of each sentence of 6 to 14 words, ends sentences with a period, sometimes adds a comma, and breaks paragraphs every 3 to 6 sentences. All of this is a writer choice that readers ignore.

## 8. Test vectors

Everything here is fixed for format v1. A change to any of it is a format change.

- `crates/stegpony-core/src/vectors.rs` pins the permutation: the first four outputs with an all-zero key over `T = 1,000,000` are `354941, 379842, 364614, 325392`.
- `crates/stegpony-core/tests/vectors/envelope_vectors.json`: six envelopes (passphrase text, empty text, an NFC pair, a file in a larger bucket, public-key text, public-key file). Each gives the inputs, every random byte the writer drew (`random_hex`; for public-key cases the last 33 are `eph || tweak`, and one case needed four attempts), and every derived value: locate key, both slots' PRP keys, Argon2id output or shared secret, HKDF output, padded plaintext, head and body. A writer fed the same random bytes must produce the same head and body.
- `crates/stegpony-core/tests/vectors/jpeg_vectors/`: baseline RGB, progressive RGB, gray and CMYK native JPEG reader vectors, including a decoy and a public-key file. `index.json` lists the keys and expected payloads. The independent checker reads their coefficients through libjpeg (`jpeglib`), rather than the Rust codec.
- `crates/stegpony-core/tests/vectors/text_vectors.json`: zero-width and dictionary texts (passphrase and public key, a decoy, a file in a larger bucket, a cover with emoji joiners, a recased and repunctuated copy, words with odd separators and a stray invisible character, a cover with unusual whitespace) with the keys to try and the payload each must reveal, and the word list's SHA-256. Like the image vectors, the texts are reveal inputs, not writer outputs.
- `crates/stegpony-core/tests/vectors/png_vectors/`: Lossless stego images (RGB, gray, RGBA) with their unmodified covers and `index.json`, which lists keys to try on each image and the payload each must reveal, or `null` for nothing. A reader must reveal exactly that. The images are reveal inputs, not writer outputs: a writer with different costs makes different images that are equally valid.

The age keys in the vectors are test keys and are published on purpose.

`tools/check_vectors.py` checks all of it independently of the Rust code: it rebuilds every passphrase envelope, checks public-key envelopes from both the sender's and the reader's side (the reader's through the Elligator 2 map), and reveals every PNG, JPEG and text vector from scratch. It needs `argon2-cffi`, `cryptography`, `Pillow`, `numpy` and `jpeglib`.
