# Error-tolerant mode (survive-messenger)

Planning draft, Rev 1
October 26, 2026
Status: decisions R1 to R5 made Oct 26, 2026 (section 7). No format or code change yet. Covers WhatsApp, Signal and Telegram
sent from Android. Telegram sent from an iPhone through the gallery needs none of this: cover
preparation plus native JPEG mode already comes through intact (`CHANNEL_PREPARATION.md`).

## 1. Why native mode can't do it

Native JPEG mode reads each slot through a syndrome-trellis code, and the AEAD tag rejects a single
wrong byte. One changed AC coefficient in a slot is enough to lose it. Measured returns:

| Route | What changes (against the sent file, same size and grid) |
|---|---|
| WhatsApp, default | 28 and 98 AC coefficients out of 2.8 million on two photos, about 5,500 on an HDR scene; +1 on the DC of thousands of blocks in every component |
| Signal, photo | 3 to 6% of nonzero luma AC, about 20% of nonzero chroma AC, 17 to 66% of DC; slight darkening; not tied to clipping |
| Telegram from Android | 7.7 to 9.7% of luma AC, 0.06 to 1.7% of chroma AC, DC in about a third of luma blocks |

## 2. Telegram from Android, in detail

Three covers pre-matched to Android Telegram's own tables (IJG q87, 4:2:0, 1280, headroom), sent
from the gallery, downloaded on the Mac (`drafts/channel-lab/run-2026-10-26-telegram-android-q87`):

- Coefficients that were **zero never change** (0.1% at the smallest step, 0 elsewhere).
- Nonzero coefficients change a lot, and by value: magnitude 1 becomes 2 about 67% of the time,
  magnitude 2 drops to 1 about 25% of the time, magnitude 3 changes about 4% of the time.
- Amplitude gain rises with frequency: about 1.0 at the lowest AC frequencies, 1.2 to 2.0 at
  higher ones. No shift, no mean colour change; luma pixel difference std 1.7 to 2.4.
- The output gains a 456-byte sRGB profile ("Google Inc. 2016", Android's Skia encoder).

That looks like a fixed filter (sharpening-like) plus a q87 re-encode, not random noise. If it is
deterministic, the writer can simulate it locally (section 5, D).

## 2a. Where the errors fall (experiment 2, Oct 26, 2026)

Per-value and per-frequency tables for all three channels, from the existing returns, are in
`drafts/channel-lab/error-tables-2026-10-26/` (not committed). The pattern that matters:

- **WhatsApp** only ever changes coefficients of magnitude 1, and only towards 0 (1.3% of luma,
  3.3% of chroma ones, mostly high frequencies). Zeros and magnitudes of 2 or more never changed.
- **Signal** changes low frequencies (zigzag 1 to 5: 11% of luma AC) and larger values most;
  zigzag 15 and up is almost untouched (0.02% or less).
- **Telegram from Android** never turns a zero into anything else and never turns a magnitude of 2
  or more into 0. Ones mostly grow to 2.

So the **zero / not-zero pattern** survives all three. Reading a coefficient as 0 (one symbol), a
magnitude of 2 or more (the other symbol) or a magnitude of 1 (an erasure, "unknown"), luma
zigzag 10 to 27 measured:

| Route | Wrong symbol | Erasure |
|---|---|---|
| WhatsApp | 0 | 0 |
| Signal | 0.0002% | 0.03% |
| Telegram from Android | 0 | 0.94% |

Zigzag 15 to 27 is even cleaner for Signal (0.0001%, 0.004%). Erasures are cheap for an
erasure-correcting code. Caveats: these were the channel's effect on existing values; values the
writer creates (0 to 2 and back) must be measured the same way, and moving a coefficient by 2 is a
larger change than native mode makes, so detectability needs its own measurement (R2 already says
High until then).

## 3. Requirements

Kept from the format: no header or marker, two slots always (payload plus decoy or filler), the same
envelope and keys, AEAD as the final check, and "a wrong key looks like an empty image".

New:
- Survive plus-or-minus-1 changes on a known fraction of coefficients, and value-dependent changes
  like Android's 1 to 2.
- The reader can't know which coefficients the writer used, and must not select elements by value,
  because the channel changes values.
- DC is never used.
- Capacity in the hundreds of bytes is acceptable. Text first; files only when they fit.

## 4. Why error correction around the native carrier is not enough

Each element feeds up to h = 4 message trits in the syndrome-trellis code, across a block of
ceil(n/m) elements. With an element error rate p and about w elements per trit, a trit survives with
probability near (1 - p)^(w * h). That is fine for WhatsApp's 1e-5 and hopeless for 10%. Wrapping
Reed-Solomon around the native carrier would cover WhatsApp alone.

## 5. Options

**A. Native carrier plus outer Reed-Solomon.** Smallest change; WhatsApp only. Reasonable as a
first step if WhatsApp is the priority.

**B. Robust carrier: dither modulation in fixed positions plus ECC.** A new carrier section: a fixed,
keyed set of low and mid-frequency luma positions (by frequency index, never by value), each
carrying one symbol by quantization-index modulation with a step Delta in quantized units and a
keyed dither, with Reed-Solomon (or a convolutional code) and interleaving across blocks, sized per
channel profile. Positions and costs still adapt: the writer prefers textured blocks. The reader
reads every position and lets the code correct the rest. This is the route the robust-steganography
literature takes (adaptive dither modulation, transport channel matching with error correction).
Cost: larger changes per coefficient, so higher detectability than native mode, and far less
capacity.

**C. Avoid the unstable values (now the leading candidate, section 2a).** The Android data says zeros and magnitudes of 3 or more mostly
survive, while 1 and 2 do not. A symbol rule that keeps embedded values away from 1 and 2 (for
example, only moving coefficients already at 3 or more, and in steps that stay there) could get
the error rate down far enough for modest ECC. It needs selection that survives the channel, which
B's fixed positions provide; C is a refinement of B, not a separate format.

**D. Model the channel.** If Android Telegram and Signal are deterministic, a local simulator lets
the writer check the round trip before sending (planning 7.3, step 5) and choose covers or
positions that survive. Cheap to test first: send the same photo twice and send a return again.

## 6. Recommendation

One new robust carrier (B, refined by C) with ECC parameters per channel profile, found by trial on
reveal like buckets. Section 2a points at the concrete form: fixed mid-frequency luma positions
(around zigzag 10 to 27), one bit each as zero versus a magnitude of 2 or more, magnitude 1 read as
an erasure, under an erasure-correcting code with interleaving. Build and verify it against WhatsApp first (lowest error rate, settles the
format), then Signal, then Telegram from Android. Run the D experiments before any code, because
they decide how much margin the code needs.

## 7. Decisions (Oct 26, 2026)

- **R1. Format v1, before 1.0.** The robust carrier becomes a new section of FORMAT.md, so 1.0
  launches with one format version.
- **R2. Rated High until measured.** Robust output is labelled plainly and rated High until the
  steganalysis baseline has been run on it.
- **R3. All three channels for 1.0.** WhatsApp, Signal and Telegram from Android. 1.0 waits until
  all three deliver real two-slot messages. Build order stays WhatsApp, Signal, Telegram from
  Android; if Telegram from Android turns out not to be deterministic, its error correction is sized
  from measured error rates rather than a channel model.
- **R4. Two slots always**, in robust mode as everywhere else.
- **R5. Files allowed when they fit**; the capacity meter decides.

## 8. Experiments before code

1. Android Telegram idempotence: send one return again; send one cover twice. Byte-identical or
   shrinking changes mean a model is possible.
2. Per-frequency and per-value error tables for WhatsApp and Signal from the existing returns.
   Done Oct 26, 2026 (section 2a).
3. A WhatsApp repeat on a later app version.
4. A round trip of writer-made symbols: covers with chosen positions set to 0 or plus or minus 2,
   through each channel, to measure errors and erasures on values the writer creates.

## 9. Estimate

Experiments 1 evening. Robust carrier with ECC and vectors 4 to 6 evenings. Per-channel tuning and
real sends 1 to 2 evenings per channel. App surface 1 to 2 evenings.
