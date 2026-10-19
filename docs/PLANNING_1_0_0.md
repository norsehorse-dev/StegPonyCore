# StegPony

Planning document, Rev 1
October 15, 2026
Status: real candidate, most likely the next new Pony app. Planning only; no repos yet. Starts when current maintenance work allows.
Origin: suggested by a user by email (Oct 2026), pointing at the steganography in Kryptos (F-Droid) as the reference. The first RC goes to that user.

When the repos are created, this file becomes `PLANNING_1_0_0.md` at each repo root.

---

## 0. Decisions to date

- Oct 15, 2026: **Name: StegPony.** A quick web search turned up nothing using it. The full sweep (USPTO, Google Play, App Store, F-Droid, GitHub) and the registrar check for stegpony.app are Q1.
- Oct 15, 2026: **Platform order.** Android and F-Droid first. iOS later: a "hide a message in a photo" app is exactly the crowded, template-farmed iOS category where 4.3(a) has landed before (Umbra, VaultPony). Desktop comes from the shared core.
- Oct 15, 2026: **Core: Rust, shared.** `stegpony-core` does its own PNG and JPEG-coefficient handling so embedding and extraction are bit-exact on every platform. Platform image decoders (BitmapFactory, UIImage/CGImage) apply color management, premultiplied alpha, and resampling that silently destroy low-order bits, so they never touch a stego image.
- Oct 15, 2026: **Three image modes in 1.0:** Lossless (PNG), JPEG (native coefficients), and Survive-messenger (recompression-robust, labeled experimental). Section 7.
- Oct 15, 2026: **Keys: passphrase and public key in 1.0.** Public key is X25519 with Elligator 2 encoded ephemeral keys, so nothing in the hidden data looks like a key. Section 6.
- Oct 15, 2026: **Text steganography in 1.0, both kinds:** dictionary words and zero-width characters, each labeled honestly for strength. Section 8.
- Oct 15, 2026: **Decoy payload in 1.0.** A second passphrase reveals a harmless message; nothing shows that a second payload exists. Section 6.4.
- Oct 15, 2026: **Launcher disguise in 1.0 (Android).** Optional alternate app name and icon. Section 10.4.
- Oct 15, 2026: **No Kryptos interop.** Its format is not documented and its design (a messenger overlay with stego as one feature) differs from this one. Kryptos is the reference for what users expect, not a format target.
- Oct 15, 2026: **Pricing.** Free everywhere at 1.0, family pattern: any future Plus feature sits behind `Entitlements.plus`, hard-wired to true.
- Oct 15, 2026: **Credit and names.** No user or tester names anywhere public: app, README, release notes, commit messages, or this file once it is in a repo. Credit reads "suggested by a user".
- Oct 15, 2026: **Distribution.** F-Droid, direct APK, GitHub releases. No IzzyOnDroid.
- Oct 15, 2026: **RCs one at a time.** Each RC is built and tested before the next one's work starts (section 14).
- Oct 16, 2026: **Argon2id v1 parameters: m = 128 MiB, t = 3, p = 4** (Q2). Timed with the core's `examples/argon2_bench.rs` on the slowest test phone (moto g play 2026): 0.34 s per derivation, so about 1.0 s of Argon2id for a reveal that misses and 1.4 s for a hide with a passphrase decoy. Twice the memory of the 64 MiB / p = 1 draft for about the same time. 256 MiB (0.63 s) was left out because 2 GB phones at minSdk 26 could kill the allocation. Lanes run on threads through argon2's `parallel` feature; the output is the same with or without it.
- Oct 16, 2026: **JPEG coefficient I/O in pure Rust** (Q6), inside stegpony-core, replacing the earlier libjpeg-turbo FFI recommendation. Only the entropy layer is needed (Huffman decode and encode of quantized coefficients, no IDCT for the format itself), so it stays small; no C cross-compile for Android, iOS or desktop, the reproducible-build harness is unchanged, and output is bit-exact across platforms by construction. libjpeg stays in the picture as a test oracle (the Python jpeglib package reads and writes DCT coefficients through libjpeg), not as a dependency. The existing dct-io crate (baseline only, first scan only, a single 0.1 release) is a second reader for tests, not a dependency.
- Oct 16, 2026: **Native JPEG carrier: all AC coefficients in every component**, including zeros and ±1; DC and MCU padding are excluded. The ordering, slots and signed ±1 rules are in FORMAT.md section 6. Carrier, J-UNIWARD costs (checked against conseal's reference implementation), CLI mode and independent libjpeg reader vectors are implemented. Output metadata follows ScrubPony's default policy (ICC kept, EXIF reduced to orientation). Phase B steganalysis and detectability calibration remain outstanding.
- Oct 17, 2026: **JPEG detectability thresholds from the steganalysis baseline** (section 18). Color DCTR with an FLD ensemble on 792 tiles from 66 quality-95 photos off the phone sampled for Q6, folds split by capture time. Payload counted over both slots per nonzero AC coefficient: 0.10 bpnzac gave P_E 0.445, 0.19 gave 0.398, 0.39 gave 0.232, 0.78 gave 0.031. At 0.39, ideal ternary J-UNIWARD gave 0.354 and nsF5 (PixelKnot's family) 0.055. Ratings: Low up to 0.15, Medium up to 0.30, High above, deliberately below the measured points. Still to measure: other test phones and daylight scenes. Open: StegPony's binary parity embedding makes about 1.5 times the changes of ternary embedding; moving to ternary is a format change, cheapest before 1.0.
- Oct 18, 2026: **PGP key support moves into 1.0** (from Later), requested by the user who suggested the app. A Curve25519 OpenPGP key's encryption subkey (v4 cv25519 or v6 X25519) is the same X25519 key the envelope already uses, so this is key import only, with no format change. stegpony-core reads public keys for recipients and unlocks secret keys with their passphrase to get the private half, through rpgp (the `pgp` crate, pure Rust, so the reproducible-build harness is unchanged); StegPony's own labelled HKDF keeps the reuse separate from OpenPGP's ECDH. The app imports by file or from PGPony's share sheet. RSA and NIST-curve keys cannot be used (the hidden key exchange is X25519 only); post-quantum composite keys are left out of 1.0, since only their X25519 part would apply. A live link where StegPony asks PGPony to unlock a key stays Later. Adds 2 to 3 evenings to Phase C.
- Oct 18, 2026: **Reveal with a hardware key in 1.0, shipped in RC2**, requested by the user who suggested the app. The OpenPGP card applet (YubiKey, Nitrokey, Token2) does the Curve25519 key exchange on the card (PSO:DECIPHER returns the shared secret), so reveal sends it the ephemeral key recovered from the Elligator 2 representative and finishes on the phone; no format change. Hiding only needs the public key and never touches the card. The core's reveal takes a key-exchange callback in place of an in-memory secret; the Android side reuses PGPony Android's card layer (NFC and USB, PIN with KDF-DO, Nitrokey 3 USB fix, exclusive NFC during a session). Curve25519 card keys only. A reveal makes two card operations (one per slot), so two touches when touch-to-use is on. Open risk: a card that strictly validates points could refuse the torsion-dirty ephemeral keys; testing on real cards settles it. Test devices: a Token2 PIN+ here (OpenPGP 3.4 with X25519; factory default is RSA 2048, so the encryption key must be cv25519) and the requesting user's own key. RC2 rather than RC1 so RC1 is not delayed and imported PGP keys get tested first. 3 to 4 evenings.
- Oct 18, 2026: **Hardware-key reveal moves from RC2 into RC1.** The requesting user's key is a Nitrokey 3A NFC (firmware 1.9.1, ed25519/cv25519), and there is no Nitrokey here to test with, so it has to be in the first test build he gets. Test devices for RC1: his Nitrokey 3A NFC and the Token2 PIN+ here. Nitrokey 3 firmware has OpenPGP over NFC switched off (Nitrokey's own statements, June 2023 and March 2024: not enough power over NFC for the storage and secure element it uses), so the Nitrokey is tested over USB only; the 3A has a USB-A plug, so that means a USB-A to USB-C OTG adapter on the phone. The app says plainly that a Nitrokey 3 needs USB when an NFC attempt fails.
- Oct 19, 2026: **Ternary embedding in format v1.** An element's symbol is its value modulo 3 and the syndrome-trellis code works over GF(3), height 4, so the direction of a ±1 change carries information. Chosen before Phase C because it changes the format. On J-UNIWARD cost maps from real phone photos it cuts distortion about 28% against the binary height-7 code at the same payload; heights 5 and 6 add only 5 to 8% more for 3 to 9 times the encoder memory. Re-run of the steganalysis baseline on the same 792 tiles: P_E 0.465 / 0.417 / 0.309 / 0.060 at 0.10 / 0.19 / 0.39 / 0.78 bpnzac (binary was 0.445 / 0.398 / 0.232 / 0.031; ideal J-UNIWARD at 0.39 was 0.354). JPEG ratings move to Low up to 0.18 bpnzac and Medium up to 0.38. Encoder speed is unchanged (0.60 s per full slot against 0.75 s binary on the same machine); the slow part of a hide was the J-UNIWARD cost map, which then got about 7 times faster by computing whole blocks with separable sums (same costs to within 5e-7), so a 12-megapixel hide takes about 7 s on two cloud cores, down from 31 s.

## 1. Summary

Hide an encrypted message or file inside an ordinary photo, or inside ordinary-looking text, and get it back out with a passphrase or a key. The hidden data has no header, no signature, and no fixed layout: without the right secret, the image is a photo and the text is text. A second passphrase can reveal a decoy instead of the real payload. Fully offline, no INTERNET permission, no account, open source.

Encryption keeps the content secret. StegPony's job is the step before that: keeping it from being obvious that there is any content at all.

## 2. Why this app, why now

Encrypted messages are easy to spot. An age file, an OpenPGP armor block, or a base64 blob in a chat says "this person is hiding something" even when nobody can read it. Steganography answers that, and the Pony family already covers the encryption half (PGPony, AgePony), so StegPony slots in as the cover layer.

Market as of October 2026 (Android):

- **Kryptos** (F-Droid, actively developed, 2.3.x). End-to-end encryption that works through any messenger, with an encrypting keyboard and on-screen decryption. Steganography is one feature: ciphertext hidden in a photo or disguised as a run of real words from 4096-word dictionaries. Photo stego was rebuilt in 2.3 with no visible signature and keyed adaptive placement. Strong app; stego is a feature inside a messenger overlay, not the product.
- **PixelKnot** (Guardian Project). F5 JPEG steganography with a password. The project page sits in the Guardian Project archive with screenshots dated 2016. This is the closest thing to a dedicated, focused stego app on Android, and it looks unmaintained: the same "replaces something people relied on that fell out of maintenance" pattern that made PGPony work.
- **Conceal** (F-Droid). Hides WAV audio in image LSBs. Last release 1.4 in January 2021.
- Desktop: OpenStego, steghide, and similar CLI tools. Old, mostly unmaintained, mostly detectable with modern steganalysis.

What StegPony does better: modern content-adaptive embedding (costs in the style of the UNIWARD family with syndrome-trellis coding, instead of F5 or plain LSB), a headerless envelope, public-key mode reusing age X25519 keys, a real decoy, text modes, an honest per-channel survival story, and one format across Android, desktop, and eventually iOS. Open source, reproducible builds.

## 3. Users and the jobs they are doing

**Journalists, activists, people in hostile jurisdictions.** The job is moving a message or a small file past someone who reads their phone or their traffic, where carrying visible ciphertext is itself the risk. Decoy, disguise, and the no-header envelope exist for them.

**Privacy users who already use PGPony or AgePony.** The job is "encrypt, then hide the fact." They will hand an `.age` or `.asc` file to StegPony through the share sheet and want it back the same way.

**People sharing through platforms that recompress.** WhatsApp, Signal (photo mode), Telegram, Instagram DMs. The job is "will this survive being sent?", and the honest answer depends on the channel. The Survive-messenger mode and the channel picker exist for them.

**Hobbyists, CTF players, and the curious.** Text modes, the capacity meter, and a clear explanation of what is and is not detectable. They file issues and talk about the app.

## 4. Goals and non-goals

Goals for 1.0:

- Hide text or a file in a PNG or JPEG cover and recover it bit-exact.
- No detectable format marker. Extraction with a wrong secret yields nothing, and the app cannot tell a wrong secret from an image with no payload.
- Passphrase and public-key modes; decoy payload.
- Survive-messenger mode with per-channel profiles and a "last verified" date per profile.
- Dictionary and zero-width text modes.
- Honest UI: capacity, detectability, and survival stated per mode, never overclaimed.
- Offline, no INTERNET permission, no analytics.
- Reproducible F-Droid build.

Non-goals for 1.0:

- Audio or video steganography.
- Messenger overlay, keyboard, or on-screen decryption (that is Kryptos's design; not this app's job).
- Kryptos, PixelKnot, or steghide format compatibility.
- Multi-recipient public-key slots (Q5).
- Natural-language text generation with a language model (later, if ever; section 8).
- Guaranteed survival on any recompressing platform.

## 5. Product shape

Four destinations:

- **Hide.** Pick a cover (camera, photo picker, file) or a text cover, pick a payload (type a message, or pick a file), pick a key (passphrase or a contact's public key), optionally add a decoy, pick "How will you send this?" (Original file / Messenger: WhatsApp, Signal, Telegram... / Text). The capacity meter updates live. Output goes to Save, Share, or Copy.
- **Reveal.** Open an image or paste text, enter a passphrase or let the app try your identities. Shows the message or offers the file for save/share/open-with. Share-target entry point: share an image into StegPony and it lands here.
- **Keys.** Your identity (X25519, age-compatible), contacts' public keys (scan QR, paste `age1...`, import from AgePony via share, import a Curve25519 PGP public key by file or from PGPony via share). Your identity can also be a Curve25519 PGP secret key, imported and unlocked with its passphrase. Export your recipient as text or QR.
- **Settings.** Launcher disguise, app lock, clipboard auto-clear, default output format, channel profiles with "last verified" dates, Help (what is detectable and what is not), More from NorseHorse, licenses.

## 6. Crypto envelope

One envelope format for every carrier (image or text). Design rule: every byte that goes into the carrier is indistinguishable from random without the secret. No magic bytes, no version field, no length field in the clear, no KDF parameters in the clear.

### 6.1 Passphrase slot

- Two derivations, because positions must be found before the salt can be read:
  - **Locate key:** Argon2id(passphrase, fixed domain string "StegPony v1 locate"). Seeds the pseudo-random permutation of carrier positions. Not the confidentiality boundary.
  - **Content key:** Argon2id(passphrase, 16-byte random salt read from the first slot positions). Single-use per message, so the AEAD nonce is fixed at zero.
- AEAD: XChaCha20-Poly1305 (or ChaCha20-Poly1305; the nonce is fixed because the key is single-use, so the extended nonce buys nothing and the plain construction is fine). Overhead: 16-byte salt plus 16-byte tag = 32 bytes.
- Argon2id parameters are fixed per format version because there is no header to carry them. Proposed v1: m = 64 MiB, t = 3, p = 1, tuned against the slowest test device in Phase A. Format versions are found by trial, newest first. Decided Oct 16, 2026: m = 128 MiB, t = 3, p = 4 (section 0).

### 6.2 Public-key slot

- Keys are X25519 and reuse **age identities and recipients**: a contact's `age1...` recipient is a valid StegPony recipient, and an `AGE-SECRET-KEY-1...` identity can be imported. The output is not age format (age has a header), only the same key type, so AgePony users bring their keys for free. (Q4.)
- Sender makes an ephemeral X25519 keypair whose public key has an Elligator 2 representative (retry until it does, about half of keys qualify), embeds the 32-byte representative, derives the content key with HKDF over the shared secret and both public keys.
- Locate key: derived from the recipient's public key. Consequence, written into Help: someone who holds your public key can locate the slot positions and run targeted steganalysis on exactly those positions, which is much stronger than blind steganalysis. Optional mitigation in the UI: add a shared passphrase on top, which mixes into the locate key.
- Overhead: 32-byte representative plus 16-byte tag = 48 bytes.

### 6.3 Length and padding

- Plaintext inside the AEAD: a 1-byte type (text, file), a length field, for files a name and MIME type, the payload, then padding.
- Ciphertext length comes from a small fixed bucket table (for example 256 B, 1 KiB, 4 KiB, 16 KiB, 64 KiB, 256 KiB, 1 MiB). The extractor tries each bucket in turn; the Argon2id work happens once per salt, so trying buckets is cheap and the AEAD tag decides.
- Inner payloads can be anything, including an `.age` or `.asc` file from AgePony or PGPony. Help explains that the outer envelope is what hides; the inner one is optional.

### 6.4 Decoy (two slots, always)

- Every StegPony carrier has two slots. The carrier's positions are split into two halves by a public, keyless rule (alternate 8x8 blocks for images, alternate positions for text). Each slot is placed within its half by its own locate key.
- With no decoy, the second slot is filled with random bytes of the same bucket size. An unused slot and a used slot look identical, so the existence of a second payload is deniable.
- On Reveal, the app tries the secret against both halves, so a user never needs to know which slot is which, and an observer cannot tell from the UI either.
- Costs: capacity per payload is half the carrier; filling both slots raises the change rate, which raises detectability. The capacity meter accounts for both slots. In Survive-messenger mode capacity may be too small for two meaningful slots, and the UI says so rather than silently dropping the decoy.
- Help is honest about the limit: a decoy protects against someone who forces a passphrase out of you and accepts what it shows; it does not defeat someone who already knows StegPony always has two slots and keeps pushing. That is the same deniability argument VeraCrypt hidden volumes make, and it is stated the same way.

### 6.5 What we do not claim

- Not undetectable. Modern steganalysis with enough clean samples from the same camera can flag embedding at high payload. The goal is low detectability at low payload, and the UI shows a payload-to-capacity ratio with a plain-language rating.
- Not robust to arbitrary edits. Cropping, filters, screenshots, and re-saving destroy the payload in Lossless and JPEG modes.

## 7. Image modes

### 7.1 Lossless (PNG)

- Spatial-domain embedding with ±1 changes (LSB matching, never LSB replacement, which is trivially detectable), content-adaptive costs (S-UNIWARD or HILL style: changes go in textured regions, never in flat sky or synthetic graphics), syndrome-trellis codes to minimize changes for a given payload.
- Survives anything that delivers the file unchanged: send as file or document, email attachment, cloud storage, USB, RelayPony.
- Cover warning: a camera photo saved as PNG is unusual in itself. Natural PNG covers are screenshots and graphics, which have large flat regions and low usable capacity. The capacity meter reflects that, and Help explains it.
- Output: PNG with no ancillary chunks beyond what a normal PNG export has.

### 7.2 JPEG (native coefficients)

- Embed in the cover's own quantized DCT coefficients. The cover is never decoded to pixels and re-encoded, so quantization tables and the camera's compression stay intact, which is the main reason JPEG stego can be hard to detect.
- J-UNIWARD style costs with syndrome-trellis codes. F5 and nsF5 are documented as the older baseline, not used.
- Coefficient access: libjpeg-turbo's coefficient API (`jpeg_read_coefficients` / `jpeg_write_coefficients`) through FFI, vendored and built inside the reproducible-build Docker harness, or a pure-Rust entropy decoder and encoder (lossless coefficient round-trip only needs Huffman decode and encode, no IDCT). Q6. Decided Oct 16, 2026: pure Rust (section 0). Open design point: embedding can create Huffman symbols missing from a file's optimized tables, so the writer keeps the original tables when every symbol fits and rebuilds optimized tables otherwise.
- Survives delivery as an unchanged file. Does not survive re-quantization, resizing, or messenger "photo" sends.
- Metadata: EXIF stripped by default (ScrubPony's logic), since a messenger-sent image usually has none. Option to keep. HEIC covers are decoded and re-encoded as JPEG, which loses the native-coefficient advantage, and the UI says so.

### 7.3 Survive-messenger (experimental)

The hard one, and the user asked for it. Honest framing goes in the UI: small capacity, higher detectability, survival verified per channel and per date, may break when a platform changes its pipeline.

Approach:

1. **Channel profiles.** For each supported channel, measure what it does to an image: maximum dimension, output quality factor and quantization tables, chroma subsampling, whether it re-encodes an image that already matches its target. Profiles are versioned data in the core, each with a "last verified" date shown in the app.
2. **Pre-matching.** Resize and compress the cover to the channel's own target before embedding, so the channel's recompression is close to idempotent and changes few coefficients. Published work on robust JPEG steganography (transport channel matching, dither-modulation robust embedding) takes this route; Phase E reads it properly before coding.
3. **Robust embedding.** Quantization-index-modulation style embedding in low and mid-frequency coefficients of textured blocks, which survive requantization best.
4. **Error correction.** Reed-Solomon or BCH with interleaving across blocks, sized per profile from measured bit-error rates.
5. **Verify before send.** The app simulates the channel locally (resize plus recompress with the profile's tables), extracts from the simulated result, and refuses to report success unless the round trip works.

Candidate channels for 1.0, each confirmed by actually sending test images through it in the Phase E channel lab: WhatsApp (standard and HD), Signal (photo mode), Telegram (compressed photo), Discord, Instagram DM. Expected capacity is in the hundreds of bytes, not kilobytes; Phase E measures it.

### 7.4 Capacity and detectability UI

- Live capacity per mode and per slot, with the payload as a percentage.
- A three-step rating (low, medium, high detectability) from payload-to-capacity ratio and cover texture, with a one-line reason. Thresholds set from the Phase B steganalysis runs (section 18), not guessed.

### 7.5 Cover handling and opsec, built into the flow

- Prefer a fresh camera shot taken in-app or just before. Warn when the cover came from Downloads or a share, since a cover that already exists publicly can be diffed against the original.
- Never reuse a cover. The app keeps a local hash list of covers it has used (opt-out, never leaves the device) and warns on reuse.
- Keep payload well under capacity; the rating does the nagging.
- Never send both the original and the stego version anywhere.

## 8. Text modes

Both modes run the same envelope (section 6) first, so the hidden content is always encrypted. Text capacity is low, and the 32 to 48 byte envelope overhead is a big share of it.

### 8.1 Dictionary words

- A 4096-word list per language gives 12 bits per word. Ciphertext becomes a run of real words.
- Light shaping that the decoder ignores: deterministic capitalization, punctuation, and line breaks so the output reads less like a list.
- Word lists are our own: common, unambiguous, no offensive or alarming words (Kryptos had to clean theirs), no words that differ only by accents or that autocorrect tends to change.
- Honest label: anyone who reads it sees word salad. It hides ciphertext from automated filters and casual eyes, not from a human who looks.
- Size example: a 100-byte message plus 32 bytes of envelope is about 88 words.
- 1.0 ships the English list; other languages are Q7.

### 8.2 Zero-width characters

- Encodes bits as invisible Unicode characters (zero-width space, non-joiner, joiner, word joiner) interleaved into a cover message the user writes. The visible text is exactly what the user typed.
- Honest label, in the UI as "weak": many platforms strip or normalize these characters, and any tool that looks for them finds them instantly. Good for a note in a document or a file, poor against anyone checking.
- Per-platform survival recorded in Help after Phase D testing (whether WhatsApp, Signal, Telegram, SMS, email, and common note apps keep them).

### 8.3 Later, maybe

Natural-looking text from an on-device language model with arithmetic coding. It needs bit-identical model output across devices, which is a project of its own. Not 1.x.

## 9. Feature list: 1.0 and later

1.0:

- Hide and Reveal for PNG, JPEG, Survive-messenger (experimental), dictionary text, zero-width text.
- Payloads: text and any file.
- Passphrase and public-key (age X25519) modes; optional passphrase on top of public key.
- Decoy slot.
- Keys: generate identity, import age identity, contacts by QR or paste, export recipient.
- PGP keys: import Curve25519 public and secret keys (v4 cv25519, v6 X25519) by file or from PGPony via share, for hiding to contacts and revealing with your own key.
- Reveal with a hardware key (OpenPGP card applet on YubiKey, Nitrokey, Token2) holding a Curve25519 encryption key, over NFC or USB (RC1).
- Channel picker on Hide; channel profiles with last-verified dates.
- Capacity meter and detectability rating.
- Cover reuse warning, EXIF strip, in-app camera capture.
- Share target (images and text), open-with for images, share-out.
- Launcher disguise, app lock (biometric or passcode), FLAG_SECURE, clipboard auto-clear.
- Family Settings sections (Help, More from NorseHorse, licenses).

Later:

- iOS app (section 19).
- Desktop app and a CLI from the same core.
- Multi-recipient public-key slots.
- Live key access through PGPony (StegPony asks PGPony to unlock a key instead of importing it).
- Post-quantum composite PGP keys.
- More dictionary languages.
- Batch hide (one payload split across several images with erasure coding, so any k of n recover it).
- Audio covers (WAV, FLAC).

## 10. Android technical notes

### 10.1 Permissions and posture

- No INTERNET permission, ever. Camera permission only when the in-app camera is used. Photo picker (no broad media permission), SAF for files.
- minSdk 26 to match family apps; target current SDK.
- FLAG_SECURE on Reveal and Keys by default, toggle for the rest.

### 10.2 Image I/O

- Images go into the core as raw file bytes, never as Bitmaps. The app only decodes to a Bitmap for thumbnails and previews, which never feed back into the core.
- Output written through SAF or MediaStore as the exact bytes the core produced. Share-out uses a FileProvider URI to the exact file, not a re-encoded bitmap.

### 10.3 Core binding

Same binding approach as the existing Rust cores in PassPony and VaultPony, so the Docker release harness and the F-Droid recipe follow a known path.

### 10.4 Launcher disguise

- `activity-alias` entries with alternate labels and icons, switched with `PackageManager.setComponentEnabledSetting`. A handful of generic choices (for example "Photo Tools", "Notes", "Calculator"-style generic utility), drawn in-house. Never a real app's name or icon.
- Honest limits in Help: the package name `com.stegpony.android` still shows in Settings > Apps and in the F-Droid client; switching can drop home-screen shortcuts on some launchers.
- Google Play's deceptive-behavior policy may object to disguise, so if a `play` flavor ever exists, disguise is a question for that flavor (Q9). The F-Droid build always has it.

### 10.5 Hardware keys

Reveal with an OpenPGP card reuses PGPony Android's card layer: NFC (IsoDep) and USB CCID transports, PIN entry including the KDF-DO itersalted-S2K PIN, the Nitrokey 3 USB fix, and exclusive NFC while a session is open. StegPony reads the card's encryption-key attributes, refuses anything but cv25519 with a plain message, and calls PSO:DECIPHER once per slot. The core never sees a secret key in this mode.

## 11. Privacy posture

- Nothing leaves the device. No network code, no permission for it.
- No logs of payloads, passphrases, or covers. The cover-reuse list stores hashes only and can be cleared or turned off.
- Identity secret key in Android Keystore-wrapped storage; passphrases never stored.
- Clipboard auto-clear after copying revealed text (default 60 seconds).
- Crash reporting: none.

## 12. Threat model and honest limits

In scope: an observer who sees the images or text you send, automated filters looking for ciphertext, casual inspection of your device, someone who forces one passphrase out of you (decoy).

Out of scope, and said so in Help: a forensic examiner with your unlocked phone and time, an adversary with the original cover, an adversary running steganalysis trained on your camera with a high-payload image, an adversary who knows StegPony is installed and insists on a second passphrase.

The help text is written for people whose safety may depend on it: plain, specific, no overclaiming. Security-adjacent copy gets human review in every language (section 17).

## 13. Architecture and stack

- **stegpony-core (Rust).** Envelope (Argon2id, X25519, Elligator 2, HKDF, ChaCha20-Poly1305 from RustCrypto and dalek crates), keyed permutation, slot layout, cost functions, syndrome-trellis coder, PNG I/O (`png` crate), JPEG coefficient I/O (Q6), robust-mode pipeline and channel profiles, ECC, dictionary and zero-width codecs, age key parsing, OpenPGP Curve25519 key import (rpgp), and reveal through an external key exchange (a callback that a hardware key answers). No platform code. Fully built and tested in the cloud session.
- **CLI.** `stegpony` binary in the core repo: hide, reveal, capacity, simulate-channel. Used for fixtures, steganalysis runs, and as the eventual desktop CLI.
- **Android.** `:app` (Compose, Material 3) and the core through the binding in 10.3. Kotlin layer is source-only from Cowork; NorseHorse builds with gradlew on the Mac.
- **Format contract.** `FORMAT.md` in the core repo: envelope, slot layout, permutation, bucket table, Argon2id parameters per version, dictionary list hashes. Test vectors (`envelope_vectors.json`, `png_vectors/`, `jpeg_vectors/`, `text_vectors.json`) are release-gating on every platform.
- **Repos.** `~/Apps/StegPonyCore` (Rust, Apache-2.0 like PGPonyCore and PonyDirect, so the scheme can be audited on its own), `~/Apps/StegPonyAndroid`, later `~/Apps/StegPony` (iOS, no suffix). Repo-local git identity `norsehorse-dev`, no AI attribution, standard gitignores, stage by path.

## 14. Phase plan, RCs, and estimate

Part-time weekday evenings. Survive-messenger is research-grade, so its estimate is the loosest.

**Phase A: core envelope and Lossless.** Envelope, keyed permutation, two-slot layout, bucket padding, Argon2id tuning, X25519 and Elligator 2, PNG spatial embedding with costs and STC, the CLI, test vectors. 6 to 8 evenings. Clean Cowork handoff.

**Phase B: JPEG native.** Coefficient I/O (Q6), J-UNIWARD style costs, STC in the DCT domain, EXIF strip, steganalysis baseline (section 18) that sets the detectability thresholds. 7 to 9 evenings. Cowork handoff.

**Phase C: Android app.** Hide and Reveal flows, share target, Keys with age import and QR, Curve25519 PGP key import (file and PGPony share), decoy UI, capacity meter and rating, cover-reuse warning, in-app camera, app lock, FLAG_SECURE, clipboard clear, launcher disguise, Settings family sections. Hardware-key reveal: core key-exchange callback, card layer ported from PGPony Android, Reveal flow with PIN and tap or USB, tested on the requesting user's Nitrokey 3A NFC and a Token2 PIN+. 13 to 17 evenings (PGP key import and hardware-key reveal added Oct 18).

**RC1 = A + B + C.** Images (Lossless and JPEG), both key modes with age and Curve25519 PGP keys, reveal with a hardware key, decoy, disguise. Goes to the requesting user first, then the Android RC pool. RC2 work does not start until RC1 is built and tested.

**Phase D: text modes.** Dictionary codec and English list, zero-width codec, per-platform survival testing, text flows in the app. 4 to 5 evenings.

**RC2 = RC1 + D.**

**Phase E: Survive-messenger.** Literature pass, channel lab (send calibration images through each platform, record what comes back), profiles, robust embedding, ECC sizing, simulate-and-verify before send, the experimental label and per-channel dates. 8 to 12 evenings.

**RC3 = RC2 + E.**

**Phase F: release.** String freeze, localization (section 17), F-Droid metadata and store graphics, stegpony.app on the Pony family shell (index, privacy, support, help, rc/), fdroiddata MR. 4 to 5 evenings.

**1.0 = A through F**, roughly 42 to 56 evenings, about eleven to fourteen weeks of weekday evenings if StegPony got all of them; maintenance on the existing apps stretches that. Contingency only if the schedule breaks: E moves to 1.1 and 1.0 ships after RC2. Never cut the envelope's no-header property or the decoy's always-two-slots rule; a stego app with a tell is worse than none.

## 15. Distribution and release engineering

- GitHub releases on `norsehorse-dev/StegPonyAndroid` and `norsehorse-dev/StegPonyCore`, direct APK on stegpony.app, F-Droid main repo through an fdroiddata inclusion MR.
- Reproducible builds through the PassPony-style Docker Linux harness (Rust core), from the first tag. One signing key so direct-APK and F-Droid installs update over each other.
- Versioning 1.0.0 / versionCode 100. Each shipped Android update gets its section in NorseHorse_Android_Update_Log.md.
- RC hosting on stegpony.app/rc/ with the APK SHA-256 beside the file.
- Google Play: not at launch. Later only after F-Droid inclusion, and only once the disguise question (Q9) is settled.

## 16. Branding

- Name: StegPony (sweep pending, Q1). Register stegpony.app.
- Icon: a horse mark partly made of pixel squares, or a horse silhouette inside a photo frame with a few pixels shifted. Generated in openart.ai and cleaned up, per the usual flow. Disguise icons are separate and deliberately plain.
- Color: open (Q10). Suggestion: muted violet or ink indigo on charcoal, which nothing else in the family uses.
- Taglines to pick from: "Hide the fact you're hiding something." and "Encrypted, then invisible."

## 17. Localization

Family set at 1.0: en, de, es, fr, zh-Hans, pt-BR, ru. Plan it as multi-agent from the start (one agent per language plus a checker pass for missing keys), since single-pass translation tends to miss strings. Help and every honest-limits string is security-adjacent and gets human review through native readers in the tester pool for ru, zh-Hans, and pt-BR, assignments kept outside the repo. Dictionary word lists are a separate job from UI strings (Q7). Budget two evenings in Phase F.

## 18. Testing

- **Core unit tests:** envelope vectors, wrong-key and no-payload images indistinguishable to the extractor, bucket trials, both slots independently recoverable, an unused slot statistically indistinguishable from a used one, Elligator 2 round trips, age key parsing against age's own test keys, PGP key import against keys made by PGPony and GnuPG (v4 and v6, locked and unlocked secret keys, refusal of RSA and NIST keys).
- **Bit-exact cross-platform:** the CLI's output equals the Android app's output for the same inputs and seed, across devices.
- **Steganalysis:** run Aletheia (open-source steganalysis toolkit) and a rich-model classifier against StegPony output at several payloads, on a cover set shot on the test phones. Compare with PixelKnot (F5) and plain LSB as baselines. The results set the rating thresholds in 7.4 and go into Help as plain numbers.
- **Robustness:** for Survive-messenger, automated channel simulation in CI, and a manual channel-lab pass through every real platform before each RC, recorded with dates.
- **Text:** zero-width survival per platform, dictionary round-trip through copy and paste, autocorrect, and line wrapping.
- **Android:** no Bitmap ever reaches the core (a test asserts the core input is file bytes), share-out bytes equal core output, disguise switching on several launchers, FLAG_SECURE, hardware-key reveal on the requesting user's Nitrokey 3A NFC and on a Token2 PIN+ over USB (including whether each card accepts torsion-dirty ephemeral points), no INTERNET permission in the merged manifest.
- **Testers:** the requesting user gets RC1 first, then the Android RC pool. Same RC pattern as the rest of the family.

## 19. iOS and desktop

- **Desktop** follows from the core: the CLI first, then a GUI on the family's desktop pattern. Low marginal cost.
- **iOS** later. The core and format are platform-neutral, so the iOS app is a UI job. Positioning matters more than code: the listing leads with the encrypted envelope, the decoy, and age key interop, not "hide messages in photos." Decide after Android 1.0 has users and the 4.3(a) picture is clearer.

## 20. Open questions

Each carries a recommendation that stands as a provisional decision unless overridden.

1. **Name sweep and domain.** Run the full sweep and the registrar check for stegpony.app. Recommendation: register stegpony.app once the sweep is clear.
2. **Argon2id parameters.** 64 MiB / t=3 / p=1 proposed. Recommendation: tune on the slowest Android test device in Phase A; target under 1.5 seconds per derivation. Decided Oct 16, 2026: 128 MiB / t=3 / p=4, 0.34 s per derivation on the slowest test phone. On iOS, reveal has to run in the main app, since a share extension's memory limit is too small for a 128 MiB derivation.
3. **Locate-key strength for public-key mode.** Recommendation: ship as described, with the optional shared passphrase on top and the limit stated in Help.
4. **Age key reuse.** Recommendation: yes. Same key type, free interop with AgePony, no new key format to teach users.
5. **Multi-recipient.** Recommendation: not in 1.0. A fixed-size recipient table later, padded so the count does not leak.
6. **JPEG coefficient I/O.** libjpeg-turbo FFI or pure-Rust entropy coder. Recommendation: libjpeg-turbo through FFI for 1.0 (proven, handles progressive and odd files), built in the Docker harness; revisit pure Rust later if the C dependency causes F-Droid friction. Decided Oct 16, 2026: pure Rust in stegpony-core, baseline first, then progressive decode and encode; libjpeg (via Python jpeglib) as the test oracle. Requirements come from sample camera JPEGs from the Android test phones (baseline or progressive, subsampling, restart intervals, table style, Ultra HDR gain maps). First sample, Oct 16, 2026 (moto g play 2026, four HDR shots): baseline SOF0, 3280x2460, 4:2:0, very high quality (luma quant table starts 2, 1, 1, 1), no restart markers, no gain map or trailing data, the full Annex K standard Huffman tables (all 162 AC symbols, so embedding never forces a table rebuild on this phone), EXIF plus a Motorola APP6 maker block (MMIMETA) that the default metadata strip removes. The other test phones still to be sampled. Codec status the same night: baseline, extended sequential and progressive decode and encode in stegpony-core, byte-identical round trip on all four samples and on libjpeg 6b/9e, libjpeg-turbo and mozjpeg output, checked by tools/check_jpeg.py.
7. **Dictionary languages.** Recommendation: English list at 1.0; add the family languages one at a time with native review, since a bad word list is a tell.
8. **Survive-messenger channels.** Recommendation: start with WhatsApp, Signal, Telegram; add Discord and Instagram DM only if the channel lab shows stable behavior.
9. **Disguise on a future Play flavor.** Recommendation: leave it out of any Play build; F-Droid and direct APK keep it.
10. **Brand color.** Recommendation: ink indigo on charcoal.
11. **App lock default.** Recommendation: off by default, offered during onboarding, with the decoy explained on the same screen.
12. **Core license.** Recommendation: Apache-2.0 for StegPonyCore, matching PGPonyCore and PonyDirect, so the scheme can be audited and reused.
