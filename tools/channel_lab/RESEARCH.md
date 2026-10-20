# Phase E research notes

Reviewed October 20, 2026. This is a research shortlist and experiment plan, not a
robust carrier specification. No messenger behavior has been measured in this lab
yet. Existing image and text formats stay as they are.

## Evidence to investigate

- [Robust adaptive steganography based on dither modulation and modification with re-compression](https://arxiv.org/html/2007.08301v2),
  published 2021. Uses dither modulation, recompression feedback, a lower-frequency
  domain and additional check information. Its experiments assume a known channel
  quality factor. This supports testing feedback against an observed channel;
  it does not establish robustness to arbitrary resizing or unknown encoders.
- [Improving Dither Modulation based Robust Steganography by Overflow Suppression](https://arxiv.org/abs/2110.08697),
  2021 preprint. The abstract identifies out-of-range reconstructed pixels as a
  major source of recompression errors and describes scaling/truncation with
  asymmetric costs. Abstract reviewed; full text was unavailable during this pass.
  Follow-up: measure clipping in bright and dark blocks before adopting its method.
- [Robust image steganography against lossy JPEG compression based on embedding domain selection and adaptive error correction](https://arxiv.org/html/2304.13297v1),
  2023 preprint. Iteratively adjusts the embedding domain and Reed-Solomon redundancy
  based on simulated recompression/extraction. It makes error correction a measured
  tradeoff instead of a fixed overhead. Follow-up: measure both error bursts and
  complete-message failures; excessive redundancy also increases embedding changes.
- [Errorless Robust JPEG Steganography using Outputs of JPEG Coders](https://janbutora.github.io/assets/pdfs/robust_stego.pdf).
  Constructs stable coefficient sets by interrogating the target compressor, with
  embedding divided into frequency lattices. Its guarantee depends on knowing the
  coding process and parameters, and assumes the image is sized to avoid resizing.
  Its evaluations include multiple encoders and Slack. This is a candidate only
  after matching the actual codec path; equal quantization tables alone are
  insufficient. It also notes that syndrome decoding propagates channel errors.

## Consequences for StegPony (engineering assessment)

1. Separate resize discovery from recompression modeling. Pre-size before robust
   embedding; do not assume a JPEG-only technique survives a changed block grid.
2. Keep measured DQT tables and sampling factors. A single estimated "quality"
   value cannot define a channel. Test more than one scene, phone and app setting.
3. First compare downloaded outputs with candidate codec implementations. Encoder
   rounding, chroma conversion and any filtering can matter even with matching
   dimensions and tables. Repeat actual sends to detect variable processing.
4. Prototype dither/quantization-index embedding with channel feedback, or stable
   coefficient selection with a matched compressor. Compare against an ordinary
   native-JPEG control at equal delivered payload. Do not choose either now.
5. Correct residual errors before opening the existing authenticated envelope.
   Select error-correction/interleaving parameters from measured error patterns and
   end-to-end failures. Successful decoding means the whole authenticated payload,
   not an acceptable average bit error rate.
6. Preserve the always-two-slots rule, hidden framing and wrong-key behavior.
   Capacity must cover both encrypted heads/bodies and robustness overhead. Any
   required method/profile discovery must have a receiver-visible derivation that
   does not expose a clear format marker or depend on a sender-only coefficient set.
7. Local simulate-and-reveal is a necessary check, not proof of real-channel success.
   Profiles need app versions, device paths, date, real send results and honest
   scope. Robust-mode detectability needs its own measurements; native JPEG ratings
   cannot be reused.

## Gates before a carrier spec

- Calibration from WhatsApp standard and HD, Signal photo, Telegram compressed
  photo, including a repeat and a byte-preserving file control.
- A second sweep around each observed resize threshold, and pre-matched images.
- A local channel model whose coefficient changes track held-out returned photos,
  plus measured worst cases such as clipped highlights, sky, foliage and night noise.
- A small-payload prototype with complete two-slot authentication after real sends,
  capacity/cost/timing measurements, and a steganalysis comparison against clean
  photos that have passed through the same channel.

The first batch only measures processing. It cannot answer whether a usable,
sufficiently inconspicuous robust carrier exists for any of these channels.
