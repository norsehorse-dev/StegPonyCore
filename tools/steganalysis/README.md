# Steganalysis baseline

How detectable native JPEG output is, measured the way an adversary would: train a detector on clean photos and StegPony output from the same camera, then test it on photos it has not seen. The results set the Low / Medium / High thresholds in `jpeg::carrier::rating`.

## Running it

```
pip install numpy scipy jpeglib conseal sealwatch
tools/steganalysis/run.sh PHOTO_DIR drafts/steganalysis
```

`PHOTO_DIR` holds unedited camera JPEGs, one scene per photo (no burst frames), all from one phone and quality setting. Keep the photos and the work directory under `drafts/`, which git ignores; nothing here belongs in the repo. sealwatch pulls in PyTorch, which is large. A run over 66 photos takes about four hours on two cores, nearly all of it feature extraction.

What it does:

1. `make_tiles.py` cuts each photo into 512x512 tiles in the coefficient domain, aligned to the MCU grid, so tiles keep the camera's own coefficients and tables. `--checker` keeps every other tile, 12 per 12-megapixel photo.
2. `stego_batch` (an example in stegpony-core) embeds with the real engine at several buckets, public-key mode, second slot filled as always.
3. `sims.py` makes two reference sets at bucket 10's payload, luma only, at the rate-distortion bound: ideal ternary J-UNIWARD (what StegPony's costs could reach) and nsF5 (the F5 family PixelKnot uses).
4. `features.py` extracts color DCTR (24000 dimensions: Y, Cb and Cr at their own resolutions).
5. `classify.py` trains an FLD ensemble with five folds split by capture time, so tiles of one photo, and neighbouring shots of one scene, never sit on both sides of a split. It reports P_E, the minimum average of false alarms and misses: 0.5 is a coin flip, 0 is certain detection.

## Results, October 2026

66 photos from one Android test phone (3280x2464, quality 95, 4:2:0, all shot within a few minutes late at night), 792 tiles. Payload counts both slots, in bits per nonzero AC coefficient (bpnzac) of the cover; a tile averages 85,756 nonzero AC coefficients.

| Set | Bytes per slot | bpnzac | P_E | Rating |
|---|---|---|---|---|
| StegPony, bucket 6 | 512 | 0.10 | 0.445 | Low |
| StegPony, bucket 8 | 1,024 | 0.19 | 0.398 | Medium |
| StegPony, bucket 10 | 2,048 | 0.39 | 0.232 | High |
| StegPony, bucket 12 | 4,096 | 0.78 | 0.031 | High |
| StegPony, bucket 14 | 8,192 | 1.56 | 0.001 | High |
| Ideal ternary J-UNIWARD | 2,048 | 0.39 | 0.354 | |
| nsF5 (PixelKnot family) | 2,048 | 0.39 | 0.055 | |

Fold-to-fold spread was under 0.05 everywhere except bucket 12 (0.000 to 0.087).

Reading it:

- At the same payload StegPony is far harder to detect than F5-style embedding (P_E 0.232 against 0.055).
- It falls short of ideal J-UNIWARD (0.354). StegPony makes about 1.5 times as many changes at the same payload, which is what binary parity embedding costs compared with ternary embedding, plus some loss from splitting the cover into two slots.
- Nearly all changes land in luma: chroma at quality 95 is too smooth to be cheap.

Thresholds: Low up to 0.15 bpnzac, Medium up to 0.30, High above. They sit below the measured points on purpose. This detector trained on about 630 pairs; detectors trained on tens of thousands of images, deep-learning detectors (SRNet-class), and full-size photos (more coefficients for the detector to pool) all detect more than this baseline does. The rating counts only the elements the engine uses: each slot is capped at 2 million elements, about a third of a 12-megapixel photo's AC coefficients, so on such a photo with a similar share of nonzero coefficients Low leaves room for about 8 KB per slot.

Limits of this run: one phone, one quality setting, one late-night session. Daylight scenes with sky and walls have fewer nonzero coefficients, which the bpnzac rule accounts for, but they have not been measured. Re-run with other phones and daylight shots before 1.0.
