# Messenger channel lab (Phase E)

Measure what a messenger actually delivers before choosing a robust carrier. These
are plain calibration photos, with no hidden payload. A completed run describes a
specific app version, send option, pair of devices and date. It is not a promise
that future messages, other clients, or embedded payloads will survive.

## Prepare a run

Requires Python 3.10+ and Pillow. Use an existing environment with Pillow, or install
it in a local virtual environment. Start small, then expand to multiple phones and
daylight, sky, walls, foliage, and dark textured scenes.

From the repository root:

```
python3 tools/channel_lab/lab.py prepare drafts/covers --limit 3 --out drafts/channel-lab-preview --dry-run
python3 tools/channel_lab/lab.py prepare PHOTO1.jpg PHOTO2.jpg PHOTO3.jpg --out drafts/channel-lab/run-01
```

The default grid is long edges 1600, 2048 and original dimensions, at Pillow JPEG
quality settings 80 and 95, with 4:2:0 sampling: six files per photo. These are probe
settings, not claims about messenger limits. `original` means original *display
dimensions*, still re-encoded after EXIF rotation. It is not an original-file copy.
No image is enlarged. Separate requested sizes can produce identical dimensions on
small inputs; the manifest records both requested and actual sizes. No MCU-aligned
crop or artificial label is added. Images have EXIF, ICC and other metadata removed;
RGB values are not color-managed, so use ordinary SDR, sRGB phone photos for this
first run. Originals are never changed. Multi-frame and non-RGB/gray inputs fail
before a run is created.

Once a channel has returned photos, `--match RETURNED.jpg` encodes with that file's
exact quantization tables instead of `--qualities` (pre-matching), so the next batch
measures how much the channel still changes when it is handed its own tables:

```
python3 tools/channel_lab/lab.py prepare PHOTO1.jpg PHOTO2.jpg --sizes 1600 --match drafts/channel-lab/run-01/received/signal-photo/p001_m1600_q80_420.jpg --out drafts/channel-lab/run-02
```

`--headroom` pulls any 16x16 area that clips (decoded pixels at 0 to 2 or 253 to
255) toward its own mean, a little at a time, until a JPEG round trip no longer
clips anywhere. Decoders disagree most at clipped pixels: in real Telegram returns
every changed AC coefficient sat in a block with clipped pixels, and covers with
headroom came back with no AC changes at all. Ids get an `_h` suffix and the
manifest records how many areas were touched.

Matched images are named with the table hash (`p001_m1600_ta66d0143_420`), and the
manifest records the file the tables came from. The sampling must match the file's.

Use `--sizes 1280,1600,2048,2560,original --qualities 70,80,90,95` for a wider sweep,
and a separate `--sampling 444` run to probe chroma handling. Folder input is flat by
default; `--recursive` opts into subfolders and `--limit` caps source count. The
output folder must be new and outside an input photo folder. Nothing is uploaded.

The run contains:

- `send/`: the exact JPEGs to transfer to the phone and send.
- `manifest.json`: source hashes, generated hashes, dimensions, file sizes,
  quantization tables (natural frequency order), component sampling/table selectors,
  progressive flags, encoder versions and generator hash.
- `sessions.json`: fill in app versions, sender/receiver device and OS, send/receive
  dates with time zones, send mode, and exact download method.
- Four CSV worksheets: stable image IDs plus a blank `received` filename and notes.
- `received/CHANNEL/`: place returned files here without re-encoding them.
- `reports/`: comparison results, generated once returned files are assigned.

The manifest includes local source paths. Keep the entire run under `drafts/`, which
is gitignored; commit only the tooling and anonymized, reviewed measurements later.

## Send and collect

1. Copy `send/` to the sending phone without converting the files. Unzip locally
   if transferring a ZIP. Keep that copy separate from returned photos.
2. Send each photo to yourself, separately, as a **photo**, using four distinct
   test sessions: WhatsApp standard, WhatsApp HD, Signal photo, Telegram compressed
   photo. Record the setting actually shown by that version of the app, including
   any global media-quality setting. `whatsapp-default` is for photos sent without
   touching any quality option, which is what most people do. If an option is unavailable, record that;
   do not substitute a document/file send and call it a photo test.
3. Use the filename stem as a caption or keep an ordered send log so renamed files
   can be paired correctly. Do not draw labels on, crop, or edit the photos.
4. Download from the receiving client, preferably another device. Saving from the
   sending phone's own chat can retrieve its cached original instead of the file
   delivered through the service, yielding a misleading pass-through result.
   Record the receiver and download method. Do not use screenshots, copied preview
   thumbnails, or an image editor to save the results.
5. Preserve the received bytes and place them under `received/CHANNEL/`. For each
   worksheet ID, enter its run-relative path, for example
   `received/signal-photo/saved_001.jpg`. Pairing is manual; the tool cannot prove
   that a renamed photo is the right one. Captions or an ordered log are essential.
6. Add a separate control: send the `send/` ZIP as a file/document, download and
   unzip on the receiving client, then compare its file hashes with the manifest
   (`lab.py control`, below).
   Keep this control separate from photo tests. Repeat at least one photo test to
   check whether processing is stable. Use a fresh run for a different app version,
   device path, or repeat; do not pool contexts into one worksheet.

## Compare the received files

Build the core's coefficient reader once, so compare can look below the pixels:

```
cargo build --release --example jpeg_tool
```

```
python3 tools/channel_lab/lab.py compare drafts/channel-lab/run-01 --channel whatsapp-standard
python3 tools/channel_lab/lab.py compare drafts/channel-lab/run-01 --channel whatsapp-hd
python3 tools/channel_lab/lab.py compare drafts/channel-lab/run-01 --channel signal-photo
python3 tools/channel_lab/lab.py compare drafts/channel-lab/run-01 --channel telegram-photo
```

Partial worksheets are allowed and missing files are counted. No assigned return
is an error, rather than a completed test. Changed sent files, duplicate or unknown
IDs, paths outside the run, and assigning the same received path twice are rejected.
A return must sit under its own channel's folder (`received/signal-photo/` for the
Signal worksheet), so a sent file or another channel's file can't pass as a return.
Existing reports are never overwritten; pass `--out NEW_REPORT.json` for a revision.

A report includes exact byte equality, actual dimensions and file size, JPEG grids
and quantization tables, and decoded RGB equality when dimensions match. JPEG, PNG
and WebP returns can be inspected; a format change is recorded. A same-table result
is **not** evidence of the same encoder, unchanged DCT coefficients, or payload
survival. A byte-identical result proves only this file's passage through the
recorded path. Calibration images contain no payload, so this tool cannot measure
message error rates or establish robust capacity.

Each file's tables are also named: `IJG q80` means they equal libjpeg's standard
tables at quality 80 exactly; anything else is `other` plus a short hash, so two
returns with the same hash share tables. A match names the table family, not the
encoder.

When a JPEG comes back with the same stored dimensions and sampling, compare reads
the quantized coefficients of both files with the core's own parser (baseline and
progressive) and tests the simplest channel model: every received coefficient is
the sent one requantized from the sent table to the received table, rounding half
away from zero. With equal tables that means unchanged. The report gives the match
rate, per component the DC and AC mismatch counts, mismatches on AC coefficients
that were zero and nonzero when sent, the mismatch rate at each zigzag position,
and a histogram of how far off the misses were. Misses come from the pixel round
trip (IDCT rounding, clipping, color conversion, chroma resampling, any filtering).
A high match rate says the channel is close to requantization for this photo; it
says nothing yet about payload survival. Without `jpeg_tool` built, compare still
runs and marks coefficients as not compared.

## File control

After the `send/` ZIP has gone through as a file or document, unzip it on the
receiving side and point the control at that folder:

```
python3 tools/channel_lab/lab.py control drafts/channel-lab/run-01 ~/Downloads/send --note "Signal, file send"
```

Files are matched to the manifest by SHA-256, so renaming doesn't matter. The
report (`reports/file-control.json`) lists which prepared files came back
byte-identical, which never came back, and any other files in the folder.

## Summary

```
python3 tools/channel_lab/lab.py summary drafts/channel-lab/run-01
```

Writes `reports/summary.md` from every channel report and the file control: per
channel, each image's sent and received size and tables, size ratio, byte equality
and coefficient match rate, then which sent sizes came back unchanged and which
were resized to what. Reports from a different manifest are refused.

Next: identify resize thresholds and quantization-table families, generate another
batch pre-matched to observed output, compare candidate local encoders against the
returned JPEG coefficients, and then test real embedded messages. A channel profile
must not become "verified" until complete two-slot messages survive real delivery.

## Tests

```
python3 -m unittest discover -s tools/channel_lab -v
```

Tests exercise EXIF rotation and metadata removal, dimensions and encoder tables,
source preservation, reproducibility within one environment, dry runs, renamed
returns, simulated resize/recompression, incomplete runs and invalid mappings,
returns outside their channel folder, IJG table naming against Pillow, the file
control and the summary. With `jpeg_tool` built they also check the coefficient
comparison on a pass-through and a recompressed return; without it that test is
skipped. They do not contact or simulate any particular messenger service.
