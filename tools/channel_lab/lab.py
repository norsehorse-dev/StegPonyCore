#!/usr/bin/env python3
"""Prepare and compare Phase E messenger calibration photos. Needs Pillow.

No messages or uploads, no hidden payload, no changes to source photos. All paths
in a run manifest are local lab records; put runs under gitignored drafts/.

Coefficient comparison uses the core's own JPEG reader through the jpeg_tool
example (cargo build --release --example jpeg_tool). Without it, compare still
runs and records that coefficients were not compared.
"""
import argparse
import csv
import hashlib
import io
import json
import platform
import subprocess
import sys
import tempfile
from array import array
from datetime import datetime, timezone
from pathlib import Path

from PIL import Image, ImageChops, ImageOps, __version__ as PILLOW_VERSION, features

CHANNELS = ("whatsapp-standard", "whatsapp-hd", "whatsapp-default", "signal-photo", "telegram-photo")
EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp"}
SCHEMA = 1
REPO = Path(__file__).resolve().parents[2]
DEFAULT_JPEG_TOOL = REPO / "target" / "release" / "examples" / "jpeg_tool"

# T.81 Annex K example tables, natural (row-major) order. libjpeg and its
# descendants scale these for their quality setting.
IJG_LUMA = (16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55,
            14, 13, 16, 24, 40, 57, 69, 56, 14, 17, 22, 29, 51, 87, 80, 62,
            18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113, 92,
            49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99)
IJG_CHROMA = (17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99,
              24, 26, 56, 99, 99, 99, 99, 99, 47, 66, 99, 99, 99, 99, 99, 99) + (99,) * 32

# Natural index of each zigzag position.
ZIGZAG = (0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5,
          12, 19, 26, 33, 40, 48, 41, 34, 27, 20, 13, 6, 7, 14, 21, 28,
          35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51,
          58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63)


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def ijg_table(base, quality):
    """libjpeg's jpeg_set_quality scaling with force_baseline."""
    scale = 5000 // quality if quality < 50 else 200 - 2 * quality
    return [min(255, max(1, (b * scale + 50) // 100)) for b in base]


IJG_TABLES = {q: (ijg_table(IJG_LUMA, q), ijg_table(IJG_CHROMA, q)) for q in range(1, 101)}


def ijg_quality(tables):
    """The libjpeg quality whose standard tables equal these exactly, else None.

    An exact match identifies the table family, not the encoder: libjpeg-turbo,
    Android's encoders and many servers all produce these tables.
    """
    if not tables or set(tables) - {"0", "1"}:
        return None
    for q, (luma, chroma) in IJG_TABLES.items():
        if tables.get("0", luma) == luma and tables.get("1", chroma) == chroma:
            return q
    return None


def table_family(info):
    """A short, stable name for a file's quantization tables."""
    q = info["ijg_quality"] if "ijg_quality" in info else ijg_quality(info.get("quantization_natural"))
    if q:
        return f"IJG q{q}"
    tables = info.get("quantization_natural") or {}
    if not tables:
        return "none"
    digest = sha256(json.dumps(tables, sort_keys=True).encode())[:8]
    return f"other {digest}"


def describe(data):
    """Actual encoder output, not a guessed JPEG quality number.

    Pillow exposes JPEG tables in natural order and components as
    (component id, horizontal sampling, vertical sampling, table id).
    """
    with Image.open(io.BytesIO(data)) as im:
        im.load()
        return {
            "sha256": sha256(data), "bytes": len(data), "format": im.format,
            "width": im.width, "height": im.height, "mode": im.mode,
            "orientation": im.getexif().get(274, 1),
            "progressive": bool(im.info.get("progressive", im.info.get("progression", False))),
            "components": [list(c) for c in getattr(im, "layer", [])],
            "quantization_natural": {str(k): list(v) for k, v in getattr(im, "quantization", {}).items()},
            "has_exif": bool(im.getexif()), "has_icc": bool(im.info.get("icc_profile")),
            "ijg_quality": ijg_quality({str(k): list(v) for k, v in getattr(im, "quantization", {}).items()}),
        }


def unclip(image, encode, low=2, high=253, rounds=12, factor=0.85):
    """Pull 16x16 areas that clip after a JPEG round trip toward their mean until none do.

    Messenger decoders disagree most where decoded pixels clip at 0 or 255 (color
    conversion, chroma upsampling, IDCT rounding). In real Telegram returns every
    changed AC coefficient sat in a block with clipped pixels. Returns the adjusted
    image, how many 16x16 areas were touched and the number of rounds used.
    """
    im = image.convert("RGB").copy()
    width, height = im.size
    touched = set()
    for round_no in range(rounds):
        decoded = Image.open(io.BytesIO(encode(im))).convert("RGB")
        px = decoded.load()
        bad = {(x // 16, y // 16) for y in range(height) for x in range(width)
               if min(px[x, y]) <= low or max(px[x, y]) >= high}
        if not bad:
            return im, len(touched), round_no
        touched |= bad
        src = im.load()
        for bx, by in bad:
            xs = range(bx * 16, min(bx * 16 + 16, width))
            ys = range(by * 16, min(by * 16 + 16, height))
            n = len(xs) * len(ys)
            mean = [min(max(sum(src[x, y][c] for x in xs for y in ys) / n, 40), 215) for c in range(3)]
            for y in ys:
                for x in xs:
                    p = src[x, y]
                    src[x, y] = tuple(round(mean[c] + (p[c] - mean[c]) * factor) for c in range(3))
    raise ValueError(f"Still clipping after {rounds} rounds")


def write_json(path, value):
    with path.open("x", encoding="utf-8") as f:
        json.dump(value, f, indent=2, ensure_ascii=False, allow_nan=False)
        f.write("\n")


def photo_paths(inputs, recursive):
    found = []
    for name in inputs:
        path = Path(name).expanduser().resolve()
        if path.is_dir():
            found.extend(sorted(p for p in (path.rglob("*") if recursive else path.iterdir())
                                if p.is_file() and p.suffix.lower() in EXTENSIONS))
        elif path.is_file():
            found.append(path)
        else:
            raise ValueError(f"Input not found: {path}")
    return list(dict.fromkeys(found))


def positive_list(value):
    try:
        result = list(dict.fromkeys(int(v) for v in value.split(",")))
        if not result or any(v <= 0 for v in result):
            raise ValueError
        return result
    except ValueError as e:
        raise argparse.ArgumentTypeError("Expected comma-separated positive integers") from e


def size_list(value):
    try:
        result = list(dict.fromkeys(0 if v == "original" else int(v) for v in value.split(",")))
        if not result or any(v < 0 for v in result):
            raise ValueError
        return result
    except ValueError as e:
        raise argparse.ArgumentTypeError("Expected pixel sizes or original, comma-separated") from e


def prepare(args):
    photos = photo_paths(args.photos, args.recursive)
    if args.limit:
        photos = photos[:args.limit]
    if not photos:
        raise ValueError("No photos found")
    if any(q > 100 for q in args.qualities):
        raise ValueError("JPEG qualities must be in 1..100")
    match = getattr(args, "match", None)
    if match:
        # Pre-matching: encode with the exact tables a channel returned, instead of a
        # quality setting, so the channel's recompression has less to change.
        raw = match.expanduser().read_bytes()
        info = describe(raw)
        tables = info["quantization_natural"]
        if info["format"] != "JPEG" or set(tables) != {"0", "1"}:
            raise ValueError("--match needs a JPEG with one luma and one chroma table")
        if [c[1:3] for c in info["components"]] != ([[2, 2], [1, 1], [1, 1]] if args.sampling == "420" else [[1, 1]] * 3):
            raise ValueError(f"--match file's sampling is not {args.sampling}; pass the matching --sampling")
        family = table_family(info)
        encodings = [(f"t{family.split()[-1]}", None, [tables["0"], tables["1"]])]
        matched = {"file": match.name, "sha256": info["sha256"], "tables": family}
    else:
        encodings = [(f"q{q}", q, None) for q in args.qualities]
        matched = None
    out = args.out.expanduser().resolve()
    if out.exists():
        raise ValueError(f"Run folder already exists; choose a new folder: {out}")
    # Keep generated files out of input folders, including recursive input trees.
    for source in args.photos:
        directory = Path(source).expanduser().resolve()
        if directory.is_dir() and out.is_relative_to(directory):
            raise ValueError("Run folder must be outside the input photo folder")
    n = len(photos) * len(args.sizes) * len(encodings)
    print(f"{len(photos)} source photos, {n} calibration JPEGs, {len(CHANNELS)} channel worksheets")
    if args.dry_run:
        for p in photos:
            print(p)
        return
    # Validate all inputs before creating the run. No partial run for a bad input.
    for path in photos:
        with Image.open(path) as im:
            im.load()
            if im.mode not in ("RGB", "L") or getattr(im, "n_frames", 1) != 1:
                raise ValueError(f"Use a single-frame RGB or gray photo: {path}")
    out.mkdir(parents=True)
    (out / "send").mkdir()
    (out / "received").mkdir()
    (out / "reports").mkdir()
    manifest = {
        "schema": SCHEMA, "created_utc": datetime.now(timezone.utc).isoformat(),
        "purpose": "Channel calibration only; no embedded payload or survival claim",
        "generator_sha256": sha256(Path(__file__).read_bytes()),
        "encoder": {"python": platform.python_version(), "pillow": PILLOW_VERSION,
                    "jpeg": features.version_codec("jpg"), "libjpeg_turbo": features.version_feature("libjpeg_turbo")},
        "settings": {"long_edges": args.sizes,
                     "qualities": [] if matched else args.qualities, "matched_tables": matched,
                     "sampling": args.sampling, "resize": "LANCZOS, never upscale",
                     "orientation": "EXIF transposed before resize", "metadata": "stripped",
                     "color": "decoded RGB, no ICC color transform",
                     "headroom": "16x16 areas that clip after a round trip pulled toward their mean"
                                 if getattr(args, "headroom", False) else None},
        "sources": [], "images": [],
    }
    for index, path in enumerate(photos, 1):
        raw = path.read_bytes()
        source_id = f"p{index:03d}"
        source_info = describe(raw)
        manifest["sources"].append({"id": source_id, "path": str(path), **source_info})
        with Image.open(io.BytesIO(raw)) as im:
            oriented = ImageOps.exif_transpose(im).convert("RGB")
            # Copy into a fresh image; EXIF/ICC/XMP must not leak through .info.
            rgb = Image.new("RGB", oriented.size)
            rgb.paste(oriented)
        for edge in args.sizes:
            resized = rgb.copy()
            if edge:
                resized.thumbnail((edge, edge), Image.Resampling.LANCZOS)
            for tag, quality, qtables in encodings:
                label = str(edge) if edge else "original"
                image_id = f"{source_id}_m{label}_{tag}_{args.sampling}"
                relative = f"send/{image_id}.jpg"
                data = io.BytesIO()
                options = {"qtables": qtables} if qtables else {"quality": quality}
                options.update(subsampling=0 if args.sampling == "444" else 2,
                               optimize=False, progressive=False)

                def encode(img, options=options):
                    buffer = io.BytesIO()
                    img.save(buffer, "JPEG", **options)
                    return buffer.getvalue()

                prepared, areas = resized, None
                if getattr(args, "headroom", False):
                    prepared, areas, _ = unclip(resized, encode)
                    image_id += "_h"
                    relative = f"send/{image_id}.jpg"
                prepared.save(data, "JPEG", **options)
                encoded = data.getvalue()
                (out / relative).write_bytes(encoded)
                manifest["images"].append({"id": image_id, "source_id": source_id,
                    "file": relative, "requested_long_edge": edge or "original",
                    "requested_quality": quality, "headroom_areas": areas, **describe(encoded)})
        print(f"prepared {source_id}: {path.name}")
    write_json(out / "manifest.json", manifest)
    sessions = {}
    for channel in CHANNELS:
        (out / "received" / channel).mkdir()
        with (out / f"{channel}.csv").open("x", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "received", "notes"])
            writer.writeheader()
            for image in manifest["images"]:
                writer.writerow({"id": image["id"], "received": "", "notes": ""})
        sessions[channel] = {"app_version": "", "sender_device_os": "", "receiver_device_os": "",
            "sent_at": "", "received_at": "", "send_mode": channel,
            "receive_method": "", "notes": ""}
    write_json(out / "sessions.json", sessions)
    print(f"Ready: {out / 'send'}\nRecord versions in sessions.json and returned filenames in each channel CSV.")


def resolve_inside(root, relative):
    path = (root / relative).resolve()
    if not path.is_relative_to(root.resolve()):
        raise ValueError(f"Path escapes run folder: {relative}")
    return path


def block_counts(info):
    """Real (unpadded) blocks per component, as T.81 A.1.1 and the core compute them."""
    comps = info["components"]
    hmax = max(c[1] for c in comps)
    vmax = max(c[2] for c in comps)
    counts = []
    for _, h, v, _ in comps:
        cw = -(-info["width"] * h // hmax)
        ch = -(-info["height"] * v // vmax)
        counts.append((-(-cw // 8), -(-ch // 8)))
    return counts


def read_coefficients(tool, path, info):
    """Quantized DCT coefficients per component, read by the core's own parser."""
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "coefs.bin"
        done = subprocess.run([str(tool), "dump", str(path), str(out)],
                              capture_output=True, text=True)
        if done.returncode:
            raise ValueError(f"jpeg_tool could not read {path.name}: {done.stderr.strip()}")
        coefs = array("h")
        coefs.frombytes(out.read_bytes())
    if sys.byteorder != "little":
        coefs.byteswap()
    parts, offset = [], 0
    for w, h in block_counts(info):
        n = w * h * 64
        parts.append(coefs[offset:offset + n])
        offset += n
    if offset != len(coefs):
        raise ValueError(f"Coefficient count of {path.name} does not match its frame header")
    return parts


def requantize(value, q_from, q_to):
    """Nearest coefficient after changing quantizer, rounding half away from zero."""
    if q_from == q_to:
        return value
    num = abs(value) * q_from
    level = (2 * num + q_to) // (2 * q_to)
    return level if value >= 0 else -level


def coefficient_comparison(tool, sent_path, sent_info, received_path, received_info):
    """Compare quantized coefficients when the block grid survived.

    The model is pure requantization: each received coefficient predicted as the
    sent one rescaled from the sent quantizer to the received one. With equal tables
    the prediction is "unchanged". Deviations come from the pixel round trip
    (IDCT, clipping, color conversion, chroma resampling, any filtering).
    """
    if received_info["format"] != "JPEG":
        return {"skipped": "received file is not a JPEG"}
    if (sent_info["width"], sent_info["height"]) != (received_info["width"], received_info["height"]):
        return {"skipped": "stored dimensions differ"}
    if [c[1:3] for c in sent_info["components"]] != [c[1:3] for c in received_info["components"]]:
        return {"skipped": "component sampling differs"}
    if tool is None:
        return {"skipped": "jpeg_tool not built or not runnable here"}
    sent = read_coefficients(tool, sent_path, sent_info)
    received = read_coefficients(tool, received_path, received_info)
    components = []
    for index, (s, r) in enumerate(zip(sent, received)):
        qs = sent_info["quantization_natural"][str(sent_info["components"][index][3])]
        qr = received_info["quantization_natural"][str(received_info["components"][index][3])]
        same_table = qs == qr
        blocks = len(s) // 64
        mismatched_blocks = dc_miss = ac_miss = ac_zero = ac_zero_miss = 0
        per_position = [0] * 64
        deltas = {}
        sb, rb = s.tobytes(), r.tobytes()
        for b in range(blocks):
            o = b * 64
            if same_table and sb[o * 2:(o + 64) * 2] == rb[o * 2:(o + 64) * 2]:
                ac_zero += sum(1 for k in range(1, 64) if s[o + k] == 0)
                continue
            missed = False
            for k in range(64):
                sv = s[o + k]
                if k and sv == 0:
                    ac_zero += 1
                predicted = requantize(sv, qs[k], qr[k])
                d = r[o + k] - predicted
                if d:
                    missed = True
                    per_position[k] += 1
                    key = str(d) if -3 <= d <= 3 else ("<-3" if d < 0 else ">3")
                    deltas[key] = deltas.get(key, 0) + 1
                    if k == 0:
                        dc_miss += 1
                    else:
                        ac_miss += 1
                        if sv == 0:
                            ac_zero_miss += 1
            mismatched_blocks += missed
        ac_total = blocks * 63
        components.append({
            "component": index, "blocks": blocks, "same_table": same_table,
            "blocks_with_any_mismatch": mismatched_blocks,
            "dc_mismatch": dc_miss, "ac_mismatch": ac_miss,
            "dc_mismatch_rate": dc_miss / blocks if blocks else 0.0,
            "ac_mismatch_rate": ac_miss / ac_total if ac_total else 0.0,
            "ac_sent_zero": ac_zero, "ac_sent_zero_mismatch": ac_zero_miss,
            "ac_sent_nonzero": ac_total - ac_zero, "ac_sent_nonzero_mismatch": ac_miss - ac_zero_miss,
            "mismatch_rate_by_zigzag": [per_position[ZIGZAG[z]] / blocks if blocks else 0.0 for z in range(64)],
            "delta_histogram": dict(sorted(deltas.items())),
        })
    total = sum(c["blocks"] * 64 for c in components)
    missed = sum(c["dc_mismatch"] + c["ac_mismatch"] for c in components)
    return {"model": "requantization of sent coefficients to received tables",
            "coefficients": total, "match_rate": 1 - missed / total if total else 0.0,
            "components": components}


def tool_runs(path):
    """True when this machine can execute the file (a Mac build can't run in a Linux VM)."""
    try:
        subprocess.run([str(path)], capture_output=True, timeout=30)
        return True
    except (OSError, subprocess.SubprocessError):
        return False


def find_jpeg_tool(explicit):
    if explicit:
        path = Path(explicit).expanduser().resolve()
        if not path.is_file() or not tool_runs(path):
            raise ValueError(f"jpeg_tool not found or not runnable here: {path}")
        return path
    if DEFAULT_JPEG_TOOL.is_file() and tool_runs(DEFAULT_JPEG_TOOL):
        return DEFAULT_JPEG_TOOL
    return None


def pixel_comparison(sent, received):
    with Image.open(io.BytesIO(sent)) as a, Image.open(io.BytesIO(received)) as b:
        a = ImageOps.exif_transpose(a).convert("RGB")
        b = ImageOps.exif_transpose(b).convert("RGB")
        if a.size != b.size:
            return {"same_display_dimensions": False, "same_decoded_rgb": None}
        delta = ImageChops.difference(a, b)
        return {"same_display_dimensions": True, "same_decoded_rgb": delta.getbbox() is None}


def compare(args):
    run = args.run.expanduser().resolve()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    if manifest["schema"] != SCHEMA:
        raise ValueError("Unsupported manifest schema")
    sessions = json.loads((run / "sessions.json").read_text(encoding="utf-8"))
    session = sessions[args.channel]
    images = {im["id"]: im for im in manifest["images"]}
    tool = find_jpeg_tool(getattr(args, "jpeg_tool", None))
    received_root = (run / "received" / args.channel).resolve()
    with (run / f"{args.channel}.csv").open(newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        if reader.fieldnames != ["id", "received", "notes"]:
            raise ValueError("Worksheet header must be id,received,notes")
        rows = list(reader)
    seen, used, results = set(), set(), []
    for row in rows:
        image_id = row["id"]
        if image_id not in images or image_id in seen:
            raise ValueError(f"Unknown or duplicate image id: {image_id}")
        seen.add(image_id)
        item = {"id": image_id, "notes": row["notes"]}
        if not row["received"].strip():
            results.append({**item, "status": "missing"})
            continue
        path = resolve_inside(run, row["received"].strip())
        if not path.is_relative_to(received_root):
            # A path into send/ or another channel would compare a file with itself
            # or with the wrong session and look like a pass-through.
            raise ValueError(f"Returned files for {args.channel} must be under received/{args.channel}/: {row['received']}")
        if path in used:
            raise ValueError(f"Returned file assigned twice: {path}")
        used.add(path)
        expected = images[image_id]
        sent = resolve_inside(run, expected["file"]).read_bytes()
        if sha256(sent) != expected["sha256"]:
            raise ValueError(f"Sent calibration file changed since preparation: {image_id}")
        received = path.read_bytes()
        info = describe(received)
        same_grid = (expected["width"], expected["height"], expected["components"]) == (
            info["width"], info["height"], info["components"])
        results.append({**item, "status": "compared", "received_file": row["received"],
            "sent": expected, "received": info,
            "same_bytes": sent == received,
            "same_dimensions": (expected["width"], expected["height"]) == (info["width"], info["height"]),
            "same_jpeg_grid": same_grid,
            "same_quantization": bool(info["quantization_natural"]) and expected["quantization_natural"] == info["quantization_natural"],
            "sent_tables": table_family(expected), "received_tables": table_family(info),
            **pixel_comparison(sent, received),
            "coefficients": coefficient_comparison(tool, resolve_inside(run, expected["file"]), expected, path, info)})
    for image_id in images.keys() - seen:
        results.append({"id": image_id, "status": "missing", "notes": "Worksheet row missing"})
    compared = sum(r["status"] == "compared" for r in results)
    if not compared:
        raise ValueError("No received files assigned yet; fill in the channel CSV first")
    incomplete = [key for key in ("app_version", "sender_device_os", "receiver_device_os", "sent_at", "received_at", "receive_method") if not session.get(key)]
    report = {"schema": SCHEMA, "channel": args.channel, "session": session,
        "manifest_sha256": sha256((run / "manifest.json").read_bytes()),
        "compared_utc": datetime.now(timezone.utc).isoformat(),
        "lab_sha256": sha256(Path(__file__).read_bytes()),
        "jpeg_tool_sha256": sha256(tool.read_bytes()) if tool else None,
        "missing_session_fields": incomplete, "compared": compared,
        "missing": len(results)-compared,
        "interpretation": "Measurements only. Equal tables or pixels do not prove coefficient equality, the same codec, or payload survival. Renamed-file mapping is supplied by the operator; it is not image identity verification.",
        "results": results}
    target = args.out or run / "reports" / f"{args.channel}.json"
    write_json(target, report)
    print(f"{compared} compared, {len(results)-compared} missing; report: {target}")
    if incomplete:
        print("Session metadata still needed: " + ", ".join(incomplete))
    if tool is None:
        print("Coefficients not compared: build the reader on this machine first with "
              "cargo build --release --example jpeg_tool, then write a new report with --out")
    for result in results:
        if result["status"] == "compared":
            coef = result["coefficients"]
            coef_text = (f"model match {coef['match_rate']:.4%}" if "match_rate" in coef
                         else f"coefficients: {coef['skipped']}")
            print(f"{result['id']}: {result['sent']['width']}x{result['sent']['height']} -> "
                  f"{result['received']['width']}x{result['received']['height']}; "
                  f"same bytes={result['same_bytes']}, same tables={result['same_quantization']}, "
                  f"tables {result['sent_tables']} -> {result['received_tables']}; {coef_text}")


def control(args):
    """Byte-preserving file control: which prepared files came back unchanged."""
    run = args.run.expanduser().resolve()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    folder = args.folder.expanduser().resolve()
    if not folder.is_dir():
        raise ValueError(f"Not a folder: {folder}")
    by_hash = {}
    for image in manifest["images"]:
        by_hash.setdefault(image["sha256"], []).append(image["id"])
    matched, unmatched = {}, []
    for path in sorted(p for p in folder.rglob("*") if p.is_file()):
        if path.name.startswith(".") or "__MACOSX" in path.relative_to(folder).parts:
            continue
        digest = sha256(path.read_bytes())
        ids = by_hash.get(digest)
        relative = str(path.relative_to(folder))
        if ids:
            for image_id in ids:
                matched.setdefault(image_id, []).append(relative)
        else:
            unmatched.append({"file": relative, "bytes": path.stat().st_size})
    missing = sorted(set(i["id"] for i in manifest["images"]) - matched.keys())
    report = {"schema": SCHEMA, "kind": "file-control",
        "manifest_sha256": sha256((run / "manifest.json").read_bytes()),
        "checked_utc": datetime.now(timezone.utc).isoformat(),
        "note": args.note or "",
        "byte_identical": len(matched), "not_returned": len(missing), "unmatched_files": len(unmatched),
        "matched": dict(sorted(matched.items())), "missing": missing, "unmatched": unmatched}
    target = args.out or run / "reports" / "file-control.json"
    write_json(target, report)
    print(f"{len(matched)} of {len(manifest['images'])} prepared files came back byte-identical; "
          f"{len(missing)} not found; {len(unmatched)} other files. Report: {target}")
    for item in unmatched:
        print(f"not a prepared file: {item['file']} ({item['bytes']} bytes)")


def percent(value):
    return f"{value:.2%}" if value is not None else ""


def summary(args):
    """One readable page from the channel reports in a run."""
    run = args.run.expanduser().resolve()
    manifest = json.loads((run / "manifest.json").read_text(encoding="utf-8"))
    manifest_hash = sha256((run / "manifest.json").read_bytes())
    lines = ["# Channel lab summary", "",
             f"Run `{run.name}`, {len(manifest['images'])} prepared images. Measurements only: "
             "no payload was embedded, so nothing here shows that a message survives.", ""]
    found = 0
    for channel in CHANNELS:
        path = run / "reports" / f"{channel}.json"
        if not path.is_file():
            continue
        report = json.loads(path.read_text(encoding="utf-8"))
        if report.get("manifest_sha256") != manifest_hash:
            raise ValueError(f"{path.name} was made for a different manifest")
        found += 1
        session = report["session"]
        lines += [f"## {channel}", ""]
        details = [f"{k.replace('_', ' ')}: {session[k]}" for k in
                   ("app_version", "sender_device_os", "receiver_device_os", "sent_at", "receive_method")
                   if session.get(k)]
        lines += ["; ".join(details) or "Session details not filled in.", ""]
        if report["missing_session_fields"]:
            lines += ["Missing session fields: " + ", ".join(report["missing_session_fields"]), ""]
        lines += ["| id | sent | received | format | tables | bytes | same bytes | coefficient model |",
                  "|---|---|---|---|---|---|---|---|"]
        kept, resized = set(), {}
        families = {}
        for r in report["results"]:
            if r["status"] != "compared":
                lines.append(f"| {r['id']} | | missing | | | | | |")
                continue
            s, x = r["sent"], r["received"]
            coef = r.get("coefficients") or {}
            coef_text = percent(coef["match_rate"]) if "match_rate" in coef else coef.get("skipped", "")
            fmt = x["format"] + (" progressive" if x["progressive"] else "")
            lines.append(f"| {r['id']} | {s['width']}x{s['height']} {r['sent_tables']} | "
                         f"{x['width']}x{x['height']} | {fmt} | {r['received_tables']} | "
                         f"{x['bytes'] / s['bytes']:.2f}x | {'yes' if r['same_bytes'] else 'no'} | {coef_text} |")
            edge = max(s["width"], s["height"])
            if r["same_dimensions"]:
                kept.add(edge)
            else:
                resized.setdefault(edge, set()).add(max(x["width"], x["height"]))
            families[r["received_tables"]] = families.get(r["received_tables"], 0) + 1
        lines += [""]
        if kept:
            lines.append(f"- Sent long edges that came back at the same size: {', '.join(map(str, sorted(kept)))}")
        if resized:
            lines.append("- Sent long edges that came back resized: " + ", ".join(
                f"{edge} to {'/'.join(map(str, sorted(to)))}" for edge, to in sorted(resized.items())))
        if families:
            lines.append("- Returned table families: " +
                         ", ".join(f"{k} ({v})" for k, v in sorted(families.items())))
        lines.append("")
    control_path = run / "reports" / "file-control.json"
    if control_path.is_file():
        c = json.loads(control_path.read_text(encoding="utf-8"))
        lines += ["## File control", "",
                  f"{c['byte_identical']} prepared files came back byte-identical, {c['not_returned']} not found, "
                  f"{c['unmatched_files']} other files. {c.get('note', '')}".rstrip(), ""]
        found += 1
    if not found:
        raise ValueError("No reports in this run yet; run compare first")
    text = "\n".join(lines).rstrip() + "\n"
    target = args.out or run / "reports" / "summary.md"
    with target.open("x", encoding="utf-8") as f:
        f.write(text)
    print(text)
    print(f"Written: {target}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("prepare", help="Make a new calibration run")
    p.add_argument("photos", nargs="+", help="Photo files or folders")
    p.add_argument("--out", type=Path, required=True, help="New output folder, normally under drafts/")
    p.add_argument("--sizes", type=size_list, default=size_list("1600,2048,original"))
    p.add_argument("--qualities", type=positive_list, default=positive_list("80,95"))
    p.add_argument("--sampling", choices=("420", "444"), default="420")
    p.add_argument("--match", type=Path, help="Encode with this returned JPEG's exact tables instead of --qualities")
    p.add_argument("--headroom", action="store_true",
                   help="Pull areas that clip after a JPEG round trip back from 0 and 255 (ids end in _h)")
    p.add_argument("--recursive", action="store_true")
    p.add_argument("--limit", type=int, help="Take the first N photos in sorted path order")
    p.add_argument("--dry-run", action="store_true")
    p.set_defaults(func=prepare)
    p = sub.add_parser("compare", help="Inspect returned photos using a channel worksheet")
    p.add_argument("run", type=Path)
    p.add_argument("--channel", choices=CHANNELS, required=True)
    p.add_argument("--out", type=Path, help="New report path; existing reports are never overwritten")
    p.add_argument("--jpeg-tool", help="Path to the jpeg_tool example; default target/release/examples/jpeg_tool")
    p.set_defaults(func=compare)
    p = sub.add_parser("control", help="Check a file/document send of the prepared photos")
    p.add_argument("run", type=Path)
    p.add_argument("folder", type=Path, help="Folder holding the downloaded, unzipped files")
    p.add_argument("--note", help="Which app and path the control went through")
    p.add_argument("--out", type=Path, help="New report path; existing reports are never overwritten")
    p.set_defaults(func=control)
    p = sub.add_parser("summary", help="Write one readable page from a run's reports")
    p.add_argument("run", type=Path)
    p.add_argument("--out", type=Path, help="New summary path; an existing summary is never overwritten")
    p.set_defaults(func=summary)
    args = parser.parse_args(argv)
    if getattr(args, "limit", None) is not None and args.limit <= 0:
        parser.error("--limit must be positive")
    try:
        args.func(args)
    except (ValueError, OSError, KeyError, Image.DecompressionBombError) as e:
        parser.exit(1, f"error: {e}\n")


if __name__ == "__main__":
    main()
