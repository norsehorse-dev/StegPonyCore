#!/usr/bin/env python3
"""Zero / not-zero symbol round trips for the error-tolerant mode (experiment 4).

`make` takes covers already prepared for a channel (the `send/` files of a lab run)
and writes test covers in which a keyed sample of mid-frequency luma AC coefficients
is set to a chosen symbol: 0, or a magnitude of 2. `compare` reads what came back
through the channel and counts, at exactly those positions, how many symbols were
read wrong (0 against a magnitude of 2 or more) and how many became erasures (a
magnitude of 1). Unselected positions in the same band are counted as a control.

This is lab tooling for docs/ERROR_TOLERANT_MODE.md, not the format: no payload,
no keys, no error correction. Needs numpy and jpeglib (libjpeg's coefficients).
"""
import argparse
import csv
import hashlib
import json
import secrets
import sys
from pathlib import Path

import numpy as np

ZIGZAG = [0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48,
          41, 34, 27, 20, 13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15,
          23, 30, 37, 44, 51, 58, 59, 52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63]
WORKSHEET = "symbols.csv"


def jpeglib_module():
    try:
        import jpeglib
    except ImportError:
        sys.exit("symbols.py needs jpeglib: pip install numpy jpeglib")
    return jpeglib


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def parse_band(text):
    lo, _, hi = text.partition("-")
    lo, hi = int(lo), int(hi or lo)
    if not 1 <= lo <= hi <= 63:
        raise argparse.ArgumentTypeError("band must be zigzag indices within 1-63, like 10-27")
    return lo, hi


def content_blocks(dct, image_path):
    """Luma blocks that hold image content (no MCU padding)."""
    from PIL import Image
    with Image.open(image_path) as im:
        width, height = im.size
    by, bx = dct.Y.shape[:2]
    return min(by, (height + 7) // 8), min(bx, (width + 7) // 8)


def classify(values):
    """0 -> symbol 0, |v| >= 2 -> symbol 1, |v| == 1 -> erasure (-1)."""
    mag = np.abs(values)
    return np.where(mag == 0, 0, np.where(mag >= 2, 1, -1))


def band_positions(lo, hi):
    """Natural-order (row, col) of zigzag indices lo..hi."""
    return [(ZIGZAG[i] // 8, ZIGZAG[i] % 8, i) for i in range(lo, hi + 1)]


def make(args):
    jpeglib = jpeglib_module()
    out = Path(args.out)
    if out.exists():
        sys.exit(f"{out} already exists; pick a new folder")
    seed = args.seed if args.seed is not None else secrets.randbits(63)
    lo, hi = args.band
    positions = band_positions(lo, hi)
    (out / "send").mkdir(parents=True)
    (out / "symbols").mkdir()
    (out / "received").mkdir()
    (out / "reports").mkdir()
    manifest = {"tool": "tools/channel_lab/symbols.py", "seed": seed, "band": [lo, hi],
                "density": args.density, "max_magnitude": args.max_magnitude, "images": []}
    rows = []
    for index, src in enumerate(sorted(Path(p) for p in args.covers)):
        dct = jpeglib.read_dct(str(src))
        rows_b, cols_b = content_blocks(dct, src)
        rng = np.random.default_rng([seed, index])
        y = dct.Y
        by, bx, zz, bit, before, after = [], [], [], [], [], []
        for r, c, z in positions:
            plane = y[:rows_b, :cols_b, r, c]
            cand = np.argwhere(np.abs(plane) <= args.max_magnitude)
            pick = cand[rng.random(len(cand)) < args.density]
            bits = rng.integers(0, 2, len(pick))
            signs = rng.choice([-1, 1], len(pick))
            for (i, j), b, s in zip(pick, bits, signs):
                v = int(y[i, j, r, c])
                if b == 0:
                    new = 0
                elif v == 0:
                    new = 2 * int(s)
                else:
                    new = 2 * (1 if v > 0 else -1) if abs(v) <= 2 else v
                y[i, j, r, c] = new
                by.append(i); bx.append(j); zz.append(z); bit.append(int(b))
                before.append(v); after.append(new)
        ident = src.stem + "_sym"
        dst = out / "send" / f"{ident}.jpg"
        dct.write_dct(str(dst))
        arrays = {k: np.array(v, dtype=np.int32) for k, v in
                  dict(by=by, bx=bx, zz=zz, bit=bit, before=before, after=after).items()}
        np.savez_compressed(out / "symbols" / f"{ident}.npz", **arrays)
        changed = int((arrays["before"] != arrays["after"]).sum())
        item = {"id": ident, "source": str(src), "source_sha256": sha256(src),
                "sent_sha256": sha256(dst), "luma_blocks": [rows_b, cols_b],
                "symbols": len(bit), "changed": changed,
                "zero_symbols": int((arrays["bit"] == 0).sum()),
                "two_symbols": int((arrays["bit"] == 1).sum())}
        manifest["images"].append(item)
        rows.append({"id": ident, "received": "", "notes": ""})
        print(f"{ident}: {item['symbols']} symbols, {changed} coefficients changed")
    (out / "manifest.json").write_text(json.dumps(manifest, indent=1) + "\n")
    with (out / WORKSHEET).open("w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=["id", "received", "notes"])
        writer.writeheader()
        writer.writerows(rows)
    print(f"seed {seed}; send the files in {out / 'send'}, then fill in {WORKSHEET}")


def rate(n, d):
    return round(n / d, 6) if d else None


def compare(args):
    jpeglib = jpeglib_module()
    run = Path(args.run)
    manifest = json.loads((run / "manifest.json").read_text())
    lo, hi = manifest["band"]
    report_path = Path(args.out) if args.out else run / "reports" / f"symbols-{args.label}.json"
    if report_path.exists():
        sys.exit(f"{report_path} exists; pass --out for a new report")
    by_id = {item["id"]: item for item in manifest["images"]}
    with (run / WORKSHEET).open(newline="") as f:
        rows = [r for r in csv.DictReader(f) if r["received"].strip()]
    if not rows:
        sys.exit(f"no received files assigned in {WORKSHEET}")
    report = {"label": args.label, "band": [lo, hi], "seed": manifest["seed"], "images": []}
    totals = {"symbols": 0, "wrong": 0, "erased": 0, "control": 0, "control_flipped": 0}
    for row in rows:
        item = by_id.get(row["id"])
        if item is None:
            sys.exit(f"unknown id {row['id']}")
        sent = run / "send" / f"{row['id']}.jpg"
        if sha256(sent) != item["sent_sha256"]:
            sys.exit(f"{sent} changed since make")
        got_path = Path(row["received"])
        got_path = got_path if got_path.is_absolute() else run / got_path
        a = jpeglib.read_dct(str(sent))
        b = jpeglib.read_dct(str(got_path))
        entry = {"id": row["id"], "received": row["received"], "received_sha256": sha256(got_path)}
        if a.Y.shape != b.Y.shape:
            entry["error"] = f"luma grid changed: {a.Y.shape[:2]} to {b.Y.shape[:2]}"
            report["images"].append(entry)
            print(f"{row['id']}: {entry['error']}")
            continue
        entry["same_tables"] = bool(np.array_equal(a.qt, b.qt))
        s = np.load(run / "symbols" / f"{row['id']}.npz")
        nat = np.array([ZIGZAG[z] for z in s["zz"]])
        got = b.Y[s["by"], s["bx"], nat // 8, nat % 8]
        cls = classify(got)
        wrong = (cls >= 0) & (cls != s["bit"])
        erased = cls == -1
        created = s["before"] != s["after"]
        entry.update({
            "symbols": int(len(cls)), "wrong": int(wrong.sum()), "erased": int(erased.sum()),
            "wrong_rate": rate(wrong.sum(), len(cls)), "erasure_rate": rate(erased.sum(), len(cls)),
            "by_symbol": {str(k): {"n": int((s["bit"] == k).sum()),
                                   "wrong": int((wrong & (s["bit"] == k)).sum()),
                                   "erased": int((erased & (s["bit"] == k)).sum())} for k in (0, 1)},
            "written_by_tool": {"n": int(created.sum()), "wrong": int((wrong & created).sum()),
                                "erased": int((erased & created).sum())},
            "already_in_cover": {"n": int((~created).sum()), "wrong": int((wrong & ~created).sum()),
                                 "erased": int((erased & ~created).sum())},
            "by_zigzag": {str(z): {"n": int((s["zz"] == z).sum()),
                                   "wrong": int((wrong & (s["zz"] == z)).sum()),
                                   "erased": int((erased & (s["zz"] == z)).sum())}
                          for z in range(lo, hi + 1)},
        })
        # Control: every other band position that was 0 or 2+ when sent.
        mask = np.zeros(a.Y.shape[:2] + (8, 8), bool)
        rows_b, cols_b = item["luma_blocks"]
        for z in range(lo, hi + 1):
            mask[:rows_b, :cols_b, ZIGZAG[z] // 8, ZIGZAG[z] % 8] = True
        mask[s["by"], s["bx"], nat // 8, nat % 8] = False
        sent_cls = classify(a.Y[mask])
        got_cls = classify(b.Y[mask])
        usable = sent_cls >= 0
        flipped = usable & (got_cls >= 0) & (got_cls != sent_cls)
        entry["control"] = {"n": int(usable.sum()), "flipped": int(flipped.sum()),
                            "erased": int((usable & (got_cls == -1)).sum())}
        for k in ("symbols", "wrong", "erased"):
            totals[k] += entry[k]
        totals["control"] += entry["control"]["n"]
        totals["control_flipped"] += entry["control"]["flipped"]
        report["images"].append(entry)
        print(f"{row['id']}: {entry['symbols']} symbols, wrong {entry['wrong']} "
              f"({100 * entry['wrong_rate']:.4f}%), erased {entry['erased']} "
              f"({100 * entry['erasure_rate']:.3f}%); written by tool: "
              f"{entry['written_by_tool']['wrong']} wrong, {entry['written_by_tool']['erased']} erased "
              f"of {entry['written_by_tool']['n']}; control flipped {entry['control']['flipped']} "
              f"of {entry['control']['n']}")
    report["totals"] = totals
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(report, indent=1) + "\n")
    print(f"wrote {report_path}")


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("make", help="Write symbol test covers from prepared covers")
    p.add_argument("covers", nargs="+", help="Prepared JPEG covers (a lab run's send/ files)")
    p.add_argument("--out", required=True, help="New run folder, normally under drafts/")
    p.add_argument("--band", type=parse_band, default=(10, 27), help="Zigzag indices, default 10-27")
    p.add_argument("--density", type=float, default=0.05,
                   help="Share of eligible band positions used, default 0.05")
    p.add_argument("--max-magnitude", type=int, default=2,
                   help="Only positions whose sent value is at most this, default 2")
    p.add_argument("--seed", type=int, help="Default: random, recorded in the manifest")
    p = sub.add_parser("compare", help="Count wrong and erased symbols in returned files")
    p.add_argument("run")
    p.add_argument("--label", required=True, help="Channel and route, like telegram-android")
    p.add_argument("--out", help="New report path; existing reports are never overwritten")
    args = parser.parse_args(argv)
    {"make": make, "compare": compare}[args.command](args)


if __name__ == "__main__":
    main()
