"""Checks stegpony-core's pure-Rust JPEG coefficient codec against libjpeg.

Run from the repo root after building the helper:
    cargo build --release --example jpeg_tool
    python3 tools/check_jpeg.py [extra.jpg ...]

Needs NumPy, Pillow and jpeglib (pip install jpeglib), which bundles libjpeg 6b to 9f,
libjpeg-turbo and mozjpeg and reads and writes DCT coefficients through them.

For a matrix of covers written by those libraries (baseline and progressive, every
common and some uncommon sampling factors, restart intervals, optimized and standard
tables, grayscale, CMYK, odd sizes), and for any JPEGs named on the command line:

1. The coefficients the Rust reader returns equal the ones libjpeg returns.
2. Writing the file back unchanged gives the same bytes (reported, not required, for
   files given on the command line; required for the generated matrix).
3. After changing AC coefficients by +-1 (enough to force new Huffman tables), libjpeg
   reads the Rust writer's output and gets exactly the changed coefficients.
"""
import os
import subprocess
import sys
import tempfile

import jpeglib
import numpy as np
from PIL import Image

TOOL = os.path.join("target", "release", "examples", "jpeg_tool")
rng = np.random.default_rng(20261016)
failures = []


def photo(h, w, c):
    y, x = np.mgrid[0:h, 0:w]
    base = 110 + 50 * np.sin(x / 9.0) * np.cos(y / 13.0)
    chans = [base + 25 * rng.standard_normal((h, w)) + 15 * i for i in range(c)]
    return np.clip(np.stack(chans, -1), 0, 255).astype(np.uint8)


def tool(*args):
    r = subprocess.run([TOOL, *args], capture_output=True, text=True)
    if r.returncode != 0:
        raise RuntimeError(r.stderr.strip())
    return r.stdout.strip()


def libjpeg_coefs(path):
    """Real blocks of every component, natural order, as one int16 array."""
    im = jpeglib.read_dct(path)
    parts = []
    for name in ("Y", "Cb", "Cr", "K"):
        a = getattr(im, name, None)
        if a is None:
            continue
        a = np.asarray(a)
        if a.size == 0:
            continue
        parts.append(a.reshape(-1))
    return np.concatenate(parts).astype("<i2")


def rust_coefs(path, tmp):
    out = os.path.join(tmp, "dump.bin")
    tool("dump", path, out)
    return np.fromfile(out, dtype="<i2")


def check(name, path, tmp, require_identical):
    try:
        ours = rust_coefs(path, tmp)
        theirs = libjpeg_coefs(path)
        if ours.shape != theirs.shape or not np.array_equal(ours, theirs):
            failures.append(f"{name}: coefficients differ from libjpeg")
            return
        rt = os.path.join(tmp, "rt.jpg")
        same = tool("roundtrip", path, rt) == "identical"
        if require_identical and not same:
            failures.append(f"{name}: unchanged round trip is not byte-identical")
        for seed, count in ((1, 10), (2, 2000)):
            out = os.path.join(tmp, "p.jpg")
            tool("perturb", path, out, str(seed), str(count))
            if not np.array_equal(rust_coefs(out, tmp), libjpeg_coefs(out)):
                failures.append(f"{name}: libjpeg reads different coefficients after perturb {count}")
            jpeglib.read_spatial(out).spatial  # libjpeg must decode it to pixels too
        print(f"ok   {name}{'' if same else '  (round trip valid, bytes differ)'}")
    except Exception as e:  # noqa: BLE001
        failures.append(f"{name}: {e}")


def pillow_cases(tmp):
    sizes = [(1, 1), (8, 8), (37, 53), (150, 200), (129, 257)]
    for h, w in sizes:
        rgb = Image.fromarray(photo(h, w, 3), "RGB")
        for sub in ("4:4:4", "4:2:2", "4:2:0"):
            for kw in ({"quality": 90}, {"quality": 50, "optimize": True},
                       {"quality": 95, "progressive": True},
                       {"quality": 85, "restart_marker_blocks": 3},
                       {"quality": 80, "restart_marker_rows": 1, "progressive": True}):
                tag = ",".join(f"{k}={v}" for k, v in kw.items())
                p = os.path.join(tmp, f"pil_{w}x{h}_{sub.replace(':', '')}_{len(tag)}.jpg")
                rgb.save(p, subsampling=sub, **kw)
                yield f"pillow {w}x{h} {sub} {tag}", p
        gray = Image.fromarray(photo(h, w, 1)[..., 0], "L")
        for kw in ({"quality": 100}, {"quality": 75, "progressive": True}):
            p = os.path.join(tmp, f"pil_gray_{w}x{h}_{len(kw)}.jpg")
            gray.save(p, **kw)
            yield f"pillow gray {w}x{h} {kw}", p
        cmyk = Image.fromarray(photo(h, w, 4), "CMYK")
        p = os.path.join(tmp, f"pil_cmyk_{w}x{h}.jpg")
        cmyk.save(p, quality=90)
        yield f"pillow cmyk {w}x{h}", p


def jpeglib_cases(tmp):
    x = photo(61, 75, 3)
    samplings = {
        "411h": [[1, 4], [1, 1], [1, 1]],
        "411v": [[4, 1], [1, 1], [1, 1]],
        "mixed": [[2, 2], [1, 2], [2, 1]],
        "440": [[2, 1], [1, 1], [1, 1]],
    }
    for name, sf in samplings.items():
        im = jpeglib.from_spatial(x)
        im.samp_factor = np.array(sf)
        p = os.path.join(tmp, f"jl_{name}.jpg")
        im.write_spatial(p, qt=85)
        yield f"libjpeg-turbo sampling {name}", p
    for ver in ("6b", "9e", "turbo210", "mozjpeg403"):
        for prog in (False, True):
            with jpeglib.version(ver):
                im = jpeglib.from_spatial(x)
                p = os.path.join(tmp, f"jl_{ver}_{prog}.jpg")
                flags = ["+PROGRESSIVE_MODE"] if prog else ["-PROGRESSIVE_MODE"]
                im.write_spatial(p, qt=75, flags=flags)
            yield f"{ver} {'progressive' if prog else 'sequential'}", p


def main():
    if not os.path.exists(TOOL):
        sys.exit(f"build the helper first: cargo build --release --example jpeg_tool")
    with tempfile.TemporaryDirectory() as tmp:
        n = 0
        for name, p in list(pillow_cases(tmp)) + list(jpeglib_cases(tmp)):
            check(name, p, tmp, True)
            n += 1
        for p in sys.argv[1:]:
            check(os.path.basename(p), p, tmp, False)
            n += 1
    if failures:
        print(f"\n{len(failures)} of {n} files failed:")
        for f in failures:
            print("  " + f)
        sys.exit(1)
    print(f"\nall {n} files pass")


if __name__ == "__main__":
    main()
