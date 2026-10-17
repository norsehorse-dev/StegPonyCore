"""Generates the JPEG codec fixtures and their libjpeg oracle.

Run from the repo root: python3 tools/make_jpeg_fixtures.py
Needs NumPy, Pillow and jpeglib. Writes crates/stegpony-core/tests/fixtures/jpeg/*.jpg
and jpeg_oracle.json, which records for every file the SHA-256 of the coefficients
libjpeg reads from it (layout as in examples/jpeg_tool.rs: components in frame order,
real blocks in raster order, natural order, i16 little-endian). The committed files are
what the tests use; this only needs re-running when a fixture is added.
"""
import hashlib
import json
import os

import jpeglib
import numpy as np
from PIL import Image

OUT = "crates/stegpony-core/tests/fixtures/jpeg/"
rng = np.random.default_rng(20261017)


def photo(h, w, c):
    y, x = np.mgrid[0:h, 0:w]
    base = 110 + 50 * np.sin(x / 9.0) * np.cos(y / 13.0)
    chans = [base + 25 * rng.standard_normal((h, w)) + 15 * i for i in range(c)]
    return np.clip(np.stack(chans, -1), 0, 255).astype(np.uint8)


def oracle(path):
    im = jpeglib.read_dct(path)
    parts = []
    for name in ("Y", "Cb", "Cr", "K"):
        a = getattr(im, name, None)
        if a is not None and np.asarray(a).size:
            parts.append(np.asarray(a).reshape(-1))
    coefs = np.concatenate(parts).astype("<i2").tobytes()
    return hashlib.sha256(coefs).hexdigest()


def main():
    os.makedirs(OUT, exist_ok=True)
    h, w = 77, 99
    rgb = Image.fromarray(photo(h, w, 3), "RGB")
    files = {}

    def pil(name, img, **kw):
        img.save(OUT + name, **kw)
        files[name] = {}

    pil("baseline_420.jpg", rgb, quality=90, subsampling="4:2:0")
    pil("baseline_444_restart.jpg", rgb, quality=85, subsampling="4:4:4", restart_marker_blocks=2)
    pil("baseline_422_optimized.jpg", rgb, quality=50, subsampling="4:2:2", optimize=True)
    pil("gray.jpg", Image.fromarray(photo(h, w, 1)[..., 0], "L"), quality=95)
    pil("cmyk.jpg", Image.fromarray(photo(h, w, 4), "CMYK"), quality=90)
    pil("progressive_turbo.jpg", rgb, quality=80, progressive=True)
    pil("progressive_restart.jpg", rgb, quality=75, progressive=True, restart_marker_rows=1)

    x = photo(h, w, 3)
    with jpeglib.version("mozjpeg403"):
        jpeglib.from_spatial(x).write_spatial(OUT + "progressive_mozjpeg.jpg", qt=75)
    files["progressive_mozjpeg.jpg"] = {}
    im = jpeglib.from_spatial(x)
    im.samp_factor = np.array([[2, 2], [1, 2], [2, 1]])
    im.write_spatial(OUT + "sampling_mixed.jpg", qt=85)
    files["sampling_mixed.jpg"] = {}

    for name in files:
        files[name]["coef_sha256"] = oracle(OUT + name)
    with open(OUT + "jpeg_oracle.json", "w") as f:
        json.dump(files, f, indent=2, sort_keys=True)
        f.write("\n")
    for name in sorted(files):
        print(name, os.path.getsize(OUT + name))


if __name__ == "__main__":
    main()
