"""Generates the synthetic cover images used by the tests.

Run from the repo root: python3 tools/make_fixtures.py
Needs Pillow and NumPy. Output is deterministic for a given Pillow/NumPy version, but
the committed fixtures are what the tests use, so this only needs re-running when a
fixture is added.
"""
import numpy as np
from PIL import Image

OUT = "crates/stegpony-core/tests/fixtures/"
rng = np.random.default_rng(20261015)


def octave_noise(h, w, octaves=6):
    img = np.zeros((h, w))
    for o in range(octaves):
        s = 2 ** (o + 2)
        small = rng.standard_normal((h // s + 2, w // s + 2))
        big = np.array(Image.fromarray(small.astype(np.float32)).resize((w + 2 * s, h + 2 * s), Image.BICUBIC))
        img += big[s:s + h, s:s + w] / (o + 1)
    return img


def photo(h, w):
    y, x = np.mgrid[0:h, 0:w]
    base = 90 + 60 * np.sin(x / 37.0) * np.cos(y / 53.0) + 0.25 * x
    chans = []
    for c in range(3):
        n = octave_noise(h, w)
        v = base + 18 * n + 6 * rng.standard_normal((h, w)) + 20 * c
        v[(x - w // 2) ** 2 + (y - h // 2) ** 2 < (h // 5) ** 2] -= 40
        chans.append(v)
    return np.clip(np.stack(chans, -1), 0, 255).astype(np.uint8)


rgb = photo(320, 320)
Image.fromarray(rgb, "RGB").save(OUT + "cover_rgb.png")
Image.fromarray(rgb, "RGB").save(OUT + "cover.jpg", quality=90)

gray = np.clip(rgb.mean(-1), 0, 255).astype(np.uint8)
Image.fromarray(gray, "L").save(OUT + "cover_gray.png")

alpha = np.full((320, 320), 255, np.uint8)
alpha[:, :64] = 0
alpha[100:140, :] = 128
rgba = np.dstack([rgb, alpha])
Image.fromarray(rgba, "RGBA").save(OUT + "cover_rgba.png")

tiny = photo(48, 48)
Image.fromarray(tiny, "RGB").save(OUT + "cover_tiny.png")

Image.fromarray(rgb, "RGB").convert("P").save(OUT + "cover_palette.png")
