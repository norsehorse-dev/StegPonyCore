"""Reference embedders at StegPony's bucket-B total payload (both slots), luma only,
simulated at the rate-distortion bound with conseal:
  juni_b<B>: ideal ternary J-UNIWARD (same cost family as StegPony)
  nsf5_b<B>: nsF5, the F5 family that PixelKnot uses
  python3 sims.py COVER_DIR OUT_DIR BUCKET
"""
import os, sys
import numpy as np, jpeglib, conseal
from sealwatch.tools import jpeg as swj

def main():
    src, out, k = sys.argv[1], sys.argv[2], int(sys.argv[3])
    bucket = 64 << (k // 2)
    bucket += bucket // 2 if k % 2 else 0
    bits = 2 * bucket * 8
    for tag in ("juni", "nsf5"):
        os.makedirs(os.path.join(out, f"{tag}_b{k}"), exist_ok=True)
    for i, n in enumerate(sorted(x for x in os.listdir(src) if x.endswith(".jpg"))):
        im = jpeglib.read_dct(os.path.join(src, n))
        nzY = int((im.Y.reshape(*im.Y.shape[:2], 64)[:, :, 1:] != 0).sum())
        alpha = bits / nzY
        qt = im.get_component_qt(0)
        x0 = swj.decompress(y=im.Y, qt=qt)
        for tag, y1 in (
            ("juni", conseal.juniward.simulate_single_channel(x0=x0, y0=im.Y, qt=qt, alpha=alpha, seed=i)),
            ("nsf5", conseal.nsF5.simulate_single_channel(y0=im.Y, alpha=min(alpha, 0.99), seed=i)),
        ):
            im.Y = y1
            im.write_dct(os.path.join(out, f"{tag}_b{k}", n))
            im.Y = jpeglib.read_dct(os.path.join(src, n)).Y
    print(f"sims at bucket {k}: {bits} bits")

if __name__ == "__main__":
    main()
