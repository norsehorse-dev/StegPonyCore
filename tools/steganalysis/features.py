"""Color DCTR features (Holub and Fridrich 2015) for every JPEG in a directory.

DCTR is computed on each component's unrounded decompressed plane at its own
resolution (Y 512x512, Cb and Cr 256x256 for 4:2:0 tiles) and concatenated, 24000
dimensions, because StegPony embeds in chroma as well as luma.
  python3 features.py IMAGE_DIR OUT.npz [QF]
"""
import os, sys
from multiprocessing import Pool
import numpy as np
import jpeglib
import sealwatch as sw
from sealwatch.tools import jpeg as swjpeg

QF = 95

def step(qf):
    return min(8 * (50 / qf), 100) if qf < 50 else max(8 * (2 - qf / 50), 0.2)

def one(path):
    im = jpeglib.read_dct(path)
    out = []
    for i, plane in enumerate((im.Y, im.Cb, im.Cr)):
        x = swjpeg.decompress(y=plane, qt=im.get_component_qt(i)) - 128
        f = sw.dctr.extract(x1=x, q=step(QF))
        out.append(np.concatenate([np.ravel(v) for v in f.values()]))
    return np.concatenate(out).astype(np.float32)

def main():
    global QF
    src, dst = sys.argv[1], sys.argv[2]
    if len(sys.argv) > 3:
        QF = int(sys.argv[3])
    names = sorted(n for n in os.listdir(src) if n.endswith(".jpg"))
    with Pool(os.cpu_count()) as pool:
        feats = pool.map(one, [os.path.join(src, n) for n in names], chunksize=4)
    np.savez(dst, names=np.array(names), X=np.stack(feats))
    print(f"{dst}: {len(names)} x {feats[0].shape[0]}")

if __name__ == "__main__":
    main()
