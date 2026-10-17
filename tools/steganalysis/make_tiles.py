"""Cut camera JPEGs into 512x512 tiles in the coefficient domain (no re-encoding).

Tiles are aligned to the 16x16 MCU grid, so every tile keeps the photo's own quantized
coefficients, quantization tables and 4:2:0 sampling. Usage:
  python3 make_tiles.py [--checker] OUT_DIR PHOTO.jpg [PHOTO.jpg ...]
--checker keeps every other tile in a checkerboard, so tiles from one photo are spread
out rather than adjacent. Writes OUT_DIR/<photo-stem>_<row>_<col>.jpg and OUT_DIR/tiles.json (tile -> source).
"""
import json, os, sys
import jpeglib
import numpy as np

TILE = 512  # pixels; 64 luma blocks, 32 chroma blocks

def main():
    args = sys.argv[1:]
    checker = args[0] == "--checker"
    if checker:
        args = args[1:]
    out, photos = args[0], args[1:]
    os.makedirs(out, exist_ok=True)
    index = {}
    for p in photos:
        im = jpeglib.read_dct(p)
        Y, Cb, Cr = im.Y, im.Cb, im.Cr
        assert Cb is not None and Y.shape[0] == 2 * Cb.shape[0] and Y.shape[1] == 2 * Cb.shape[1], p
        lb, cb = TILE // 8, TILE // 16
        stem = os.path.splitext(os.path.basename(p))[0]
        for r in range(Y.shape[0] // lb):
            for c in range(Y.shape[1] // lb):
                if checker and (r + c) % 2:
                    continue
                t = jpeglib.from_dct(
                    Y=np.ascontiguousarray(Y[r*lb:(r+1)*lb, c*lb:(c+1)*lb]),
                    Cb=np.ascontiguousarray(Cb[r*cb:(r+1)*cb, c*cb:(c+1)*cb]),
                    Cr=np.ascontiguousarray(Cr[r*cb:(r+1)*cb, c*cb:(c+1)*cb]),
                    qt=im.qt, quant_tbl_no=im.quant_tbl_no)
                name = f"{stem}_{r}_{c}.jpg"
                t.write_dct(os.path.join(out, name))
                index[name] = stem
    with open(os.path.join(out, "tiles.json"), "w") as f:
        json.dump(index, f, indent=1)
    print(f"{len(index)} tiles from {len(photos)} photos")

if __name__ == "__main__":
    main()
