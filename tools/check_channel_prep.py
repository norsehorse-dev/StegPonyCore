"""Check Rust-prepared covers through independent Pillow/libjpeg coefficient I/O.

Build: cargo build --locked --release --example jpeg_tool
Run: python3 tools/check_channel_prep.py [extra-camera.jpg ...]
Needs the same numpy, Pillow, jpeglib dependencies as check_jpeg.py.
No real messenger is contacted, and this does not verify Telegram delivery.
"""
import io
import subprocess
import sys
import tempfile
from pathlib import Path

import jpeglib
import numpy as np
from PIL import Image, ImageOps
from check_jpeg import libjpeg_coefs

TOOL = Path("target/release/examples/jpeg_tool")


def check(source, destination, dump, tables):
    destination.unlink(missing_ok=True)  # Fresh scratch output; helper refuses overwrites.
    result = subprocess.run([str(TOOL), "prepare-telegram", str(source), str(destination)],
                            check=True, capture_output=True, text=True)
    with Image.open(source) as im:
        w, h = ImageOps.exif_transpose(im).size
    longest = max(w, h)
    expected = (w, h) if longest <= 1280 else tuple(max(1, (d*1280 + longest//2)//longest) for d in (w,h))
    with Image.open(destination) as im:
        im.load()
        assert im.size == expected, (source, im.size, expected)
        assert im.quantization == tables, source
        assert [(c[1],c[2],c[3]) for c in im.layer] == [(2,2,0),(1,1,1),(1,1,1)], source
        assert not im.getexif() and not im.info.get("icc_profile"), source
        extrema = im.convert("RGB").getextrema()
        assert all(lo>2 and hi<253 for lo,hi in extrema), (source, "libjpeg sees clipping", extrema)
    subprocess.run([str(TOOL), "dump", str(destination), str(dump)], check=True)
    assert np.array_equal(np.fromfile(dump, dtype="<i2"), libjpeg_coefs(str(destination))), source
    # Exercise libjpeg's full spatial decoder too, not only its DCT API.
    jpeglib.read_spatial(str(destination)).spatial
    print(f"ok {source.name}: {result.stdout.strip()}")


def main():
    reference = io.BytesIO()
    Image.new("RGB",(1,1)).save(reference,"JPEG",quality=72,subsampling=2)
    with Image.open(io.BytesIO(reference.getvalue())) as im:
        tables = im.quantization
    with tempfile.TemporaryDirectory() as tmp:
        root = Path(tmp)
        sources = []
        for name, size, kind in [("odd",(33,17),"RGB"), ("resize",(1281,721),"RGB"),
                                 ("portrait",(721,1281),"RGB"), ("gray",(17,9),"L"),
                                 ("opaque",(32,48),"RGBA")]:
            w,h = size
            y,x = np.mgrid[:h,:w]
            rgb = np.stack([(x*7+y*19)%256,(x*31+y*3)%256,(x*13+y*17)%256],axis=-1).astype(np.uint8)
            im = Image.fromarray(rgb).convert(kind)
            path = root / f"{name}.png"
            im.save(path)
            sources.append(path)
        for color,name in [((0,0,0),"black"),((255,255,255),"white"),((255,0,0),"red"),((0,0,255),"blue")]:
            path=root/f"{name}.png"
            Image.new("RGB",(33,17),color).save(path)
            sources.append(path)
        sources += sorted(Path("crates/stegpony-core/tests/fixtures/jpeg").glob("*.jpg"))
        sources = [p for p in sources if p.name != "cmyk.jpg"]
        sources += [Path(p) for p in sys.argv[1:]]
        for source in sources:
            check(source,root/"prepared.jpg",root/"coefs.bin",tables)
    print(f"all {len(sources)} prepared covers pass; real Telegram delivery still untested")


if __name__ == "__main__":
    main()
