"""Tests symbols.py's bookkeeping on synthetic covers, not any real channel."""
import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

import numpy as np
from PIL import Image

import symbols

try:
    import jpeglib
except ImportError:  # pragma: no cover
    jpeglib = None


@unittest.skipIf(jpeglib is None, "needs jpeglib")
class SymbolTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        rng = np.random.default_rng(7)
        pixels = rng.integers(40, 216, (96, 128, 3), dtype=np.uint8)
        self.cover = self.root / "p001_cover.jpg"
        Image.fromarray(pixels).save(self.cover, quality=87, subsampling=2)
        self.run = self.root / "run"

    def make(self, **extra):
        argv = ["make", str(self.cover), "--out", str(self.run), "--seed", "11",
                "--density", "0.3"] + [str(x) for kv in extra.items() for x in kv]
        with redirect_stdout(io.StringIO()):
            symbols.main(argv)
        return json.loads((self.run / "manifest.json").read_text())

    def assign(self, path):
        with (self.run / symbols.WORKSHEET).open("w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=["id", "received", "notes"])
            w.writeheader()
            w.writerow({"id": "p001_cover_sym", "received": str(path), "notes": ""})

    def compare(self, label="test"):
        with redirect_stdout(io.StringIO()):
            symbols.main(["compare", str(self.run), "--label", label])
        return json.loads((self.run / "reports" / f"symbols-{label}.json").read_text())

    def test_written_symbols_read_back(self):
        manifest = self.make()
        item = manifest["images"][0]
        self.assertGreater(item["symbols"], 100)
        self.assertEqual(item["zero_symbols"] + item["two_symbols"], item["symbols"])
        sent = self.run / "send" / "p001_cover_sym.jpg"
        s = np.load(self.run / "symbols" / "p001_cover_sym.npz")
        nat = np.array([symbols.ZIGZAG[z] for z in s["zz"]])
        values = jpeglib.read_dct(str(sent)).Y[s["by"], s["bx"], nat // 8, nat % 8]
        self.assertTrue(np.array_equal(values, s["after"]))
        self.assertTrue(np.array_equal(symbols.classify(values), s["bit"]))
        self.assertTrue(np.all((s["zz"] >= 10) & (s["zz"] <= 27)))
        self.assertEqual(self.cover.read_bytes()[:2], b"\xff\xd8")

    def test_pass_through_has_no_errors(self):
        self.make()
        self.assign(self.run / "send" / "p001_cover_sym.jpg")
        report = self.compare()
        image = report["images"][0]
        self.assertEqual((image["wrong"], image["erased"]), (0, 0))
        self.assertEqual(image["control"]["flipped"], 0)
        self.assertTrue(image["same_tables"])

    def test_counts_wrong_and_erased(self):
        self.make()
        sent = self.run / "send" / "p001_cover_sym.jpg"
        s = np.load(self.run / "symbols" / "p001_cover_sym.npz")
        nat = np.array([symbols.ZIGZAG[z] for z in s["zz"]])
        dct = jpeglib.read_dct(str(sent))
        # Three erasures (set to 1) and two wrong symbols (0 <-> 2).
        for k in range(3):
            dct.Y[s["by"][k], s["bx"][k], nat[k] // 8, nat[k] % 8] = 1
        flips = 0
        for k in range(3, len(s["bit"])):
            if flips == 2:
                break
            dct.Y[s["by"][k], s["bx"][k], nat[k] // 8, nat[k] % 8] = 2 if s["bit"][k] == 0 else 0
            flips += 1
        received = self.run / "received" / "back.jpg"
        dct.write_dct(str(received))
        self.assign("received/back.jpg")
        image = self.compare()["images"][0]
        self.assertEqual((image["wrong"], image["erased"]), (2, 3))

    def test_refuses_existing_folder_and_report(self):
        self.make()
        with self.assertRaises(SystemExit):
            self.make()
        self.assign(self.run / "send" / "p001_cover_sym.jpg")
        self.compare("again")
        with self.assertRaises(SystemExit):
            self.compare("again")

    def test_detects_changed_sent_file(self):
        self.make()
        sent = self.run / "send" / "p001_cover_sym.jpg"
        sent.write_bytes(sent.read_bytes() + b"\x00")
        self.assign(sent)
        with self.assertRaises(SystemExit):
            self.compare()


if __name__ == "__main__":
    unittest.main()
