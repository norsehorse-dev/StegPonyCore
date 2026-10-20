"""Tests the lab's data handling, not any real messenger channel."""
import csv
import io
import json
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path
from types import SimpleNamespace

from PIL import Image
import lab


class ChannelLabTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.photo = self.root / "camera.jpg"
        image = Image.new("RGB", (80, 48))
        image.putdata([(x*7 % 256, x*13 % 256, x*19 % 256) for x in range(80*48)])
        exif = Image.Exif()
        exif[274] = 6
        exif[315] = "private author"
        image.save(self.photo, quality=95, exif=exif)
        self.original = self.photo.read_bytes()
        self.out = self.root / "run"

    def prepare(self, **overrides):
        kwargs = dict(photos=[str(self.photo)], recursive=False, limit=None, out=self.out,
                      sizes=[32, 160, 0], qualities=[80, 95], sampling="420", dry_run=False)
        kwargs.update(overrides)
        with redirect_stdout(io.StringIO()):
            lab.prepare(SimpleNamespace(**kwargs))
        return json.loads((self.out / "manifest.json").read_text()) if self.out.exists() else None

    def worksheet(self, rows):
        with (self.out / "signal-photo.csv").open("w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["id", "received", "notes"])
            writer.writeheader()
            writer.writerows(rows)

    def compare(self):
        with redirect_stdout(io.StringIO()):
            lab.compare(SimpleNamespace(run=self.out, channel="signal-photo", out=None))
        return json.loads((self.out / "reports/signal-photo.json").read_text())

    def test_orientation_dimensions_tables_and_metadata(self):
        manifest = self.prepare()
        self.assertEqual(self.photo.read_bytes(), self.original)
        self.assertEqual(len(manifest["images"]), 6)
        for item in manifest["images"]:
            self.assertFalse(item["has_exif"])
            self.assertFalse(item["has_icc"])
            self.assertEqual(item["components"][0][1:3], [2, 2])
            self.assertEqual(len(item["quantization_natural"]["0"]), 64)
            dims = (item["width"], item["height"])
            self.assertEqual(dims, (19,32) if item["requested_long_edge"] == 32 else (48,80))
        self.assertNotEqual(manifest["images"][0]["quantization_natural"],
                            manifest["images"][1]["quantization_natural"])
        # The generated JPEGs are repeatable in this pinned environment.
        other = self.root / "other"
        again = self.prepare(out=other)
        again = json.loads((other / "manifest.json").read_text())
        self.assertEqual([i["sha256"] for i in manifest["images"]], [i["sha256"] for i in again["images"]])

    def test_compare_renamed_return_and_partial_run(self):
        manifest = self.prepare()
        item = manifest["images"][0]
        received = self.out / "received/signal-photo/renamed.jpg"
        received.write_bytes((self.out / item["file"]).read_bytes())
        self.worksheet([dict(id=item["id"], received="received/signal-photo/renamed.jpg", notes="control")])
        report = self.compare()
        self.assertEqual((report["compared"], report["missing"]), (1,5))
        result = report["results"][0]
        self.assertTrue(result["same_bytes"])
        self.assertTrue(result["same_decoded_rgb"])
        self.assertTrue(result["same_quantization"])
        self.assertIn("app_version", report["missing_session_fields"])
        with self.assertRaises(FileExistsError):
            self.compare()

    def test_compare_resized_recompressed_return(self):
        item = self.prepare()["images"][0]
        received = self.out / "received/signal-photo/changed.jpg"
        with Image.open(self.out / item["file"]) as im:
            im.resize((8,12)).save(received, quality=60, subsampling=0)
        self.worksheet([dict(id=item["id"], received="received/signal-photo/changed.jpg", notes="simulation")])
        result = self.compare()["results"][0]
        self.assertFalse(result["same_bytes"])
        self.assertFalse(result["same_dimensions"])
        self.assertFalse(result["same_jpeg_grid"])
        self.assertFalse(result["same_quantization"])
        self.assertIsNone(result["same_decoded_rgb"])

    def test_changed_sent_file_is_rejected(self):
        item = self.prepare()["images"][0]
        source = self.out / item["file"]
        returned = self.out / "received/signal-photo/test.jpg"
        returned.write_bytes(source.read_bytes())
        source.write_bytes(source.read_bytes() + b"changed")
        self.worksheet([dict(id=item["id"], received="received/signal-photo/test.jpg", notes="")])
        with self.assertRaisesRegex(ValueError, "changed since"):
            self.compare()
        self.assertFalse((self.out / "reports/signal-photo.json").exists())

    def test_bad_inputs_and_existing_run_never_overwrite(self):
        with self.assertRaisesRegex(ValueError, "qualities"):
            self.prepare(qualities=[101])
        self.assertFalse(self.out.exists())
        bad = self.root / "broken.jpg"
        bad.write_bytes(b"invalid")
        with self.assertRaises(OSError):
            self.prepare(photos=[str(self.photo),str(bad)])
        self.assertFalse(self.out.exists())
        self.prepare()
        marker = self.out / "marker"
        marker.write_text("keep")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.prepare()
        self.assertEqual(marker.read_text(), "keep")

    def test_dry_run_and_input_folder_protection(self):
        self.prepare(dry_run=True)
        self.assertFalse(self.out.exists())
        with self.assertRaisesRegex(ValueError, "outside"):
            self.prepare(photos=[str(self.root)])

    def test_paths_and_duplicate_mapping_are_rejected(self):
        items = self.prepare()["images"]
        self.worksheet([dict(id=items[0]["id"], received="../camera.jpg", notes="")])
        with self.assertRaisesRegex(ValueError, "escapes"):
            self.compare()
        self.worksheet([dict(id=items[0]["id"], received="", notes="")]*2)
        with self.assertRaisesRegex(ValueError, "duplicate"):
            self.compare()
        self.worksheet([dict(id="unknown", received="", notes="")])
        with self.assertRaisesRegex(ValueError, "Unknown"):
            self.compare()

    def test_no_returns_is_not_success(self):
        self.prepare()
        with self.assertRaisesRegex(ValueError, "No received"):
            self.compare()

    def test_returns_must_sit_in_their_channel_folder(self):
        items = self.prepare()["images"]
        for path in (items[0]["file"], "received/whatsapp-hd/x.jpg"):
            self.worksheet([dict(id=items[0]["id"], received=path, notes="")])
            with self.assertRaisesRegex(ValueError, "must be under received/signal-photo/"):
                self.compare()

    def test_ijg_quality_matches_pillow_tables(self):
        image = Image.new("RGB", (16, 16), (90, 120, 30))
        for quality in (1, 10, 25, 49, 50, 51, 75, 80, 95, 100):
            data = io.BytesIO()
            image.save(data, "JPEG", quality=quality)
            self.assertEqual(lab.describe(data.getvalue())["ijg_quality"], quality)
        data = io.BytesIO()
        image.save(data, "JPEG", qtables=[[3] * 64, [5] * 64])
        info = lab.describe(data.getvalue())
        self.assertIsNone(info["ijg_quality"])
        self.assertTrue(lab.table_family(info).startswith("other "))

    def test_requantize_rounds_half_away_from_zero(self):
        self.assertEqual(lab.requantize(7, 2, 2), 7)
        self.assertEqual(lab.requantize(3, 2, 4), 2)
        self.assertEqual(lab.requantize(-3, 2, 4), -2)
        self.assertEqual(lab.requantize(1, 2, 5), 0)
        self.assertEqual(lab.requantize(-5, 1, 2), -3)

    def test_without_jpeg_tool_coefficients_are_marked_skipped(self):
        item = self.prepare()["images"][0]
        received = self.out / "received/signal-photo/copy.jpg"
        received.write_bytes((self.out / item["file"]).read_bytes())
        self.worksheet([dict(id=item["id"], received="received/signal-photo/copy.jpg", notes="")])
        saved = lab.DEFAULT_JPEG_TOOL
        lab.DEFAULT_JPEG_TOOL = self.root / "no-such-tool"
        try:
            result = self.compare()["results"][0]
        finally:
            lab.DEFAULT_JPEG_TOOL = saved
        self.assertEqual(result["coefficients"], {"skipped": "jpeg_tool not built or not runnable here"})

    @unittest.skipUnless(lab.find_jpeg_tool(None), "build jpeg_tool to run coefficient tests")
    def test_coefficients_pass_through_and_recompression(self):
        items = {i["id"]: i for i in self.prepare(photos=[str(self.big_photo())], sizes=[0])["images"]}
        q95 = next(i for i in items.values() if i["requested_quality"] == 95)
        q80 = next(i for i in items.values() if i["requested_quality"] == 80)
        folder = self.out / "received/signal-photo"
        (folder / "same.jpg").write_bytes((self.out / q80["file"]).read_bytes())
        with Image.open(self.out / q95["file"]) as im:
            im.save(folder / "again.jpg", quality=80)
        self.worksheet([dict(id=q80["id"], received="received/signal-photo/same.jpg", notes=""),
                        dict(id=q95["id"], received="received/signal-photo/again.jpg", notes="")])
        results = {r["id"]: r for r in self.compare()["results"]}
        same = results[q80["id"]]["coefficients"]
        self.assertEqual(same["match_rate"], 1.0)
        self.assertTrue(all(c["same_table"] for c in same["components"]))
        again = results[q95["id"]]["coefficients"]
        self.assertFalse(again["components"][0]["same_table"])
        self.assertEqual(results[q95["id"]]["received_tables"], "IJG q80")
        blocks = [c["blocks"] for c in again["components"]]
        self.assertEqual(blocks, [8 * 6, 4 * 3, 4 * 3])
        self.assertEqual(again["coefficients"], sum(blocks) * 64)
        self.assertGreater(again["match_rate"], 0.5)
        self.assertLessEqual(again["match_rate"], 1.0)
        for c in again["components"]:
            self.assertEqual(c["ac_sent_zero"] + c["ac_sent_nonzero"], c["blocks"] * 63)
            self.assertEqual(len(c["mismatch_rate_by_zigzag"]), 64)

    def big_photo(self):
        path = self.root / "texture.png"
        image = Image.new("RGB", (64, 48))
        image.putdata([((x * 37 + y * 11) % 256, (x * x + y) % 256, (y * 23) % 256)
                       for y in range(48) for x in range(64)])
        image.save(path)
        return path

    def test_file_control_matches_by_hash(self):
        items = self.prepare()["images"]
        folder = self.root / "downloaded"
        (folder / "inner").mkdir(parents=True)
        (folder / "__MACOSX").mkdir()
        (folder / "inner" / "renamed.jpg").write_bytes((self.out / items[0]["file"]).read_bytes())
        (folder / "__MACOSX" / "._renamed.jpg").write_bytes(b"resource fork")
        (folder / "changed.jpg").write_bytes((self.out / items[1]["file"]).read_bytes() + b"x")
        with redirect_stdout(io.StringIO()):
            lab.control(SimpleNamespace(run=self.out, folder=folder, note="file send", out=None))
        report = json.loads((self.out / "reports/file-control.json").read_text())
        self.assertEqual(report["matched"], {items[0]["id"]: ["inner/renamed.jpg"]})
        self.assertEqual(report["unmatched"], [{"file": "changed.jpg", "bytes": items[1]["bytes"] + 1}])
        self.assertEqual(report["not_returned"], len(items) - 1)
        with self.assertRaises(FileExistsError):
            with redirect_stdout(io.StringIO()):
                lab.control(SimpleNamespace(run=self.out, folder=folder, note="", out=None))

    def test_summary_reads_reports_and_never_overwrites(self):
        items = self.prepare()["images"]
        received = self.out / "received/signal-photo/r.jpg"
        received.write_bytes((self.out / items[2]["file"]).read_bytes())
        with self.assertRaisesRegex(ValueError, "No reports"):
            with redirect_stdout(io.StringIO()):
                lab.summary(SimpleNamespace(run=self.out, out=None))
        self.worksheet([dict(id=items[2]["id"], received="received/signal-photo/r.jpg", notes="")])
        self.compare()
        with redirect_stdout(io.StringIO()):
            lab.summary(SimpleNamespace(run=self.out, out=None))
        text = (self.out / "reports/summary.md").read_text()
        self.assertIn("## signal-photo", text)
        self.assertIn(items[2]["id"], text)
        self.assertIn("came back at the same size", text)
        with self.assertRaises(FileExistsError):
            with redirect_stdout(io.StringIO()):
                lab.summary(SimpleNamespace(run=self.out, out=None))


if __name__ == "__main__":
    unittest.main()
