from __future__ import annotations

import io
import json
import unittest
from pathlib import Path

from PIL import Image

from tools import render_evidence, render_raster_evidence

ROOT = Path(__file__).resolve().parents[1]


class RasterEvidenceTests(unittest.TestCase):
    def _render(self) -> dict[str, bytes]:
        return render_raster_evidence.render_bundle(
            render_evidence.VERIFICATION_PATH.read_bytes(),
            render_evidence.INVENTORY_PATH.read_bytes(),
            (ROOT / render_evidence.MANIFEST_PATH).read_bytes(),
            (ROOT / render_evidence.CAST_PATH).read_bytes(),
            generator_payload=render_raster_evidence.GENERATOR_PATH.read_bytes(),
            vector_generator_payload=render_evidence.GENERATOR_PATH.read_bytes(),
        )

    def test_bundle_has_real_png_and_six_frame_gif_outputs(self) -> None:
        outputs = self._render()
        self.assertEqual(set(outputs), set(render_raster_evidence.ALL_OUTPUT_PATHS))

        expected_png_sizes = {
            render_raster_evidence.TERMINAL_PNG_PATH: (1440, 661),
            render_raster_evidence.SUMMARY_PNG_PATH: (1440, 1220),
        }
        for path, expected_size in expected_png_sizes.items():
            with Image.open(io.BytesIO(outputs[path])) as image:
                self.assertEqual(image.format, "PNG")
                self.assertEqual(image.size, expected_size)

        workflow = outputs[render_raster_evidence.WORKFLOW_GIF_PATH]
        self.assertNotIn(b"NETSCAPE2.0", workflow)
        with Image.open(io.BytesIO(workflow)) as animation:
            self.assertEqual(animation.format, "GIF")
            self.assertEqual(animation.size, (1280, 720))
            self.assertNotIn("loop", animation.info)
            animation.seek(5)
            self.assertEqual(animation.tell(), 5)
            with self.assertRaises(EOFError):
                animation.seek(6)

        manifest = json.loads(outputs[render_raster_evidence.MANIFEST_PATH])
        self.assertEqual(manifest["schema"], render_raster_evidence.SCHEMA)
        self.assertEqual(
            manifest["source_commit"],
            json.loads(render_evidence.VERIFICATION_PATH.read_bytes())["source_commit"],
        )
        self.assertEqual(len(manifest["outputs"]), 3)

    def test_rendering_is_byte_deterministic(self) -> None:
        self.assertEqual(self._render(), self._render())

    def test_committed_raster_bundle_is_complete_or_absent(self) -> None:
        paths = [ROOT / path for path in render_raster_evidence.ALL_OUTPUT_PATHS]
        if not any(path.exists() for path in paths):
            return
        self.assertTrue(all(path.is_file() for path in paths))
        expected = self._render()
        for relative_path, payload in expected.items():
            self.assertEqual((ROOT / relative_path).read_bytes(), payload)


if __name__ == "__main__":
    unittest.main()
