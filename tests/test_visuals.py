from __future__ import annotations

import json
import unittest
from pathlib import Path
from xml.etree import ElementTree

from tools import render_architecture, render_evidence, render_raster_evidence

ROOT = Path(__file__).resolve().parents[1]


class VisualEvidenceTests(unittest.TestCase):
    def test_architecture_svg_is_current_and_code_derived(self) -> None:
        expected = render_architecture.render()
        observed = (ROOT / "docs" / "assets" / "architecture.svg").read_bytes()
        self.assertEqual(observed, expected)
        text = observed.decode("utf-8")
        self.assertIn("Netveil installed execution boundary", text)
        self.assertIn("-I -E -S -B", text)
        self.assertIn("installed RECORD is not a signature", text)

    def test_committed_release_evidence_views_are_current(self) -> None:
        evidence_paths = (
            render_evidence.VERIFICATION_PATH,
            render_evidence.INVENTORY_PATH,
        )
        if not all(path.is_file() for path in evidence_paths):
            self.assertFalse(
                any(path.exists() for path in evidence_paths),
                "release evidence must be either complete or absent",
            )
            return

        outputs = render_evidence.render_bundle(
            render_evidence.VERIFICATION_PATH.read_bytes(),
            render_evidence.INVENTORY_PATH.read_bytes(),
            generator_payload=render_evidence.GENERATOR_PATH.read_bytes(),
        )
        for relative_path, expected in outputs.items():
            observed = (ROOT / relative_path).read_bytes()
            self.assertEqual(observed, expected, relative_path)

        for relative_path in (
            render_evidence.CLI_SVG_PATH,
            render_evidence.COUNTS_SVG_PATH,
            render_evidence.MATRIX_SVG_PATH,
            render_evidence.PROVENANCE_SVG_PATH,
        ):
            ElementTree.fromstring(outputs[relative_path])
        for line in outputs[render_evidence.CAST_PATH].splitlines():
            json.loads(line)

    def test_readme_presents_every_reproducible_visual(self) -> None:
        readme = (ROOT / "README.md").read_text()
        expected_links = {
            "docs/assets/architecture.svg",
            *render_evidence.VISUAL_OUTPUT_PATHS,
            *render_raster_evidence.RASTER_OUTPUT_PATHS,
            render_evidence.MANIFEST_PATH,
            render_raster_evidence.MANIFEST_PATH,
            "docs/evidence/fresh-wheel-verification.json",
            "docs/evidence/release-inventory.json",
        }
        for link in expected_links:
            self.assertIn(link, readme)


if __name__ == "__main__":
    unittest.main()
