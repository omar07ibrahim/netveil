from __future__ import annotations

import unittest
from pathlib import Path

from tools import render_architecture

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


if __name__ == "__main__":
    unittest.main()
