from __future__ import annotations

import unittest
from importlib import resources


class PackagingContractTests(unittest.TestCase):
    def test_pep561_marker_is_packaged(self) -> None:
        marker = resources.files("netveil").joinpath("py.typed")
        self.assertTrue(marker.is_file())
        self.assertIn(marker.read_bytes(), (b"", b"\n"))


if __name__ == "__main__":
    unittest.main()
