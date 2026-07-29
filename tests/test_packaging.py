from __future__ import annotations

import stat
import tomllib
import unittest
from importlib import resources
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


class PackagingContractTests(unittest.TestCase):
    def test_pep561_marker_is_packaged(self) -> None:
        marker = resources.files("netveil").joinpath("py.typed")
        self.assertTrue(marker.is_file())
        self.assertIn(marker.read_bytes(), (b"", b"\n"))

    def test_static_launcher_replaces_generated_entry_point(self) -> None:
        document = tomllib.loads((ROOT / "pyproject.toml").read_text())
        project = document["project"]
        setuptools = document["tool"]["setuptools"]
        self.assertNotIn("scripts", project)
        self.assertEqual(project["dependencies"], [])
        self.assertEqual(setuptools["script-files"], ["scripts/netveil-audit"])
        self.assertEqual(setuptools["py-modules"], ["netveil_bootstrap"])

        launcher = ROOT / "scripts" / "netveil-audit"
        self.assertEqual(launcher.read_bytes().splitlines()[0], b"#!/bin/sh")
        self.assertTrue(launcher.stat().st_mode & stat.S_IXUSR)

    def test_source_manifest_keeps_release_evidence_reproducible(self) -> None:
        manifest = (ROOT / "MANIFEST.in").read_text().splitlines()
        required = {
            "include README.md",
            "include SECURITY.md",
            "include requirements-dev.txt",
            "include scripts/netveil-audit",
            "recursive-include docs *.md",
            "recursive-include docs/assets *.svg *.json *.cast *.gif",
            "recursive-include tests *.py",
            "recursive-include tools *.py",
        }
        self.assertTrue(required.issubset(manifest))

    def test_developer_tool_versions_are_exactly_pinned(self) -> None:
        requirements = (ROOT / "requirements-dev.txt").read_text().splitlines()
        pins = [line for line in requirements if line and not line.startswith("#")]
        self.assertGreaterEqual(len(pins), 4)
        self.assertTrue(all(line.count("==") == 1 for line in pins))

    def test_package_metadata_identifies_omar_and_public_project_links(self) -> None:
        document = tomllib.loads((ROOT / "pyproject.toml").read_text())
        project = document["project"]

        self.assertEqual(project["authors"], [{"name": "Omar Ibrahim"}])
        self.assertEqual(
            project["urls"]["Repository"],
            "https://github.com/omar07ibrahim/Hello-World",
        )
        self.assertIn("Typing :: Typed", project["classifiers"])


if __name__ == "__main__":
    unittest.main()
