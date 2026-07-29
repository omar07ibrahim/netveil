from __future__ import annotations

import base64
import contextlib
import hashlib
import io
import os
import stat
import sys
import tempfile
import unittest
from collections.abc import Iterator
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
LAUNCHER_PATH = ROOT / "scripts" / "netveil-audit"
BOOTSTRAP_FIXTURE = ROOT / "tests" / "fixtures" / "launcher_bootstrap_fixture.py"


class _FakeHash:
    def __init__(self, value: str, mode: str = "sha256") -> None:
        self.mode = mode
        self.value = value


class _FakeRecord:
    def __init__(
        self,
        payload: bytes,
        *,
        path: str = "artifact",
        mode: str = "sha256",
        size: int | None = None,
    ) -> None:
        self.path = path
        digest = hashlib.sha256(payload).digest()
        value = base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")
        self.hash: _FakeHash | None = _FakeHash(value, mode)
        self.size = len(payload) if size is None else size

    def __str__(self) -> str:
        return self.path


class _FakeDistribution:
    def __init__(
        self,
        root: Path,
        files: list[_FakeRecord] | None,
    ) -> None:
        self.root = root
        self.files = files
        self.metadata = {
            "Name": "netveil-audit",
            "Version": "0.3.0",
        }
        self.locations: dict[str, Path] = {}

    def locate_file(self, record: object) -> Path:
        raw_path = str(record)
        return self.locations.get(raw_path, self.root / raw_path)


def _load_launcher() -> ModuleType:
    module = ModuleType("netveil_launcher_test")
    module.__file__ = str(LAUNCHER_PATH)
    source = LAUNCHER_PATH.read_bytes()
    exec(  # noqa: S102 - test loads the repository-owned launcher source.
        compile(source, str(LAUNCHER_PATH), "exec", dont_inherit=True),
        module.__dict__,
    )
    return module


@contextlib.contextmanager
def _without_netveil_modules() -> Iterator[None]:
    saved = {
        name: module
        for name, module in sys.modules.items()
        if name == "netveil_bootstrap"
        or name == "netveil"
        or name.startswith("netveil.")
    }
    for name in saved:
        sys.modules.pop(name, None)
    try:
        yield
    finally:
        for name in tuple(sys.modules):
            if (
                name == "netveil_bootstrap"
                or name == "netveil"
                or name.startswith("netveil.")
            ):
                sys.modules.pop(name, None)
        sys.modules.update(saved)


class LauncherBoundaryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.launcher = _load_launcher()
        self.bootstrap_payload = BOOTSTRAP_FIXTURE.read_bytes()

    def test_polyglot_header_requests_exact_isolation_profile(self) -> None:
        lines = LAUNCHER_PATH.read_text().splitlines()
        self.assertEqual(lines[0], "#!/bin/sh")
        self.assertEqual(
            lines[6],
            'exec "$netveil_script_directory/python" -IESB "$0" "$@"',
        )
        self.assertFalse(self.launcher._startup_is_isolated())

    def test_python_main_guard_fails_closed_without_isolation(self) -> None:
        namespace = {
            "__file__": str(LAUNCHER_PATH),
            "__name__": "__main__",
        }
        stderr = io.StringIO()
        with (
            patch.object(sys, "stderr", stderr),
            self.assertRaises(SystemExit) as raised,
        ):
            exec(  # noqa: S102 - test executes repository-owned launcher source.
                compile(
                    LAUNCHER_PATH.read_bytes(),
                    str(LAUNCHER_PATH),
                    "exec",
                    dont_inherit=True,
                ),
                namespace,
            )
        self.assertEqual(raised.exception.code, 10)
        self.assertEqual(stderr.getvalue(), "netveil-audit: artifact_unverified\n")

    def test_site_root_is_bound_to_installed_prefix_layout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            prefix = Path(directory)
            launcher = prefix / "bin" / "netveil-audit"
            launcher.parent.mkdir()
            launcher.write_bytes(b"launcher")
            site_root = (
                prefix
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "site-packages"
            )
            (site_root / "netveil_audit-0.3.0.dist-info").mkdir(parents=True)
            self.assertEqual(self.launcher._site_root(launcher), site_root)

            duplicate = (
                prefix
                / "lib"
                / f"python{sys.version_info.major}.{sys.version_info.minor}"
                / "dist-packages"
                / "netveil_audit-0.3.0.dist-info"
            )
            duplicate.mkdir(parents=True)
            with self.assertRaises(self.launcher._LaunchFailure):
                self.launcher._site_root(launcher)

        with self.assertRaises(self.launcher._LaunchFailure):
            self.launcher._site_root(Path("/tmp/netveil-audit"))

    def test_record_reader_pins_exact_regular_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            payload = b"record-bound"
            path.write_bytes(payload)
            record = _FakeRecord(payload)
            observed, identity = self.launcher._read_record_bound(path, record)
            self.assertEqual(observed, payload)
            self.assertEqual(identity, self.launcher._identity(path.stat()))

            path.write_bytes(b"record-b0und")
            with self.assertRaises(self.launcher._LaunchFailure):
                self.launcher._read_record_bound(path, record)

    def test_record_reader_rejects_contract_and_file_shape_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            path = root / "artifact"
            path.write_bytes(b"x")
            for record in (
                _FakeRecord(b"x", mode="sha512"),
                _FakeRecord(b"x", size=True),
                _FakeRecord(b"x", size=-1),
                _FakeRecord(
                    b"x",
                    size=self.launcher._MAX_ARTIFACT_FILE_BYTES + 1,
                ),
            ):
                with (
                    self.subTest(record=record),
                    self.assertRaises(self.launcher._LaunchFailure),
                ):
                    self.launcher._read_record_bound(path, record)

            no_hash = _FakeRecord(b"x")
            no_hash.hash = None
            with self.assertRaises(self.launcher._LaunchFailure):
                self.launcher._read_record_bound(path, no_hash)

            directory_path = root / "directory"
            directory_path.mkdir()
            with self.assertRaises(self.launcher._LaunchFailure):
                self.launcher._read_record_bound(
                    directory_path,
                    _FakeRecord(b"", size=0),
                )

            symlink = root / "link"
            symlink.symlink_to(path)
            with self.assertRaises(self.launcher._LaunchFailure):
                self.launcher._read_record_bound(symlink, _FakeRecord(b"x"))

            oversized = root / "oversized"
            oversized.write_bytes(b"x" * (self.launcher._MAX_ARTIFACT_FILE_BYTES + 1))
            with self.assertRaises(self.launcher._LaunchFailure):
                self.launcher._read_bounded_regular(oversized)

    def test_record_reader_handles_io_and_close_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "artifact"
            path.write_bytes(b"x")
            record = _FakeRecord(b"x")
            with (
                patch.object(self.launcher.os, "open", side_effect=OSError),
                self.assertRaises(self.launcher._LaunchFailure),
            ):
                self.launcher._read_record_bound(path, record)
            with (
                patch.object(self.launcher.os, "read", side_effect=OSError),
                self.assertRaises(self.launcher._LaunchFailure),
            ):
                self.launcher._read_record_bound(path, record)
            with (
                patch.object(self.launcher.os, "close", side_effect=OSError),
                self.assertRaises(self.launcher._LaunchFailure),
            ):
                self.launcher._read_record_bound(path, record)
            with (
                patch.object(self.launcher.os, "read", return_value=b"xx"),
                self.assertRaises(self.launcher._LaunchFailure),
            ):
                self.launcher._read_record_bound(path, record)

    def _installed_artifact(
        self,
        root: Path,
    ) -> tuple[Path, Path, _FakeDistribution, bytes]:
        prefix = root / "prefix"
        launcher_path = prefix / "bin" / "netveil-audit"
        launcher_path.parent.mkdir(parents=True)
        launcher_payload = b"trusted launcher"
        launcher_path.write_bytes(launcher_payload)
        site_root = (
            prefix
            / "lib"
            / f"python{sys.version_info.major}.{sys.version_info.minor}"
            / "site-packages"
        )
        dist_info = site_root / "netveil_audit-0.3.0.dist-info"
        dist_info.mkdir(parents=True)
        (dist_info / "METADATA").write_bytes(b"bounded metadata")
        (dist_info / "RECORD").write_bytes(b"bounded record")
        bootstrap_payload = b"trusted bootstrap"
        (site_root / "netveil_bootstrap.py").write_bytes(bootstrap_payload)
        launcher_record_path = os.path.relpath(launcher_path, site_root)
        records = [
            _FakeRecord(launcher_payload, path=launcher_record_path),
            _FakeRecord(bootstrap_payload, path="netveil_bootstrap.py"),
        ]
        return (
            launcher_path,
            site_root,
            _FakeDistribution(site_root, records),
            bootstrap_payload,
        )

    def test_verified_bootstrap_binds_launcher_and_source_records(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            launcher_path, site_root, distribution, expected = self._installed_artifact(
                Path(directory)
            )
            original_path = list(sys.path)
            try:
                with patch.object(
                    self.launcher.importlib.metadata,
                    "PathDistribution",
                    return_value=cast(metadata.Distribution, distribution),
                ):
                    payload, bootstrap_path = self.launcher._verified_bootstrap(
                        launcher_path
                    )
            finally:
                sys.path[:] = original_path
        self.assertEqual(payload, expected)
        self.assertEqual(bootstrap_path, site_root / "netveil_bootstrap.py")

    def test_verified_bootstrap_rejects_metadata_and_record_drift(self) -> None:
        mutations = (
            "missing-metadata",
            "wrong-name",
            "wrong-version",
            "missing-launcher",
            "missing-bootstrap",
            "entry-points",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                launcher_path, _, distribution, _ = self._installed_artifact(
                    Path(directory)
                )
                assert distribution.files is not None
                if mutation == "missing-metadata":
                    distribution.metadata.pop("Name")
                elif mutation == "wrong-name":
                    distribution.metadata["Name"] = "other"
                elif mutation == "wrong-version":
                    distribution.metadata["Version"] = "9.9.9"
                elif mutation == "missing-launcher":
                    distribution.files = [
                        record
                        for record in distribution.files
                        if str(record) == "netveil_bootstrap.py"
                    ]
                elif mutation == "missing-bootstrap":
                    distribution.files = [
                        record
                        for record in distribution.files
                        if str(record) != "netveil_bootstrap.py"
                    ]
                else:
                    site_root = distribution.root
                    (
                        site_root / "netveil_audit-0.3.0.dist-info" / "entry_points.txt"
                    ).write_bytes(b"[console_scripts]\n")
                with (
                    patch.object(
                        self.launcher.importlib.metadata,
                        "PathDistribution",
                        return_value=cast(metadata.Distribution, distribution),
                    ),
                    self.assertRaises(self.launcher._LaunchFailure),
                ):
                    self.launcher._verified_bootstrap(launcher_path)

    def test_record_inventory_and_terminal_identity_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            _, _, distribution, _ = self._installed_artifact(Path(directory))
            distribution.files = None
            with self.assertRaises(self.launcher._LaunchFailure):
                self.launcher._records(cast(metadata.Distribution, distribution))

        duplicate = _FakeRecord(b"x", path="same")
        distribution = _FakeDistribution(Path("/unused"), [duplicate, duplicate])
        with self.assertRaises(self.launcher._LaunchFailure):
            self.launcher._records(cast(metadata.Distribution, distribution))

        with tempfile.TemporaryDirectory() as directory:
            launcher_path, _, distribution, _ = self._installed_artifact(
                Path(directory)
            )
            with (
                patch.object(
                    self.launcher.os,
                    "lstat",
                    side_effect=PermissionError,
                ),
                patch.object(
                    self.launcher.importlib.metadata,
                    "PathDistribution",
                    return_value=cast(metadata.Distribution, distribution),
                ),
                self.assertRaises(self.launcher._LaunchFailure),
            ):
                self.launcher._verified_bootstrap(launcher_path)

        for mismatch_call in (2, 4):
            with (
                self.subTest(mismatch_call=mismatch_call),
                tempfile.TemporaryDirectory() as directory,
            ):
                launcher_path, _, distribution, _ = self._installed_artifact(
                    Path(directory)
                )
                reads = [
                    (b"launcher", (1,)),
                    (b"launcher", (1 if mismatch_call != 2 else 2,)),
                    (b"bootstrap", (3,)),
                    (b"bootstrap", (3 if mismatch_call != 4 else 4,)),
                ]
                with (
                    patch.object(
                        self.launcher.importlib.metadata,
                        "PathDistribution",
                        return_value=cast(metadata.Distribution, distribution),
                    ),
                    patch.object(
                        self.launcher,
                        "_read_record_bound",
                        side_effect=reads,
                    ),
                    self.assertRaises(self.launcher._LaunchFailure),
                ):
                    self.launcher._verified_bootstrap(launcher_path)

    def test_verified_bootstrap_bytes_are_executed_in_memory(self) -> None:
        with (
            _without_netveil_modules(),
            patch.object(sys, "argv", ["netveil-audit", "safe"]),
        ):
            self.assertEqual(
                self.launcher._execute_bootstrap(
                    self.bootstrap_payload,
                    BOOTSTRAP_FIXTURE,
                ),
                23,
            )

    def test_preload_invalid_result_and_exception_fail_closed(self) -> None:
        with (
            patch.dict(sys.modules, {"netveil": ModuleType("netveil")}),
            self.assertRaises(self.launcher._LaunchFailure),
        ):
            self.launcher._execute_bootstrap(
                self.bootstrap_payload,
                BOOTSTRAP_FIXTURE,
            )

        with (
            _without_netveil_modules(),
            patch.object(
                sys,
                "argv",
                ["netveil-audit", "invalid"],
            ),
            self.assertRaises(self.launcher._LaunchFailure),
        ):
            self.launcher._execute_bootstrap(self.bootstrap_payload, BOOTSTRAP_FIXTURE)

        with _without_netveil_modules():
            with (
                patch.object(sys, "argv", ["netveil-audit", "explode"]),
                self.assertRaises(RuntimeError),
            ):
                self.launcher._execute_bootstrap(
                    self.bootstrap_payload,
                    BOOTSTRAP_FIXTURE,
                )
            self.assertNotIn("netveil_bootstrap", sys.modules)

        marker = "PRIVATE-LAUNCHER-MARKER"
        stderr = io.StringIO()
        with (
            patch.object(
                self.launcher,
                "_startup_is_isolated",
                side_effect=RuntimeError(marker),
            ),
            patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(
                self.launcher.main(),
                self.launcher._INTERNAL_FAILURE_EXIT,
            )
        self.assertEqual(stderr.getvalue(), "netveil-audit: internal_error\n")
        self.assertNotIn(marker, stderr.getvalue())

    def test_exact_error_writer_handles_partial_and_broken_output(self) -> None:
        class PartialWriter(io.StringIO):
            def write(self, value: str) -> int:
                return super().write(value[:1])

        writer = PartialWriter()
        with patch.object(sys, "stderr", writer):
            self.assertEqual(
                self.launcher._write_failure("safe", 23),
                23,
            )
        self.assertEqual(writer.getvalue(), "netveil-audit: safe\n")

        for written in (0, None, 100):
            broken = io.StringIO()
            with (
                patch.object(broken, "write", return_value=written),
                patch.object(sys, "stderr", broken),
            ):
                self.assertEqual(
                    self.launcher._write_failure("safe", 23),
                    self.launcher._OUTPUT_FAILURE_EXIT,
                )
        with patch.object(sys.stderr, "write", side_effect=OSError):
            self.assertEqual(
                self.launcher._write_failure("safe", 23),
                self.launcher._OUTPUT_FAILURE_EXIT,
            )

    def test_file_flags_and_identity_are_fail_closed(self) -> None:
        required = os.O_CLOEXEC | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK
        self.assertEqual(self.launcher._file_flags() & required, required)
        status = LAUNCHER_PATH.stat()
        self.assertTrue(stat.S_ISREG(status.st_mode))
        self.assertEqual(
            self.launcher._identity(status),
            (
                status.st_dev,
                status.st_ino,
                status.st_mode,
                status.st_uid,
                status.st_gid,
                status.st_nlink,
                status.st_size,
                status.st_mtime_ns,
                status.st_ctime_ns,
            ),
        )
        with (
            patch("builtins.hasattr", return_value=False),
            self.assertRaises(self.launcher._LaunchFailure),
        ):
            self.launcher._file_flags()

    def test_main_maps_success_and_failures_to_stable_codes(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(sys, "stderr", stderr),
            patch.object(self.launcher, "_startup_is_isolated", return_value=False),
        ):
            self.assertEqual(
                self.launcher.main(),
                self.launcher._ARTIFACT_FAILURE_EXIT,
            )
        self.assertEqual(stderr.getvalue(), "netveil-audit: artifact_unverified\n")

        with (
            patch.object(self.launcher, "_startup_is_isolated", return_value=True),
            patch.object(
                self.launcher,
                "_verified_bootstrap",
                return_value=(b"source", Path("/bootstrap")),
            ),
            patch.object(self.launcher, "_execute_bootstrap", return_value=23),
        ):
            self.assertEqual(self.launcher.main(), 23)

        stderr = io.StringIO()
        with (
            patch.object(sys, "stderr", stderr),
            patch.object(self.launcher, "_startup_is_isolated", return_value=True),
            patch.object(
                self.launcher,
                "_verified_bootstrap",
                side_effect=KeyboardInterrupt,
            ),
        ):
            self.assertEqual(
                self.launcher.main(),
                self.launcher._INTERNAL_FAILURE_EXIT,
            )
        self.assertEqual(stderr.getvalue(), "netveil-audit: interrupted\n")
