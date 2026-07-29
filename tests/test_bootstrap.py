from __future__ import annotations

import base64
import contextlib
import hashlib
import importlib
import io
import os
import py_compile
import stat
import subprocess
import sys
import tempfile
import unittest
from collections.abc import Callable, Iterator
from dataclasses import dataclass, replace
from importlib import metadata
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest.mock import patch

import netveil_bootstrap as bootstrap

ROOT = Path(__file__).resolve().parents[1]
SOURCE_ROOT = ROOT / "src"


@dataclass(slots=True)
class _FakeHash:
    mode: str
    value: str


@dataclass(slots=True)
class _FakeRecord:
    path: str
    hash: _FakeHash | None
    size: int | None

    def __str__(self) -> str:
        return self.path


@dataclass(slots=True)
class _FakeEntryPoint:
    group: str
    name: str
    value: str


@dataclass
class _FakeDistribution:
    root: Path
    version: str
    files: list[_FakeRecord] | None
    metadata: dict[str, str]
    entry_points: list[_FakeEntryPoint]

    def locate_file(self, path: object) -> Path:
        return self.root / str(path)


def _hash(payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _record(path: str, payload: bytes) -> _FakeRecord:
    return _FakeRecord(path, _FakeHash("sha256", _hash(payload)), len(payload))


def _write(root: Path, relative: str, payload: bytes) -> _FakeRecord:
    target = root / relative
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_bytes(payload)
    return _record(relative, payload)


def _create_artifact(root: Path) -> _FakeDistribution:
    records: list[_FakeRecord] = []
    records.append(
        _write(
            root,
            bootstrap._BOOTSTRAP_FILE,
            (SOURCE_ROOT / bootstrap._BOOTSTRAP_FILE).read_bytes(),
        )
    )
    for name in sorted(bootstrap._PACKAGE_FILES):
        records.append(
            _write(
                root,
                f"netveil/{name}",
                (SOURCE_ROOT / "netveil" / name).read_bytes(),
            )
        )

    metadata_root = f"netveil_audit-{bootstrap._DISTRIBUTION_VERSION}.dist-info"
    metadata_payloads = {
        "METADATA": (b"Metadata-Version: 2.4\nName: netveil-audit\nVersion: 0.3.0\n"),
        "WHEEL": b"Wheel-Version: 1.0\nRoot-Is-Purelib: true\nTag: py3-none-any\n",
        "top_level.txt": b"netveil\nnetveil_bootstrap\n",
    }
    for name, payload in metadata_payloads.items():
        records.append(_write(root, f"{metadata_root}/{name}", payload))

    return _FakeDistribution(
        root=root,
        version=bootstrap._DISTRIBUTION_VERSION,
        files=records,
        metadata={
            "Name": bootstrap._DISTRIBUTION_NAME,
            "Version": bootstrap._DISTRIBUTION_VERSION,
        },
        entry_points=[],
    )


@contextlib.contextmanager
def _isolated_netveil_modules() -> Iterator[None]:
    saved_modules = {
        name: module
        for name, module in sys.modules.items()
        if name == "netveil" or name.startswith("netveil.")
    }
    saved_meta_path = list(sys.meta_path)
    for name in saved_modules:
        sys.modules.pop(name, None)
    try:
        yield
    finally:
        for name in tuple(sys.modules):
            if name == "netveil" or name.startswith("netveil."):
                sys.modules.pop(name, None)
        sys.modules.update(saved_modules)
        sys.meta_path[:] = saved_meta_path


def _verify(
    root: Path,
    distribution: _FakeDistribution,
) -> bootstrap._VerifiedArtifact:
    with (
        _isolated_netveil_modules(),
        patch.object(bootstrap, "__file__", str(root / bootstrap._BOOTSTRAP_FILE)),
        patch.object(
            metadata,
            "distribution",
            return_value=cast(metadata.Distribution, distribution),
        ),
    ):
        return bootstrap._verify_installed_artifact()


class BootstrapArtifactTests(unittest.TestCase):
    def test_importing_bootstrap_does_not_import_package(self) -> None:
        command = (
            "import sys;"
            f"sys.path.insert(0,{str(SOURCE_ROOT)!r});"
            "import netveil_bootstrap;"
            "print(any(n == 'netveil' or n.startswith('netveil.') "
            "for n in sys.modules))"
        )
        completed = subprocess.run(
            (sys.executable, "-I", "-B", "-c", command),
            check=True,
            capture_output=True,
            text=True,
            env={
                "HOME": "/nonexistent",
                "LANG": "C.UTF-8",
                "LC_ALL": "C.UTF-8",
                "PATH": os.environ.get("PATH", ""),
                "PYTHONHASHSEED": "0",
                "TZ": "UTC",
            },
        )
        self.assertEqual(completed.stdout, "False\n")
        self.assertEqual(completed.stderr, "")

    def test_exact_artifact_returns_pinned_source_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            distribution = _create_artifact(root)
            artifact = _verify(root, distribution)
        self.assertEqual(artifact.version, bootstrap._DISTRIBUTION_VERSION)
        self.assertEqual(
            {module for module, _, _, _ in artifact.sources},
            {module for module, _, _ in bootstrap._SOURCE_MODULES},
        )
        self.assertTrue(all(payload for _, _, payload, _ in artifact.sources))

    def test_loaded_package_and_missing_distribution_fail_closed(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            _create_artifact(root)
            with (
                patch.dict(sys.modules, {"netveil": ModuleType("netveil")}),
                self.assertRaises(bootstrap._BootstrapFailure),
            ):
                bootstrap._verify_installed_artifact()

        with (
            _isolated_netveil_modules(),
            patch.object(
                metadata,
                "distribution",
                side_effect=metadata.PackageNotFoundError("netveil-audit"),
            ),
            self.assertRaises(bootstrap._BootstrapFailure),
        ):
            bootstrap._verify_installed_artifact()

    def test_metadata_identity_and_entrypoint_are_exact(self) -> None:
        mutations = ("version", "name", "metadata-version", "entrypoint")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                distribution = _create_artifact(root)
                if mutation == "version":
                    distribution.version = "9.9.9"
                elif mutation == "name":
                    distribution.metadata["Name"] = "other"
                elif mutation == "metadata-version":
                    distribution.metadata["Version"] = "9.9.9"
                else:
                    distribution.entry_points.append(
                        _FakeEntryPoint(
                            group="console_scripts",
                            name="netveil-audit",
                            value="netveil.cli:entrypoint",
                        )
                    )
                with self.assertRaises(bootstrap._BootstrapFailure):
                    _verify(root, distribution)

    def test_missing_duplicate_nested_and_extra_package_records_fail(self) -> None:
        mutations = ("missing", "duplicate", "nested", "extra-disk")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                distribution = _create_artifact(root)
                assert distribution.files is not None
                if mutation == "missing":
                    distribution.files = [
                        record
                        for record in distribution.files
                        if str(record) != "netveil/parser.py"
                    ]
                elif mutation == "duplicate":
                    distribution.files.append(distribution.files[0])
                elif mutation == "nested":
                    distribution.files.append(
                        _FakeRecord(
                            "netveil/plugins/evil.py",
                            _FakeHash("sha256", "x"),
                            1,
                        )
                    )
                else:
                    (root / "netveil" / "evil.py").write_text("raise SystemExit\n")
                with self.assertRaises(bootstrap._BootstrapFailure):
                    _verify(root, distribution)

    def test_hash_size_type_and_location_drift_fail(self) -> None:
        mutations = (
            "hash",
            "algorithm",
            "size",
            "size-type",
            "oversized",
            "symlink",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                distribution = _create_artifact(root)
                assert distribution.files is not None
                record = next(
                    item
                    for item in distribution.files
                    if str(item) == "netveil/parser.py"
                )
                if mutation == "hash":
                    assert record.hash is not None
                    record.hash.value = "wrong"
                elif mutation == "algorithm":
                    assert record.hash is not None
                    record.hash.mode = "sha512"
                elif mutation == "size":
                    assert record.size is not None
                    record.size += 1
                elif mutation == "size-type":
                    record.size = True
                elif mutation == "oversized":
                    record.size = bootstrap._MAX_ARTIFACT_FILE_BYTES + 1
                else:
                    target = root / "netveil" / "parser.py"
                    target.unlink()
                    target.symlink_to(root / "netveil" / "model.py")
                with self.assertRaises(bootstrap._BootstrapFailure):
                    _verify(root, distribution)

    def test_metadata_payloads_and_top_levels_are_record_bound(self) -> None:
        mutations = ("payload", "top-level", "entry-point", "missing-record")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                distribution = _create_artifact(root)
                assert distribution.files is not None
                metadata_root = (
                    f"netveil_audit-{bootstrap._DISTRIBUTION_VERSION}.dist-info"
                )
                if mutation == "payload":
                    (root / metadata_root / "WHEEL").write_bytes(b"tampered\n")
                elif mutation == "top-level":
                    path = root / metadata_root / "top_level.txt"
                    payload = b"netveil_bootstrap\nnetveil\n"
                    path.write_bytes(payload)
                    record = next(
                        item
                        for item in distribution.files
                        if str(item).endswith("/top_level.txt")
                    )
                    record.hash = _FakeHash("sha256", _hash(payload))
                    record.size = len(payload)
                elif mutation == "entry-point":
                    distribution.entry_points.append(
                        _FakeEntryPoint(
                            group="console_scripts",
                            name="other",
                            value="other:main",
                        )
                    )
                else:
                    distribution.files = [
                        item
                        for item in distribution.files
                        if not str(item).endswith("/METADATA")
                    ]
                with self.assertRaises(bootstrap._BootstrapFailure):
                    _verify(root, distribution)

    def test_cache_is_inert_but_its_shape_is_bounded(self) -> None:
        mutations = ("valid", "unknown", "symlink", "directory")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                distribution = _create_artifact(root)
                package_root = root / "netveil"
                cache = package_root / "__pycache__"
                cache.mkdir()
                known = next(iter(sorted(bootstrap._cache_names())))
                target = cache / known
                if mutation == "valid":
                    target.write_bytes(b"untrusted and deliberately unread")
                    assert distribution.files is not None
                    distribution.files.append(
                        _FakeRecord(
                            f"netveil/__pycache__/{known}",
                            None,
                            None,
                        )
                    )
                    artifact = _verify(root, distribution)
                    self.assertEqual(
                        artifact.version,
                        bootstrap._DISTRIBUTION_VERSION,
                    )
                    continue
                if mutation == "unknown":
                    target = cache / "evil.pyc"
                    target.write_bytes(b"x")
                elif mutation == "symlink":
                    target.symlink_to(package_root / "model.py")
                else:
                    target.mkdir()
                with self.assertRaises(bootstrap._BootstrapFailure):
                    _verify(root, distribution)


class BootstrapSourceLoaderTests(unittest.TestCase):
    def test_verified_bytes_ignore_disk_tamper_and_unchecked_hash_pyc(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            distribution = _create_artifact(root)
            package_root = root / "netveil"
            cache = package_root / "__pycache__"
            cache.mkdir()
            cache_name = f"cli.{sys.implementation.cache_tag}.pyc"
            malicious_source = root / "malicious.py"
            marker = root / "BYTECODE_EXECUTED"
            malicious_source.write_text(
                "from pathlib import Path\n"
                f"Path({str(marker)!r}).write_text('executed')\n"
            )
            py_compile.compile(
                str(malicious_source),
                cfile=str(cache / cache_name),
                doraise=True,
                invalidation_mode=py_compile.PycInvalidationMode.UNCHECKED_HASH,
            )
            assert distribution.files is not None
            distribution.files.append(
                _FakeRecord(
                    f"netveil/__pycache__/{cache_name}",
                    None,
                    None,
                )
            )

            with (
                _isolated_netveil_modules(),
                patch.object(
                    bootstrap,
                    "__file__",
                    str(root / bootstrap._BOOTSTRAP_FILE),
                ),
                patch.object(
                    metadata,
                    "distribution",
                    return_value=cast(metadata.Distribution, distribution),
                ),
            ):
                artifact = bootstrap._verify_installed_artifact()
                artifact = replace(
                    artifact,
                    package_root=SOURCE_ROOT / "netveil",
                )
                (package_root / "cli.py").write_text(
                    "raise AssertionError('disk source executed')\n"
                )
                cli = bootstrap._load_verified_cli(artifact)
                self.assertEqual(
                    cli._DISTRIBUTION_VERSION,
                    bootstrap._DISTRIBUTION_VERSION,
                )
                with self.assertRaises(ModuleNotFoundError):
                    importlib.import_module("netveil.evil")
            self.assertFalse(marker.exists())

    def test_finder_ignores_other_modules_and_rejects_unknown_netveil_module(
        self,
    ) -> None:
        artifact = bootstrap._VerifiedArtifact(
            version="0.3.0",
            package_root=Path("/verified"),
            sources=(("netveil", "__init__.py", b"", True),),
        )
        finder = bootstrap._VerifiedSourceFinder(artifact)
        self.assertIsNone(finder.find_spec("json", None))
        with self.assertRaises(ModuleNotFoundError):
            finder.find_spec("netveil.evil", None)
        spec = finder.find_spec("netveil", None)
        self.assertIsNotNone(spec)


class BootstrapBoundaryTests(unittest.TestCase):
    def test_descriptor_reader_rejects_growth_nonregular_and_read_failure(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload"
            path.write_bytes(b"abc")
            descriptor = os.open(path, os.O_RDONLY)
            try:
                current = os.fstat(descriptor)
                changed = os.stat_result(
                    (
                        current.st_mode,
                        current.st_ino,
                        current.st_dev,
                        current.st_nlink,
                        current.st_uid,
                        current.st_gid,
                        current.st_size + 1,
                        current.st_atime,
                        current.st_mtime,
                        current.st_ctime,
                    )
                )
                with (
                    patch.object(os, "fstat", side_effect=(current, changed)),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._read_descriptor(descriptor, expected_size=3)
                with (
                    patch.object(os, "read", side_effect=OSError("PRIVATE")),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._read_descriptor(descriptor, expected_size=3)
            finally:
                os.close(descriptor)

        descriptor, writable = os.pipe()
        try:
            with self.assertRaises(bootstrap._BootstrapFailure):
                bootstrap._read_descriptor(descriptor, expected_size=0)
        finally:
            os.close(descriptor)
            os.close(writable)

    def test_platform_and_record_contract_fail_closed(self) -> None:
        with (
            patch.object(os, "name", "unsupported"),
            self.assertRaises(bootstrap._BootstrapFailure),
        ):
            bootstrap._file_flags()
        record = cast(
            metadata.PackagePath,
            _FakeRecord("x", None, None),
        )
        with self.assertRaises(bootstrap._BootstrapFailure):
            bootstrap._record_contract(record)

    def test_directory_flag_close_and_invalid_size_failures(self) -> None:
        directory_flag = os.O_DIRECTORY
        del os.O_DIRECTORY
        try:
            with self.assertRaises(bootstrap._BootstrapFailure):
                bootstrap._directory_flags()
        finally:
            os.O_DIRECTORY = directory_flag  # type: ignore[misc]

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "payload"
            path.write_bytes(b"x")
            descriptor = os.open(path, os.O_RDONLY)
            try:
                with (
                    patch.object(os, "close", side_effect=OSError("PRIVATE")),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._close(descriptor)
            finally:
                os.close(descriptor)

        for invalid in (-1, True, bootstrap._MAX_ARTIFACT_FILE_BYTES + 1):
            with (
                self.subTest(invalid=invalid),
                self.assertRaises(bootstrap._BootstrapFailure),
            ):
                bootstrap._read_descriptor(-1, expected_size=invalid)

    def test_path_reader_rejects_missing_same_size_tamper_and_overread(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            payload = b"abc"
            path = root / "payload"
            path.write_bytes(payload)
            record = cast(metadata.PackagePath, _record("payload", payload))
            with self.assertRaises(bootstrap._BootstrapFailure):
                bootstrap._read_path(root / "missing", record=record)
            with (
                patch.object(os, "open", return_value=-1),
                self.assertRaises(bootstrap._BootstrapFailure),
            ):
                bootstrap._read_path(path, record=record)

            wrong = cast(
                metadata.PackagePath,
                _FakeRecord(
                    "payload",
                    _FakeHash("sha256", _hash(b"xyz")),
                    len(payload),
                ),
            )
            with self.assertRaises(bootstrap._BootstrapFailure):
                bootstrap._read_path(path, record=wrong)

            descriptor = os.open(path, os.O_RDONLY)
            try:
                current = os.fstat(descriptor)
                with (
                    patch.object(os, "fstat", side_effect=(current, current)),
                    patch.object(os, "read", return_value=b"abcd"),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._read_descriptor(descriptor, expected_size=3)
            finally:
                os.close(descriptor)

    def test_cache_and_package_scan_low_level_failures(self) -> None:
        implementation = sys.implementation
        with (
            patch.object(
                sys,
                "implementation",
                type("Implementation", (), {"cache_tag": None})(),
            ),
            self.assertRaises(bootstrap._BootstrapFailure),
        ):
            bootstrap._cache_names()
        self.assertIs(sys.implementation, implementation)

        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cache = root / "__pycache__"
            cache.mkdir()
            root_descriptor = os.open(root, os.O_RDONLY | os.O_DIRECTORY)
            cache_descriptor = os.open(cache, os.O_RDONLY | os.O_DIRECTORY)
            try:
                cache_status = os.fstat(cache_descriptor)
                regular_status = os.stat_result(
                    (
                        stat.S_IFREG | 0o600,
                        cache_status.st_ino,
                        cache_status.st_dev,
                        cache_status.st_nlink,
                        cache_status.st_uid,
                        cache_status.st_gid,
                        cache_status.st_size,
                        cache_status.st_atime,
                        cache_status.st_mtime,
                        cache_status.st_ctime,
                    )
                )
                with (
                    patch.object(os, "open", return_value=cache_descriptor),
                    patch.object(os, "fstat", return_value=regular_status),
                    patch.object(os, "close"),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._verify_cache_directory(root_descriptor)

                with (
                    patch.object(os, "open", side_effect=OSError("PRIVATE")),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._verify_cache_directory(root_descriptor)
                with (
                    patch.object(os, "open", return_value=-1),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._verify_cache_directory(root_descriptor)

                changed_status = os.stat_result(
                    (
                        cache_status.st_mode,
                        cache_status.st_ino,
                        cache_status.st_dev,
                        cache_status.st_nlink,
                        cache_status.st_uid,
                        cache_status.st_gid,
                        cache_status.st_size,
                        cache_status.st_atime,
                        cache_status.st_mtime + 1,
                        cache_status.st_ctime,
                    )
                )
                with (
                    patch.object(os, "open", return_value=cache_descriptor),
                    patch.object(
                        os,
                        "fstat",
                        side_effect=(cache_status, changed_status),
                    ),
                    patch.object(os, "listdir", return_value=[]),
                    patch.object(os, "close"),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._verify_cache_directory(root_descriptor)

                with (
                    patch.object(os, "listdir", side_effect=OSError("PRIVATE")),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._scan_package_directory(root_descriptor)
                with (
                    patch.object(os, "listdir", return_value=["x", "x"]),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    bootstrap._scan_package_directory(root_descriptor)
            finally:
                os.close(cache_descriptor)
                os.close(root_descriptor)

    def test_record_collection_and_metadata_rare_failures(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            distribution = _create_artifact(root)
            distribution.files = None
            with self.assertRaises(bootstrap._BootstrapFailure):
                bootstrap._collect_records(cast(metadata.Distribution, distribution))

        mutations = ("normalized-duplicate", "bootstrap", "metadata-key", "unicode")
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                distribution = _create_artifact(root)
                assert distribution.files is not None
                if mutation == "normalized-duplicate":
                    source = next(
                        item
                        for item in distribution.files
                        if str(item) == "netveil/parser.py"
                    )
                    distribution.files.append(
                        _FakeRecord(
                            "netveil/./parser.py",
                            source.hash,
                            source.size,
                        )
                    )
                elif mutation == "bootstrap":
                    distribution.files = [
                        item
                        for item in distribution.files
                        if str(item) != bootstrap._BOOTSTRAP_FILE
                    ]
                elif mutation == "metadata-key":
                    distribution.metadata.pop("Name")
                else:
                    metadata_root = (
                        f"netveil_audit-{bootstrap._DISTRIBUTION_VERSION}.dist-info"
                    )
                    path = root / metadata_root / "top_level.txt"
                    payload = b"\xffetveil\nnetveil_bootstrap\n"
                    path.write_bytes(payload)
                    record = next(
                        item
                        for item in distribution.files
                        if str(item).endswith("/top_level.txt")
                    )
                    record.hash = _FakeHash("sha256", _hash(payload))
                    record.size = len(payload)
                with self.assertRaises(bootstrap._BootstrapFailure):
                    _verify(root, distribution)

    def test_artifact_location_directory_and_terminal_identity_failures(self) -> None:
        mutations = (
            "bootstrap-locate",
            "bootstrap-inode",
            "root-kind",
            "root-locate",
            "root-inode",
            "root-missing",
            "terminal-drift",
        )
        for mutation in mutations:
            with (
                self.subTest(mutation=mutation),
                tempfile.TemporaryDirectory() as directory,
            ):
                root = Path(directory)
                distribution = _create_artifact(root)
                original_locate = distribution.locate_file
                locate_override: Callable[[object], Path] | None = None
                if mutation == "bootstrap-locate":

                    def locate_bootstrap_failure(
                        path: object,
                        fallback: Callable[[object], Path] = original_locate,
                    ) -> Path:
                        if str(path) == bootstrap._BOOTSTRAP_FILE:
                            raise OSError("PRIVATE")
                        return fallback(path)

                    locate_override = locate_bootstrap_failure
                elif mutation == "bootstrap-inode":
                    copy = root / "bootstrap-copy.py"
                    copy.write_bytes((root / bootstrap._BOOTSTRAP_FILE).read_bytes())

                    def locate_bootstrap_copy(
                        path: object,
                        copy_path: Path = copy,
                        fallback: Callable[[object], Path] = original_locate,
                    ) -> Path:
                        if str(path) == bootstrap._BOOTSTRAP_FILE:
                            return copy_path
                        return fallback(path)

                    locate_override = locate_bootstrap_copy
                elif mutation == "root-kind":
                    kind = stat.S_ISDIR
                    package_mode = (root / "netveil").stat().st_mode

                    def is_directory(
                        mode: int,
                        *,
                        expected_mode: int = package_mode,
                        fallback: Callable[[int], bool] = kind,
                    ) -> bool:
                        if mode == expected_mode:
                            return False
                        return fallback(mode)

                    with (
                        patch.object(stat, "S_ISDIR", side_effect=is_directory),
                        self.assertRaises(bootstrap._BootstrapFailure),
                    ):
                        _verify(root, distribution)
                    continue
                elif mutation == "root-locate":

                    def locate_root_failure(
                        path: object,
                        fallback: Callable[[object], Path] = original_locate,
                    ) -> Path:
                        if str(path) == "netveil":
                            raise OSError("PRIVATE")
                        return fallback(path)

                    locate_override = locate_root_failure
                elif mutation == "root-inode":
                    other = root / "other-netveil"
                    other.mkdir()

                    def locate_other_root(
                        path: object,
                        other_root: Path = other,
                        fallback: Callable[[object], Path] = original_locate,
                    ) -> Path:
                        if str(path) == "netveil":
                            return other_root
                        return fallback(path)

                    locate_override = locate_other_root
                elif mutation == "root-missing":
                    package_root = root / "netveil"
                    moved_root = root / "moved-netveil"
                    package_root.rename(moved_root)
                    with self.assertRaises(bootstrap._BootstrapFailure):
                        _verify(root, distribution)
                    continue
                else:
                    original_scan = bootstrap._scan_package_directory
                    calls = 0

                    def drift(
                        descriptor: int,
                        *,
                        scan: Callable[[int], frozenset[str]] = original_scan,
                        package_root: Path = root / "netveil",
                    ) -> frozenset[str]:
                        nonlocal calls
                        calls += 1
                        observed = scan(descriptor)
                        if calls == 2:
                            os.utime(package_root, None)
                        return observed

                    with (
                        patch.object(
                            bootstrap,
                            "_scan_package_directory",
                            side_effect=drift,
                        ),
                        self.assertRaises(bootstrap._BootstrapFailure),
                    ):
                        _verify(root, distribution)
                    continue
                self.assertIsNotNone(locate_override)
                with (
                    patch.object(
                        distribution,
                        "locate_file",
                        side_effect=locate_override,
                    ),
                    self.assertRaises(bootstrap._BootstrapFailure),
                ):
                    _verify(root, distribution)

    def test_loader_preload_spec_and_import_failure_cleanup(self) -> None:
        artifact = bootstrap._VerifiedArtifact(
            version="0.3.0",
            package_root=Path("/verified"),
            sources=(("netveil", "__init__.py", b"", True),),
        )
        with (
            patch.dict(sys.modules, {"netveil": ModuleType("netveil")}),
            self.assertRaises(bootstrap._BootstrapFailure),
        ):
            bootstrap._load_verified_cli(artifact)

        finder = bootstrap._VerifiedSourceFinder(artifact)
        with (
            patch.object(importlib.util, "spec_from_loader", return_value=None),
            self.assertRaises(ModuleNotFoundError),
        ):
            finder.find_spec("netveil", None)

        broken = bootstrap._VerifiedArtifact(
            version="0.3.0",
            package_root=SOURCE_ROOT / "netveil",
            sources=(
                (
                    "netveil",
                    "__init__.py",
                    (
                        b"import sys, types\n"
                        b"sys.modules['netveil.partial'] = "
                        b"types.ModuleType('netveil.partial')\n"
                        b"raise RuntimeError('broken')\n"
                    ),
                    True,
                ),
            ),
        )
        with _isolated_netveil_modules():
            before = list(sys.meta_path)
            with self.assertRaises(RuntimeError):
                bootstrap._load_verified_cli(broken)
            self.assertEqual(sys.meta_path, before)
            self.assertNotIn("netveil", sys.modules)
            self.assertNotIn("netveil.partial", sys.modules)

        removes_finder = bootstrap._VerifiedArtifact(
            version="0.3.0",
            package_root=SOURCE_ROOT / "netveil",
            sources=(
                (
                    "netveil",
                    "__init__.py",
                    b"import sys\nsys.meta_path.pop(0)\nraise RuntimeError('broken')\n",
                    True,
                ),
            ),
        )
        with _isolated_netveil_modules():
            before = list(sys.meta_path)
            with self.assertRaises(RuntimeError):
                bootstrap._load_verified_cli(removes_finder)
            self.assertEqual(sys.meta_path, before)

    def test_text_writer_oserror_and_successful_main_result(self) -> None:
        stream = io.StringIO()
        with patch.object(stream, "write", side_effect=OSError("PRIVATE")):
            self.assertFalse(bootstrap._write_text(stream, "x"))

        artifact = bootstrap._VerifiedArtifact(
            version="0.3.0",
            package_root=Path("/verified"),
            sources=(),
        )
        cli = ModuleType("netveil.cli")

        def run(
            argv: object,
            *,
            verified_distribution_version: str,
        ) -> int:
            self.assertEqual(argv, ["--version"])
            self.assertEqual(verified_distribution_version, "0.3.0")
            return 23

        cli._main_verified = run  # type: ignore[attr-defined]
        with (
            patch.object(
                bootstrap,
                "_verify_installed_artifact",
                return_value=artifact,
            ),
            patch.object(bootstrap, "_load_verified_cli", return_value=cli),
        ):
            self.assertEqual(bootstrap.main(["--version"]), 23)

    def test_bootstrap_main_redacts_failures_and_validates_result_type(self) -> None:
        stderr = io.StringIO()
        cases = (
            (
                bootstrap._BootstrapFailure("artifact_unverified", 10),
                10,
                "artifact_unverified",
            ),
            (KeyboardInterrupt(), 70, "interrupted"),
            (SystemExit(99), 70, "internal_error"),
            (RuntimeError("PRIVATE"), 70, "internal_error"),
        )
        for failure, expected_exit, expected_code in cases:
            with (
                self.subTest(expected_code=expected_code),
                patch.object(
                    bootstrap,
                    "_verify_installed_artifact",
                    side_effect=failure,
                ),
                patch.object(sys, "stderr", stderr),
            ):
                self.assertEqual(bootstrap.main([]), expected_exit)
            self.assertEqual(
                stderr.getvalue(),
                f"netveil-audit: {expected_code}\n",
            )
            stderr.seek(0)
            stderr.truncate()

        artifact = bootstrap._VerifiedArtifact(
            version="0.3.0",
            package_root=Path("/verified"),
            sources=(),
        )
        cli = ModuleType("netveil.cli")
        cli._main_verified = (  # type: ignore[attr-defined]
            lambda *args, **kwargs: "not-an-int"
        )
        with (
            patch.object(
                bootstrap,
                "_verify_installed_artifact",
                return_value=artifact,
            ),
            patch.object(bootstrap, "_load_verified_cli", return_value=cli),
            patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(bootstrap.main([]), bootstrap._INTERNAL_FAILURE_EXIT)
        self.assertEqual(stderr.getvalue(), "netveil-audit: internal_error\n")

    def test_short_stderr_write_is_bounded(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(stderr, "write", return_value=0),
            patch.object(sys, "stderr", stderr),
        ):
            self.assertEqual(
                bootstrap._emit_failure("safe", 10),
                bootstrap._OUTPUT_FAILURE_EXIT,
            )


if __name__ == "__main__":
    unittest.main()
