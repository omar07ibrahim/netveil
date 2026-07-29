"""Stdlib-only integrity bootstrap for the installed Netveil command."""

from __future__ import annotations

import base64
import hashlib
import importlib
import importlib.abc
import importlib.util
import os
import stat
import sys
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from importlib import metadata
from pathlib import Path, PurePosixPath
from types import ModuleType
from typing import Final, NoReturn, TextIO

_DISTRIBUTION_NAME: Final = "netveil-audit"
_DISTRIBUTION_VERSION: Final = "0.3.0"
_BOOTSTRAP_FILE: Final = "netveil_bootstrap.py"
_MAX_ARTIFACT_FILE_BYTES: Final = 1_048_576
_ARTIFACT_FAILURE_EXIT: Final = 10
_OUTPUT_FAILURE_EXIT: Final = 15
_INTERNAL_FAILURE_EXIT: Final = 70
_SOURCE_MODULES: Final = (
    ("netveil", "__init__.py", True),
    ("netveil.cli", "cli.py", False),
    ("netveil.model", "model.py", False),
    ("netveil.parser", "parser.py", False),
    ("netveil.privacy", "privacy.py", False),
)
_PACKAGE_FILES: Final = frozenset(
    {filename for _, filename, _ in _SOURCE_MODULES} | {"py.typed"}
)
_METADATA_FILES: Final = (
    "METADATA",
    "WHEEL",
    "top_level.txt",
)


class _BootstrapFailure(Exception):
    def __init__(self, code: str, exit_code: int) -> None:
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class _PinnedBytes:
    payload: bytes
    identity: tuple[int, ...]


@dataclass(frozen=True, slots=True)
class _VerifiedArtifact:
    version: str
    package_root: Path
    sources: tuple[tuple[str, str, bytes, bool], ...]


def _fail(code: str = "artifact_unverified") -> NoReturn:
    raise _BootstrapFailure(code, _ARTIFACT_FAILURE_EXIT)


def _identity(status: os.stat_result) -> tuple[int, ...]:
    return (
        status.st_dev,
        status.st_ino,
        status.st_mode,
        status.st_uid,
        status.st_gid,
        status.st_nlink,
        status.st_size,
        status.st_mtime_ns,
        status.st_ctime_ns,
    )


def _file_flags() -> int:
    required = ("O_CLOEXEC", "O_NOCTTY", "O_NOFOLLOW", "O_NONBLOCK")
    if os.name != "posix" or any(not hasattr(os, name) for name in required):
        _fail("platform_unsupported")
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK


def _directory_flags() -> int:
    if not hasattr(os, "O_DIRECTORY"):
        _fail("platform_unsupported")
    return _file_flags() | os.O_DIRECTORY


def _close(descriptor: int) -> None:
    try:
        os.close(descriptor)
    except OSError:
        _fail()


def _read_descriptor(
    descriptor: int,
    *,
    expected_size: int,
) -> _PinnedBytes:
    if (
        type(expected_size) is not int
        or expected_size < 0
        or expected_size > _MAX_ARTIFACT_FILE_BYTES
    ):
        _fail()
    try:
        before = os.fstat(descriptor)
        if not stat.S_ISREG(before.st_mode) or before.st_size != expected_size:
            _fail()
        chunks: list[bytes] = []
        observed = 0
        while observed <= expected_size:
            chunk = os.read(
                descriptor,
                min(65_536, expected_size + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError:
        _fail()
    if (
        len(payload) != expected_size
        or _identity(before) != _identity(after)
        or after.st_size != len(payload)
    ):
        _fail()
    return _PinnedBytes(payload=payload, identity=_identity(after))


def _record_contract(record: metadata.PackagePath) -> tuple[int, str]:
    file_hash = record.hash
    file_size = record.size
    if (
        file_hash is None
        or file_hash.mode != "sha256"
        or type(file_size) is not int
        or file_size < 0
        or file_size > _MAX_ARTIFACT_FILE_BYTES
    ):
        _fail()
    return file_size, file_hash.value


def _sha256_record_value(payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _read_path(
    path: Path,
    *,
    record: metadata.PackagePath,
) -> _PinnedBytes:
    expected_size, expected_hash = _record_contract(record)
    descriptor = -1
    try:
        descriptor = os.open(path, _file_flags())
        pinned = _read_descriptor(descriptor, expected_size=expected_size)
    except OSError:
        _fail()
    finally:
        if descriptor >= 0:  # pragma: no branch - acquisition failure re-raises.
            _close(descriptor)
    if _sha256_record_value(pinned.payload) != expected_hash:
        _fail()
    return pinned


def _read_package_file(
    root_descriptor: int,
    *,
    name: str,
    record: metadata.PackagePath,
    distribution: metadata.Distribution,
) -> bytes:
    expected_size, expected_hash = _record_contract(record)
    descriptor = -1
    located_descriptor = -1
    try:
        descriptor = os.open(
            name,
            _file_flags(),
            dir_fd=root_descriptor,
        )
        pinned = _read_descriptor(descriptor, expected_size=expected_size)
        located = Path(str(distribution.locate_file(record)))
        located_descriptor = os.open(located, _file_flags())
        located_status = os.fstat(located_descriptor)
        current_status = os.stat(
            name,
            dir_fd=root_descriptor,
            follow_symlinks=False,
        )
    except OSError:
        _fail()
    finally:
        if located_descriptor >= 0:
            _close(located_descriptor)
        if descriptor >= 0:  # pragma: no branch - acquisition failure re-raises.
            _close(descriptor)
    if (
        _identity(located_status) != pinned.identity
        or _identity(current_status) != pinned.identity
        or _sha256_record_value(pinned.payload) != expected_hash
    ):
        _fail()
    return pinned.payload


def _cache_names() -> frozenset[str]:
    cache_tag = sys.implementation.cache_tag
    if type(cache_tag) is not str or not cache_tag:
        _fail()
    return frozenset(
        f"{Path(filename).stem}.{cache_tag}.pyc" for _, filename, _ in _SOURCE_MODULES
    )


def _verify_cache_directory(root_descriptor: int) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            "__pycache__",
            _directory_flags(),
            dir_fd=root_descriptor,
        )
        before = os.fstat(descriptor)
        if not stat.S_ISDIR(before.st_mode):
            _fail()
        names = os.listdir(descriptor)
        if len(names) != len(set(names)) or not set(names).issubset(_cache_names()):
            _fail()
        for name in names:
            status = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if not stat.S_ISREG(status.st_mode):
                _fail()
        after = os.fstat(descriptor)
    except OSError:
        _fail()
    finally:
        if descriptor >= 0:  # pragma: no branch - acquisition failure re-raises.
            _close(descriptor)
    if _identity(before) != _identity(after):
        _fail()


def _scan_package_directory(root_descriptor: int) -> frozenset[str]:
    try:
        names = os.listdir(root_descriptor)
    except OSError:
        _fail()
    if len(names) != len(set(names)):
        _fail()
    observed = frozenset(names)
    allowed = _PACKAGE_FILES | {"__pycache__"}
    if not _PACKAGE_FILES.issubset(observed) or not observed.issubset(allowed):
        _fail()
    if "__pycache__" in observed:
        _verify_cache_directory(root_descriptor)
    return observed


def _collect_records(
    distribution: metadata.Distribution,
) -> tuple[
    dict[str, metadata.PackagePath],
    metadata.PackagePath,
    dict[str, metadata.PackagePath],
]:
    files = distribution.files
    if files is None:
        _fail()
    records: dict[str, metadata.PackagePath] = {}
    for record in files:
        raw_path = str(record)
        if raw_path in records:
            _fail()
        records[raw_path] = record

    package_records: dict[str, metadata.PackagePath] = {}
    allowed_cache_paths = {f"netveil/__pycache__/{name}" for name in _cache_names()}
    for raw_path, record in records.items():
        path = PurePosixPath(raw_path)
        if not path.parts or path.parts[0] != "netveil":
            continue
        if len(path.parts) == 2 and path.name in _PACKAGE_FILES:
            if path.name in package_records:
                _fail()
            package_records[path.name] = record
        elif raw_path not in allowed_cache_paths:
            _fail()
    if set(package_records) != _PACKAGE_FILES:
        _fail()

    bootstrap_record = records.get(_BOOTSTRAP_FILE)
    if bootstrap_record is None:
        _fail()

    metadata_root = f"netveil_audit-{_DISTRIBUTION_VERSION}.dist-info"
    metadata_records: dict[str, metadata.PackagePath] = {}
    for name in _METADATA_FILES:
        metadata_record = records.get(f"{metadata_root}/{name}")
        if metadata_record is None:
            _fail()
        metadata_records[name] = metadata_record
    return package_records, bootstrap_record, metadata_records


def _verify_distribution_metadata(
    distribution: metadata.Distribution,
    records: Mapping[str, metadata.PackagePath],
) -> None:
    try:
        project_name = distribution.metadata["Name"]
        project_version = distribution.metadata["Version"]
    except KeyError:
        _fail()
    if (
        distribution.version != _DISTRIBUTION_VERSION
        or project_name != _DISTRIBUTION_NAME
        or project_version != _DISTRIBUTION_VERSION
    ):
        _fail()
    if list(distribution.entry_points):
        _fail()

    payloads = {
        name: _read_path(
            Path(str(distribution.locate_file(record))),
            record=record,
        ).payload
        for name, record in records.items()
    }
    if payloads["top_level.txt"] != b"netveil\nnetveil_bootstrap\n":
        _fail()


def _verify_installed_artifact() -> _VerifiedArtifact:
    """Bind installed source bytes before any ``netveil`` package import."""

    if any(name == "netveil" or name.startswith("netveil.") for name in sys.modules):
        _fail()
    try:
        distribution = metadata.distribution(_DISTRIBUTION_NAME)
    except metadata.PackageNotFoundError:
        _fail()

    package_records, bootstrap_record, metadata_records = _collect_records(distribution)
    _verify_distribution_metadata(distribution, metadata_records)

    bootstrap_path = Path(__file__)
    bootstrap_pinned = _read_path(bootstrap_path, record=bootstrap_record)
    try:
        recorded_bootstrap = Path(str(distribution.locate_file(bootstrap_record)))
        recorded_pinned = _read_path(
            recorded_bootstrap,
            record=bootstrap_record,
        )
    except OSError:
        _fail()
    if bootstrap_pinned.identity != recorded_pinned.identity:
        _fail()

    package_root = bootstrap_path.parent / "netveil"
    root_descriptor = -1
    recorded_root_descriptor = -1
    try:
        root_descriptor = os.open(package_root, _directory_flags())
        root_before = os.fstat(root_descriptor)
        if not stat.S_ISDIR(root_before.st_mode):
            _fail()
        recorded_root = Path(str(distribution.locate_file("netveil")))
        recorded_root_descriptor = os.open(recorded_root, _directory_flags())
        recorded_root_status = os.fstat(recorded_root_descriptor)
        if _identity(root_before) != _identity(recorded_root_status):
            _fail()
        observed_before = _scan_package_directory(root_descriptor)
        payloads = {
            name: _read_package_file(
                root_descriptor,
                name=name,
                record=package_records[name],
                distribution=distribution,
            )
            for name in sorted(_PACKAGE_FILES)
        }
        observed_after = _scan_package_directory(root_descriptor)
        root_after = os.fstat(root_descriptor)
    except OSError:
        _fail()
    finally:
        if recorded_root_descriptor >= 0:
            _close(recorded_root_descriptor)
        if root_descriptor >= 0:  # pragma: no branch - acquisition failure re-raises.
            _close(root_descriptor)
    if observed_before != observed_after or _identity(root_before) != _identity(
        root_after
    ):
        _fail()

    sources = tuple(
        (module, filename, payloads[filename], is_package)
        for module, filename, is_package in _SOURCE_MODULES
    )
    return _VerifiedArtifact(
        version=distribution.version,
        package_root=package_root,
        sources=sources,
    )


class _VerifiedSourceLoader(importlib.abc.Loader):
    def __init__(self, *, source: bytes, origin: str) -> None:
        self._source = source
        self._origin = origin

    def create_module(self, spec: importlib.machinery.ModuleSpec) -> ModuleType | None:
        del spec
        return None

    def exec_module(self, module: ModuleType) -> None:
        code = compile(
            self._source,
            self._origin,
            "exec",
            dont_inherit=True,
        )
        exec(code, module.__dict__)  # noqa: S102 - executes only verified bytes.


class _VerifiedSourceFinder(importlib.abc.MetaPathFinder):
    def __init__(self, artifact: _VerifiedArtifact) -> None:
        self._sources = {
            module: (
                artifact.package_root / filename,
                payload,
                is_package,
            )
            for module, filename, payload, is_package in artifact.sources
        }

    def find_spec(
        self,
        fullname: str,
        path: Sequence[str] | None,
        target: ModuleType | None = None,
    ) -> importlib.machinery.ModuleSpec | None:
        del path, target
        if fullname != "netveil" and not fullname.startswith("netveil."):
            return None
        source = self._sources.get(fullname)
        if source is None:
            raise ModuleNotFoundError("verified Netveil module is not allowed")
        origin, payload, is_package = source
        loader = _VerifiedSourceLoader(source=payload, origin=str(origin))
        spec = importlib.util.spec_from_loader(
            fullname,
            loader,
            origin=str(origin),
            is_package=is_package,
        )
        if spec is None:
            raise ModuleNotFoundError("verified Netveil module is unavailable")
        return spec


def _load_verified_cli(artifact: _VerifiedArtifact) -> ModuleType:
    if any(name == "netveil" or name.startswith("netveil.") for name in sys.modules):
        _fail()
    finder = _VerifiedSourceFinder(artifact)
    sys.meta_path.insert(0, finder)
    try:
        cli = importlib.import_module("netveil.cli")
    except BaseException:  # Cleanup must cover import-time exits.
        for name in tuple(sys.modules):
            if name == "netveil" or name.startswith("netveil."):
                sys.modules.pop(name, None)
        if finder in sys.meta_path:
            sys.meta_path.remove(finder)
        raise
    return cli


def _write_text(stream: TextIO, payload: str) -> bool:
    offset = 0
    try:
        while offset < len(payload):
            written = stream.write(payload[offset:])
            if (
                type(written) is not int
                or written <= 0
                or written > len(payload) - offset
            ):
                return False
            offset += written
        stream.flush()
    except OSError:
        return False
    return True


def _emit_failure(code: str, exit_code: int) -> int:
    if not _write_text(sys.stderr, f"netveil-audit: {code}\n"):
        return _OUTPUT_FAILURE_EXIT
    return exit_code


def main(argv: Sequence[str] | None = None) -> int:
    """Verify, source-load, and execute the installed command."""

    try:
        artifact = _verify_installed_artifact()
        cli = _load_verified_cli(artifact)
        run = cli._main_verified
        result = run(
            argv,
            verified_distribution_version=artifact.version,
        )
        if type(result) is not int:
            raise TypeError
        return result
    except _BootstrapFailure as failure:
        return _emit_failure(failure.code, failure.exit_code)
    except KeyboardInterrupt:
        return _emit_failure("interrupted", _INTERNAL_FAILURE_EXIT)
    except SystemExit:
        return _emit_failure("internal_error", _INTERNAL_FAILURE_EXIT)
    except Exception:  # noqa: BLE001 - never expose bootstrap tracebacks.
        return _emit_failure("internal_error", _INTERNAL_FAILURE_EXIT)
