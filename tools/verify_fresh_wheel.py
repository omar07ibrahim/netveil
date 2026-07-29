#!/usr/bin/env python3
"""Verify one pinned Netveil wheel in a disposable, offline virtual environment.

The verifier never builds a distribution and never resolves dependencies.  It
first pins and inspects the exact wheel bytes supplied by the caller, then asks
pip to install a private copy with ``--no-index --no-deps``.  Product processes
run with bounded output capture and receive only synthetic IETF documentation
range inputs.
"""

from __future__ import annotations

import base64
import csv
import gzip
import hashlib
import importlib.metadata
import importlib.util
import io
import json
import marshal
import os
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import venv
import zlib
from collections.abc import Iterator, Mapping, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from email import policy
from email.parser import BytesParser
from pathlib import Path, PurePosixPath
from types import CodeType
from typing import Final, NoReturn
from zipfile import BadZipFile, ZipFile, ZipInfo

_DISTRIBUTION_NAME: Final = "netveil-audit"
_DISTRIBUTION_VERSION: Final = "0.3.0"
_WHEEL_NAME: Final = "netveil_audit-0.3.0-py3-none-any.whl"
_SDIST_NAME: Final = "netveil_audit-0.3.0.tar.gz"
_DIST_INFO: Final = "netveil_audit-0.3.0.dist-info"
_WHEEL_SCRIPT: Final = "netveil_audit-0.3.0.data/scripts/netveil-audit"
_LAUNCHER_NAME: Final = "netveil-audit"
_BOOTSTRAP_NAME: Final = "netveil_bootstrap.py"
_SCHEMA: Final = "netveil.fresh-wheel-verification.v1"
_INVENTORY_SCHEMA: Final = "netveil.release-inventory.v1"
_INVENTORY_NAME: Final = "release-inventory.json"

_MAX_WHEEL_BYTES: Final = 32 * 1_048_576
_MAX_INVENTORY_BYTES: Final = 16 * 1_048_576
_MAX_RELEASE_ARTIFACT_BYTES: Final = 512 * 1_048_576
_MAX_COMPRESSED_SDIST_BYTES: Final = 128 * 1_048_576
_MAX_EXPANDED_SDIST_BYTES: Final = 256 * 1_048_576
_MAX_SDIST_MEMBER_BYTES: Final = 64 * 1_048_576
_MAX_SDIST_FILE_BYTES: Final = 192 * 1_048_576
_MAX_SDIST_MEMBERS: Final = 20_000
_MAX_MEMBER_BYTES: Final = 2 * 1_048_576
_MAX_EXPANDED_BYTES: Final = 16 * 1_048_576
_MAX_PROCESS_OUTPUT_BYTES: Final = 1_048_576
_PROCESS_TIMEOUT_SECONDS: Final = 30.0
_ARTIFACT_FAILURE: Final = b"netveil-audit: artifact_unverified\n"
_LOWER_HEX: Final = frozenset("0123456789abcdef")
_TAR_BLOCK_BYTES: Final = 512
_TAR_TRAILER_BYTES: Final = 2 * _TAR_BLOCK_BYTES

_EXPECTED_WHEEL_MEMBERS: Final = frozenset(
    {
        _WHEEL_SCRIPT,
        "netveil/__init__.py",
        "netveil/cli.py",
        "netveil/model.py",
        "netveil/parser.py",
        "netveil/privacy.py",
        "netveil/py.typed",
        _BOOTSTRAP_NAME,
        f"{_DIST_INFO}/METADATA",
        f"{_DIST_INFO}/RECORD",
        f"{_DIST_INFO}/WHEEL",
        f"{_DIST_INFO}/licenses/LICENSE",
        f"{_DIST_INFO}/top_level.txt",
    }
)
_CHECKS: Final = (
    "wheel_archive",
    "fresh_install",
    "entry_points_absent",
    "launcher_identity",
    "direct_and_path_commands",
    "isolated_startup",
    "environment_injection_inert",
    "unchecked_bytecode_inert",
    "unknown_bytecode_rejected",
    "tamper_fail_closed",
    "metadata_drift_rejected",
    "coordinated_bootstrap_record_mutation_accepted",
    "unknown_package_file_rejected",
    "receipt_deterministic",
    "receipt_redacted",
    "public_demo_capture",
    "syscall_trace_offline",
    "release_inventory_integrity",
    "source_commit_bound",
)
_CORPUS: Final = (
    b"# Synthetic IETF documentation ranges only\n"
    b"192.0.2.10:443\n"
    b"192.0.2.10:443\n"
    b"198.51.100.20:80\n"
    b"203.0.113.30:65535\n"
    b"[2001:db8::10]:8443\n"
)
# Deliberately public, deterministic demonstration material. It is never
# suitable for a private corpus; its sole purpose is reproducible CLI output
# over the synthetic IETF documentation-range corpus above.
_PUBLIC_DEMO_KEY: Final = b"netveil-public-demo-key-v1-00001"
_RAW_ENDPOINT_TOKENS: Final = (
    b"192.0.2.10",
    b"198.51.100.20",
    b"203.0.113.30",
    b"2001:db8::10",
)
_ATTACK_SOURCE: Final = (
    b"import os\n"
    b"from pathlib import Path\n"
    b'Path(os.environ["NETVEIL_VERIFY_MARKER"]).write_bytes(b"executed")\n'
)
_PROBE_SOURCE: Final = b"""\
import json
import sys
from pathlib import Path

def main(argv):
    root = str(Path(__file__).parent)
    document = {
        "argv_exact": list(argv) == ["isolation-probe"],
        "dont_write_bytecode": sys.flags.dont_write_bytecode,
        "empty_path_absent": "" not in sys.path,
        "ignore_environment": sys.flags.ignore_environment,
        "implementation": sys.implementation.name,
        "isolated": sys.flags.isolated,
        "netveil_package_absent": not any(
            name == "netveil" or name.startswith("netveil.")
            for name in sys.modules
        ),
        "no_site": sys.flags.no_site,
        "safe_path": sys.flags.safe_path,
        "cache_tag": sys.implementation.cache_tag,
        "site_root_count": sys.path.count(root),
        "version": "{}.{}.{}".format(*sys.version_info[:3]),
    }
    sys.stdout.write(
        json.dumps(document, sort_keys=True, separators=(",", ":")) + "\\n"
    )
    sys.stdout.flush()
    return 0
"""
_EXPECTED_PROBE: Final = {
    "argv_exact": True,
    "dont_write_bytecode": 1,
    "empty_path_absent": True,
    "ignore_environment": 1,
    "netveil_package_absent": True,
    "isolated": 1,
    "no_site": 1,
    "safe_path": True,
    "site_root_count": 1,
}


class VerificationFailure(RuntimeError):
    """A stable, deliberately redacted verification failure."""

    def __init__(self, code: str) -> None:
        super().__init__(code)
        self.code = code


@dataclass(frozen=True, slots=True)
class RecordEntry:
    """One parsed wheel or installed RECORD row."""

    path: str
    digest: str | None
    size: int | None


@dataclass(frozen=True, slots=True)
class WheelMemberEvidence:
    """One archive member bound into the public verification evidence."""

    path: str
    sha256: str
    size: int
    mode: str


@dataclass(frozen=True, slots=True)
class WheelEvidence:
    """Pinned evidence extracted without installing the wheel."""

    payload: bytes
    sha256: str
    launcher: bytes
    members: tuple[WheelMemberEvidence, ...]


@dataclass(frozen=True, slots=True)
class InventoryArtifactEvidence:
    """One artifact digest asserted by the unsigned builder inventory."""

    filename: str
    kind: str
    sha256: str
    size_bytes: int
    members: tuple[InventoryMemberEvidence, ...] | None


@dataclass(frozen=True, slots=True)
class InventoryMemberEvidence:
    """One safe logical member of the canonical release sdist."""

    path: str
    kind: str
    mode: str
    size_bytes: int
    sha256: str | None


@dataclass(frozen=True, slots=True)
class ReleaseInventoryEvidence:
    """Strictly parsed unsigned integrity inventory from the release builder."""

    source_commit: str
    source_date_epoch: int
    sha256: str
    artifacts: tuple[InventoryArtifactEvidence, ...]


@dataclass(frozen=True, slots=True)
class ProcessResult:
    """Bounded child-process result."""

    returncode: int
    stdout: bytes
    stderr: bytes


@dataclass(frozen=True, slots=True)
class InstalledLayout:
    """Paths inside one disposable installation."""

    prefix: Path
    python: Path
    launcher: Path
    site_root: Path
    dist_info: Path
    bootstrap: Path
    package_root: Path
    record: Path
    evidence: InstalledEvidence | None = None


@dataclass(frozen=True, slots=True)
class InstalledRecordRowEvidence:
    """One selected installed RECORD binding with no private filesystem path."""

    path: str
    sha256: str | None
    size_bytes: int | None


@dataclass(frozen=True, slots=True)
class InstalledFileEvidence:
    """Stable content and mode evidence for one installed regular file."""

    logical_path: str
    mode: str
    sha256: str
    size_bytes: int


@dataclass(frozen=True, slots=True)
class InstalledEvidence:
    """Path-free evidence captured from the fresh installed artifact."""

    launcher: InstalledFileEvidence
    record: InstalledFileEvidence
    selected_record_rows: tuple[InstalledRecordRowEvidence, ...]


@dataclass(frozen=True, slots=True)
class InterpreterEvidence:
    """Path-free identity reported by the isolated installed interpreter."""

    implementation: str
    version: str
    cache_tag: str


@dataclass(frozen=True, slots=True)
class PlatformEvidence:
    """Hostname-free verifier platform identity."""

    sys_platform: str
    system: str
    release: str
    machine: str


@dataclass(frozen=True, slots=True)
class TraceEvidence:
    """Normalized path-free evidence from one process/network syscall trace."""

    label: str
    normalized_sha256: str
    process_count: int
    exec_chain: tuple[str, ...]
    exec_count: int
    exit_syscall_count: int
    network_syscall_count: int
    post_launch_process_count: int


@dataclass(frozen=True, slots=True)
class ReceiptEvidence:
    """Private paths retained only for the syscall trace gate."""

    corpus: Path
    key: Path
    output: bytes


@dataclass(frozen=True, slots=True)
class PublicDemoEvidence:
    """Reproducible public CLI output over synthetic, non-secret inputs."""

    corpus_sha256: str
    corpus_size_bytes: int
    corpus_physical_lines: int
    public_key_sha256: str
    public_key_size_bytes: int
    version_stdout: str
    receipt: dict[str, object]
    receipt_stdout_sha256: str


@dataclass(frozen=True, slots=True)
class VerificationSummary:
    """Stable evidence safe to render outside the private workspace."""

    source_commit: str
    release_inventory: ReleaseInventoryEvidence
    installed: InstalledEvidence
    interpreter: InterpreterEvidence
    platform: PlatformEvidence
    syscall_traces: tuple[TraceEvidence, ...]
    public_demo: PublicDemoEvidence
    wheel_sha256: str
    wheel_size_bytes: int
    wheel_members: tuple[WheelMemberEvidence, ...]

    def document(self) -> dict[str, object]:
        artifact_documents: list[dict[str, object]] = []
        for artifact in self.release_inventory.artifacts:
            artifact_document: dict[str, object] = {
                "filename": artifact.filename,
                "kind": artifact.kind,
                "sha256": artifact.sha256,
                "size_bytes": artifact.size_bytes,
            }
            if artifact.members is not None:
                member_documents: list[dict[str, object]] = []
                for member in artifact.members:
                    member_document: dict[str, object] = {
                        "kind": member.kind,
                        "mode": member.mode,
                        "path": member.path,
                        "size_bytes": member.size_bytes,
                    }
                    if member.sha256 is not None:
                        member_document["sha256"] = member.sha256
                    member_documents.append(member_document)
                artifact_document["members"] = member_documents
            artifact_documents.append(artifact_document)

        def installed_file_document(
            evidence: InstalledFileEvidence,
        ) -> dict[str, object]:
            return {
                "logical_path": evidence.logical_path,
                "mode": evidence.mode,
                "sha256": evidence.sha256,
                "size_bytes": evidence.size_bytes,
            }

        return {
            "checks": [{"name": name, "status": "pass"} for name in _CHECKS],
            "installed": {
                "launcher": installed_file_document(self.installed.launcher),
                "record": installed_file_document(self.installed.record),
                "selected_record_rows": [
                    {
                        "path": row.path,
                        "sha256": row.sha256,
                        "size_bytes": row.size_bytes,
                    }
                    for row in self.installed.selected_record_rows
                ],
            },
            "integrity_evidence": {
                "artifacts": artifact_documents,
                "attestation_verified": False,
                "inventory_schema": _INVENTORY_SCHEMA,
                "inventory_sha256": self.release_inventory.sha256,
                "inventory_type": "unsigned_sha256_manifest",
                "signature_verified": False,
                "source_commit": self.release_inventory.source_commit,
                "source_date_epoch": self.release_inventory.source_date_epoch,
            },
            "interpreter": {
                "cache_tag": self.interpreter.cache_tag,
                "implementation": self.interpreter.implementation,
                "version": self.interpreter.version,
            },
            "platform": {
                "machine": self.platform.machine,
                "release": self.platform.release,
                "sys_platform": self.platform.sys_platform,
                "system": self.platform.system,
            },
            "public_demo": {
                "classification": (
                    "synthetic_ietf_documentation_ranges_with_public_demo_key"
                ),
                "commands": [
                    {
                        "argv": ["netveil-audit", "--version"],
                        "exit_code": 0,
                        "stderr": "",
                        "stdout": self.public_demo.version_stdout,
                    },
                    {
                        "argv": [
                            "netveil-audit",
                            "receipt",
                            "documentation-corpus.txt",
                            "--key-file",
                            "public-demo.key",
                        ],
                        "exit_code": 0,
                        "stderr": "",
                        "stdout_json": self.public_demo.receipt,
                        "stdout_sha256": self.public_demo.receipt_stdout_sha256,
                    },
                ],
                "corpus": {
                    "physical_lines": self.public_demo.corpus_physical_lines,
                    "sha256": self.public_demo.corpus_sha256,
                    "size_bytes": self.public_demo.corpus_size_bytes,
                },
                "public_demo_key": {
                    "classification": "public_non_secret_test_material",
                    "sha256": self.public_demo.public_key_sha256,
                    "size_bytes": self.public_demo.public_key_size_bytes,
                    "source_constant": ("tools/verify_fresh_wheel.py:_PUBLIC_DEMO_KEY"),
                },
            },
            "schema": _SCHEMA,
            "source_commit": self.source_commit,
            "status": "pass",
            "syscall_traces": [
                {
                    "exec_chain": list(trace.exec_chain),
                    "exec_count": trace.exec_count,
                    "exit_syscall_count": trace.exit_syscall_count,
                    "label": trace.label,
                    "network_syscall_count": trace.network_syscall_count,
                    "normalized_sha256": trace.normalized_sha256,
                    "post_launch_process_count": trace.post_launch_process_count,
                    "process_count": trace.process_count,
                }
                for trace in self.syscall_traces
            ],
            "wheel": {
                "members": [
                    {
                        "mode": member.mode,
                        "path": member.path,
                        "sha256": member.sha256,
                        "size_bytes": member.size,
                    }
                    for member in self.wheel_members
                ],
                "sha256": self.wheel_sha256,
                "size_bytes": self.wheel_size_bytes,
            },
        }


def _fail(code: str) -> NoReturn:
    raise VerificationFailure(code)


def _identity(value: os.stat_result) -> tuple[int, ...]:
    return (
        value.st_dev,
        value.st_ino,
        value.st_mode,
        value.st_uid,
        value.st_gid,
        value.st_nlink,
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def _read_exact_inventory(path: Path) -> bytes:
    if os.name != "posix" or path.name != _INVENTORY_NAME:
        _fail("inventory_path_invalid")
    required = ("O_CLOEXEC", "O_NOCTTY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        _fail("platform_unsupported")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > _MAX_INVENTORY_BYTES
        ):
            _fail("inventory_path_invalid")
        chunks: list[bytes] = []
        observed = 0
        while observed <= before.st_size:
            chunk = os.read(
                descriptor,
                min(65_536, before.st_size + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError:
        _fail("inventory_path_invalid")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                _fail("inventory_path_invalid")
    if len(payload) != before.st_size or _identity(before) != _identity(after):
        _fail("inventory_path_changed")
    return payload


def _reject_json_constant(_: str) -> NoReturn:
    _fail("inventory_invalid")


def _unique_json_object(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    document: dict[str, object] = {}
    for key, value in pairs:
        if key in document:
            _fail("inventory_invalid")
        document[key] = value
    return document


def _parse_inventory_members(
    raw_members: object,
) -> tuple[InventoryMemberEvidence, ...]:
    if (
        not isinstance(raw_members, list)
        or not 1 <= len(raw_members) <= _MAX_SDIST_MEMBERS
    ):
        _fail("inventory_invalid")
    members: list[InventoryMemberEvidence] = []
    total_file_bytes = 0
    for raw_member in raw_members:
        if not isinstance(raw_member, dict):
            _fail("inventory_invalid")
        kind = raw_member.get("kind")
        expected_keys = (
            {"kind", "mode", "path", "size_bytes", "sha256"}
            if kind == "file"
            else {"kind", "mode", "path", "size_bytes"}
        )
        if set(raw_member) != expected_keys:
            _fail("inventory_invalid")
        path_text = raw_member["path"]
        mode = raw_member["mode"]
        size_bytes = raw_member["size_bytes"]
        sha256 = raw_member.get("sha256")
        if not isinstance(path_text, str):
            _fail("inventory_invalid")
        path = PurePosixPath(path_text)
        first = path.parts[0] if path.parts else ""
        if (
            not path_text
            or "\\" in path_text
            or path.is_absolute()
            or path.as_posix() != path_text
            or any(part in ("", ".", "..") for part in path.parts)
            or (len(first) >= 2 and first[0].isalpha() and first[1] == ":")
            or any(
                ord(character) < 32 or ord(character) == 127 for character in path_text
            )
            or kind not in ("directory", "file")
            or not isinstance(mode, str)
            or type(size_bytes) is not int
        ):
            _fail("inventory_invalid")
        if kind == "directory":
            if mode != "0755" or size_bytes != 0 or sha256 is not None:
                _fail("inventory_invalid")
        else:
            if (
                mode not in ("0644", "0755")
                or not 0 <= size_bytes <= _MAX_SDIST_MEMBER_BYTES
                or not isinstance(sha256, str)
                or len(sha256) != 64
                or any(character not in _LOWER_HEX for character in sha256)
            ):
                _fail("inventory_invalid")
            total_file_bytes += size_bytes
            if total_file_bytes > _MAX_SDIST_FILE_BYTES:
                _fail("inventory_invalid")
        members.append(
            InventoryMemberEvidence(
                path=path_text,
                kind=kind,
                mode=mode,
                size_bytes=size_bytes,
                sha256=sha256,
            )
        )
    paths = [member.path for member in members]
    if paths != sorted(paths) or len(paths) != len(set(paths)):
        _fail("inventory_invalid")
    return tuple(members)


def _parse_release_inventory(payload: bytes) -> ReleaseInventoryEvidence:
    if (
        type(payload) is not bytes
        or not payload.endswith(b"\n")
        or payload.endswith(b"\n\n")
    ):
        _fail("inventory_not_canonical")
    try:
        text = payload.decode("ascii")
        document = json.loads(
            text,
            object_pairs_hook=_unique_json_object,
            parse_constant=_reject_json_constant,
        )
    except VerificationFailure:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError):
        _fail("inventory_invalid")
    if _canonical_json(document) + b"\n" != payload:
        _fail("inventory_not_canonical")
    if (
        not isinstance(document, dict)
        or set(document)
        != {
            "artifacts",
            "schema",
            "source_commit",
            "source_date_epoch",
        }
        or document["schema"] != _INVENTORY_SCHEMA
    ):
        _fail("inventory_invalid")
    source_commit = document["source_commit"]
    if not isinstance(source_commit, str):
        _fail("inventory_invalid")
    try:
        _validate_source_commit(source_commit)
    except VerificationFailure:
        _fail("inventory_invalid")
    source_date_epoch = document["source_date_epoch"]
    if (
        type(source_date_epoch) is not int
        or not 0 <= source_date_epoch <= (1 << 32) - 1
    ):
        _fail("inventory_invalid")
    raw_artifacts = document["artifacts"]
    if not isinstance(raw_artifacts, list) or len(raw_artifacts) != 2:
        _fail("inventory_invalid")
    artifacts: list[InventoryArtifactEvidence] = []
    for raw_artifact in raw_artifacts:
        if not isinstance(raw_artifact, dict):
            _fail("inventory_invalid")
        kind = raw_artifact.get("kind")
        expected_keys = {"filename", "kind", "sha256", "size_bytes"}
        if kind == "sdist":
            expected_keys.add("members")
        if set(raw_artifact) != expected_keys:
            _fail("inventory_invalid")
        filename = raw_artifact["filename"]
        sha256 = raw_artifact["sha256"]
        size_bytes = raw_artifact["size_bytes"]
        if (
            not isinstance(filename, str)
            or not filename
            or "\\" in filename
            or PurePosixPath(filename).name != filename
            or any(
                ord(character) < 32 or ord(character) == 127 for character in filename
            )
            or kind not in ("wheel", "sdist")
            or not isinstance(sha256, str)
            or len(sha256) != 64
            or any(character not in _LOWER_HEX for character in sha256)
            or type(size_bytes) is not int
            or not 0 < size_bytes <= _MAX_RELEASE_ARTIFACT_BYTES
        ):
            _fail("inventory_invalid")
        members = (
            _parse_inventory_members(raw_artifact["members"])
            if kind == "sdist"
            else None
        )
        artifacts.append(
            InventoryArtifactEvidence(
                filename=filename,
                kind=kind,
                sha256=sha256,
                size_bytes=size_bytes,
                members=members,
            )
        )
    if [artifact.filename for artifact in artifacts] != sorted(
        artifact.filename for artifact in artifacts
    ) or {artifact.kind for artifact in artifacts} != {"wheel", "sdist"}:
        _fail("inventory_invalid")
    return ReleaseInventoryEvidence(
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        sha256=hashlib.sha256(payload).hexdigest(),
        artifacts=tuple(artifacts),
    )


def _bind_release_inventory(
    inventory: ReleaseInventoryEvidence,
    *,
    expected_source_commit: str,
    wheel_path: Path,
    wheel_payload: bytes,
    sdist_path: Path,
    sdist_payload: bytes,
) -> None:
    if inventory.source_commit != expected_source_commit:
        _fail("inventory_source_commit_mismatch")
    by_kind = {artifact.kind: artifact for artifact in inventory.artifacts}
    wheel = by_kind["wheel"]
    sdist = by_kind["sdist"]
    if wheel.filename != _WHEEL_NAME or wheel_path.name != wheel.filename:
        _fail("inventory_wheel_name_mismatch")
    if sdist.filename != _SDIST_NAME:
        _fail("inventory_sdist_name_mismatch")
    if sdist_path.name != sdist.filename:
        _fail("inventory_sdist_name_mismatch")
    if wheel.size_bytes != len(wheel_payload):
        _fail("inventory_wheel_size_mismatch")
    if wheel.sha256 != hashlib.sha256(wheel_payload).hexdigest():
        _fail("inventory_wheel_sha256_mismatch")
    if sdist.size_bytes != len(sdist_payload):
        _fail("inventory_sdist_size_mismatch")
    if sdist.sha256 != hashlib.sha256(sdist_payload).hexdigest():
        _fail("inventory_sdist_sha256_mismatch")


def _bind_sdist_members(
    inventory: ReleaseInventoryEvidence,
    actual_members: tuple[InventoryMemberEvidence, ...],
) -> None:
    sdist = next(
        artifact for artifact in inventory.artifacts if artifact.kind == "sdist"
    )
    if sdist.members != actual_members:
        _fail("inventory_sdist_members_mismatch")


def _read_exact_wheel(path: Path) -> bytes:
    if os.name != "posix" or path.name != _WHEEL_NAME:
        _fail("wheel_path_invalid")
    required = ("O_CLOEXEC", "O_NOCTTY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        _fail("platform_unsupported")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > _MAX_WHEEL_BYTES
        ):
            _fail("wheel_path_invalid")
        chunks: list[bytes] = []
        observed = 0
        while observed <= before.st_size:
            chunk = os.read(
                descriptor,
                min(65_536, before.st_size + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError:
        _fail("wheel_path_invalid")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                _fail("wheel_path_invalid")
    if len(payload) != before.st_size or _identity(before) != _identity(after):
        _fail("wheel_path_changed")
    return payload


def _read_exact_sdist(path: Path) -> bytes:
    if os.name != "posix" or path.name != _SDIST_NAME:
        _fail("sdist_path_invalid")
    required = ("O_CLOEXEC", "O_NOCTTY", "O_NOFOLLOW", "O_NONBLOCK")
    if any(not hasattr(os, name) for name in required):
        _fail("platform_unsupported")
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK
    descriptor = -1
    try:
        descriptor = os.open(path, flags)
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > _MAX_COMPRESSED_SDIST_BYTES
        ):
            _fail("sdist_path_invalid")
        chunks: list[bytes] = []
        observed = 0
        while observed <= before.st_size:
            chunk = os.read(
                descriptor,
                min(65_536, before.st_size + 1 - observed),
            )
            if not chunk:
                break
            chunks.append(chunk)
            observed += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    except OSError:
        _fail("sdist_path_invalid")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                _fail("sdist_path_invalid")
    if len(payload) != before.st_size or _identity(before) != _identity(after):
        _fail("sdist_path_changed")
    return payload


def _safe_sdist_member_name(member: tarfile.TarInfo) -> str:
    raw_name = member.name
    if (
        not isinstance(raw_name, str)
        or not raw_name
        or "\\" in raw_name
        or "\x00" in raw_name
        or any(ord(character) < 32 or ord(character) == 127 for character in raw_name)
    ):
        _fail("sdist_member_unsafe")
    normalized = (
        raw_name[:-1] if member.isdir() and raw_name.endswith("/") else raw_name
    )
    path = PurePosixPath(normalized)
    first = path.parts[0] if path.parts else ""
    if (
        not normalized
        or path.is_absolute()
        or path.as_posix() != normalized
        or any(part in ("", ".", "..") for part in path.parts)
        or (len(first) >= 2 and first[0].isalpha() and first[1] == ":")
        or (not member.isdir() and raw_name.endswith("/"))
    ):
        _fail("sdist_member_unsafe")
    return normalized


def _inspect_sdist(
    payload: bytes,
    *,
    source_date_epoch: int,
) -> tuple[InventoryMemberEvidence, ...]:
    if (
        type(payload) is not bytes
        or len(payload) < 18
        or payload[:4] != b"\x1f\x8b\x08\x00"
        or int.from_bytes(payload[4:8], "little") != source_date_epoch
    ):
        _fail("sdist_not_canonical")
    compressed = io.BytesIO(payload)
    try:
        with gzip.GzipFile(fileobj=compressed, mode="rb") as archive:
            tar_payload = archive.read(_MAX_EXPANDED_SDIST_BYTES + 1)
    except (EOFError, OSError, gzip.BadGzipFile, zlib.error):
        _fail("sdist_archive_invalid")
    if (
        not 0 < len(tar_payload) <= _MAX_EXPANDED_SDIST_BYTES
        or len(tar_payload) % _TAR_BLOCK_BYTES
        or len(tar_payload) < _TAR_TRAILER_BYTES
    ):
        _fail("sdist_archive_invalid")

    observed: list[InventoryMemberEvidence] = []
    observed_paths: set[str] = set()
    total_file_bytes = 0
    archive_offset = -1
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            members = archive.getmembers()
            archive_offset = archive.offset
            if not 1 <= len(members) <= _MAX_SDIST_MEMBERS:
                _fail("sdist_archive_invalid")
            for member in members:
                if (
                    not (member.isdir() or member.isreg())
                    or member.sparse is not None
                    or member.uid != 0
                    or member.gid != 0
                    or member.uname != ""
                    or member.gname != ""
                    or member.linkname
                    or member.pax_headers
                    or member.mtime != source_date_epoch
                ):
                    _fail("sdist_member_unsafe")
                name = _safe_sdist_member_name(member)
                if name in observed_paths:
                    _fail("sdist_member_duplicate")
                observed_paths.add(name)
                if member.isdir():
                    if member.size != 0 or member.mode != 0o755:
                        _fail("sdist_not_canonical")
                    observed.append(
                        InventoryMemberEvidence(
                            path=name,
                            kind="directory",
                            mode="0755",
                            size_bytes=0,
                            sha256=None,
                        )
                    )
                    continue
                if (
                    not 0 <= member.size <= _MAX_SDIST_MEMBER_BYTES
                    or member.mode not in (0o644, 0o755)
                ):
                    _fail("sdist_member_unsafe")
                total_file_bytes += member.size
                if total_file_bytes > _MAX_SDIST_FILE_BYTES:
                    _fail("sdist_archive_invalid")
                extracted = archive.extractfile(member)
                if extracted is None:
                    _fail("sdist_archive_invalid")
                member_payload = extracted.read(_MAX_SDIST_MEMBER_BYTES + 1)
                if len(member_payload) != member.size:
                    _fail("sdist_archive_invalid")
                observed.append(
                    InventoryMemberEvidence(
                        path=name,
                        kind="file",
                        mode=f"{member.mode:04o}",
                        size_bytes=len(member_payload),
                        sha256=hashlib.sha256(member_payload).hexdigest(),
                    )
                )
    except VerificationFailure:
        raise
    except (OSError, tarfile.TarError, UnicodeError, ValueError):
        _fail("sdist_archive_invalid")
    if (
        archive_offset < 0
        or len(tar_payload) - archive_offset < _TAR_TRAILER_BYTES
        or any(tar_payload[archive_offset:])
        or [member.path for member in observed]
        != sorted(member.path for member in observed)
    ):
        _fail("sdist_not_canonical")
    return tuple(observed)


def _validate_member_name(name: str) -> None:
    path = PurePosixPath(name)
    if (
        not name
        or "\\" in name
        or path.is_absolute()
        or any(part in ("", ".", "..") for part in path.parts)
    ):
        _fail("wheel_archive_invalid")


def _validate_zip_member(info: ZipInfo) -> None:
    _validate_member_name(info.filename)
    mode = info.external_attr >> 16
    if (
        info.is_dir()
        or info.flag_bits & 0x1
        or info.file_size < 0
        or info.file_size > _MAX_MEMBER_BYTES
        or not mode
        or not stat.S_ISREG(mode)
    ):
        _fail("wheel_archive_invalid")


def _decode_record_digest(value: str) -> str:
    if not value.startswith("sha256="):
        _fail("record_invalid")
    digest = value.removeprefix("sha256=")
    try:
        decoded = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4))
    except (UnicodeError, ValueError):
        _fail("record_invalid")
    if len(decoded) != hashlib.sha256().digest_size:
        _fail("record_invalid")
    return digest


def _parse_record(payload: bytes) -> dict[str, RecordEntry]:
    try:
        text = payload.decode("utf-8")
        rows = list(csv.reader(io.StringIO(text, newline="")))
    except (UnicodeError, csv.Error):
        _fail("record_invalid")
    records: dict[str, RecordEntry] = {}
    for row in rows:
        if len(row) != 3:
            _fail("record_invalid")
        path, raw_digest, raw_size = row
        if not path or path in records:
            _fail("record_invalid")
        digest = _decode_record_digest(raw_digest) if raw_digest else None
        if raw_size:
            if not raw_size.isascii() or not raw_size.isdecimal():
                _fail("record_invalid")
            size: int | None = int(raw_size)
        else:
            size = None
        if (digest is None) != (size is None):
            _fail("record_invalid")
        records[path] = RecordEntry(path=path, digest=digest, size=size)
    return records


def _record_digest(payload: bytes) -> str:
    digest = hashlib.sha256(payload).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode("ascii")


def _assert_record_match(entry: RecordEntry, payload: bytes) -> None:
    if entry.size != len(payload) or entry.digest != _record_digest(payload):
        _fail("record_mismatch")


def _parse_metadata(payload: bytes) -> Mapping[str, str]:
    message = BytesParser(policy=policy.default).parsebytes(payload)
    if (
        message["Name"] != _DISTRIBUTION_NAME
        or message["Version"] != _DISTRIBUTION_VERSION
        or message["Requires-Python"] != ">=3.11"
        or message.get_all("Requires-Dist", []) != []
    ):
        _fail("wheel_metadata_invalid")
    return dict(message.items())


def _inspect_wheel(payload: bytes) -> WheelEvidence:
    try:
        with ZipFile(io.BytesIO(payload)) as archive:
            infos = archive.infolist()
            names = [info.filename for info in infos]
            if len(names) != len(set(names)):
                _fail("wheel_archive_invalid")
            for info in infos:
                _validate_zip_member(info)
            if (
                frozenset(names) != _EXPECTED_WHEEL_MEMBERS
                or sum(info.file_size for info in infos) > _MAX_EXPANDED_BYTES
            ):
                _fail("wheel_inventory_invalid")
            members = {name: archive.read(name) for name in names}
            member_info = {info.filename: info for info in infos}
    except VerificationFailure:
        raise
    except (BadZipFile, KeyError, OSError, RuntimeError):
        _fail("wheel_archive_invalid")

    _parse_metadata(members[f"{_DIST_INFO}/METADATA"])
    if members[f"{_DIST_INFO}/top_level.txt"] != b"netveil\nnetveil_bootstrap\n":
        _fail("wheel_metadata_invalid")
    wheel_metadata = BytesParser(policy=policy.default).parsebytes(
        members[f"{_DIST_INFO}/WHEEL"]
    )
    if (
        wheel_metadata["Wheel-Version"] != "1.0"
        or wheel_metadata["Root-Is-Purelib"] != "true"
        or wheel_metadata.get_all("Tag", []) != ["py3-none-any"]
    ):
        _fail("wheel_metadata_invalid")

    record_name = f"{_DIST_INFO}/RECORD"
    records = _parse_record(members[record_name])
    if set(records) != set(members):
        _fail("record_invalid")
    for name, member_payload in members.items():
        entry = records[name]
        if name == record_name:
            if entry.digest is not None or entry.size is not None:
                _fail("record_invalid")
        else:
            _assert_record_match(entry, member_payload)

    launcher = members[_WHEEL_SCRIPT]
    launcher_mode = member_info[_WHEEL_SCRIPT].external_attr >> 16
    if not launcher_mode & stat.S_IXUSR:
        _fail("launcher_invalid")
    _validate_launcher_bytes(launcher)
    return WheelEvidence(
        payload=payload,
        sha256=hashlib.sha256(payload).hexdigest(),
        launcher=launcher,
        members=tuple(
            WheelMemberEvidence(
                path=name,
                sha256=hashlib.sha256(members[name]).hexdigest(),
                size=len(members[name]),
                mode=f"{stat.S_IMODE(member_info[name].external_attr >> 16):04o}",
            )
            for name in sorted(members)
        ),
    )


def _validate_launcher_bytes(payload: bytes) -> None:
    if (
        not payload.startswith(b"#!/bin/sh\n")
        or b'exec "$netveil_script_directory/python" -IESB "$0" "$@"\n' not in payload
        or b"[project.scripts]" in payload
    ):
        _fail("launcher_invalid")


def _write_exclusive(path: Path, payload: bytes, *, mode: int) -> None:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC,
            mode,
        )
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                _fail("private_file_write_failed")
            offset += written
        os.fsync(descriptor)
    except OSError:
        _fail("private_file_write_failed")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                _fail("private_file_write_failed")


def _base_environment(
    root: Path, layout: InstalledLayout | None = None
) -> dict[str, str]:
    home = root / "home"
    temporary = root / "tmp"
    home.mkdir(exist_ok=True)
    temporary.mkdir(exist_ok=True)
    binary = layout.launcher.parent if layout is not None else root
    return {
        "HOME": str(home),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
        "PATH": str(binary),
        "PIP_CONFIG_FILE": os.devnull,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PIP_NO_INPUT": "1",
        "PIP_ROOT_USER_ACTION": "ignore",
        "TMPDIR": str(temporary),
    }


def _kill_process_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (OSError, ProcessLookupError):
        try:
            process.kill()
        except OSError:
            pass


def _run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
) -> ProcessResult:
    try:
        with (
            tempfile.TemporaryFile("w+b") as stdout_file,
            tempfile.TemporaryFile("w+b") as stderr_file,
        ):
            process = subprocess.Popen(
                list(argv),
                cwd=cwd,
                env=dict(env),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                close_fds=True,
                start_new_session=True,
            )
            try:
                returncode = process.wait(timeout=_PROCESS_TIMEOUT_SECONDS)
            except subprocess.TimeoutExpired:
                _kill_process_group(process)
                process.wait()
                _fail("process_timeout")
            stdout_file.seek(0)
            stderr_file.seek(0)
            stdout = stdout_file.read(_MAX_PROCESS_OUTPUT_BYTES + 1)
            stderr = stderr_file.read(_MAX_PROCESS_OUTPUT_BYTES + 1)
    except OSError:
        _fail("process_start_failed")
    if (
        len(stdout) > _MAX_PROCESS_OUTPUT_BYTES
        or len(stderr) > _MAX_PROCESS_OUTPUT_BYTES
    ):
        _fail("process_output_unbounded")
    return ProcessResult(returncode=returncode, stdout=stdout, stderr=stderr)


def _create_fresh_install(
    root: Path,
    wheel: WheelEvidence,
) -> InstalledLayout:
    pinned_wheel = root / _WHEEL_NAME
    _write_exclusive(pinned_wheel, wheel.payload, mode=0o600)
    prefix = root / "venv"
    try:
        venv.EnvBuilder(
            system_site_packages=False,
            clear=False,
            symlinks=False,
            with_pip=False,
        ).create(prefix)
    except (OSError, subprocess.SubprocessError):
        _fail("venv_creation_failed")
    python = prefix / "bin" / "python"
    if not python.is_file():
        _fail("venv_creation_failed")
    environment = _base_environment(root)
    ensurepip = _run_process(
        (
            str(python),
            "-I",
            "-m",
            "ensurepip",
            "--default-pip",
        ),
        cwd=root,
        env=environment,
    )
    if ensurepip.returncode != 0:
        _fail("ensurepip_failed")
    install = _run_process(
        (
            str(python),
            "-I",
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--disable-pip-version-check",
            "--no-cache-dir",
            str(pinned_wheel),
        ),
        cwd=root,
        env=environment,
    )
    if install.returncode != 0:
        _fail("wheel_install_failed")
    return _inspect_install(prefix, python, wheel.launcher)


def _installed_record_path(site_root: Path, launcher: Path) -> str:
    return PurePosixPath(os.path.relpath(launcher, site_root)).as_posix()


def _read_installed_regular(
    path: Path,
    *,
    maximum: int,
) -> tuple[bytes, os.stat_result]:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_size <= 0
            or before.st_size > maximum
        ):
            _fail("installed_layout_invalid")
        chunks: list[bytes] = []
        observed = 0
        while observed < before.st_size:
            chunk = os.read(
                descriptor,
                min(65_536, before.st_size - observed),
            )
            if not chunk:
                _fail("installed_layout_invalid")
            chunks.append(chunk)
            observed += len(chunk)
        payload = b"".join(chunks)
        after = os.fstat(descriptor)
    except VerificationFailure:
        raise
    except OSError:
        _fail("installed_layout_invalid")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                _fail("installed_layout_invalid")
    if len(payload) != before.st_size or _identity(before) != _identity(after):
        _fail("installed_layout_changed")
    return payload, before


def _record_sha256_hex(digest: str | None) -> str | None:
    if digest is None:
        return None
    try:
        decoded = base64.urlsafe_b64decode(digest + "=" * (-len(digest) % 4))
    except (UnicodeError, ValueError):
        _fail("record_invalid")
    if len(decoded) != hashlib.sha256().digest_size:
        _fail("record_invalid")
    return decoded.hex()


def _inspect_install(
    prefix: Path,
    python: Path,
    expected_launcher: bytes,
) -> InstalledLayout:
    candidates = {
        path.resolve()
        for library in ("lib", "lib64")
        for path in (prefix / library).glob(f"python*/site-packages/{_DIST_INFO}")
        if path.is_dir()
    }
    if len(candidates) != 1:
        _fail("installed_layout_invalid")
    dist_info = candidates.pop()
    site_root = dist_info.parent
    launcher = prefix / "bin" / _LAUNCHER_NAME
    bootstrap = site_root / _BOOTSTRAP_NAME
    package_root = site_root / "netveil"
    record_path = dist_info / "RECORD"
    required = (launcher, bootstrap, package_root / "cli.py", record_path)
    if any(not path.is_file() for path in required):
        _fail("installed_layout_invalid")
    launcher_payload, launcher_status = _read_installed_regular(
        launcher,
        maximum=_MAX_MEMBER_BYTES,
    )
    record_payload, record_status = _read_installed_regular(
        record_path,
        maximum=_MAX_MEMBER_BYTES,
    )
    if not launcher_status.st_mode & stat.S_IXUSR:
        _fail("launcher_invalid")
    if launcher_payload != expected_launcher:
        _fail("launcher_identity_mismatch")
    _validate_launcher_bytes(launcher_payload)
    records = _parse_record(record_payload)
    relative_launcher = _installed_record_path(site_root, launcher)
    launcher_record = records.get(relative_launcher)
    if launcher_record is None:
        _fail("launcher_record_missing")
    _assert_record_match(launcher_record, launcher_payload)
    record_record_path = f"{_DIST_INFO}/RECORD"
    record_record = records.get(record_record_path)
    if (
        record_record is None
        or record_record.digest is not None
        or record_record.size is not None
    ):
        _fail("record_invalid")
    if (dist_info / "entry_points.txt").exists():
        _fail("entry_points_present")
    distribution = importlib.metadata.PathDistribution(dist_info)
    if (
        list(distribution.entry_points)
        or distribution.metadata["Name"] != _DISTRIBUTION_NAME
        or distribution.version != _DISTRIBUTION_VERSION
    ):
        _fail("entry_points_present")
    selected_paths = {
        relative_launcher,
        _BOOTSTRAP_NAME,
        "netveil/__init__.py",
        "netveil/cli.py",
        "netveil/model.py",
        "netveil/parser.py",
        "netveil/privacy.py",
        "netveil/py.typed",
        f"{_DIST_INFO}/METADATA",
        record_record_path,
        f"{_DIST_INFO}/WHEEL",
        f"{_DIST_INFO}/licenses/LICENSE",
        f"{_DIST_INFO}/top_level.txt",
    }
    selected_rows = tuple(
        InstalledRecordRowEvidence(
            path=path,
            sha256=_record_sha256_hex(records[path].digest),
            size_bytes=records[path].size,
        )
        for path in sorted(selected_paths & records.keys())
    )
    if not {
        relative_launcher,
        record_record_path,
    }.issubset(row.path for row in selected_rows):
        _fail("record_invalid")
    evidence = InstalledEvidence(
        launcher=InstalledFileEvidence(
            logical_path="bin/netveil-audit",
            mode=f"{stat.S_IMODE(launcher_status.st_mode):04o}",
            sha256=hashlib.sha256(launcher_payload).hexdigest(),
            size_bytes=len(launcher_payload),
        ),
        record=InstalledFileEvidence(
            logical_path=f"site-packages/{record_record_path}",
            mode=f"{stat.S_IMODE(record_status.st_mode):04o}",
            sha256=hashlib.sha256(record_payload).hexdigest(),
            size_bytes=len(record_payload),
        ),
        selected_record_rows=selected_rows,
    )
    return InstalledLayout(
        prefix=prefix,
        python=python,
        launcher=launcher,
        site_root=site_root,
        dist_info=dist_info,
        bootstrap=bootstrap,
        package_root=package_root,
        record=record_path,
        evidence=evidence,
    )


def _assert_no_private_output(
    result: ProcessResult,
    forbidden: Sequence[bytes],
) -> None:
    output = result.stdout + result.stderr
    if any(token and token in output for token in forbidden):
        _fail("private_output_detected")


def _invoke(
    layout: InstalledLayout,
    arguments: Sequence[str],
    *,
    cwd: Path,
    env: Mapping[str, str],
    through_path: bool = False,
) -> ProcessResult:
    command = _LAUNCHER_NAME if through_path else str(layout.launcher)
    return _run_process((command, *arguments), cwd=cwd, env=env)


def _verify_user_commands(
    layout: InstalledLayout,
    *,
    root: Path,
    env: Mapping[str, str],
) -> None:
    forbidden = (str(root).encode(),)
    expected_version = b"netveil-audit 0.3.0\n"
    for arguments, exact_stdout in (
        (("--version",), expected_version),
        (("--help",), None),
    ):
        direct = _invoke(layout, arguments, cwd=root, env=env)
        path = _invoke(
            layout,
            arguments,
            cwd=root,
            env=env,
            through_path=True,
        )
        if (
            direct.returncode != 0
            or path.returncode != 0
            or direct.stderr
            or path.stderr
            or direct.stdout != path.stdout
            or (exact_stdout is not None and direct.stdout != exact_stdout)
        ):
            _fail("command_contract_failed")
        if exact_stdout is None and (
            not direct.stdout.startswith(b"usage: netveil-audit ")
            or b"receipt" not in direct.stdout
            or b"--version" not in direct.stdout
        ):
            _fail("help_contract_failed")
        _assert_no_private_output(direct, forbidden)
        _assert_no_private_output(path, forbidden)


def _updated_record(
    payload: bytes,
    *,
    path: str,
    replacement: bytes,
) -> bytes:
    records = _parse_record(payload)
    if path not in records:
        _fail("record_rewrite_failed")
    try:
        rows = list(csv.reader(io.StringIO(payload.decode("utf-8"), newline="")))
    except (UnicodeError, csv.Error):
        _fail("record_rewrite_failed")
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    replaced = 0
    for row in rows:
        if row[0] == path:
            writer.writerow(
                (
                    path,
                    f"sha256={_record_digest(replacement)}",
                    str(len(replacement)),
                )
            )
            replaced += 1
        else:
            writer.writerow(row)
    if replaced != 1:
        _fail("record_rewrite_failed")
    return output.getvalue().encode("utf-8")


@contextmanager
def _temporary_bytes(path: Path, payload: bytes) -> Iterator[None]:
    existed = path.exists()
    original = b""
    original_mode = 0
    if existed:
        try:
            status = path.lstat()
            if not stat.S_ISREG(status.st_mode):
                _fail("mutation_target_invalid")
            original = path.read_bytes()
            original_mode = stat.S_IMODE(status.st_mode)
        except OSError:
            _fail("mutation_target_invalid")
    try:
        path.write_bytes(payload)
        yield
    except OSError:
        _fail("mutation_failed")
    finally:
        try:
            if existed:
                path.write_bytes(original)
                path.chmod(original_mode)
            else:
                path.unlink(missing_ok=True)
        except OSError:
            _fail("mutation_restore_failed")


def _poisoned_environment(
    env: Mapping[str, str],
    *,
    attack_root: Path,
    marker: Path,
) -> dict[str, str]:
    poisoned = dict(env)
    poisoned.update(
        {
            "NETVEIL_VERIFY_MARKER": str(marker),
            "PYTHONHOME": str(attack_root / "invalid-python-home"),
            "PYTHONINSPECT": "1",
            "PYTHONPATH": str(attack_root),
            "PYTHONSTARTUP": str(attack_root / "startup.py"),
        }
    )
    return poisoned


def _verify_isolation(
    layout: InstalledLayout,
    *,
    root: Path,
    env: Mapping[str, str],
) -> InterpreterEvidence:
    attack_root = root / "startup-attack"
    attack_root.mkdir()
    marker = root / "startup-marker"
    poisoned = _poisoned_environment(env, attack_root=attack_root, marker=marker)
    attack_paths = (
        attack_root / "sitecustomize.py",
        attack_root / "usercustomize.py",
        attack_root / "startup.py",
        layout.site_root / "sitecustomize.py",
        layout.site_root / "usercustomize.py",
    )
    try:
        for path in attack_paths:
            if path.exists():
                _fail("startup_probe_collision")
            path.write_bytes(_ATTACK_SOURCE)
        for through_path in (False, True):
            result = _invoke(
                layout,
                ("--version",),
                cwd=root,
                env=poisoned,
                through_path=through_path,
            )
            if (
                result.returncode != 0
                or result.stdout != b"netveil-audit 0.3.0\n"
                or result.stderr
                or marker.exists()
            ):
                _fail("environment_isolation_failed")
            _assert_no_private_output(
                result,
                (str(root).encode(), str(marker).encode()),
            )

        original_record = layout.record.read_bytes()
        rewritten = _updated_record(
            original_record,
            path=_BOOTSTRAP_NAME,
            replacement=_PROBE_SOURCE,
        )
        with (
            _temporary_bytes(layout.bootstrap, _PROBE_SOURCE),
            _temporary_bytes(layout.record, rewritten),
        ):
            probe = _invoke(
                layout,
                ("isolation-probe",),
                cwd=root,
                env=poisoned,
            )
        try:
            probe_document = json.loads(probe.stdout)
        except (UnicodeError, json.JSONDecodeError):
            _fail("isolation_probe_failed")
        if not isinstance(probe_document, dict):
            _fail("isolation_probe_failed")
        implementation = probe_document.pop("implementation", None)
        version = probe_document.pop("version", None)
        cache_tag = probe_document.pop("cache_tag", None)
        expected_version = (
            f"{sys.version_info.major}."
            f"{sys.version_info.minor}."
            f"{sys.version_info.micro}"
        )
        if (
            probe.returncode != 0
            or probe.stderr
            or probe_document != _EXPECTED_PROBE
            or implementation != sys.implementation.name
            or version != expected_version
            or cache_tag != sys.implementation.cache_tag
            or marker.exists()
        ):
            _fail("isolation_probe_failed")
        _assert_no_private_output(
            probe,
            (str(root).encode(), str(marker).encode()),
        )
        if (
            not isinstance(implementation, str)
            or not isinstance(version, str)
            or not isinstance(cache_tag, str)
        ):
            _fail("isolation_probe_failed")
        evidence = InterpreterEvidence(
            implementation=implementation,
            version=version,
            cache_tag=cache_tag,
        )
    finally:
        for path in attack_paths:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                _fail("startup_probe_cleanup_failed")
    return evidence


def _unchecked_hash_pyc(source: bytes, claimed_source: bytes) -> bytes:
    code = compile(source, "<netveil-adversarial-pyc>", "exec", dont_inherit=True)
    if not isinstance(code, CodeType):
        _fail("pyc_probe_failed")
    source_hash = importlib.util.source_hash(claimed_source)
    return (
        importlib.util.MAGIC_NUMBER
        + struct.pack("<I", 1)
        + source_hash
        + marshal.dumps(code)
    )


def _marker_absent(marker: Path) -> None:
    if marker.exists():
        _fail("adversarial_code_executed")


def _expect_successful_version(
    layout: InstalledLayout,
    *,
    root: Path,
    env: Mapping[str, str],
    marker: Path,
) -> None:
    result = _invoke(layout, ("--version",), cwd=root, env=env)
    if (
        result.returncode != 0
        or result.stdout != b"netveil-audit 0.3.0\n"
        or result.stderr
    ):
        _fail("bytecode_inertness_failed")
    _marker_absent(marker)
    _assert_no_private_output(
        result,
        (str(root).encode(), str(marker).encode()),
    )


def _expect_artifact_failure(
    layout: InstalledLayout,
    *,
    root: Path,
    env: Mapping[str, str],
    marker: Path,
) -> None:
    marker.unlink(missing_ok=True)
    result = _invoke(layout, ("--version",), cwd=root, env=env)
    if result.returncode != 10 or result.stdout or result.stderr != _ARTIFACT_FAILURE:
        _fail("tamper_not_rejected")
    _marker_absent(marker)
    _assert_no_private_output(
        result,
        (str(root).encode(), str(marker).encode()),
    )


def _verify_bytecode_and_tamper(
    layout: InstalledLayout,
    *,
    root: Path,
    env: Mapping[str, str],
) -> None:
    marker = root / "adversarial-marker"
    adversarial_env = dict(env)
    adversarial_env["NETVEIL_VERIFY_MARKER"] = str(marker)
    cache_tag = sys.implementation.cache_tag
    if not cache_tag:
        _fail("pyc_probe_failed")

    top_cache = layout.site_root / "__pycache__"
    package_cache = layout.package_root / "__pycache__"
    top_cache.mkdir(exist_ok=True)
    package_cache.mkdir(exist_ok=True)
    bootstrap_source = layout.bootstrap.read_bytes()
    cli_path = layout.package_root / "cli.py"
    cli_source = cli_path.read_bytes()
    malicious_bootstrap_pyc = _unchecked_hash_pyc(
        _ATTACK_SOURCE,
        bootstrap_source,
    )
    malicious_cli_pyc = _unchecked_hash_pyc(_ATTACK_SOURCE, cli_source)

    top_pyc = top_cache / f"netveil_bootstrap.{cache_tag}.pyc"
    with _temporary_bytes(top_pyc, malicious_bootstrap_pyc):
        _expect_successful_version(
            layout,
            root=root,
            env=adversarial_env,
            marker=marker,
        )
    cli_pyc = package_cache / f"cli.{cache_tag}.pyc"
    with _temporary_bytes(cli_pyc, malicious_cli_pyc):
        _expect_successful_version(
            layout,
            root=root,
            env=adversarial_env,
            marker=marker,
        )

    unknown_pyc = package_cache / f"unknown.{cache_tag}.pyc"
    with _temporary_bytes(unknown_pyc, malicious_cli_pyc):
        _expect_artifact_failure(
            layout,
            root=root,
            env=adversarial_env,
            marker=marker,
        )

    launcher_payload = layout.launcher.read_bytes()
    function_header = (
        b"def _execute_bootstrap(payload: bytes, bootstrap_path: Path) -> int:\n"
    )
    if launcher_payload.count(function_header) != 1:
        _fail("tamper_probe_unavailable")
    launcher_tamper = launcher_payload.replace(
        function_header,
        function_header
        + b'    Path(os.environ["NETVEIL_VERIFY_MARKER"]).write_bytes(b"executed")\n',
    )
    tamper_cases = (
        (layout.launcher, launcher_tamper),
        (layout.bootstrap, bootstrap_source + b"\n" + _ATTACK_SOURCE),
        (cli_path, cli_source + b"\n" + _ATTACK_SOURCE),
    )
    for path, payload in tamper_cases:
        with _temporary_bytes(path, payload):
            _expect_artifact_failure(
                layout,
                root=root,
                env=adversarial_env,
                marker=marker,
            )

    metadata_paths = (
        layout.dist_info / "METADATA",
        layout.dist_info / "WHEEL",
        layout.dist_info / "top_level.txt",
    )
    for path in metadata_paths:
        original = path.read_bytes()
        with _temporary_bytes(path, original + b"\n# uncoordinated drift\n"):
            _expect_artifact_failure(
                layout,
                root=root,
                env=adversarial_env,
                marker=marker,
            )
    record_payload = layout.record.read_bytes()
    record_drift = _updated_record(
        record_payload,
        path=_BOOTSTRAP_NAME,
        replacement=b"uncoordinated bootstrap claim",
    )
    with _temporary_bytes(layout.record, record_drift):
        _expect_artifact_failure(
            layout,
            root=root,
            env=adversarial_env,
            marker=marker,
        )

    unknown_source = layout.package_root / "unknown.py"
    if unknown_source.exists():
        _fail("unknown_file_probe_collision")
    with _temporary_bytes(unknown_source, _ATTACK_SOURCE):
        _expect_artifact_failure(
            layout,
            root=root,
            env=adversarial_env,
            marker=marker,
        )
    _expect_successful_version(
        layout,
        root=root,
        env=adversarial_env,
        marker=marker,
    )


def _canonical_json(document: object) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _verify_receipt_document(
    payload: bytes,
    *,
    key: bytes,
) -> dict[str, object]:
    if not payload.endswith(b"\n") or payload.endswith(b"\n\n"):
        _fail("receipt_not_canonical")
    try:
        document = json.loads(payload)
    except (UnicodeError, json.JSONDecodeError):
        _fail("receipt_invalid")
    if (
        not isinstance(document, dict)
        or document.get("schema") != "netveil.aggregate-receipt.v1"
        or _canonical_json(document) + b"\n" != payload
    ):
        _fail("receipt_not_canonical")
    report = document.get("report")
    digest = document.get("report_digest")
    if not isinstance(report, dict) or not isinstance(digest, dict):
        _fail("receipt_invalid")
    counts = report.get("counts")
    by_version = report.get("endpoint_occurrences_by_ip_version")
    by_scope = report.get("endpoint_occurrences_by_scope")
    duplicates = report.get("duplicates")
    if (
        counts
        != {
            "endpoint_occurrences": 5,
            "physical_lines": 6,
            "source_bytes": len(_CORPUS),
            "unique_endpoints": 4,
        }
        or not isinstance(by_version, dict)
        or by_version.get("ipv4") != 4
        or by_version.get("ipv6") != 1
        or not isinstance(by_scope, dict)
        or by_scope.get("documentation") != 5
        or not isinstance(duplicates, dict)
        or duplicates.get("group_count") != 1
    ):
        _fail("receipt_semantics_invalid")
    expected_digest = hashlib.sha256(_canonical_json(report)).hexdigest()
    if digest != {"algorithm": "sha256", "value": expected_digest}:
        _fail("receipt_digest_invalid")
    source_id = report.get("source_content_id")
    if (
        not isinstance(source_id, str)
        or not source_id.startswith("nvs1_")
        or len(source_id) != 69
    ):
        _fail("receipt_identifier_invalid")

    forbidden = (
        *_RAW_ENDPOINT_TOKENS,
        hashlib.sha256(_CORPUS).hexdigest().encode(),
        key,
        key.hex().encode(),
        base64.b64encode(key),
        base64.urlsafe_b64encode(key),
    )
    if any(token and token in payload for token in forbidden):
        _fail("receipt_private_data_detected")
    return dict(document)


def _verify_receipt(
    layout: InstalledLayout,
    *,
    root: Path,
    env: Mapping[str, str],
) -> ReceiptEvidence:
    corpus_path = root / "documentation-corpus.txt"
    key_path = root / "private-receipt.key"
    _write_exclusive(corpus_path, _CORPUS, mode=0o600)
    key = os.urandom(32)
    _write_exclusive(key_path, key, mode=0o600)
    key_status = key_path.lstat()
    if (
        not stat.S_ISREG(key_status.st_mode)
        or stat.S_IMODE(key_status.st_mode) != 0o600
        or key_status.st_uid != os.geteuid()
        or key_status.st_nlink != 1
    ):
        _fail("private_key_policy_failed")
    arguments = ("receipt", str(corpus_path), "--key-file", str(key_path))
    first = _invoke(layout, arguments, cwd=root, env=env)
    second = _invoke(layout, arguments, cwd=root, env=env)
    through_path = _invoke(
        layout,
        arguments,
        cwd=root,
        env=env,
        through_path=True,
    )
    if (
        first.returncode != 0
        or second.returncode != 0
        or through_path.returncode != 0
        or first.stderr
        or second.stderr
        or through_path.stderr
        or first.stdout != second.stdout
        or first.stdout != through_path.stdout
    ):
        _fail("receipt_command_failed")
    _assert_no_private_output(
        first,
        (str(root).encode(), str(corpus_path).encode(), str(key_path).encode()),
    )
    _verify_receipt_document(first.stdout, key=key)
    return ReceiptEvidence(
        corpus=corpus_path,
        key=key_path,
        output=first.stdout,
    )


def _capture_public_demo(
    layout: InstalledLayout,
    *,
    root: Path,
    env: Mapping[str, str],
) -> PublicDemoEvidence:
    demo_root = root / "public-demo"
    try:
        demo_root.mkdir(mode=0o700)
    except OSError:
        _fail("public_demo_failed")
    corpus_path = demo_root / "documentation-corpus.txt"
    key_path = demo_root / "public-demo.key"
    _write_exclusive(corpus_path, _CORPUS, mode=0o600)
    _write_exclusive(key_path, _PUBLIC_DEMO_KEY, mode=0o600)
    try:
        key_status = key_path.lstat()
    except OSError:
        _fail("public_demo_failed")
    if (
        not stat.S_ISREG(key_status.st_mode)
        or stat.S_IMODE(key_status.st_mode) != 0o600
        or key_status.st_uid != os.geteuid()
        or key_status.st_nlink != 1
    ):
        _fail("public_demo_failed")

    version = _invoke(
        layout,
        ("--version",),
        cwd=demo_root,
        env=env,
        through_path=True,
    )
    receipt = _invoke(
        layout,
        ("receipt", corpus_path.name, "--key-file", key_path.name),
        cwd=demo_root,
        env=env,
        through_path=True,
    )
    if (
        version.returncode != 0
        or version.stdout != b"netveil-audit 0.3.0\n"
        or version.stderr
        or receipt.returncode != 0
        or receipt.stderr
    ):
        _fail("public_demo_failed")
    _assert_no_private_output(
        version,
        (str(root).encode(), str(corpus_path).encode(), str(key_path).encode()),
    )
    _assert_no_private_output(
        receipt,
        (str(root).encode(), str(corpus_path).encode(), str(key_path).encode()),
    )
    document = _verify_receipt_document(receipt.stdout, key=_PUBLIC_DEMO_KEY)
    try:
        version_stdout = version.stdout.decode("ascii")
    except UnicodeError:
        _fail("public_demo_failed")
    return PublicDemoEvidence(
        corpus_sha256=hashlib.sha256(_CORPUS).hexdigest(),
        corpus_size_bytes=len(_CORPUS),
        corpus_physical_lines=_CORPUS.count(b"\n"),
        public_key_sha256=hashlib.sha256(_PUBLIC_DEMO_KEY).hexdigest(),
        public_key_size_bytes=len(_PUBLIC_DEMO_KEY),
        version_stdout=version_stdout,
        receipt=document,
        receipt_stdout_sha256=hashlib.sha256(receipt.stdout).hexdigest(),
    )


def _strace_binary() -> Path:
    if not sys.platform.startswith("linux"):
        _fail("syscall_trace_unsupported")
    located = shutil.which(
        "strace",
        path="/usr/bin:/bin:/usr/sbin:/sbin",
    )
    if located is None:
        _fail("strace_unavailable")
    path = Path(located)
    try:
        status = path.lstat()
    except OSError:
        _fail("strace_unavailable")
    if (
        not stat.S_ISREG(status.st_mode)
        or not status.st_mode & stat.S_IXUSR
        or status.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        _fail("strace_unavailable")
    return path


def _read_trace_files(prefix: Path) -> tuple[bytes, ...]:
    paths = sorted(prefix.parent.glob(f"{prefix.name}.*"))
    if not paths:
        _fail("syscall_trace_missing")
    payloads: list[bytes] = []
    for path in paths:
        try:
            status = path.lstat()
            if (
                not stat.S_ISREG(status.st_mode)
                or status.st_size < 1
                or status.st_size > _MAX_PROCESS_OUTPUT_BYTES
            ):
                _fail("syscall_trace_invalid")
            payload = path.read_bytes()
        except OSError:
            _fail("syscall_trace_invalid")
        if len(payload) != status.st_size:
            _fail("syscall_trace_invalid")
        payloads.append(payload)
    return tuple(payloads)


def _validate_syscall_trace(
    payloads: Sequence[bytes],
    *,
    layout: InstalledLayout,
    label: str = "unit",
) -> TraceEvidence:
    if len(payloads) != 1:
        _fail("post_launch_process_detected")
    try:
        lines = payloads[0].decode("utf-8").splitlines()
    except UnicodeError:
        _fail("syscall_trace_invalid")
    if not lines:
        _fail("syscall_trace_invalid")
    exec_paths: list[str] = []
    exit_syscall_count = 0
    for line in lines:
        syscall = line.split("(", 1)[0].strip()
        if syscall == "execve":
            match = re.match(r'^execve\("([^"\\]+)"', line)
            if match is None or not line.rstrip().endswith("= 0"):
                _fail("exec_chain_invalid")
            exec_paths.append(match.group(1))
        elif syscall in ("exit", "exit_group"):
            exit_syscall_count += 1
        else:
            # The trace selector contains only process and network syscalls.
            # Anything else is therefore a fork/clone/wait or network action.
            _fail("network_or_process_activity_detected")
    expected = [str(layout.launcher), str(layout.python)]
    if exec_paths != expected or exit_syscall_count < 1:
        _fail("exec_chain_invalid")
    normalized = {
        "exec_chain": ["installed_launcher", "installed_python"],
        "exec_count": len(exec_paths),
        "exit_syscall_count": exit_syscall_count,
        "label": label,
        "network_syscall_count": 0,
        "post_launch_process_count": 0,
        "process_count": len(payloads),
    }
    return TraceEvidence(
        label=label,
        normalized_sha256=hashlib.sha256(_canonical_json(normalized)).hexdigest(),
        process_count=len(payloads),
        exec_chain=("installed_launcher", "installed_python"),
        exec_count=len(exec_paths),
        exit_syscall_count=exit_syscall_count,
        network_syscall_count=0,
        post_launch_process_count=0,
    )


def _trace_invocation(
    layout: InstalledLayout,
    arguments: Sequence[str],
    *,
    root: Path,
    env: Mapping[str, str],
    label: str,
    expected_stdout: bytes,
) -> TraceEvidence:
    prefix = root / f"syscall-trace-{label}"
    result = _run_process(
        (
            str(_strace_binary()),
            "-ff",
            "-qq",
            "-s",
            "256",
            "-e",
            "trace=network,process",
            "-o",
            str(prefix),
            "--",
            str(layout.launcher),
            *arguments,
        ),
        cwd=root,
        env=env,
    )
    if result.returncode != 0 or result.stdout != expected_stdout or result.stderr:
        _fail("traced_command_failed")
    _assert_no_private_output(result, (str(root).encode(),))
    return _validate_syscall_trace(
        _read_trace_files(prefix),
        layout=layout,
        label=label,
    )


def _verify_syscall_traces(
    layout: InstalledLayout,
    receipt: ReceiptEvidence,
    *,
    root: Path,
    env: Mapping[str, str],
) -> tuple[TraceEvidence, ...]:
    version = _trace_invocation(
        layout,
        ("--version",),
        root=root,
        env=env,
        label="version",
        expected_stdout=b"netveil-audit 0.3.0\n",
    )
    receipt_trace = _trace_invocation(
        layout,
        (
            "receipt",
            str(receipt.corpus),
            "--key-file",
            str(receipt.key),
        ),
        root=root,
        env=env,
        label="receipt",
        expected_stdout=receipt.output,
    )
    return (receipt_trace, version)


def _platform_evidence() -> PlatformEvidence:
    try:
        uname = os.uname()
    except (AttributeError, OSError):
        _fail("platform_unsupported")
    values = (sys.platform, uname.sysname, uname.release, uname.machine)
    if any(
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(ord(character) < 32 or ord(character) == 127 for character in value)
        for value in values
    ):
        _fail("platform_unsupported")
    return PlatformEvidence(
        sys_platform=sys.platform,
        system=uname.sysname,
        release=uname.release,
        machine=uname.machine,
    )


def _validate_source_commit(source_commit: str) -> None:
    if len(source_commit) != 40 or any(
        character not in _LOWER_HEX for character in source_commit
    ):
        _fail("source_commit_invalid")


def verify_wheel(
    path: Path,
    *,
    inventory_path: Path,
    sdist_path: Path,
    source_commit: str,
) -> VerificationSummary:
    """Run the complete offline fresh-wheel verification."""

    _validate_source_commit(source_commit)
    inventory = _parse_release_inventory(_read_exact_inventory(inventory_path))
    if inventory.source_commit != source_commit:
        _fail("inventory_source_commit_mismatch")
    wheel_payload = _read_exact_wheel(path)
    sdist_payload = _read_exact_sdist(sdist_path)
    _bind_release_inventory(
        inventory,
        expected_source_commit=source_commit,
        wheel_path=path,
        wheel_payload=wheel_payload,
        sdist_path=sdist_path,
        sdist_payload=sdist_payload,
    )
    sdist_members = _inspect_sdist(
        sdist_payload,
        source_date_epoch=inventory.source_date_epoch,
    )
    _bind_sdist_members(inventory, sdist_members)
    wheel = _inspect_wheel(wheel_payload)
    with tempfile.TemporaryDirectory(prefix="netveil-wheel-verifier-") as raw_root:
        root = Path(raw_root)
        layout = _create_fresh_install(root, wheel)
        environment = _base_environment(root, layout)
        _verify_user_commands(layout, root=root, env=environment)
        interpreter = _verify_isolation(layout, root=root, env=environment)
        _verify_bytecode_and_tamper(layout, root=root, env=environment)
        receipt = _verify_receipt(layout, root=root, env=environment)
        public_demo = _capture_public_demo(
            layout,
            root=root,
            env=environment,
        )
        syscall_traces = _verify_syscall_traces(
            layout,
            receipt,
            root=root,
            env=environment,
        )
        final_layout = _inspect_install(
            layout.prefix,
            layout.python,
            wheel.launcher,
        )
        installed = final_layout.evidence
        if installed is None:
            _fail("installed_layout_invalid")
    return VerificationSummary(
        source_commit=source_commit,
        release_inventory=inventory,
        installed=installed,
        interpreter=interpreter,
        platform=_platform_evidence(),
        syscall_traces=syscall_traces,
        public_demo=public_demo,
        wheel_sha256=wheel.sha256,
        wheel_size_bytes=len(wheel.payload),
        wheel_members=wheel.members,
    )


def _write_text(stream: object, payload: str) -> bool:
    writer = getattr(stream, "write", None)
    flusher = getattr(stream, "flush", None)
    if not callable(writer) or not callable(flusher):
        return False
    offset = 0
    try:
        while offset < len(payload):
            written = writer(payload[offset:])
            if (
                type(written) is not int
                or written <= 0
                or written > len(payload) - offset
            ):
                return False
            offset += written
        flusher()
    except OSError:
        return False
    return True


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point with stable, path-free output."""

    arguments = list(sys.argv[1:] if argv is None else argv)
    if arguments == ["--help"]:
        text = (
            "usage: verify_fresh_wheel.py --source-commit COMMIT "
            "--inventory release-inventory.json "
            "--sdist netveil_audit-0.3.0.tar.gz "
            "netveil_audit-0.3.0-py3-none-any.whl\n"
        )
        return 0 if _write_text(sys.stdout, text) else 70
    if (
        len(arguments) != 7
        or arguments[0] != "--source-commit"
        or arguments[2] != "--inventory"
        or arguments[3].startswith("-")
        or arguments[4] != "--sdist"
        or arguments[5].startswith("-")
        or arguments[6].startswith("-")
    ):
        _write_text(sys.stderr, "netveil-wheel-verifier: usage_error\n")
        return 2
    try:
        source_commit = arguments[1]
        _validate_source_commit(source_commit)
        summary = verify_wheel(
            Path(arguments[6]),
            inventory_path=Path(arguments[3]),
            sdist_path=Path(arguments[5]),
            source_commit=source_commit,
        )
        rendered = _canonical_json(summary.document()).decode("ascii") + "\n"
        return 0 if _write_text(sys.stdout, rendered) else 70
    except VerificationFailure as failure:
        _write_text(
            sys.stderr,
            f"netveil-wheel-verifier: {failure.code}\n",
        )
        return 1
    except Exception:  # noqa: BLE001 - the CLI boundary must redact all internals.
        _write_text(sys.stderr, "netveil-wheel-verifier: internal_error\n")
        return 70


if __name__ == "__main__":
    raise SystemExit(main())
