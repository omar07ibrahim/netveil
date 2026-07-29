#!/usr/bin/env python3
"""Build and normalize a deterministic Netveil release with the standard library.

The build backend owns wheel bytes: this helper copies the wheel byte-for-byte
and never opens or repacks it.  The setuptools sdist is treated as an untrusted
tar.gz container and rewritten into one canonical archive before publication.
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import tarfile
import tempfile
import zlib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Final, NoReturn

INVENTORY_SCHEMA: Final = "netveil.release-inventory.v1"
INVENTORY_FILENAME: Final = "release-inventory.json"

_MAX_COMPRESSED_SDIST_BYTES: Final = 128 * 1_048_576
_MAX_TAR_BYTES: Final = 256 * 1_048_576
_MAX_MEMBER_BYTES: Final = 64 * 1_048_576
_MAX_TOTAL_FILE_BYTES: Final = 192 * 1_048_576
_MAX_MEMBERS: Final = 20_000
_MAX_ARTIFACT_BYTES: Final = 512 * 1_048_576
_BUILD_TIMEOUT_SECONDS: Final = 10 * 60
_GIT_TIMEOUT_SECONDS: Final = 60
_MAX_GIT_OUTPUT_BYTES: Final = 1_048_576
_TAR_BLOCK_BYTES: Final = 512
_TAR_TRAILER_BYTES: Final = 2 * _TAR_BLOCK_BYTES
_GZIP_MAX_MTIME: Final = (1 << 32) - 1
_LOWER_HEX: Final = frozenset("0123456789abcdef")


class ReleaseBuildError(RuntimeError):
    """A stable release failure that does not disclose archive contents."""

    __slots__ = ("code",)

    code: str

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(f"netveil_release_error:{code}")


@dataclass(frozen=True, slots=True)
class _CanonicalMember:
    """One validated logical member ready for canonical tar serialization."""

    name: str
    payload: bytes | None
    executable: bool

    @property
    def is_directory(self) -> bool:
        return self.payload is None


def _fail(code: str) -> NoReturn:
    raise ReleaseBuildError(code)


def _validated_epoch(source_date_epoch: int) -> int:
    if (
        type(source_date_epoch) is not int
        or not 0 <= source_date_epoch <= _GZIP_MAX_MTIME
    ):
        _fail("source_date_epoch_invalid")
    return source_date_epoch


def _validated_source_commit(source_commit: str) -> str:
    if (
        type(source_commit) is not str
        or len(source_commit) != 40
        or any(character not in _LOWER_HEX for character in source_commit)
    ):
        _fail("source_commit_invalid")
    return source_commit


def _canonical_member_name(member: tarfile.TarInfo) -> str:
    raw_name = member.name
    if (
        type(raw_name) is not str
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


def _decompress_sdist(payload: bytes) -> bytes:
    if (
        type(payload) is not bytes
        or not 0 < len(payload) <= _MAX_COMPRESSED_SDIST_BYTES
    ):
        _fail("sdist_invalid")
    source = io.BytesIO(payload)
    try:
        with gzip.GzipFile(fileobj=source, mode="rb") as compressed:
            tar_payload = compressed.read(_MAX_TAR_BYTES + 1)
    except (EOFError, OSError, gzip.BadGzipFile, zlib.error):
        _fail("sdist_invalid")
    if (
        not 0 < len(tar_payload) <= _MAX_TAR_BYTES
        or len(tar_payload) % _TAR_BLOCK_BYTES
        or len(tar_payload) < _TAR_TRAILER_BYTES
    ):
        _fail("sdist_invalid")
    return tar_payload


def _read_members(tar_payload: bytes) -> tuple[_CanonicalMember, ...]:
    observed: dict[str, _CanonicalMember] = {}
    total_file_bytes = 0
    archive_offset = -1
    try:
        with tarfile.open(fileobj=io.BytesIO(tar_payload), mode="r:") as archive:
            members = archive.getmembers()
            archive_offset = archive.offset
            if not 1 <= len(members) <= _MAX_MEMBERS:
                _fail("sdist_invalid")
            for member in members:
                if not (member.isdir() or member.isreg()):
                    _fail("sdist_member_unsafe")
                if member.sparse is not None:
                    _fail("sdist_member_unsafe")
                name = _canonical_member_name(member)
                if name in observed:
                    _fail("sdist_member_duplicate")
                if member.isdir():
                    if member.size != 0:
                        _fail("sdist_member_unsafe")
                    observed[name] = _CanonicalMember(
                        name=name,
                        payload=None,
                        executable=True,
                    )
                    continue
                if not 0 <= member.size <= _MAX_MEMBER_BYTES:
                    _fail("sdist_member_unsafe")
                total_file_bytes += member.size
                if total_file_bytes > _MAX_TOTAL_FILE_BYTES:
                    _fail("sdist_invalid")
                extracted = archive.extractfile(member)
                if extracted is None:
                    _fail("sdist_invalid")
                content = extracted.read(_MAX_MEMBER_BYTES + 1)
                if len(content) != member.size:
                    _fail("sdist_invalid")
                observed[name] = _CanonicalMember(
                    name=name,
                    payload=content,
                    executable=bool(member.mode & 0o111),
                )
    except ReleaseBuildError:
        raise
    except (OSError, tarfile.TarError, UnicodeError, ValueError):
        _fail("sdist_invalid")

    if (
        archive_offset < 0
        or len(tar_payload) - archive_offset < _TAR_TRAILER_BYTES
        or any(tar_payload[archive_offset:])
    ):
        _fail("sdist_invalid")
    return tuple(observed[name] for name in sorted(observed))


def _serialize_tar(
    members: tuple[_CanonicalMember, ...],
    *,
    source_date_epoch: int,
) -> bytes:
    destination = io.BytesIO()
    try:
        with tarfile.open(
            fileobj=destination,
            mode="w:",
            format=tarfile.USTAR_FORMAT,
        ) as archive:
            for member in members:
                information = tarfile.TarInfo(
                    member.name + "/" if member.is_directory else member.name
                )
                information.type = (
                    tarfile.DIRTYPE if member.is_directory else tarfile.REGTYPE
                )
                information.size = 0 if member.payload is None else len(member.payload)
                information.mode = (
                    0o755 if member.is_directory or member.executable else 0o644
                )
                information.mtime = source_date_epoch
                information.uid = 0
                information.gid = 0
                information.uname = ""
                information.gname = ""
                information.linkname = ""
                information.pax_headers = {}
                archive.addfile(
                    information,
                    None if member.payload is None else io.BytesIO(member.payload),
                )
    except (OSError, tarfile.TarError, UnicodeError, ValueError):
        _fail("sdist_not_canonicalizable")
    return destination.getvalue()


def normalize_sdist_bytes(
    payload: bytes,
    *,
    source_date_epoch: int,
) -> bytes:
    """Return one canonical gzip-compressed USTAR sdist."""

    epoch = _validated_epoch(source_date_epoch)
    members = _read_members(_decompress_sdist(payload))
    canonical_tar = _serialize_tar(members, source_date_epoch=epoch)
    destination = io.BytesIO()
    try:
        with gzip.GzipFile(
            filename="",
            mode="wb",
            compresslevel=9,
            fileobj=destination,
            mtime=epoch,
        ) as compressed:
            compressed.write(canonical_tar)
    except (OSError, ValueError, zlib.error):
        _fail("sdist_not_canonicalizable")
    return destination.getvalue()


def _read_regular_file(path: Path, *, maximum: int) -> bytes:
    descriptor = -1
    try:
        descriptor = os.open(
            path,
            os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_nlink != 1
            or not 0 < before.st_size <= maximum
        ):
            _fail("artifact_invalid")
        chunks: list[bytes] = []
        consumed = 0
        while consumed < before.st_size:
            chunk = os.read(descriptor, min(1_048_576, before.st_size - consumed))
            if not chunk:
                _fail("artifact_invalid")
            chunks.append(chunk)
            consumed += len(chunk)
        after = os.fstat(descriptor)
        if consumed != before.st_size or (
            after.st_dev,
            after.st_ino,
            after.st_mode,
            after.st_size,
            after.st_mtime_ns,
            after.st_ctime_ns,
        ) != (
            before.st_dev,
            before.st_ino,
            before.st_mode,
            before.st_size,
            before.st_mtime_ns,
            before.st_ctime_ns,
        ):
            _fail("artifact_invalid")
        return b"".join(chunks)
    except ReleaseBuildError:
        raise
    except OSError:
        _fail("artifact_invalid")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def _write_new_file(path: Path, payload: bytes, *, mode: int = 0o644) -> None:
    descriptor = -1
    created = False
    try:
        descriptor = os.open(
            path,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC | os.O_NOFOLLOW,
            mode,
        )
        created = True
        offset = 0
        while offset < len(payload):
            written = os.write(descriptor, payload[offset:])
            if written <= 0:
                raise OSError
            offset += written
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        if stat.S_IMODE(os.fstat(descriptor).st_mode) != mode or os.fstat(
            descriptor
        ).st_size != len(payload):
            raise OSError
    except OSError:
        if created:
            try:
                path.unlink(missing_ok=True)
            except OSError:
                pass
        _fail("artifact_write_failed")
    finally:
        if descriptor >= 0:
            try:
                os.close(descriptor)
            except OSError:
                pass


def normalize_sdist(
    source: Path,
    destination: Path,
    *,
    source_date_epoch: int,
) -> None:
    """Normalize one sdist path into a new destination file."""

    if not source.name.endswith(".tar.gz") or destination.name != source.name:
        _fail("sdist_path_invalid")
    payload = _read_regular_file(source, maximum=_MAX_COMPRESSED_SDIST_BYTES)
    normalized = normalize_sdist_bytes(
        payload,
        source_date_epoch=source_date_epoch,
    )
    _write_new_file(destination, normalized)


def _sdist_member_inventory(payload: bytes) -> list[dict[str, object]]:
    members = _read_members(_decompress_sdist(payload))
    inventory: list[dict[str, object]] = []
    for member in members:
        if member.is_directory:
            inventory.append(
                {
                    "kind": "directory",
                    "mode": "0755",
                    "path": member.name,
                    "size_bytes": 0,
                }
            )
        else:
            assert member.payload is not None
            inventory.append(
                {
                    "kind": "file",
                    "mode": "0755" if member.executable else "0644",
                    "path": member.name,
                    "sha256": hashlib.sha256(member.payload).hexdigest(),
                    "size_bytes": len(member.payload),
                }
            )
    return inventory


def artifact_inventory(
    artifacts: Sequence[Path],
    *,
    source_date_epoch: int,
    source_commit: str,
) -> bytes:
    """Render canonical unsigned integrity evidence for release artifacts.

    The inventory binds artifact bytes to a builder-observed Git commit.  It is
    deliberately not represented as a signature or third-party attestation.
    """

    epoch = _validated_epoch(source_date_epoch)
    commit = _validated_source_commit(source_commit)
    records: dict[str, dict[str, object]] = {}
    for path in artifacts:
        if not isinstance(path, Path):
            _fail("artifact_invalid")
        name = path.name
        if not name or name in records or PurePosixPath(name).name != name:
            _fail("artifact_invalid")
        if name.endswith(".whl"):
            kind = "wheel"
        elif name.endswith(".tar.gz"):
            kind = "sdist"
        else:
            _fail("artifact_invalid")
        payload = _read_regular_file(path, maximum=_MAX_ARTIFACT_BYTES)
        record: dict[str, object] = {
            "filename": name,
            "kind": kind,
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size_bytes": len(payload),
        }
        if kind == "sdist":
            record["members"] = _sdist_member_inventory(payload)
        records[name] = record
    if len(records) != 2 or {record["kind"] for record in records.values()} != {
        "wheel",
        "sdist",
    }:
        _fail("artifact_invalid")
    document = {
        "artifacts": [records[name] for name in sorted(records)],
        "schema": INVENTORY_SCHEMA,
        "source_commit": commit,
        "source_date_epoch": epoch,
    }
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            allow_nan=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("ascii")
        + b"\n"
    )


def sanitized_build_environment(
    *,
    source_date_epoch: int,
    home: Path,
) -> Mapping[str, str]:
    """Return the complete, minimal environment used for the backend process."""

    epoch = _validated_epoch(source_date_epoch)
    if not home.is_absolute():
        _fail("build_path_invalid")
    return {
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
        "PIP_DISABLE_PIP_VERSION_CHECK": "1",
        "PIP_NO_INDEX": "1",
        "PYTHONDONTWRITEBYTECODE": "1",
        "PYTHONHASHSEED": "0",
        "PYTHONNOUSERSITE": "1",
        "SOURCE_DATE_EPOCH": str(epoch),
        "TZ": "UTC",
    }


def _git_binary() -> Path:
    located = shutil.which("git", path=os.defpath)
    if located is None:
        _fail("git_unavailable")
    try:
        path = Path(located).resolve(strict=True)
        status = path.stat()
    except (OSError, RuntimeError):
        _fail("git_unavailable")
    if (
        not stat.S_ISREG(status.st_mode)
        or not status.st_mode & stat.S_IXUSR
        or status.st_mode & (stat.S_ISUID | stat.S_ISGID)
    ):
        _fail("git_unavailable")
    return path


def _git_environment(home: Path) -> Mapping[str, str]:
    if not home.is_absolute():
        _fail("build_path_invalid")
    return {
        "GIT_CONFIG_GLOBAL": os.devnull,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_OPTIONAL_LOCKS": "0",
        "GIT_TERMINAL_PROMPT": "0",
        "HOME": str(home),
        "LANG": "C",
        "LC_ALL": "C",
        "PATH": os.defpath,
    }


def _run_git(
    project: Path,
    home: Path,
    arguments: Sequence[str],
) -> bytes:
    try:
        completed = subprocess.run(
            (str(_git_binary()), *arguments),
            cwd=project,
            env=dict(_git_environment(home)),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=False,
            timeout=_GIT_TIMEOUT_SECONDS,
        )
    except (OSError, subprocess.TimeoutExpired):
        _fail("source_repository_invalid")
    if completed.returncode != 0 or len(completed.stdout) > _MAX_GIT_OUTPUT_BYTES:
        _fail("source_repository_invalid")
    return completed.stdout


def _git_source_commit(project: Path, home: Path) -> str:
    top_level_payload = _run_git(
        project,
        home,
        ("rev-parse", "--show-toplevel"),
    )
    try:
        top_level_text = top_level_payload.decode(sys.getfilesystemencoding())
        top_level = Path(top_level_text.removesuffix("\n")).resolve(strict=True)
    except (OSError, RuntimeError, UnicodeError):
        _fail("source_repository_invalid")
    if (
        not top_level_payload.endswith(b"\n")
        or top_level_payload.endswith(b"\n\n")
        or top_level != project
    ):
        _fail("source_repository_invalid")

    commit_payload = _run_git(
        project,
        home,
        ("rev-parse", "--verify", "HEAD^{commit}"),
    )
    try:
        commit = commit_payload.decode("ascii").removesuffix("\n")
    except UnicodeError:
        _fail("source_repository_invalid")
    if (
        not commit_payload.endswith(b"\n")
        or commit_payload.endswith(b"\n\n")
        or len(commit_payload) != 41
    ):
        _fail("source_repository_invalid")
    try:
        validated_commit = _validated_source_commit(commit)
    except ReleaseBuildError:
        _fail("source_repository_invalid")

    status = _run_git(
        project,
        home,
        ("status", "--porcelain=v1", "--untracked-files=all"),
    )
    if status:
        _fail("worktree_dirty")
    return validated_commit


def _materialize_source_snapshot(
    archive_payload: bytes,
    destination: Path,
) -> None:
    members = _read_members(archive_payload)
    if not members:
        _fail("source_archive_invalid")
    try:
        destination.mkdir(mode=0o700)
        for member in members:
            path = destination / member.name
            if member.is_directory:
                path.mkdir(mode=0o755, parents=True, exist_ok=False)
            else:
                path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
                assert member.payload is not None
                _write_new_file(
                    path,
                    member.payload,
                    mode=0o755 if member.executable else 0o644,
                )
    except ReleaseBuildError:
        raise
    except OSError:
        _fail("source_archive_invalid")


def _export_clean_head(
    project: Path,
    destination: Path,
    archive_path: Path,
    home: Path,
) -> str:
    commit = _git_source_commit(project, home)
    if (
        destination.exists()
        or archive_path.exists()
        or destination.is_relative_to(project)
        or archive_path.is_relative_to(project)
    ):
        _fail("build_path_invalid")
    _run_git(
        project,
        home,
        (
            "archive",
            "--format=tar",
            f"--output={archive_path}",
            commit,
        ),
    )
    archive_payload = _read_regular_file(
        archive_path,
        maximum=_MAX_TAR_BYTES,
    )
    _materialize_source_snapshot(archive_payload, destination)
    try:
        archive_path.unlink()
    except OSError:
        _fail("source_archive_invalid")
    return commit


def _backend_artifacts(directory: Path) -> tuple[Path, Path]:
    try:
        entries = tuple(sorted(directory.iterdir(), key=lambda path: path.name))
    except OSError:
        _fail("backend_output_invalid")
    if len(entries) != 2 or any(
        entry.is_symlink() or not entry.is_file() for entry in entries
    ):
        _fail("backend_output_invalid")
    wheels = tuple(path for path in entries if path.name.endswith(".whl"))
    sdists = tuple(path for path in entries if path.name.endswith(".tar.gz"))
    if len(wheels) != 1 or len(sdists) != 1:
        _fail("backend_output_invalid")
    return wheels[0], sdists[0]


def _build_python_path(python_executable: Path | None) -> Path:
    """Keep a virtual-environment launcher path without dereferencing it."""

    candidate = Path(sys.executable) if python_executable is None else python_executable
    try:
        python = Path(os.path.abspath(candidate))
    except (OSError, TypeError, ValueError):
        _fail("build_path_invalid")
    if not python.is_absolute() or not python.is_file():
        _fail("build_path_invalid")
    return python


def build_release(
    project_root: Path,
    output_directory: Path,
    *,
    source_date_epoch: int,
    python_executable: Path | None = None,
) -> bytes:
    """Run the backend once and atomically publish wheel, sdist, and inventory."""

    epoch = _validated_epoch(source_date_epoch)
    try:
        project = project_root.resolve(strict=True)
        output = output_directory.resolve(strict=False)
    except (OSError, RuntimeError):
        _fail("build_path_invalid")
    if (
        not project.is_dir()
        or not output.is_absolute()
        or output.exists()
        or output.is_symlink()
        or output == project
        or output.is_relative_to(project)
    ):
        _fail("build_path_invalid")
    python = _build_python_path(python_executable)
    try:
        with tempfile.TemporaryDirectory(
            prefix="netveil-build-",
        ) as temporary:
            workspace = Path(temporary)
            backend = workspace / "backend"
            home = workspace / "home"
            source = workspace / "source"
            archive_path = workspace / "source.tar"
            for directory in (backend, home):
                directory.mkdir(mode=0o700)
            source_commit = _export_clean_head(
                project,
                source,
                archive_path,
                home,
            )
            command = (
                str(python),
                "-m",
                "build",
                "--no-isolation",
                "--outdir",
                str(backend),
                str(source),
            )
            try:
                completed = subprocess.run(
                    command,
                    cwd=source,
                    env=dict(
                        sanitized_build_environment(
                            source_date_epoch=epoch,
                            home=home,
                        )
                    ),
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    check=False,
                    timeout=_BUILD_TIMEOUT_SECONDS,
                )
            except (OSError, subprocess.TimeoutExpired):
                _fail("backend_failed")
            if completed.returncode != 0:
                _fail("backend_failed")
            if _git_source_commit(project, home) != source_commit:
                _fail("source_commit_changed")
            wheel, sdist = _backend_artifacts(backend)
            output.parent.mkdir(parents=True, exist_ok=True)
            if output.exists() or output.is_symlink():
                _fail("build_path_invalid")
            with tempfile.TemporaryDirectory(
                prefix=f".{output.name}.publish-",
                dir=output.parent,
            ) as publication_temporary:
                release = Path(publication_temporary) / "release"
                release.mkdir(mode=0o700)
                wheel_payload = _read_regular_file(
                    wheel,
                    maximum=_MAX_ARTIFACT_BYTES,
                )
                _write_new_file(release / wheel.name, wheel_payload)
                normalize_sdist(
                    sdist,
                    release / sdist.name,
                    source_date_epoch=epoch,
                )
                inventory = artifact_inventory(
                    (release / wheel.name, release / sdist.name),
                    source_date_epoch=epoch,
                    source_commit=source_commit,
                )
                _write_new_file(release / INVENTORY_FILENAME, inventory)
                os.rename(release, output)
                return inventory
    except ReleaseBuildError:
        raise
    except OSError:
        _fail("artifact_write_failed")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Build a wheel and canonical sdist without dependency isolation, "
            "then emit deterministic SHA-256 inventory evidence."
        )
    )
    parser.add_argument("project_root", type=Path)
    parser.add_argument("output_directory", type=Path)
    parser.add_argument(
        "--source-date-epoch",
        type=int,
        required=True,
    )
    parser.add_argument("--python", type=Path)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(argv)
    try:
        inventory = build_release(
            namespace.project_root,
            namespace.output_directory,
            source_date_epoch=namespace.source_date_epoch,
            python_executable=namespace.python,
        )
    except ReleaseBuildError as error:
        print(str(error), file=sys.stderr)
        return 2
    sys.stdout.buffer.write(inventory)
    sys.stdout.buffer.flush()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
