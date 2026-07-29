"""Fail-closed command-line boundary for installed Netveil artifacts."""

from __future__ import annotations

import argparse
import hmac
import os
import stat
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from enum import IntEnum
from pathlib import Path
from typing import Any, BinaryIO, Final, NoReturn, TextIO

from netveil.parser import MAX_INPUT_BYTES, EndpointParseError, parse_corpus
from netveil.privacy import (
    MIN_PSEUDONYMIZATION_KEY_BYTES,
    build_privacy_receipt,
)

_DISTRIBUTION_NAME: Final = "netveil-audit"
_DISTRIBUTION_VERSION: Final = "0.3.0"
_MAX_KEY_BYTES: Final = 4_096


class CliExitCode(IntEnum):
    """Stable process exit codes for automation."""

    SUCCESS = 0
    USAGE = 2
    ARTIFACT_UNVERIFIED = 10
    CORPUS_UNAVAILABLE = 11
    KEY_UNAVAILABLE = 12
    CORPUS_REJECTED = 13
    KEY_REJECTED = 14
    OUTPUT_FAILED = 15
    INTERNAL_ERROR = 70


class _CliFailure(Exception):
    def __init__(self, code: str, exit_code: CliExitCode) -> None:
        super().__init__(code)
        self.code = code
        self.exit_code = exit_code


class _CliCompletion(Exception):
    def __init__(self, exit_code: CliExitCode) -> None:
        super().__init__(int(exit_code))
        self.exit_code = exit_code


@dataclass(frozen=True, slots=True)
class _ReadFile:
    payload: bytes
    device: int
    inode: int


class _SafeArgumentParser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        del message
        raise _CliFailure("usage_error", CliExitCode.USAGE)

    def _print_message(
        self,
        message: str | None,
        file: Any | None = None,
    ) -> None:
        if message and not _write_text(file or sys.stderr, message):
            raise _CliFailure("output_failed", CliExitCode.OUTPUT_FAILED)

    def exit(self, status: int = 0, message: str | None = None) -> NoReturn:
        if message is not None:
            self._print_message(
                message,
                sys.stdout if status == 0 else sys.stderr,
            )
        if status == 0:
            raise _CliCompletion(CliExitCode.SUCCESS)
        raise _CliFailure("usage_error", CliExitCode.USAGE)


def _fail(code: str, exit_code: CliExitCode) -> NoReturn:
    raise _CliFailure(code, exit_code)


def _open_flags() -> int:
    required_flags = ("O_CLOEXEC", "O_NOCTTY", "O_NOFOLLOW", "O_NONBLOCK")
    if os.name != "posix" or any(not hasattr(os, name) for name in required_flags):
        _fail("platform_unsupported", CliExitCode.INTERNAL_ERROR)
    return os.O_RDONLY | os.O_CLOEXEC | os.O_NOCTTY | os.O_NOFOLLOW | os.O_NONBLOCK


def _file_identity(status: os.stat_result) -> tuple[int, ...]:
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


def _read_open_file(
    descriptor: int,
    *,
    maximum_bytes: int,
) -> tuple[bytes | None, os.stat_result | None, os.stat_result | None]:
    before: os.stat_result | None = None
    after: os.stat_result | None = None
    payload: bytes | None = None
    operation_failed = False
    try:
        before = os.fstat(descriptor)
        if stat.S_ISREG(before.st_mode) and before.st_size <= maximum_bytes:
            chunks: list[bytes] = []
            observed = 0
            while observed <= maximum_bytes:
                chunk = os.read(
                    descriptor,
                    min(65_536, maximum_bytes + 1 - observed),
                )
                if not chunk:
                    break
                chunks.append(chunk)
                observed += len(chunk)
            payload = b"".join(chunks)
            after = os.fstat(descriptor)
    except OSError:
        operation_failed = True
    if operation_failed:
        return None, None, None
    return payload, before, after


def _read_bounded_file(
    path: Path,
    *,
    maximum_bytes: int,
    failure_code: str,
    failure_exit: CliExitCode,
    key_policy: bool,
) -> _ReadFile:
    descriptor: int | None = None
    open_failed = False
    try:
        descriptor = os.open(path, _open_flags())
    except OSError:
        open_failed = True
    if open_failed or descriptor is None:
        _fail(failure_code, failure_exit)

    payload: bytes | None = None
    before: os.stat_result | None = None
    after: os.stat_result | None = None
    close_failed = False
    try:
        payload, before, after = _read_open_file(
            descriptor,
            maximum_bytes=maximum_bytes,
        )
    finally:
        try:
            os.close(descriptor)
        except OSError:
            close_failed = True

    if (
        close_failed
        or payload is None
        or before is None
        or after is None
        or not stat.S_ISREG(before.st_mode)
        or len(payload) > maximum_bytes
        or len(payload) != after.st_size
        or _file_identity(before) != _file_identity(after)
    ):
        _fail(failure_code, failure_exit)

    if key_policy and (
        len(payload) < MIN_PSEUDONYMIZATION_KEY_BYTES
        or before.st_uid != os.geteuid()
        or before.st_nlink != 1
        or not before.st_mode & stat.S_IRUSR
        or before.st_mode
        & (
            stat.S_IRWXG
            | stat.S_IRWXO
            | stat.S_IXUSR
            | stat.S_ISUID
            | stat.S_ISGID
            | stat.S_ISVTX
        )
    ):
        _fail("key_rejected", CliExitCode.KEY_REJECTED)
    return _ReadFile(
        payload=payload,
        device=before.st_dev,
        inode=before.st_ino,
    )


def _parser(version: str) -> _SafeArgumentParser:
    parser = _SafeArgumentParser(
        prog="netveil-audit",
        description="Create an offline pseudonymized endpoint-corpus receipt.",
        allow_abbrev=False,
    )
    parser.add_argument(
        "--version",
        action="store_true",
        help="print the verified installed distribution version",
    )
    subparsers = parser.add_subparsers(dest="command")
    receipt = subparsers.add_parser(
        "receipt",
        help="write one canonical public receipt to standard output",
        allow_abbrev=False,
    )
    receipt.add_argument("corpus", type=Path, metavar="CORPUS")
    receipt.add_argument(
        "--key-file",
        required=True,
        type=Path,
        metavar="KEY_FILE",
    )
    parser.set_defaults(distribution_version=version)
    return parser


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


def _write_binary(stream: BinaryIO, payload: bytes) -> bool:
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
    except (BrokenPipeError, OSError):
        return False
    return True


def _emit_failure(failure: _CliFailure) -> int:
    if not _write_text(sys.stderr, f"netveil-audit: {failure.code}\n"):
        return int(CliExitCode.OUTPUT_FAILED)
    return int(failure.exit_code)


def _write_receipt(payload: bytes) -> None:
    if not _write_binary(sys.stdout.buffer, payload + b"\n"):
        _fail("output_failed", CliExitCode.OUTPUT_FAILED)


def _run_receipt(corpus_path: Path, key_path: Path) -> None:
    corpus_file = _read_bounded_file(
        corpus_path,
        maximum_bytes=MAX_INPUT_BYTES,
        failure_code="corpus_unavailable",
        failure_exit=CliExitCode.CORPUS_UNAVAILABLE,
        key_policy=False,
    )
    parse_failure: str | None = None
    try:
        parse_corpus(corpus_file.payload)
    except EndpointParseError as error:
        location = "" if error.line_number is None else f":line={error.line_number}"
        parse_failure = f"corpus_rejected:{error.code.value}{location}"
    if parse_failure is not None:
        _fail(
            parse_failure,
            CliExitCode.CORPUS_REJECTED,
        )

    key_file = _read_bounded_file(
        key_path,
        maximum_bytes=_MAX_KEY_BYTES,
        failure_code="key_unavailable",
        failure_exit=CliExitCode.KEY_UNAVAILABLE,
        key_policy=True,
    )
    if (corpus_file.device, corpus_file.inode) == (key_file.device, key_file.inode) or (
        len(corpus_file.payload) == len(key_file.payload)
        and hmac.compare_digest(corpus_file.payload, key_file.payload)
    ):
        _fail("key_rejected", CliExitCode.KEY_REJECTED)
    receipt = build_privacy_receipt(
        corpus_file.payload,
        pseudonymization_key=key_file.payload,
    )
    _write_receipt(receipt.canonical_json_bytes())


def _main_verified(
    argv: Sequence[str] | None = None,
    *,
    verified_distribution_version: str | None = None,
) -> int:
    """Run only after the external bootstrap has verified source bytes."""

    try:
        if verified_distribution_version != _DISTRIBUTION_VERSION:
            _fail("artifact_unverified", CliExitCode.ARTIFACT_UNVERIFIED)
        raw_arguments = tuple(sys.argv[1:] if argv is None else argv)
        if "--version" in raw_arguments and raw_arguments != ("--version",):
            _fail("usage_error", CliExitCode.USAGE)
        key_option_count = sum(
            argument == "--key-file" or argument.startswith("--key-file=")
            for argument in raw_arguments
        )
        if key_option_count > 1 or "--key-file=" in raw_arguments:
            _fail("usage_error", CliExitCode.USAGE)
        arguments = _parser(verified_distribution_version).parse_args(raw_arguments)
        if arguments.version:
            if not _write_text(
                sys.stdout,
                f"{_DISTRIBUTION_NAME} {verified_distribution_version}\n",
            ):
                _fail("output_failed", CliExitCode.OUTPUT_FAILED)
            return int(CliExitCode.SUCCESS)
        if arguments.command != "receipt":
            _fail("usage_error", CliExitCode.USAGE)
        _run_receipt(arguments.corpus, arguments.key_file)
    except _CliCompletion as completion:
        return int(completion.exit_code)
    except _CliFailure as failure:
        return _emit_failure(failure)
    except KeyboardInterrupt:
        return _emit_failure(_CliFailure("interrupted", CliExitCode.INTERNAL_ERROR))
    except Exception:  # noqa: BLE001 - CLI must never render sensitive tracebacks.
        return _emit_failure(_CliFailure("internal_error", CliExitCode.INTERNAL_ERROR))
    return int(CliExitCode.SUCCESS)
