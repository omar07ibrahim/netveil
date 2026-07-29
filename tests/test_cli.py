from __future__ import annotations

import hashlib
import io
import json
import os
import socket
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from typing import TextIO, cast
from unittest.mock import patch

from netveil import (
    MIN_PSEUDONYMIZATION_KEY_BYTES,
    build_privacy_receipt,
    cli,
)
from netveil.cli import CliExitCode

_DEMO_KEY = bytes(range(MIN_PSEUDONYMIZATION_KEY_BYTES))
_DEMO_CORPUS = (
    b"# IETF documentation ranges only\n"
    b"192.0.2.10:443\n"
    b"192.0.2.10:443\n"
    b"[2001:db8::10]:8443\n"
)


class _CapturedStdout:
    def __init__(self) -> None:
        self.buffer = io.BytesIO()
        self.text = io.StringIO()

    def write(self, value: str) -> int:
        return self.text.write(value)

    def flush(self) -> None:
        self.text.flush()
        self.buffer.flush()


def _write(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.write_bytes(payload)
    path.chmod(mode)


class CliWorkflowTests(unittest.TestCase):
    def _run_main(self, arguments: list[str] | None) -> tuple[int, bytes, str, str]:
        stdout = _CapturedStdout()
        stderr = io.StringIO()
        with (
            patch.object(sys, "stdout", cast(TextIO, stdout)),
            patch.object(sys, "stderr", stderr),
        ):
            result = cli._main_verified(
                arguments,
                verified_distribution_version=cli._DISTRIBUTION_VERSION,
            )
        return (
            result,
            stdout.buffer.getvalue(),
            stdout.text.getvalue(),
            stderr.getvalue(),
        )

    def test_receipt_command_emits_exact_public_bytes_without_network(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = root / "private-corpus.txt"
            key_path = root / "private-key.bin"
            _write(corpus_path, _DEMO_CORPUS)
            _write(key_path, _DEMO_KEY)

            with (
                patch.object(
                    socket,
                    "socket",
                    side_effect=AssertionError("network"),
                ),
                patch.object(
                    socket,
                    "getaddrinfo",
                    side_effect=AssertionError("resolution"),
                ),
                patch.object(
                    subprocess,
                    "Popen",
                    side_effect=AssertionError("process"),
                ),
                patch.object(
                    subprocess,
                    "run",
                    side_effect=AssertionError("process"),
                ),
            ):
                result, binary_output, text_output, error_output = self._run_main(
                    [
                        "receipt",
                        str(corpus_path),
                        "--key-file",
                        str(key_path),
                    ]
                )

        expected = build_privacy_receipt(
            _DEMO_CORPUS,
            pseudonymization_key=_DEMO_KEY,
        ).canonical_json_bytes()
        self.assertEqual(result, CliExitCode.SUCCESS)
        self.assertEqual(binary_output, expected + b"\n")
        self.assertEqual(text_output, "")
        self.assertEqual(error_output, "")
        document = json.loads(binary_output)
        self.assertEqual(document["schema"], "netveil.aggregate-receipt.v1")
        self.assertNotIn("192.0.2.10", binary_output.decode())
        self.assertNotIn(_DEMO_KEY.hex(), binary_output.decode())
        self.assertNotIn(
            hashlib.sha256(_DEMO_CORPUS).hexdigest(), binary_output.decode()
        )

    def test_version_is_bound_to_verified_distribution(self) -> None:
        result, binary_output, text_output, error_output = self._run_main(["--version"])
        self.assertEqual(result, CliExitCode.SUCCESS)
        self.assertEqual(binary_output, b"")
        self.assertEqual(text_output, "netveil-audit 0.3.0\n")
        self.assertEqual(error_output, "")
        with patch.object(sys, "argv", ["netveil-audit", "--version"]):
            result, binary_output, text_output, error_output = self._run_main(None)
        self.assertEqual(result, CliExitCode.SUCCESS)
        self.assertEqual(binary_output, b"")
        self.assertEqual(text_output, "netveil-audit 0.3.0\n")
        self.assertEqual(error_output, "")

    def test_version_cannot_bypass_or_mix_with_a_workflow(self) -> None:
        marker = "PRIVATE-VERSION-MIX-MARKER"
        for arguments in (
            ["--version", "--version"],
            ["--version", f"--unknown={marker}"],
            [
                "--version",
                "receipt",
                f"{marker}-corpus",
                "--key-file",
                f"{marker}-key",
            ],
        ):
            with self.subTest(arguments=arguments):
                result, binary, text, error = self._run_main(arguments)
                self.assertEqual(result, CliExitCode.USAGE)
                self.assertEqual(binary, b"")
                self.assertEqual(text, "")
                self.assertEqual(error, "netveil-audit: usage_error\n")
                self.assertNotIn(marker, error)

    def test_key_option_must_appear_exactly_once(self) -> None:
        marker = "PRIVATE-REPEATED-KEY-MARKER"
        for arguments in (
            [
                "receipt",
                f"{marker}-corpus",
                "--key-file",
                f"{marker}-first",
                "--key-file",
                f"{marker}-second",
            ],
            [
                "receipt",
                f"{marker}-corpus",
                f"--key-file={marker}-first",
                "--key-file",
                f"{marker}-second",
            ],
            ["receipt", f"{marker}-corpus", "--key-file="],
        ):
            with self.subTest(arguments=arguments):
                result, binary, text, error = self._run_main(arguments)
                self.assertEqual(result, CliExitCode.USAGE)
                self.assertEqual(binary, b"")
                self.assertEqual(text, "")
                self.assertEqual(error, "netveil-audit: usage_error\n")
                self.assertNotIn(marker, error)

    def test_long_options_cannot_be_abbreviated(self) -> None:
        marker = "PRIVATE-ABBREVIATION-MARKER"
        for arguments in (
            ["--ver"],
            ["receipt", f"{marker}-corpus", "--key-f", f"{marker}-key"],
        ):
            with self.subTest(arguments=arguments):
                result, binary, text, error = self._run_main(arguments)
                self.assertEqual(result, CliExitCode.USAGE)
                self.assertEqual(binary, b"")
                self.assertEqual(text, "")
                self.assertEqual(error, "netveil-audit: usage_error\n")
                self.assertNotIn(marker, error)

    def test_invalid_corpus_is_rejected_before_key_access_without_echo(self) -> None:
        marker = "PRIVATE-ENDPOINT-MARKER"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = root / f"{marker}-corpus.txt"
            missing_key = root / f"{marker}-missing-key.bin"
            _write(corpus_path, f"{marker}:443\n".encode())

            result, binary_output, text_output, error_output = self._run_main(
                [
                    "receipt",
                    str(corpus_path),
                    "--key-file",
                    str(missing_key),
                ]
            )

        self.assertEqual(result, CliExitCode.CORPUS_REJECTED)
        self.assertEqual(binary_output, b"")
        self.assertEqual(text_output, "")
        self.assertEqual(
            error_output,
            "netveil-audit: corpus_rejected:invalid_address:line=1\n",
        )
        self.assertNotIn(marker, error_output)

    def test_empty_corpus_error_has_no_synthetic_line_number(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = root / "empty.txt"
            _write(corpus_path, b"")

            result, _, _, error_output = self._run_main(
                [
                    "receipt",
                    str(corpus_path),
                    "--key-file",
                    str(root / "unused-key"),
                ]
            )

        self.assertEqual(result, CliExitCode.CORPUS_REJECTED)
        self.assertEqual(
            error_output,
            "netveil-audit: corpus_rejected:empty_corpus\n",
        )

    def test_key_access_and_permission_failures_are_stable_and_redacted(self) -> None:
        marker = "PRIVATE-KEY-PATH"
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = root / "corpus.txt"
            _write(corpus_path, _DEMO_CORPUS)

            missing_key = root / f"{marker}-missing"
            result, _, _, error_output = self._run_main(
                [
                    "receipt",
                    str(corpus_path),
                    "--key-file",
                    str(missing_key),
                ]
            )
            self.assertEqual(result, CliExitCode.KEY_UNAVAILABLE)
            self.assertEqual(error_output, "netveil-audit: key_unavailable\n")
            self.assertNotIn(marker, error_output)

            insecure_key = root / f"{marker}-insecure"
            _write(insecure_key, _DEMO_KEY, 0o644)
            result, _, _, error_output = self._run_main(
                [
                    "receipt",
                    str(corpus_path),
                    "--key-file",
                    str(insecure_key),
                ]
            )
            self.assertEqual(result, CliExitCode.KEY_REJECTED)
            self.assertEqual(error_output, "netveil-audit: key_rejected\n")
            self.assertNotIn(marker, error_output)

    def test_corpus_cannot_be_reused_or_copied_as_its_own_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = root / "corpus.txt"
            copied_key_path = root / "copied-key.bin"
            _write(corpus_path, _DEMO_CORPUS)
            _write(copied_key_path, _DEMO_CORPUS)

            for key_path in (corpus_path, copied_key_path):
                with self.subTest(key_path=key_path.name):
                    result, binary, text, error = self._run_main(
                        [
                            "receipt",
                            str(corpus_path),
                            "--key-file",
                            str(key_path),
                        ]
                    )
                    self.assertEqual(result, CliExitCode.KEY_REJECTED)
                    self.assertEqual(binary, b"")
                    self.assertEqual(text, "")
                    self.assertEqual(error, "netveil-audit: key_rejected\n")

    def test_usage_failure_never_echoes_unrecognized_argument(self) -> None:
        marker = "PRIVATE-COMMAND-LINE-MARKER"
        result, binary_output, text_output, error_output = self._run_main(
            [f"--unknown={marker}"]
        )
        self.assertEqual(result, CliExitCode.USAGE)
        self.assertEqual(binary_output, b"")
        self.assertEqual(text_output, "")
        self.assertEqual(error_output, "netveil-audit: usage_error\n")
        self.assertNotIn(marker, error_output)

    def test_missing_command_is_a_stable_usage_failure(self) -> None:
        result, _, _, error_output = self._run_main([])
        self.assertEqual(result, CliExitCode.USAGE)
        self.assertEqual(error_output, "netveil-audit: usage_error\n")

    def test_help_returns_success_without_leaving_main(self) -> None:
        result, binary_output, text_output, error_output = self._run_main(["--help"])
        self.assertEqual(result, CliExitCode.SUCCESS)
        self.assertEqual(binary_output, b"")
        self.assertIn("usage: netveil-audit", text_output)
        self.assertEqual(error_output, "")

    def test_artifact_failure_happens_before_argument_or_path_handling(self) -> None:
        marker = "PRIVATE-PATH-MARKER"
        stdout = _CapturedStdout()
        stderr = io.StringIO()
        with (
            patch.object(sys, "stdout", cast(TextIO, stdout)),
            patch.object(sys, "stderr", stderr),
        ):
            result = cli._main_verified([f"--unknown={marker}"])
        self.assertEqual(result, CliExitCode.ARTIFACT_UNVERIFIED)
        self.assertEqual(stderr.getvalue(), "netveil-audit: artifact_unverified\n")
        self.assertNotIn(marker, stderr.getvalue())

    def test_unexpected_failure_and_interrupt_are_redacted(self) -> None:
        for failure, expected in (
            (RuntimeError("PRIVATE-INTERNAL-MARKER"), "internal_error"),
            (KeyboardInterrupt(), "interrupted"),
        ):
            with self.subTest(expected=expected):
                stdout = _CapturedStdout()
                stderr = io.StringIO()
                with (
                    patch.object(
                        cli,
                        "_parser",
                        side_effect=failure,
                    ),
                    patch.object(sys, "stdout", cast(TextIO, stdout)),
                    patch.object(sys, "stderr", stderr),
                ):
                    result = cli._main_verified(
                        [],
                        verified_distribution_version=cli._DISTRIBUTION_VERSION,
                    )
                self.assertEqual(result, CliExitCode.INTERNAL_ERROR)
                self.assertEqual(stderr.getvalue(), f"netveil-audit: {expected}\n")
                self.assertNotIn("PRIVATE-INTERNAL-MARKER", stderr.getvalue())

    def test_output_failure_is_redacted(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            corpus_path = root / "corpus.txt"
            key_path = root / "key.bin"
            _write(corpus_path, _DEMO_CORPUS)
            _write(key_path, _DEMO_KEY)
            stderr = io.StringIO()
            stdout = _CapturedStdout()
            with (
                patch.object(
                    stdout.buffer,
                    "write",
                    side_effect=BrokenPipeError("PRIVATE-OUTPUT-MARKER"),
                ),
                patch.object(sys, "stdout", cast(TextIO, stdout)),
                patch.object(sys, "stderr", stderr),
            ):
                result = cli._main_verified(
                    [
                        "receipt",
                        str(corpus_path),
                        "--key-file",
                        str(key_path),
                    ],
                    verified_distribution_version=cli._DISTRIBUTION_VERSION,
                )
        self.assertEqual(result, CliExitCode.OUTPUT_FAILED)
        self.assertEqual(stderr.getvalue(), "netveil-audit: output_failed\n")
        self.assertNotIn("PRIVATE-OUTPUT-MARKER", stderr.getvalue())

    def test_short_version_write_is_an_output_failure(self) -> None:
        stdout = _CapturedStdout()
        stderr = io.StringIO()
        with (
            patch.object(stdout, "write", return_value=0),
            patch.object(sys, "stdout", cast(TextIO, stdout)),
            patch.object(sys, "stderr", stderr),
        ):
            result = cli._main_verified(
                ["--version"],
                verified_distribution_version=cli._DISTRIBUTION_VERSION,
            )
        self.assertEqual(result, CliExitCode.OUTPUT_FAILED)
        self.assertEqual(stderr.getvalue(), "netveil-audit: output_failed\n")


@unittest.skipUnless(os.name == "posix", "safe file policy requires POSIX")
class CliFileBoundaryTests(unittest.TestCase):
    def test_accepts_exact_regular_owner_only_key(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            key_path = Path(directory) / "key.bin"
            _write(key_path, _DEMO_KEY, 0o600)
            observed = cli._read_bounded_file(
                key_path,
                maximum_bytes=cli._MAX_KEY_BYTES,
                failure_code="key_unavailable",
                failure_exit=CliExitCode.KEY_UNAVAILABLE,
                key_policy=True,
            )
        self.assertEqual(observed.payload, _DEMO_KEY)

    def test_rejects_insecure_short_linked_and_wrong_owner_keys(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            cases: list[tuple[str, bytes, int]] = [
                ("short", b"x" * 31, 0o600),
                ("group-readable", _DEMO_KEY, 0o640),
                ("owner-executable", _DEMO_KEY, 0o700),
            ]
            for name, payload, mode in cases:
                with self.subTest(name=name):
                    key_path = root / name
                    _write(key_path, payload, mode)
                    with self.assertRaises(cli._CliFailure) as raised:
                        cli._read_bounded_file(
                            key_path,
                            maximum_bytes=cli._MAX_KEY_BYTES,
                            failure_code="key_unavailable",
                            failure_exit=CliExitCode.KEY_UNAVAILABLE,
                            key_policy=True,
                        )
                    self.assertEqual(raised.exception.code, "key_rejected")
                    key_path.unlink()

            linked = root / "linked"
            alias = root / "alias"
            _write(linked, _DEMO_KEY)
            os.link(linked, alias)
            with self.assertRaises(cli._CliFailure) as linked_failure:
                cli._read_bounded_file(
                    linked,
                    maximum_bytes=cli._MAX_KEY_BYTES,
                    failure_code="key_unavailable",
                    failure_exit=CliExitCode.KEY_UNAVAILABLE,
                    key_policy=True,
                )
            self.assertEqual(linked_failure.exception.code, "key_rejected")

            linked.unlink()
            alias.unlink()
            wrong_owner = root / "wrong-owner"
            _write(wrong_owner, _DEMO_KEY)
            current_uid = wrong_owner.stat().st_uid
            with (
                patch.object(os, "geteuid", return_value=current_uid + 1),
                self.assertRaises(cli._CliFailure) as owner_failure,
            ):
                cli._read_bounded_file(
                    wrong_owner,
                    maximum_bytes=cli._MAX_KEY_BYTES,
                    failure_code="key_unavailable",
                    failure_exit=CliExitCode.KEY_UNAVAILABLE,
                    key_policy=True,
                )
            self.assertEqual(owner_failure.exception.code, "key_rejected")

    def test_rejects_symlink_directory_fifo_missing_and_oversized_files(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            target = root / "target"
            _write(target, _DEMO_KEY)
            symlink = root / "symlink"
            symlink.symlink_to(target)
            fifo = root / "fifo"
            os.mkfifo(fifo)
            oversized = root / "oversized"
            _write(oversized, b"x" * 33)

            for name, path, maximum in (
                ("symlink", symlink, cli._MAX_KEY_BYTES),
                ("directory", root, cli._MAX_KEY_BYTES),
                ("fifo", fifo, cli._MAX_KEY_BYTES),
                ("missing", root / "missing", cli._MAX_KEY_BYTES),
                ("oversized", oversized, 32),
            ):
                with (
                    self.subTest(name=name),
                    self.assertRaises(cli._CliFailure) as raised,
                ):
                    cli._read_bounded_file(
                        path,
                        maximum_bytes=maximum,
                        failure_code="file_unavailable",
                        failure_exit=CliExitCode.CORPUS_UNAVAILABLE,
                        key_policy=False,
                    )
                self.assertEqual(raised.exception.code, "file_unavailable")
                self.assertIsNone(raised.exception.__context__)

    def test_detects_file_identity_change_and_close_failure(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            _write(path, b"abc")
            status = path.stat()
            changed = os.stat_result(
                (
                    status.st_mode,
                    status.st_ino,
                    status.st_dev,
                    status.st_nlink,
                    status.st_uid,
                    status.st_gid,
                    status.st_size + 1,
                    status.st_atime,
                    status.st_mtime,
                    status.st_ctime,
                )
            )
            with (
                patch.object(
                    cli,
                    "_read_open_file",
                    return_value=(b"abc", status, changed),
                ),
                self.assertRaises(cli._CliFailure),
            ):
                cli._read_bounded_file(
                    path,
                    maximum_bytes=10,
                    failure_code="changed",
                    failure_exit=CliExitCode.CORPUS_UNAVAILABLE,
                    key_policy=False,
                )

            real_close = os.close

            def close_then_fail(descriptor: int) -> None:
                real_close(descriptor)
                raise OSError("PRIVATE-CLOSE-MARKER")

            with (
                patch.object(os, "close", side_effect=close_then_fail),
                self.assertRaises(cli._CliFailure) as close_failure,
            ):
                cli._read_bounded_file(
                    path,
                    maximum_bytes=10,
                    failure_code="close_failed",
                    failure_exit=CliExitCode.CORPUS_UNAVAILABLE,
                    key_policy=False,
                )
            self.assertEqual(close_failure.exception.code, "close_failed")
            self.assertIsNone(close_failure.exception.__context__)

    def test_low_level_read_failure_returns_only_empty_sentinels(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            _write(path, b"abc")
            descriptor = os.open(path, os.O_RDONLY)
            try:
                with patch.object(os, "fstat", side_effect=OSError("PRIVATE")):
                    result = cli._read_open_file(descriptor, maximum_bytes=10)
            finally:
                os.close(descriptor)
        self.assertEqual(result, (None, None, None))

    def test_low_level_read_stops_at_bound_without_waiting_for_eof(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "input"
            _write(path, b"abc")
            descriptor = os.open(path, os.O_RDONLY)
            try:
                current = os.fstat(descriptor)
                before_growth = os.stat_result(
                    (
                        current.st_mode,
                        current.st_ino,
                        current.st_dev,
                        current.st_nlink,
                        current.st_uid,
                        current.st_gid,
                        2,
                        current.st_atime,
                        current.st_mtime,
                        current.st_ctime,
                    )
                )
                with patch.object(
                    os,
                    "fstat",
                    side_effect=(before_growth, current),
                ):
                    payload, before, after = cli._read_open_file(
                        descriptor,
                        maximum_bytes=2,
                    )
            finally:
                os.close(descriptor)
        self.assertEqual(payload, b"abc")
        self.assertIsNotNone(before)
        self.assertIsNotNone(after)

    def test_unsupported_platform_fails_before_open(self) -> None:
        with (
            patch.object(os, "name", "unsupported"),
            self.assertRaises(cli._CliFailure) as raised,
        ):
            cli._open_flags()
        self.assertEqual(raised.exception.code, "platform_unsupported")


class CliOutputBoundaryTests(unittest.TestCase):
    def test_emit_failure_survives_broken_stderr(self) -> None:
        stderr = io.StringIO()
        with (
            patch.object(
                stderr,
                "write",
                side_effect=OSError("PRIVATE-STDERR-MARKER"),
            ),
            patch.object(sys, "stderr", stderr),
        ):
            result = cli._emit_failure(
                cli._CliFailure("safe", CliExitCode.CORPUS_REJECTED)
            )
        self.assertEqual(result, CliExitCode.OUTPUT_FAILED)

    def test_parser_exit_messages_use_bounded_writes(self) -> None:
        parser = cli._SafeArgumentParser(prog="netveil-audit")
        stderr = io.StringIO()
        with (
            patch.object(stderr, "write", return_value=0),
            self.assertRaises(cli._CliFailure) as output_failure,
        ):
            parser._print_message("help", stderr)
        self.assertEqual(output_failure.exception.code, "output_failed")

        with (
            patch.object(sys, "stderr", stderr),
            self.assertRaises(cli._CliFailure) as usage_failure,
        ):
            parser.exit(2, "usage failed\n")
        self.assertEqual(usage_failure.exception.code, "usage_error")

        stdout = io.StringIO()
        with (
            patch.object(sys, "stdout", stdout),
            self.assertRaises(cli._CliCompletion) as completion,
        ):
            parser.exit(0, "done\n")
        self.assertEqual(completion.exception.exit_code, CliExitCode.SUCCESS)
        self.assertEqual(stdout.getvalue(), "done\n")

    def test_exact_writers_reject_zero_and_accept_partial_progress(self) -> None:
        text = io.StringIO()
        binary = io.BytesIO()
        with patch.object(
            text,
            "write",
            side_effect=lambda value: min(2, len(value)),
        ) as text_write:
            self.assertTrue(cli._write_text(text, "abcdef"))
        with patch.object(
            binary,
            "write",
            side_effect=lambda value: min(2, len(value)),
        ) as binary_write:
            self.assertTrue(cli._write_binary(binary, b"abcdef"))
        self.assertEqual(text_write.call_count, 3)
        self.assertEqual(binary_write.call_count, 3)

        with (
            patch.object(text, "write", return_value=0),
            patch.object(binary, "write", return_value=0),
        ):
            self.assertFalse(cli._write_text(text, "x"))
            self.assertFalse(cli._write_binary(binary, b"x"))


if __name__ == "__main__":
    unittest.main()
