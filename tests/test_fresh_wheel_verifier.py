from __future__ import annotations

import csv
import gzip
import hashlib
import importlib.util
import io
import json
import marshal
import stat
import tarfile
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from types import CodeType
from unittest.mock import patch
from zipfile import ZIP_DEFLATED, ZipFile, ZipInfo

from tools import verify_fresh_wheel as verifier

_SOURCE_COMMIT = "a" * 40
_SOURCE_DATE_EPOCH = 1_700_000_000
_LAUNCHER = (
    b"#!/bin/sh\n"
    b'""":"\n'
    b'case "$0" in\n'
    b"    */*) netveil_script_directory=${0%/*} ;;\n"
    b"    *) exit 70 ;;\n"
    b"esac\n"
    b'exec "$netveil_script_directory/python" -IESB "$0" "$@"\n'
    b"exit 70\n"
    b'":"""\n'
    b"\n"
    b"raise SystemExit(0)\n"
)


def _record_payload(members: dict[str, bytes]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    record_name = f"{verifier._DIST_INFO}/RECORD"
    for name in sorted((*members, record_name)):
        if name == record_name:
            writer.writerow((name, "", ""))
        else:
            payload = members[name]
            writer.writerow(
                (
                    name,
                    f"sha256={verifier._record_digest(payload)}",
                    str(len(payload)),
                )
            )
    return output.getvalue().encode()


def _wheel_members() -> dict[str, bytes]:
    members = {
        verifier._WHEEL_SCRIPT: _LAUNCHER,
        "netveil/__init__.py": b"",
        "netveil/cli.py": b"",
        "netveil/model.py": b"",
        "netveil/parser.py": b"",
        "netveil/privacy.py": b"",
        "netveil/py.typed": b"",
        verifier._BOOTSTRAP_NAME: b"",
        f"{verifier._DIST_INFO}/METADATA": (
            b"Metadata-Version: 2.4\n"
            b"Name: netveil-audit\n"
            b"Version: 0.3.0\n"
            b"Requires-Python: >=3.11\n"
        ),
        f"{verifier._DIST_INFO}/WHEEL": (
            b"Wheel-Version: 1.0\n"
            b"Generator: verifier-test\n"
            b"Root-Is-Purelib: true\n"
            b"Tag: py3-none-any\n"
        ),
        f"{verifier._DIST_INFO}/licenses/LICENSE": b"test-only license\n",
        f"{verifier._DIST_INFO}/top_level.txt": (b"netveil\nnetveil_bootstrap\n"),
    }
    members[f"{verifier._DIST_INFO}/RECORD"] = _record_payload(members)
    return members


def _zip_bytes(members: dict[str, bytes]) -> bytes:
    output = io.BytesIO()
    with ZipFile(output, "w") as archive:
        for name, payload in members.items():
            info = ZipInfo(name)
            info.create_system = 3
            permissions = 0o755 if name == verifier._WHEEL_SCRIPT else 0o644
            info.external_attr = (stat.S_IFREG | permissions) << 16
            info.compress_type = ZIP_DEFLATED
            archive.writestr(info, payload)
    return output.getvalue()


def _installed_record(
    *,
    site_root: Path,
    launcher: Path,
    launcher_payload: bytes,
) -> bytes:
    relative = verifier._installed_record_path(site_root, launcher)
    output = io.StringIO(newline="")
    writer = csv.writer(output, lineterminator="\n")
    writer.writerow(
        (
            relative,
            f"sha256={verifier._record_digest(launcher_payload)}",
            str(len(launcher_payload)),
        )
    )
    writer.writerow((f"{verifier._DIST_INFO}/RECORD", "", ""))
    return output.getvalue().encode()


def _receipt(key: bytes) -> bytes:
    report: dict[str, object] = {
        "counts": {
            "endpoint_occurrences": 5,
            "physical_lines": 6,
            "source_bytes": len(verifier._CORPUS),
            "unique_endpoints": 4,
        },
        "duplicates": {"group_count": 1},
        "endpoint_occurrences_by_ip_version": {"ipv4": 4, "ipv6": 1},
        "endpoint_occurrences_by_scope": {"documentation": 5},
        "source_content_id": "nvs1_" + "0" * 64,
    }
    document = {
        "report": report,
        "report_digest": {
            "algorithm": "sha256",
            "value": hashlib.sha256(verifier._canonical_json(report)).hexdigest(),
        },
        "schema": "netveil.aggregate-receipt.v1",
    }
    payload = verifier._canonical_json(document) + b"\n"
    if key in payload:
        raise AssertionError("test fixture unexpectedly contains private key")
    return payload


def _sdist_payload() -> bytes:
    tar_payload = io.BytesIO()
    with tarfile.open(
        fileobj=tar_payload,
        mode="w:",
        format=tarfile.USTAR_FORMAT,
    ) as archive:
        directory = tarfile.TarInfo("netveil_audit-0.3.0/")
        directory.type = tarfile.DIRTYPE
        directory.mode = 0o755
        directory.mtime = _SOURCE_DATE_EPOCH
        directory.uid = 0
        directory.gid = 0
        directory.uname = ""
        directory.gname = ""
        archive.addfile(directory)

        readme_payload = b"# Netveil test sdist\n"
        readme = tarfile.TarInfo("netveil_audit-0.3.0/README.md")
        readme.type = tarfile.REGTYPE
        readme.mode = 0o644
        readme.mtime = _SOURCE_DATE_EPOCH
        readme.uid = 0
        readme.gid = 0
        readme.uname = ""
        readme.gname = ""
        readme.size = len(readme_payload)
        archive.addfile(readme, io.BytesIO(readme_payload))
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename="",
        mode="wb",
        compresslevel=9,
        fileobj=compressed,
        mtime=_SOURCE_DATE_EPOCH,
    ) as archive:
        archive.write(tar_payload.getvalue())
    return compressed.getvalue()


def _sdist_inventory_members() -> list[dict[str, object]]:
    readme_payload = b"# Netveil test sdist\n"
    return [
        {
            "kind": "directory",
            "mode": "0755",
            "path": "netveil_audit-0.3.0",
            "size_bytes": 0,
        },
        {
            "kind": "file",
            "mode": "0644",
            "path": "netveil_audit-0.3.0/README.md",
            "sha256": hashlib.sha256(readme_payload).hexdigest(),
            "size_bytes": len(readme_payload),
        },
    ]


def _inventory_payload(
    wheel_payload: bytes,
    *,
    source_commit: str = _SOURCE_COMMIT,
    wheel_filename: str = verifier._WHEEL_NAME,
    wheel_sha256: str | None = None,
    wheel_size_bytes: int | None = None,
    sdist_sha256: str | None = None,
) -> bytes:
    sdist_payload = _sdist_payload()
    artifacts = [
        {
            "filename": wheel_filename,
            "kind": "wheel",
            "sha256": (
                hashlib.sha256(wheel_payload).hexdigest()
                if wheel_sha256 is None
                else wheel_sha256
            ),
            "size_bytes": (
                len(wheel_payload) if wheel_size_bytes is None else wheel_size_bytes
            ),
        },
        {
            "filename": verifier._SDIST_NAME,
            "kind": "sdist",
            "members": _sdist_inventory_members(),
            "sha256": (
                hashlib.sha256(sdist_payload).hexdigest()
                if sdist_sha256 is None
                else sdist_sha256
            ),
            "size_bytes": len(sdist_payload),
        },
    ]
    artifacts.sort(key=lambda artifact: str(artifact["filename"]))
    return (
        verifier._canonical_json(
            {
                "artifacts": artifacts,
                "schema": verifier._INVENTORY_SCHEMA,
                "source_commit": source_commit,
                "source_date_epoch": _SOURCE_DATE_EPOCH,
            }
        )
        + b"\n"
    )


class WheelArchiveContractTests(unittest.TestCase):
    def test_accepts_exact_inventory_and_record_bound_launcher(self) -> None:
        payload = _zip_bytes(_wheel_members())

        evidence = verifier._inspect_wheel(payload)

        self.assertEqual(evidence.payload, payload)
        self.assertEqual(evidence.launcher, _LAUNCHER)
        self.assertEqual(evidence.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(
            [member.path for member in evidence.members],
            sorted(_wheel_members()),
        )
        self.assertTrue(
            all(member.mode in ("0644", "0755") for member in evidence.members)
        )

    def test_rejects_entry_points_even_when_recorded(self) -> None:
        members = _wheel_members()
        record_name = f"{verifier._DIST_INFO}/RECORD"
        members.pop(record_name)
        members[f"{verifier._DIST_INFO}/entry_points.txt"] = (
            b"[console_scripts]\nnetveil-audit=netveil_bootstrap:entrypoint\n"
        )
        members[record_name] = _record_payload(members)

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^wheel_inventory_invalid$",
        ):
            verifier._inspect_wheel(_zip_bytes(members))

    def test_rejects_stale_record_hash(self) -> None:
        members = _wheel_members()
        members["netveil/cli.py"] = b"# unrecorded mutation\n"

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^record_mismatch$",
        ):
            verifier._inspect_wheel(_zip_bytes(members))

    def test_rejects_duplicate_record_paths(self) -> None:
        digest = verifier._record_digest(b"x")
        payload = (
            f"netveil/cli.py,sha256={digest},1\nnetveil/cli.py,sha256={digest},1\n"
        ).encode()

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^record_invalid$",
        ):
            verifier._parse_record(payload)

    def test_exact_wheel_reader_rejects_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            target = root / "target.whl"
            target.write_bytes(b"wheel")
            link = root / verifier._WHEEL_NAME
            link.symlink_to(target)

            with self.assertRaisesRegex(
                verifier.VerificationFailure,
                "^wheel_path_invalid$",
            ):
                verifier._read_exact_wheel(link)


class ReleaseInventoryContractTests(unittest.TestCase):
    def test_accepts_exact_canonical_unsigned_inventory(self) -> None:
        wheel_payload = b"test wheel bytes"
        payload = _inventory_payload(wheel_payload)

        inventory = verifier._parse_release_inventory(payload)

        self.assertEqual(inventory.source_commit, _SOURCE_COMMIT)
        self.assertEqual(inventory.source_date_epoch, 1_700_000_000)
        self.assertEqual(inventory.sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(
            {artifact.kind for artifact in inventory.artifacts},
            {"wheel", "sdist"},
        )

    def test_rejects_malformed_and_noncanonical_inventory(self) -> None:
        canonical = _inventory_payload(b"test wheel bytes")
        document = json.loads(canonical)
        malformed_document = dict(document)
        malformed_document.pop("source_commit")
        malformed = verifier._canonical_json(malformed_document) + b"\n"
        noncanonical = json.dumps(document, indent=2).encode("ascii") + b"\n"

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^inventory_invalid$",
        ):
            verifier._parse_release_inventory(malformed)
        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^inventory_not_canonical$",
        ):
            verifier._parse_release_inventory(noncanonical)

    def test_rejects_duplicate_inventory_keys(self) -> None:
        payload = _inventory_payload(b"test wheel bytes")
        duplicated = payload.replace(
            b'{"artifacts":',
            b'{"schema":"netveil.release-inventory.v1","artifacts":',
            1,
        )

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^inventory_invalid$",
        ):
            verifier._parse_release_inventory(duplicated)

    def test_rejects_commit_name_size_and_sha256_mismatches(self) -> None:
        wheel_payload = b"not required to be a valid wheel for binding failures"
        cases = (
            (
                "commit",
                _inventory_payload(wheel_payload),
                "b" * 40,
                "inventory_source_commit_mismatch",
            ),
            (
                "name",
                _inventory_payload(
                    wheel_payload,
                    wheel_filename="unexpected-0.3.0-py3-none-any.whl",
                ),
                _SOURCE_COMMIT,
                "inventory_wheel_name_mismatch",
            ),
            (
                "size",
                _inventory_payload(
                    wheel_payload,
                    wheel_size_bytes=len(wheel_payload) + 1,
                ),
                _SOURCE_COMMIT,
                "inventory_wheel_size_mismatch",
            ),
            (
                "sha256",
                _inventory_payload(
                    wheel_payload,
                    wheel_sha256="b" * 64,
                ),
                _SOURCE_COMMIT,
                "inventory_wheel_sha256_mismatch",
            ),
            (
                "sdist_sha256",
                _inventory_payload(
                    wheel_payload,
                    sdist_sha256="b" * 64,
                ),
                _SOURCE_COMMIT,
                "inventory_sdist_sha256_mismatch",
            ),
        )
        for label, inventory_payload, expected_commit, failure_code in cases:
            with self.subTest(label=label), tempfile.TemporaryDirectory() as raw_root:
                root = Path(raw_root)
                wheel = root / verifier._WHEEL_NAME
                sdist = root / verifier._SDIST_NAME
                inventory = root / verifier._INVENTORY_NAME
                wheel.write_bytes(wheel_payload)
                sdist.write_bytes(_sdist_payload())
                inventory.write_bytes(inventory_payload)

                with self.assertRaisesRegex(
                    verifier.VerificationFailure,
                    f"^{failure_code}$",
                ):
                    verifier.verify_wheel(
                        wheel,
                        inventory_path=inventory,
                        sdist_path=sdist,
                        source_commit=expected_commit,
                    )

    def test_sdist_member_inventory_matches_safe_canonical_archive(self) -> None:
        payload = _sdist_payload()
        inventory = verifier._parse_release_inventory(
            _inventory_payload(b"test wheel bytes")
        )
        actual = verifier._inspect_sdist(
            payload,
            source_date_epoch=_SOURCE_DATE_EPOCH,
        )

        verifier._bind_sdist_members(inventory, actual)
        self.assertEqual(
            [member.path for member in actual],
            [
                "netveil_audit-0.3.0",
                "netveil_audit-0.3.0/README.md",
            ],
        )

    def test_sdist_member_inventory_mismatch_is_rejected(self) -> None:
        payload = _inventory_payload(b"test wheel bytes")
        document = json.loads(payload)
        sdist = next(
            artifact
            for artifact in document["artifacts"]
            if artifact["kind"] == "sdist"
        )
        sdist["members"][1]["sha256"] = "b" * 64
        inventory = verifier._parse_release_inventory(
            verifier._canonical_json(document) + b"\n"
        )
        actual = verifier._inspect_sdist(
            _sdist_payload(),
            source_date_epoch=_SOURCE_DATE_EPOCH,
        )

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^inventory_sdist_members_mismatch$",
        ):
            verifier._bind_sdist_members(inventory, actual)

    def test_windows_drive_like_sdist_members_are_rejected_consistently(
        self,
    ) -> None:
        payload = _inventory_payload(b"test wheel bytes")
        document = json.loads(payload)
        sdist = next(
            artifact
            for artifact in document["artifacts"]
            if artifact["kind"] == "sdist"
        )
        sdist["members"][0]["path"] = "C:escape"

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^inventory_invalid$",
        ):
            verifier._parse_release_inventory(
                verifier._canonical_json(document) + b"\n"
            )

        member = tarfile.TarInfo("C:escape")
        member.type = tarfile.REGTYPE
        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^sdist_member_unsafe$",
        ):
            verifier._safe_sdist_member_name(member)


class InstalledLayoutContractTests(unittest.TestCase):
    def create_layout(self, root: Path) -> tuple[Path, Path]:
        prefix = root / "venv"
        binary = prefix / "bin"
        site_root = prefix / "lib" / "python3.11" / "site-packages"
        dist_info = site_root / verifier._DIST_INFO
        package = site_root / "netveil"
        binary.mkdir(parents=True)
        dist_info.mkdir(parents=True)
        package.mkdir()
        python = binary / "python"
        python.write_bytes(b"test interpreter placeholder")
        launcher = binary / verifier._LAUNCHER_NAME
        launcher.write_bytes(_LAUNCHER)
        launcher.chmod(0o755)
        (site_root / verifier._BOOTSTRAP_NAME).write_bytes(b"")
        (package / "cli.py").write_bytes(b"")
        (dist_info / "METADATA").write_bytes(
            b"Metadata-Version: 2.4\nName: netveil-audit\nVersion: 0.3.0\n"
        )
        (dist_info / "RECORD").write_bytes(
            _installed_record(
                site_root=site_root,
                launcher=launcher,
                launcher_payload=_LAUNCHER,
            )
        )
        return prefix, python

    def test_binds_installed_launcher_to_record_and_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            prefix, python = self.create_layout(root)

            layout = verifier._inspect_install(prefix, python, _LAUNCHER)

            self.assertEqual(layout.launcher.read_bytes(), _LAUNCHER)
            self.assertEqual(layout.dist_info.name, verifier._DIST_INFO)
            self.assertIsNotNone(layout.evidence)
            assert layout.evidence is not None
            self.assertEqual(layout.evidence.launcher.mode, "0755")
            self.assertEqual(
                layout.evidence.launcher.sha256,
                hashlib.sha256(_LAUNCHER).hexdigest(),
            )
            self.assertGreater(layout.evidence.record.size_bytes, 0)
            self.assertEqual(
                {row.path for row in layout.evidence.selected_record_rows},
                {
                    verifier._installed_record_path(
                        layout.site_root,
                        layout.launcher,
                    ),
                    f"{verifier._DIST_INFO}/RECORD",
                },
            )

    def test_rejects_installed_entry_points(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            root = Path(raw_root)
            prefix, python = self.create_layout(root)
            dist_info = next(prefix.glob("lib/python*/site-packages/*.dist-info"))
            (dist_info / "entry_points.txt").write_bytes(
                b"[console_scripts]\nnetveil-audit=netveil_bootstrap:entrypoint\n"
            )

            with self.assertRaisesRegex(
                verifier.VerificationFailure,
                "^entry_points_present$",
            ):
                verifier._inspect_install(prefix, python, _LAUNCHER)


class AdversarialPrimitiveTests(unittest.TestCase):
    def test_record_rewrite_changes_only_selected_binding(self) -> None:
        original = (
            b"netveil_bootstrap.py,sha256="
            + verifier._record_digest(b"old").encode()
            + b",3\nother.py,sha256="
            + verifier._record_digest(b"same").encode()
            + b",4\n"
        )

        updated = verifier._updated_record(
            original,
            path="netveil_bootstrap.py",
            replacement=b"new bytes",
        )
        records = verifier._parse_record(updated)

        self.assertEqual(
            records["netveil_bootstrap.py"].digest,
            verifier._record_digest(b"new bytes"),
        )
        self.assertEqual(
            records["other.py"].digest,
            verifier._record_digest(b"same"),
        )

    def test_temporary_mutation_restores_bytes_and_mode_after_failure(self) -> None:
        with tempfile.TemporaryDirectory() as raw_root:
            path = Path(raw_root) / "artifact.py"
            path.write_bytes(b"original")
            path.chmod(0o640)

            with (
                self.assertRaisesRegex(RuntimeError, "^stop$"),
                verifier._temporary_bytes(path, b"tampered"),
            ):
                self.assertEqual(path.read_bytes(), b"tampered")
                raise RuntimeError("stop")

            self.assertEqual(path.read_bytes(), b"original")
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o640)

    def test_unchecked_hash_pyc_contains_adversarial_code_object(self) -> None:
        payload = verifier._unchecked_hash_pyc(
            b"sentinel = 7\n",
            b"trusted source\n",
        )

        self.assertEqual(payload[:4], importlib.util.MAGIC_NUMBER)
        self.assertEqual(int.from_bytes(payload[4:8], "little"), 1)
        code = marshal.loads(payload[16:])
        self.assertIsInstance(code, CodeType)
        namespace: dict[str, object] = {}
        exec(code, namespace)  # noqa: S102 - executes fixed unit-test bytes.
        self.assertEqual(namespace["sentinel"], 7)

    def test_receipt_validator_accepts_canonical_redacted_fixture(self) -> None:
        key = b"k" * 32

        document = verifier._verify_receipt_document(_receipt(key), key=key)

        self.assertEqual(document["schema"], "netveil.aggregate-receipt.v1")

    def test_public_demo_key_is_explicit_non_secret_test_material(self) -> None:
        self.assertEqual(len(verifier._PUBLIC_DEMO_KEY), 32)
        self.assertEqual(
            hashlib.sha256(verifier._PUBLIC_DEMO_KEY).hexdigest(),
            "2d27befbc438954c4a55d8c0e36192c5a4a7e9e3f15c17d6e427c4a3499d945d",
        )

    def test_receipt_validator_rejects_private_key_material(self) -> None:
        key = b"k" * 32
        payload = _receipt(key)
        document = json.loads(payload)
        document["private"] = key.hex()

        with self.assertRaisesRegex(
            verifier.VerificationFailure,
            "^receipt_private_data_detected$",
        ):
            verifier._verify_receipt_document(
                verifier._canonical_json(document) + b"\n",
                key=key,
            )

    def test_syscall_trace_accepts_only_launcher_python_exec_chain(self) -> None:
        root = Path("/private-verifier-root")
        layout = verifier.InstalledLayout(
            prefix=root / "venv",
            python=root / "venv/bin/python",
            launcher=root / "venv/bin/netveil-audit",
            site_root=root / "venv/lib/python3.11/site-packages",
            dist_info=root / "dist-info",
            bootstrap=root / "bootstrap.py",
            package_root=root / "netveil",
            record=root / "RECORD",
        )
        payload = (
            f'execve("{layout.launcher}", ["netveil-audit"], 0x0) = 0\n'
            f'execve("{layout.python}", ["python", "-IESB"], 0x0) = 0\n'
            "exit_group(0) = ?\n"
        ).encode()

        evidence = verifier._validate_syscall_trace(
            (payload,),
            layout=layout,
            label="version",
        )

        self.assertEqual(
            evidence.exec_chain,
            ("installed_launcher", "installed_python"),
        )
        self.assertEqual(evidence.network_syscall_count, 0)
        self.assertEqual(evidence.post_launch_process_count, 0)
        self.assertEqual(len(evidence.normalized_sha256), 64)

    def test_syscall_trace_rejects_network_and_post_launch_processes(self) -> None:
        root = Path("/private-verifier-root")
        layout = verifier.InstalledLayout(
            prefix=root / "venv",
            python=root / "venv/bin/python",
            launcher=root / "venv/bin/netveil-audit",
            site_root=root / "venv/lib/python3.11/site-packages",
            dist_info=root / "dist-info",
            bootstrap=root / "bootstrap.py",
            package_root=root / "netveil",
            record=root / "RECORD",
        )
        prefix = (
            f'execve("{layout.launcher}", ["netveil-audit"], 0x0) = 0\n'
            f'execve("{layout.python}", ["python", "-IESB"], 0x0) = 0\n'
        )
        for syscall in (
            "socket(AF_INET, SOCK_STREAM, IPPROTO_IP) = 3\n",
            "clone(child_stack=NULL, flags=SIGCHLD) = 42\n",
        ):
            with (
                self.subTest(syscall=syscall),
                self.assertRaisesRegex(
                    verifier.VerificationFailure,
                    "^network_or_process_activity_detected$",
                ),
            ):
                verifier._validate_syscall_trace(
                    ((prefix + syscall + "exit_group(0) = ?\n").encode(),),
                    layout=layout,
                )

    def test_source_commit_must_be_exact_lowercase_sha1(self) -> None:
        verifier._validate_source_commit(_SOURCE_COMMIT)
        for invalid in ("a" * 39, "A" * 40, "g" * 40, "/private/path"):
            with (
                self.subTest(invalid=invalid),
                self.assertRaisesRegex(
                    verifier.VerificationFailure,
                    "^source_commit_invalid$",
                ),
            ):
                verifier._validate_source_commit(invalid)


class VerifierCliTests(unittest.TestCase):
    def test_success_json_contains_no_input_path(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()
        summary = verifier.VerificationSummary(
            source_commit=_SOURCE_COMMIT,
            release_inventory=verifier._parse_release_inventory(
                _inventory_payload(b"summary wheel bytes")
            ),
            installed=verifier.InstalledEvidence(
                launcher=verifier.InstalledFileEvidence(
                    logical_path="bin/netveil-audit",
                    mode="0755",
                    sha256="c" * 64,
                    size_bytes=456,
                ),
                record=verifier.InstalledFileEvidence(
                    logical_path=("site-packages/netveil_audit-0.3.0.dist-info/RECORD"),
                    mode="0644",
                    sha256="d" * 64,
                    size_bytes=789,
                ),
                selected_record_rows=(
                    verifier.InstalledRecordRowEvidence(
                        path="../../../bin/netveil-audit",
                        sha256="c" * 64,
                        size_bytes=456,
                    ),
                ),
            ),
            interpreter=verifier.InterpreterEvidence(
                implementation="cpython",
                version="3.11.0",
                cache_tag="cpython-311",
            ),
            platform=verifier.PlatformEvidence(
                sys_platform="linux",
                system="Linux",
                release="test-kernel",
                machine="x86_64",
            ),
            syscall_traces=(
                verifier.TraceEvidence(
                    label="version",
                    normalized_sha256="e" * 64,
                    process_count=1,
                    exec_chain=("installed_launcher", "installed_python"),
                    exec_count=2,
                    exit_syscall_count=1,
                    network_syscall_count=0,
                    post_launch_process_count=0,
                ),
            ),
            public_demo=verifier.PublicDemoEvidence(
                corpus_sha256=hashlib.sha256(verifier._CORPUS).hexdigest(),
                corpus_size_bytes=len(verifier._CORPUS),
                corpus_physical_lines=verifier._CORPUS.count(b"\n"),
                public_key_sha256=hashlib.sha256(verifier._PUBLIC_DEMO_KEY).hexdigest(),
                public_key_size_bytes=len(verifier._PUBLIC_DEMO_KEY),
                version_stdout="netveil-audit 0.3.0\n",
                receipt=json.loads(_receipt(verifier._PUBLIC_DEMO_KEY)),
                receipt_stdout_sha256=hashlib.sha256(
                    _receipt(verifier._PUBLIC_DEMO_KEY)
                ).hexdigest(),
            ),
            wheel_sha256="a" * 64,
            wheel_size_bytes=123,
            wheel_members=(
                verifier.WheelMemberEvidence(
                    path="netveil/cli.py",
                    sha256="b" * 64,
                    size=7,
                    mode="0644",
                ),
            ),
        )

        with (
            patch.object(verifier, "verify_wheel", return_value=summary),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = verifier.main(
                [
                    "--source-commit",
                    _SOURCE_COMMIT,
                    "--inventory",
                    "/home/private/workspace/release-inventory.json",
                    "--sdist",
                    "/home/private/workspace/netveil_audit-0.3.0.tar.gz",
                    ("/home/private/workspace/netveil_audit-0.3.0-py3-none-any.whl"),
                ]
            )

        self.assertEqual(result, 0)
        self.assertEqual(stderr.getvalue(), "")
        document = json.loads(stdout.getvalue())
        self.assertEqual(document["status"], "pass")
        self.assertEqual(document["source_commit"], _SOURCE_COMMIT)
        self.assertEqual(
            document["integrity_evidence"]["inventory_type"],
            "unsigned_sha256_manifest",
        )
        self.assertFalse(document["integrity_evidence"]["signature_verified"])
        self.assertFalse(document["integrity_evidence"]["attestation_verified"])
        self.assertEqual(document["installed"]["launcher"]["mode"], "0755")
        self.assertEqual(document["installed"]["record"]["size_bytes"], 789)
        self.assertEqual(document["platform"]["machine"], "x86_64")
        self.assertEqual(
            document["public_demo"]["classification"],
            "synthetic_ietf_documentation_ranges_with_public_demo_key",
        )
        self.assertEqual(
            document["public_demo"]["commands"][0]["stdout"],
            "netveil-audit 0.3.0\n",
        )
        self.assertEqual(
            document["public_demo"]["public_demo_key"]["classification"],
            "public_non_secret_test_material",
        )
        self.assertEqual(
            document["syscall_traces"][0]["exec_chain"],
            ["installed_launcher", "installed_python"],
        )
        self.assertEqual(document["interpreter"]["implementation"], "cpython")
        self.assertEqual(document["wheel"]["members"][0]["path"], "netveil/cli.py")
        self.assertNotIn("/home/private", stdout.getvalue())
        self.assertEqual(
            [item["name"] for item in document["checks"]],
            list(verifier._CHECKS),
        )

    def test_failure_is_stable_and_redacts_input_path(self) -> None:
        stdout = io.StringIO()
        stderr = io.StringIO()

        with (
            patch.object(
                verifier,
                "verify_wheel",
                side_effect=verifier.VerificationFailure("wheel_path_invalid"),
            ),
            redirect_stdout(stdout),
            redirect_stderr(stderr),
        ):
            result = verifier.main(
                [
                    "--source-commit",
                    _SOURCE_COMMIT,
                    "--inventory",
                    "/home/private/release-inventory.json",
                    "--sdist",
                    "/home/private/netveil_audit-0.3.0.tar.gz",
                    "/home/private/secret.whl",
                ]
            )

        self.assertEqual(result, 1)
        self.assertEqual(stdout.getvalue(), "")
        self.assertEqual(
            stderr.getvalue(),
            "netveil-wheel-verifier: wheel_path_invalid\n",
        )
        self.assertNotIn("/home/private", stderr.getvalue())

    def test_usage_is_stable(self) -> None:
        stderr = io.StringIO()

        with redirect_stderr(stderr):
            result = verifier.main([])

        self.assertEqual(result, 2)
        self.assertEqual(
            stderr.getvalue(),
            "netveil-wheel-verifier: usage_error\n",
        )


if __name__ == "__main__":
    unittest.main()
