from __future__ import annotations

import gzip
import hashlib
import io
import json
import os
import shutil
import subprocess
import sys
import tarfile
import tempfile
import unittest
from pathlib import Path
from typing import Any
from unittest.mock import patch

from tools import build_release

EPOCH = 1_700_000_000
SOURCE_COMMIT = "a" * 40
ROOT = Path(__file__).resolve().parents[1]


def _gzip_tar(
    members: tuple[tuple[str, bytes | None, int, bytes], ...],
    *,
    gzip_filename: str,
    gzip_mtime: int,
    reverse: bool = False,
) -> bytes:
    tar_payload = io.BytesIO()
    ordered = tuple(reversed(members)) if reverse else members
    with tarfile.open(
        fileobj=tar_payload,
        mode="w:",
        format=tarfile.PAX_FORMAT,
    ) as archive:
        for index, (name, payload, mode, member_type) in enumerate(ordered):
            information = tarfile.TarInfo(name)
            information.type = member_type
            information.mode = mode
            information.mtime = 111 + index
            information.uid = 1000 + index
            information.gid = 2000 + index
            information.uname = f"user-{index}"
            information.gname = f"group-{index}"
            information.size = 0 if payload is None else len(payload)
            information.pax_headers = {"comment": f"nondeterministic-{index}"}
            archive.addfile(
                information,
                None if payload is None else io.BytesIO(payload),
            )
    compressed = io.BytesIO()
    with gzip.GzipFile(
        filename=gzip_filename,
        mode="wb",
        compresslevel=1 if reverse else 6,
        fileobj=compressed,
        mtime=gzip_mtime,
    ) as archive:
        archive.write(tar_payload.getvalue())
    return compressed.getvalue()


def _safe_members() -> tuple[tuple[str, bytes | None, int, bytes], ...]:
    return (
        ("netveil_audit-0.3.0/", None, 0o700, tarfile.DIRTYPE),
        (
            "netveil_audit-0.3.0/README.md",
            b"# Netveil\n",
            0o600,
            tarfile.REGTYPE,
        ),
        (
            "netveil_audit-0.3.0/scripts/",
            None,
            0o777,
            tarfile.DIRTYPE,
        ),
        (
            "netveil_audit-0.3.0/scripts/netveil-audit",
            b"#!/bin/sh\nexit 0\n",
            0o700,
            tarfile.REGTYPE,
        ),
    )


def _git(project: Path, *arguments: str) -> subprocess.CompletedProcess[bytes]:
    environment = dict(os.environ)
    environment.update(
        {
            "GIT_AUTHOR_EMAIL": "31526072+omar07ibrahim@users.noreply.github.com",
            "GIT_AUTHOR_NAME": "Omar Ibrahim",
            "GIT_COMMITTER_EMAIL": ("31526072+omar07ibrahim@users.noreply.github.com"),
            "GIT_COMMITTER_NAME": "Omar Ibrahim",
        }
    )
    return subprocess.run(
        ("git", *arguments),
        cwd=project,
        env=environment,
        stdin=subprocess.DEVNULL,
        capture_output=True,
        check=True,
    )


def _initialize_repository(project: Path) -> str:
    project.mkdir()
    (project / ".gitignore").write_text("ignored.generated\n")
    (project / "tracked.txt").write_text("tracked commit bytes\n")
    _git(project, "init", "--quiet")
    _git(project, "add", ".gitignore", "tracked.txt")
    _git(project, "commit", "--quiet", "-m", "Create test fixture")
    return _git(project, "rev-parse", "HEAD").stdout.decode("ascii").strip()


class ReleaseBuilderTests(unittest.TestCase):
    def test_new_release_files_begin_owner_only_before_final_mode(self) -> None:
        observed_creation_modes: list[int] = []
        real_open = os.open

        def guarded_open(path: Path, flags: int, mode: int) -> int:
            observed_creation_modes.append(mode)
            return real_open(path, flags, mode)

        with tempfile.TemporaryDirectory() as temporary:
            destination = Path(temporary) / "launcher"
            with patch("tools.build_release.os.open", side_effect=guarded_open):
                build_release._write_new_file(
                    destination,
                    b"release bytes\n",
                    mode=0o755,
                )

            self.assertEqual(observed_creation_modes, [0o600])
            self.assertEqual(destination.read_bytes(), b"release bytes\n")
            self.assertEqual(destination.stat().st_mode & 0o777, 0o755)

    def test_logically_identical_sdists_normalize_byte_identically(self) -> None:
        first = _gzip_tar(
            _safe_members(),
            gzip_filename="first-random-name.tar",
            gzip_mtime=123,
        )
        second = _gzip_tar(
            _safe_members(),
            gzip_filename="second-random-name.tar",
            gzip_mtime=987_654,
            reverse=True,
        )

        normalized_first = build_release.normalize_sdist_bytes(
            first,
            source_date_epoch=EPOCH,
        )
        normalized_second = build_release.normalize_sdist_bytes(
            second,
            source_date_epoch=EPOCH,
        )
        self.assertEqual(normalized_first, normalized_second)
        self.assertEqual(normalized_first[3], 0)
        self.assertEqual(
            int.from_bytes(normalized_first[4:8], "little"),
            EPOCH,
        )

        with tarfile.open(
            fileobj=io.BytesIO(normalized_first),
            mode="r:gz",
        ) as archive:
            members = archive.getmembers()
            self.assertEqual(
                [member.name for member in members],
                [
                    "netveil_audit-0.3.0",
                    "netveil_audit-0.3.0/README.md",
                    "netveil_audit-0.3.0/scripts",
                    "netveil_audit-0.3.0/scripts/netveil-audit",
                ],
            )
            for member in members:
                self.assertEqual(member.mtime, EPOCH)
                self.assertEqual(member.uid, 0)
                self.assertEqual(member.gid, 0)
                self.assertEqual(member.uname, "")
                self.assertEqual(member.gname, "")
            self.assertEqual(
                [member.mode for member in members],
                [0o755, 0o644, 0o755, 0o755],
            )

    def test_unsafe_archive_members_are_rejected(self) -> None:
        cases = {
            "absolute": (("/absolute.txt", b"x", 0o644, tarfile.REGTYPE),),
            "backslash": (("root\\escape.txt", b"x", 0o644, tarfile.REGTYPE),),
            "character_device": (("root/device", None, 0o600, tarfile.CHRTYPE),),
            "duplicate": (
                ("root/file.txt", b"one", 0o644, tarfile.REGTYPE),
                ("root/file.txt", b"two", 0o644, tarfile.REGTYPE),
            ),
            "hard_link": (("root/link", None, 0o644, tarfile.LNKTYPE),),
            "symlink": (("root/link", None, 0o777, tarfile.SYMTYPE),),
            "traversal": (("root/../../escape.txt", b"x", 0o644, tarfile.REGTYPE),),
        }
        for label, members in cases.items():
            with self.subTest(label=label):
                payload = _gzip_tar(
                    members,
                    gzip_filename=f"{label}.tar",
                    gzip_mtime=1,
                )
                with self.assertRaises(build_release.ReleaseBuildError):
                    build_release.normalize_sdist_bytes(
                        payload,
                        source_date_epoch=EPOCH,
                    )

    def test_inventory_is_stable_sorted_and_hash_bound(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            wheel = root / "netveil_audit-0.3.0-py3-none-any.whl"
            sdist = root / "netveil_audit-0.3.0.tar.gz"
            wheel.write_bytes(b"backend-owned-wheel-bytes")
            sdist.write_bytes(
                build_release.normalize_sdist_bytes(
                    _gzip_tar(
                        _safe_members(),
                        gzip_filename="source.tar",
                        gzip_mtime=99,
                    ),
                    source_date_epoch=EPOCH,
                )
            )
            first = build_release.artifact_inventory(
                (wheel, sdist),
                source_date_epoch=EPOCH,
                source_commit=SOURCE_COMMIT,
            )
            second = build_release.artifact_inventory(
                (sdist, wheel),
                source_date_epoch=EPOCH,
                source_commit=SOURCE_COMMIT,
            )

        self.assertEqual(first, second)
        document: dict[str, Any] = json.loads(first)
        self.assertEqual(document["schema"], build_release.INVENTORY_SCHEMA)
        self.assertEqual(document["source_commit"], SOURCE_COMMIT)
        self.assertEqual(document["source_date_epoch"], EPOCH)
        artifacts = document["artifacts"]
        self.assertEqual(
            [artifact["filename"] for artifact in artifacts],
            sorted((sdist.name, wheel.name)),
        )
        by_name = {artifact["filename"]: artifact for artifact in artifacts}
        self.assertEqual(
            by_name[wheel.name]["sha256"],
            hashlib.sha256(b"backend-owned-wheel-bytes").hexdigest(),
        )
        self.assertEqual(
            by_name[wheel.name]["size_bytes"],
            len(b"backend-owned-wheel-bytes"),
        )
        sdist_members = by_name[sdist.name]["members"]
        self.assertEqual(
            [member["path"] for member in sdist_members],
            [
                "netveil_audit-0.3.0",
                "netveil_audit-0.3.0/README.md",
                "netveil_audit-0.3.0/scripts",
                "netveil_audit-0.3.0/scripts/netveil-audit",
            ],
        )
        self.assertNotIn("sha256", sdist_members[0])
        self.assertEqual(
            sdist_members[1]["sha256"],
            hashlib.sha256(b"# Netveil\n").hexdigest(),
        )

    def test_normalization_never_overwrites_an_existing_destination(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "input" / "netveil_audit-0.3.0.tar.gz"
            destination = root / "output" / source.name
            source.parent.mkdir()
            destination.parent.mkdir()
            source.write_bytes(
                _gzip_tar(
                    _safe_members(),
                    gzip_filename="source.tar",
                    gzip_mtime=99,
                )
            )
            destination.write_bytes(b"retained-existing-artifact")

            with self.assertRaises(build_release.ReleaseBuildError):
                build_release.normalize_sdist(
                    source,
                    destination,
                    source_date_epoch=EPOCH,
                )
            self.assertEqual(
                destination.read_bytes(),
                b"retained-existing-artifact",
            )

    def test_sanitized_environment_is_complete_and_reproducible(self) -> None:
        home = Path("/private/netveil-build-home")
        first = build_release.sanitized_build_environment(
            source_date_epoch=EPOCH,
            home=home,
        )
        second = build_release.sanitized_build_environment(
            source_date_epoch=EPOCH,
            home=home,
        )
        self.assertEqual(first, second)
        self.assertEqual(first["SOURCE_DATE_EPOCH"], str(EPOCH))
        self.assertEqual(first["HOME"], str(home))
        self.assertEqual(first["PYTHONHASHSEED"], "0")
        for excluded in (
            "GIT_CONFIG_GLOBAL",
            "LD_PRELOAD",
            "PYTHONHOME",
            "PYTHONPATH",
        ):
            self.assertNotIn(excluded, first)

    def test_pinned_backend_accepts_the_live_project_metadata(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            for name in ("LICENSE", "README.md", "pyproject.toml"):
                shutil.copy2(ROOT / name, project / name)
            for name in ("scripts", "src"):
                shutil.copytree(ROOT / name, project / name)
            home = Path(temporary) / "home"
            home.mkdir()

            completed = subprocess.run(
                (
                    sys.executable,
                    "-c",
                    (
                        "from setuptools import build_meta;"
                        "build_meta.get_requires_for_build_sdist()"
                    ),
                ),
                cwd=project,
                env=dict(
                    build_release.sanitized_build_environment(
                        source_date_epoch=EPOCH,
                        home=home,
                    )
                ),
                stdin=subprocess.DEVNULL,
                capture_output=True,
                check=False,
                timeout=30,
            )

        self.assertEqual(
            completed.returncode,
            0,
            msg=(completed.stdout + completed.stderr).decode(
                "utf-8",
                errors="replace",
            ),
        )

    def test_git_source_commit_rejects_tracked_and_untracked_changes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            expected_commit = _initialize_repository(project)
            home = root / "home"
            home.mkdir()

            self.assertEqual(
                build_release._git_source_commit(project.resolve(), home),
                expected_commit,
            )
            tracked = project / "tracked.txt"
            tracked.write_text("dirty tracked bytes\n")
            with self.assertRaisesRegex(
                build_release.ReleaseBuildError,
                "^netveil_release_error:worktree_dirty$",
            ):
                build_release._git_source_commit(project.resolve(), home)
            tracked.write_text("tracked commit bytes\n")

            untracked = project / "untracked.txt"
            untracked.write_text("dirty untracked bytes\n")
            with self.assertRaisesRegex(
                build_release.ReleaseBuildError,
                "^netveil_release_error:worktree_dirty$",
            ):
                build_release._git_source_commit(project.resolve(), home)

    def test_exported_source_is_exact_head_and_excludes_ignored_state(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            project = root / "project"
            expected_commit = _initialize_repository(project)
            (project / "ignored.generated").write_text(
                "must not influence the backend\n"
            )
            home = root / "home"
            home.mkdir()
            snapshot = root / "snapshot"

            observed_commit = build_release._export_clean_head(
                project.resolve(),
                snapshot,
                root / "source.tar",
                home,
            )

            self.assertEqual(observed_commit, expected_commit)
            self.assertEqual(
                (snapshot / "tracked.txt").read_text(),
                "tracked commit bytes\n",
            )
            self.assertEqual(
                (snapshot / ".gitignore").read_text(),
                "ignored.generated\n",
            )
            self.assertFalse((snapshot / "ignored.generated").exists())
            self.assertFalse((snapshot / ".git").exists())

    def test_release_destination_must_be_outside_source_tree(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()

            with self.assertRaisesRegex(
                build_release.ReleaseBuildError,
                "^netveil_release_error:build_path_invalid$",
            ):
                build_release.build_release(
                    project,
                    project / "release",
                    source_date_epoch=EPOCH,
                    python_executable=Path(sys.executable),
                )

    def test_build_python_preserves_a_virtual_environment_symlink(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            binary = root / "venv/bin"
            binary.mkdir(parents=True)
            launcher = binary / "python"
            launcher.symlink_to(Path(sys.executable))

            observed = build_release._build_python_path(launcher)
            dereferenced = launcher.resolve()

        self.assertEqual(observed, launcher.absolute())
        self.assertNotEqual(observed, dereferenced)

    def test_backend_orchestration_is_mocked_and_wheel_bytes_are_untouched(
        self,
    ) -> None:
        backend_wheel = b"opaque-backend-wheel-bytes"
        backend_sdist = _gzip_tar(
            _safe_members(),
            gzip_filename="backend-random-name.tar",
            gzip_mtime=42,
        )
        observed_commands: list[tuple[str, ...]] = []
        observed_environments: list[dict[str, str]] = []
        observed_working_directories: list[Path] = []

        def fake_export(
            project: Path,
            destination: Path,
            archive_path: Path,
            home: Path,
        ) -> str:
            del project, archive_path, home
            destination.mkdir()
            return SOURCE_COMMIT

        def fake_run(
            command: tuple[str, ...],
            *,
            cwd: Path,
            env: dict[str, str],
            stdin: int,
            capture_output: bool,
            check: bool,
            timeout: int,
        ) -> subprocess.CompletedProcess[bytes]:
            del stdin, capture_output, check, timeout
            observed_commands.append(command)
            observed_environments.append(env)
            observed_working_directories.append(cwd)
            backend = Path(command[command.index("--outdir") + 1])
            (backend / "netveil_audit-0.3.0-py3-none-any.whl").write_bytes(
                backend_wheel
            )
            (backend / "netveil_audit-0.3.0.tar.gz").write_bytes(backend_sdist)
            return subprocess.CompletedProcess(
                command,
                0,
                stdout=b"",
                stderr=b"",
            )

        with tempfile.TemporaryDirectory() as temporary:
            project = Path(temporary) / "project"
            project.mkdir()
            output = Path(temporary) / "release"
            with (
                patch(
                    "tools.build_release._export_clean_head",
                    side_effect=fake_export,
                ),
                patch(
                    "tools.build_release._git_source_commit",
                    return_value=SOURCE_COMMIT,
                ),
                patch(
                    "tools.build_release.subprocess.run",
                    side_effect=fake_run,
                ),
            ):
                inventory = build_release.build_release(
                    project,
                    output,
                    source_date_epoch=EPOCH,
                    python_executable=Path(sys.executable),
                )

            wheel = output / "netveil_audit-0.3.0-py3-none-any.whl"
            normalized_sdist = output / "netveil_audit-0.3.0.tar.gz"
            self.assertEqual(wheel.read_bytes(), backend_wheel)
            self.assertEqual(
                normalized_sdist.read_bytes(),
                build_release.normalize_sdist_bytes(
                    backend_sdist,
                    source_date_epoch=EPOCH,
                ),
            )
            self.assertEqual(
                (output / build_release.INVENTORY_FILENAME).read_bytes(),
                inventory,
            )
            self.assertEqual(json.loads(inventory)["source_commit"], SOURCE_COMMIT)

        self.assertEqual(len(observed_commands), 1)
        command = observed_commands[0]
        self.assertEqual(
            command[:4],
            (
                os.path.abspath(sys.executable),
                "-m",
                "build",
                "--no-isolation",
            ),
        )
        backend_path = Path(command[command.index("--outdir") + 1])
        self.assertFalse(backend_path.is_relative_to(project))
        self.assertEqual(observed_working_directories, [Path(command[-1])])
        self.assertFalse(observed_working_directories[0].is_relative_to(project))
        self.assertEqual(
            observed_environments[0],
            dict(
                build_release.sanitized_build_environment(
                    source_date_epoch=EPOCH,
                    home=Path(observed_environments[0]["HOME"]),
                )
            ),
        )


if __name__ == "__main__":
    unittest.main()
