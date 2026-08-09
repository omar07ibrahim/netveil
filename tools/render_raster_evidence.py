#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import io
import json
import os
import platform
import re
import stat
import sys
import tempfile
import textwrap
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import Any, NoReturn

from PIL import Image, ImageDraw, ImageFont
from PIL import __version__ as PILLOW_VERSION

from tools import render_evidence

ROOT = Path(__file__).resolve().parents[1]
GENERATOR_PATH = ROOT / "tools" / "render_raster_evidence.py"
VERIFICATION_PATH = ROOT / "docs" / "evidence" / "fresh-wheel-verification.json"
INVENTORY_PATH = ROOT / "docs" / "evidence" / "release-inventory.json"
VECTOR_MANIFEST_PATH = ROOT / "docs" / "evidence" / "visual-manifest.json"
CAST_PATH = ROOT / "docs" / "evidence" / "cli-session.cast"

TERMINAL_PNG_PATH = "docs/assets/cli-session.png"
SUMMARY_PNG_PATH = "docs/assets/verification-summary.png"
WORKFLOW_GIF_PATH = "docs/assets/workflow-demo.gif"
MANIFEST_PATH = "docs/evidence/raster-manifest.json"
RASTER_OUTPUT_PATHS = (
    TERMINAL_PNG_PATH,
    SUMMARY_PNG_PATH,
    WORKFLOW_GIF_PATH,
)
ALL_OUTPUT_PATHS = (*RASTER_OUTPUT_PATHS, MANIFEST_PATH)

SCHEMA = "netveil.raster-evidence.v1"
MAX_INPUT_BYTES = 2 * 1024 * 1024
MAX_TRANSCRIPT_LINES = 64
ANSI_ESCAPE = re.compile(r"\x1b(?:[@-_][0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")

BACKGROUND = (9, 15, 28)
PANEL = (17, 27, 46)
PANEL_ALT = (24, 38, 62)
TEXT = (232, 238, 247)
MUTED = (151, 166, 190)
ACCENT = (89, 210, 172)
BLUE = (96, 165, 250)
AMBER = (251, 191, 36)
RED = (248, 113, 113)


class RasterEvidenceError(RuntimeError):
    """Raster evidence is malformed, unsafe, inconsistent, or stale."""


def _fail(message: str) -> NoReturn:
    raise RasterEvidenceError(message)


def _canonical_json(document: object) -> bytes:
    return (
        json.dumps(
            document,
            ensure_ascii=True,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
        + b"\n"
    )


def _sha256(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


def _entry(path: str, payload: bytes) -> dict[str, object]:
    return {
        "path": path,
        "sha256": _sha256(payload),
        "size_bytes": len(payload),
    }


def _font(size: int) -> Any:
    return ImageFont.load_default(size=size)


def _png_bytes(image: Image.Image) -> bytes:
    output = io.BytesIO()
    image.save(
        output,
        format="PNG",
        optimize=False,
        compress_level=9,
        dpi=(96, 96),
    )
    return output.getvalue()


def _gif_bytes(frames: Sequence[Image.Image]) -> bytes:
    if len(frames) != 6:
        _fail("workflow animation must contain exactly six frames")
    output = io.BytesIO()
    frames[0].save(
        output,
        format="GIF",
        save_all=True,
        append_images=list(frames[1:]),
        duration=(900, 900, 1050, 1250, 1050, 1400),
        disposal=2,
        optimize=False,
    )
    return output.getvalue()


def _wrap_lines(text: str, width: int) -> list[str]:
    lines: list[str] = []
    for raw_line in text.splitlines():
        if not raw_line:
            lines.append("")
            continue
        wrapped = textwrap.wrap(
            raw_line,
            width=width,
            break_long_words=True,
            break_on_hyphens=False,
            drop_whitespace=False,
            replace_whitespace=False,
        )
        lines.extend(wrapped or [""])
    if len(lines) > MAX_TRANSCRIPT_LINES:
        _fail("captured transcript exceeds the raster line bound")
    return lines


def _validated_facts(
    verification_payload: bytes,
    inventory_payload: bytes,
    vector_manifest_payload: bytes,
    cast_payload: bytes,
    *,
    vector_generator_payload: bytes,
) -> render_evidence.EvidenceFacts:
    vector_outputs = render_evidence.render_bundle(
        verification_payload,
        inventory_payload,
        generator_payload=vector_generator_payload,
    )
    if vector_outputs[render_evidence.MANIFEST_PATH] != vector_manifest_payload:
        _fail("vector manifest is stale")
    if vector_outputs[render_evidence.CAST_PATH] != cast_payload:
        _fail("terminal cast is stale")
    for line in cast_payload.splitlines():
        try:
            json.loads(line)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise RasterEvidenceError("terminal cast is not valid JSONL") from error
    return render_evidence.parse_evidence(
        verification_payload,
        inventory_payload,
    )


def _terminal_transcript(facts: render_evidence.EvidenceFacts) -> str:
    receipt = facts.receipt_stdout.decode("utf-8").rstrip("\n")
    transcript = (
        "$ netveil-audit --version\n"
        f"{facts.version_stdout}"
        "$ netveil-audit receipt documentation-corpus.txt "
        "--key-file public-demo.key\n"
        f"{receipt}\n"
    )
    transcript = ANSI_ESCAPE.sub("", transcript)
    forbidden = (
        "/home/",
        "/Users/",
        "BEGIN PRIVATE KEY",
        "OPENAI_API_KEY",
        "NETVEIL_KEY",
    )
    if any(value in transcript for value in forbidden):
        _fail("terminal transcript contains a private-path or credential marker")
    return transcript


def _draw_window_header(
    draw: Any,
    *,
    width: int,
    title: str,
    subtitle: str,
) -> None:
    draw.rounded_rectangle(
        (36, 30, width - 36, 122),
        radius=18,
        fill=PANEL_ALT,
        outline=(51, 68, 96),
        width=2,
    )
    for index, color in enumerate((RED, AMBER, ACCENT)):
        x = 65 + index * 28
        draw.ellipse((x, 63, x + 13, 76), fill=color)
    draw.text((170, 49), title, font=_font(26), fill=TEXT)
    draw.text((170, 82), subtitle, font=_font(16), fill=MUTED)


def _render_terminal(facts: render_evidence.EvidenceFacts) -> bytes:
    lines = _wrap_lines(_terminal_transcript(facts), 112)
    line_height = 27
    height = 190 + len(lines) * line_height + 66
    if height > 2300:
        _fail("terminal raster exceeds its height bound")
    image = Image.new("RGB", (1440, height), BACKGROUND)
    draw = ImageDraw.Draw(image)
    _draw_window_header(
        draw,
        width=1440,
        title="Netveil · verified wheel CLI",
        subtitle=(
            "actual stdout · synthetic IETF documentation corpus · "
            f"source {facts.source_commit[:12]}"
        ),
    )
    draw.rounded_rectangle(
        (36, 145, 1404, height - 42),
        radius=18,
        fill=PANEL,
        outline=(51, 68, 96),
        width=2,
    )
    y = 178
    for line in lines:
        color = ACCENT if line.startswith("$") else TEXT
        if '"report_digest"' in line or '"status"' in line:
            color = BLUE
        draw.text((68, y), line, font=_font(18), fill=color)
        y += line_height
    draw.text(
        (68, height - 34),
        "Rendered deterministically from the committed asciinema cast and receipt.",
        font=_font(14),
        fill=MUTED,
    )
    return _png_bytes(image)


def _draw_metric_bar(
    draw: Any,
    *,
    x: int,
    y: int,
    label: str,
    value: int,
    maximum: int,
    color: tuple[int, int, int],
) -> None:
    draw.text((x, y), label, font=_font(17), fill=TEXT)
    draw.text((x + 390, y), str(value), font=_font(18), fill=color)
    draw.rounded_rectangle(
        (x, y + 30, x + 430, y + 46),
        radius=8,
        fill=(38, 52, 76),
    )
    extent = 0 if maximum == 0 else max(4, int(430 * value / maximum))
    if extent:
        draw.rounded_rectangle(
            (x, y + 30, x + extent, y + 46),
            radius=8,
            fill=color,
        )


def _render_summary(facts: render_evidence.EvidenceFacts) -> bytes:
    image = Image.new("RGB", (1440, 1220), BACKGROUND)
    draw = ImageDraw.Draw(image)
    _draw_window_header(
        draw,
        width=1440,
        title="Netveil · release evidence summary",
        subtitle=(
            f"{len(facts.checks)} verifier checks · {len(facts.traces)} traces · "
            f"CPython {facts.interpreter}"
        ),
    )
    draw.rounded_rectangle(
        (36, 145, 704, 655),
        radius=18,
        fill=PANEL,
        outline=(51, 68, 96),
        width=2,
    )
    draw.text((66, 174), "Public receipt facts", font=_font(24), fill=TEXT)
    metrics = (
        ("Physical lines", facts.physical_lines, BLUE),
        ("Endpoint occurrences", facts.endpoint_occurrences, ACCENT),
        ("Unique endpoints", facts.unique_endpoints, AMBER),
        ("Duplicate groups", facts.duplicate_groups, RED),
    )
    maximum = max(value for _, value, _ in metrics)
    for index, (label, value, color) in enumerate(metrics):
        _draw_metric_bar(
            draw,
            x=68,
            y=232 + index * 92,
            label=label,
            value=value,
            maximum=maximum,
            color=color,
        )
    draw.text(
        (68, 606),
        "Counts are from the verified synthetic documentation-range receipt.",
        font=_font(14),
        fill=MUTED,
    )

    draw.rounded_rectangle(
        (736, 145, 1404, 655),
        radius=18,
        fill=PANEL,
        outline=(51, 68, 96),
        width=2,
    )
    draw.text((766, 174), "Observed execution boundary", font=_font(24), fill=TEXT)
    y = 232
    for trace in facts.traces:
        draw.rounded_rectangle(
            (766, y, 1374, y + 122),
            radius=14,
            fill=PANEL_ALT,
        )
        draw.text((790, y + 18), trace.label, font=_font(20), fill=BLUE)
        draw.text(
            (790, y + 54),
            f"network syscalls  {trace.network_count}",
            font=_font(18),
            fill=ACCENT if trace.network_count == 0 else RED,
        )
        draw.text(
            (790, y + 82),
            f"post-launch children  {trace.child_count}",
            font=_font(18),
            fill=ACCENT if trace.child_count == 0 else RED,
        )
        y += 145
    draw.text(
        (766, 606),
        "Two fixed Linux strace observations; not a universal network-proof claim.",
        font=_font(14),
        fill=MUTED,
    )

    draw.rounded_rectangle(
        (36, 687, 1404, 1178),
        radius=18,
        fill=PANEL,
        outline=(51, 68, 96),
        width=2,
    )
    draw.text((66, 716), "Fresh-wheel verification matrix", font=_font(24), fill=TEXT)
    midpoint = (len(facts.checks) + 1) // 2
    columns = (facts.checks[:midpoint], facts.checks[midpoint:])
    for column, checks in enumerate(columns):
        x = 72 + column * 665
        for index, check in enumerate(checks):
            y = 770 + index * 36
            draw.ellipse((x, y + 4, x + 14, y + 18), fill=ACCENT)
            draw.text((x + 27, y), check.replace("_", " "), font=_font(16), fill=TEXT)
    draw.text(
        (66, 1137),
        f"All {len(facts.checks)} recorded checks passed · source {facts.source_commit}",
        font=_font(14),
        fill=MUTED,
    )
    return _png_bytes(image)


def _workflow_frame(
    facts: render_evidence.EvidenceFacts,
    *,
    index: int,
    title: str,
    kicker: str,
    items: Sequence[str],
) -> Image.Image:
    image = Image.new("RGB", (1280, 720), BACKGROUND)
    draw = ImageDraw.Draw(image)
    draw.text((64, 52), "NETVEIL / REAL EVIDENCE REPLAY", font=_font(16), fill=ACCENT)
    draw.text((64, 91), title, font=_font(38), fill=TEXT)
    draw.text((64, 148), kicker, font=_font(19), fill=MUTED)
    draw.rounded_rectangle(
        (64, 202, 1216, 585),
        radius=24,
        fill=PANEL,
        outline=(51, 68, 96),
        width=2,
    )
    y = 246
    for item in items:
        wrapped = textwrap.wrap(item, width=85, break_on_hyphens=False) or [""]
        draw.ellipse((96, y + 7, 112, y + 23), fill=BLUE)
        for line_index, line in enumerate(wrapped):
            draw.text(
                (130, y + line_index * 29),
                line,
                font=_font(21),
                fill=TEXT,
            )
        y += max(58, len(wrapped) * 29 + 20)
    for step in range(6):
        x = 64 + step * 192
        color = ACCENT if step <= index else (51, 68, 96)
        draw.rounded_rectangle((x, 632, x + 156, 644), radius=6, fill=color)
    draw.text(
        (64, 668),
        f"frame {index + 1}/6 · source {facts.source_commit[:12]}",
        font=_font(15),
        fill=MUTED,
    )
    return image


def _render_workflow(facts: render_evidence.EvidenceFacts) -> bytes:
    artifacts = {artifact.kind: artifact for artifact in facts.artifacts}
    wheel = artifacts["wheel"]
    sdist = artifacts["sdist"]
    frames = [
        _workflow_frame(
            facts,
            index=0,
            title="Build from an immutable source revision",
            kicker="The release inventory binds exact wheel and sdist bytes.",
            items=(
                f"wheel  {wheel.size_bytes} bytes  sha256:{wheel.sha256[:16]}…",
                f"sdist  {sdist.size_bytes} bytes  sha256:{sdist.sha256[:16]}…",
                f"source commit  {facts.source_commit}",
            ),
        ),
        _workflow_frame(
            facts,
            index=1,
            title="Install the exact wheel into a fresh venv",
            kicker="No index and no dependencies are used for the installed artifact.",
            items=(
                "The static launcher and installed RECORD are captured separately.",
                f"launcher mode {facts.launcher_mode} · {facts.launcher_size_bytes} bytes",
                f"closed RECORD inventory · {facts.selected_record_rows} selected rows",
            ),
        ),
        _workflow_frame(
            facts,
            index=2,
            title="Run the guarded installed command",
            kicker="The recorded stdout comes from the verified wheel.",
            items=(
                f"$ netveil-audit --version -> {facts.version_stdout.strip()}",
                "$ netveil-audit receipt documentation-corpus.txt --key-file …",
                "Only synthetic IETF documentation ranges enter this replay.",
            ),
        ),
        _workflow_frame(
            facts,
            index=3,
            title="Emit one pseudonymized aggregate receipt",
            kicker="Counts and equality remain visible; raw endpoints and key bytes do not.",
            items=(
                f"{facts.endpoint_occurrences} occurrences · {facts.unique_endpoints} unique",
                f"IPv4 {facts.ipv4_occurrences} · IPv6 {facts.ipv6_occurrences}",
                f"duplicate groups {facts.duplicate_groups} · source bytes {facts.source_bytes}",
            ),
        ),
        _workflow_frame(
            facts,
            index=4,
            title="Observe the narrow syscall boundary",
            kicker="Fixed Linux traces are evidence, not a universal non-network theorem.",
            items=tuple(
                f"{trace.label}: network={trace.network_count}, "
                f"post-launch children={trace.child_count}, exec={trace.exec_count}"
                for trace in facts.traces
            ),
        ),
        _workflow_frame(
            facts,
            index=5,
            title="Verify, reproduce, and state the limit",
            kicker="Every claim remains bound to the recorded artifact and environment.",
            items=(
                f"{len(facts.checks)}/{len(facts.checks)} verifier checks passed",
                "Pseudonymization is not anonymity or authorization to probe systems.",
                "The manifest binds every PNG/GIF byte to the same release evidence.",
            ),
        ),
    ]
    return _gif_bytes(frames)


def render_bundle(
    verification_payload: bytes,
    inventory_payload: bytes,
    vector_manifest_payload: bytes,
    cast_payload: bytes,
    *,
    generator_payload: bytes,
    vector_generator_payload: bytes,
) -> dict[str, bytes]:
    """Render the complete raster bundle from validated release evidence."""

    facts = _validated_facts(
        verification_payload,
        inventory_payload,
        vector_manifest_payload,
        cast_payload,
        vector_generator_payload=vector_generator_payload,
    )
    outputs = {
        TERMINAL_PNG_PATH: _render_terminal(facts),
        SUMMARY_PNG_PATH: _render_summary(facts),
        WORKFLOW_GIF_PATH: _render_workflow(facts),
    }
    manifest = {
        "claim_boundary": (
            "deterministic renderings of one synthetic fresh-wheel verification; "
            "not anonymity, authorization, publisher authentication, or host attestation"
        ),
        "generator": _entry("tools/render_raster_evidence.py", generator_payload),
        "inputs": [
            _entry(
                "docs/evidence/fresh-wheel-verification.json",
                verification_payload,
            ),
            _entry("docs/evidence/release-inventory.json", inventory_payload),
            _entry("docs/evidence/visual-manifest.json", vector_manifest_payload),
            _entry("docs/evidence/cli-session.cast", cast_payload),
            _entry("tools/render_evidence.py", vector_generator_payload),
        ],
        "outputs": [_entry(path, outputs[path]) for path in sorted(outputs)],
        "runtime": {
            "font": "Pillow embedded default",
            "pillow": PILLOW_VERSION,
            "python": platform.python_version(),
        },
        "schema": SCHEMA,
        "source_commit": facts.source_commit,
    }
    outputs[MANIFEST_PATH] = _canonical_json(manifest)
    return outputs


def _read_input(path: Path, label: str) -> bytes:
    try:
        status = path.lstat()
        if (
            not stat.S_ISREG(status.st_mode)
            or not 0 < status.st_size <= MAX_INPUT_BYTES
        ):
            _fail(f"{label} is not one bounded regular file")
        payload = path.read_bytes()
    except OSError as error:
        raise RasterEvidenceError(f"{label} cannot be read") from error
    if len(payload) != status.st_size:
        _fail(f"{label} changed while being read")
    return payload


def _assert_safe_target(path: Path) -> None:
    try:
        relative = path.relative_to(ROOT)
    except ValueError:
        _fail("generated output escaped the repository")
    current = ROOT
    for part in relative.parts[:-1]:
        current /= part
        if current.exists() and current.is_symlink():
            _fail(f"generated output parent is a symlink: {relative.as_posix()}")
    if path.exists() and not stat.S_ISREG(path.lstat().st_mode):
        _fail(f"generated output is not regular: {relative.as_posix()}")


def _replace_file(path: Path, payload: bytes) -> None:
    _assert_safe_target(path)
    temporary: Path | None = None
    try:
        path.parent.mkdir(mode=0o755, parents=True, exist_ok=True)
        descriptor, raw_temporary = tempfile.mkstemp(
            prefix=f".{path.name}.",
            dir=path.parent,
        )
        temporary = Path(raw_temporary)
        try:
            os.fchmod(descriptor, 0o644)
            offset = 0
            while offset < len(payload):
                written = os.write(descriptor, payload[offset:])
                if written <= 0:
                    raise OSError("write made no progress")
                offset += written
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        os.replace(temporary, path)
    except OSError as error:
        if temporary is not None:
            try:
                temporary.unlink(missing_ok=True)
            except OSError:
                pass
        raise RasterEvidenceError(f"cannot publish {path.name}") from error


def _check_outputs(outputs: Mapping[str, bytes]) -> None:
    stale: list[str] = []
    for relative_path in ALL_OUTPUT_PATHS:
        path = ROOT / relative_path
        _assert_safe_target(path)
        try:
            observed = path.read_bytes()
        except OSError:
            stale.append(relative_path)
            continue
        if observed != outputs[relative_path]:
            stale.append(relative_path)
    if stale:
        _fail("stale generated raster evidence: " + ", ".join(stale))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render deterministic PNG and GIF views from committed Netveil "
            "release evidence."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless every committed raster byte is current",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(argv)
    try:
        outputs = render_bundle(
            _read_input(VERIFICATION_PATH, "fresh-wheel verification"),
            _read_input(INVENTORY_PATH, "release inventory"),
            _read_input(VECTOR_MANIFEST_PATH, "vector manifest"),
            _read_input(CAST_PATH, "terminal cast"),
            generator_payload=_read_input(GENERATOR_PATH, "raster renderer"),
            vector_generator_payload=_read_input(
                render_evidence.GENERATOR_PATH,
                "vector renderer",
            ),
        )
        if namespace.check:
            _check_outputs(outputs)
        else:
            for relative_path in ALL_OUTPUT_PATHS:
                _replace_file(ROOT / relative_path, outputs[relative_path])
    except (RasterEvidenceError, render_evidence.EvidenceRenderError) as error:
        print(f"netveil-raster-renderer: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
