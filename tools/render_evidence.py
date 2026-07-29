#!/usr/bin/env python3
"""Render Netveil's committed release evidence as deterministic inert visuals."""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import stat
import sys
import tempfile
import textwrap
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Final, NoReturn, cast

ROOT: Final = Path(__file__).resolve().parents[1]
VERIFICATION_PATH: Final = ROOT / "docs/evidence/fresh-wheel-verification.json"
INVENTORY_PATH: Final = ROOT / "docs/evidence/release-inventory.json"
GENERATOR_PATH: Final = ROOT / "tools/render_evidence.py"

CLI_SVG_PATH: Final = "docs/assets/cli-session.svg"
COUNTS_SVG_PATH: Final = "docs/assets/receipt-counts.svg"
MATRIX_SVG_PATH: Final = "docs/assets/verification-matrix.svg"
PROVENANCE_SVG_PATH: Final = "docs/assets/artifact-provenance.svg"
CAST_PATH: Final = "docs/evidence/cli-session.cast"
MANIFEST_PATH: Final = "docs/evidence/visual-manifest.json"

VISUAL_OUTPUT_PATHS: Final = (
    CLI_SVG_PATH,
    COUNTS_SVG_PATH,
    MATRIX_SVG_PATH,
    PROVENANCE_SVG_PATH,
    CAST_PATH,
)
ALL_OUTPUT_PATHS: Final = (*VISUAL_OUTPUT_PATHS, MANIFEST_PATH)

VERIFICATION_SCHEMA: Final = "netveil.fresh-wheel-verification.v1"
INVENTORY_SCHEMA: Final = "netveil.release-inventory.v1"
VISUAL_MANIFEST_SCHEMA: Final = "netveil.visual-evidence.v1"
MAX_INPUT_BYTES: Final = 16 * 1_048_576
LOWER_HEX: Final = frozenset("0123456789abcdef")
RAW_ENDPOINTS: Final = (
    "192.0.2.10",
    "198.51.100.20",
    "203.0.113.30",
    "2001:db8::10",
)

BACKGROUND: Final = "#07111f"
PANEL: Final = "#101d31"
PANEL_ALT: Final = "#0c1728"
BORDER: Final = "#29405e"
TEXT: Final = "#f4f8ff"
MUTED: Final = "#a8b7c9"
CYAN: Final = "#67e8f9"
VIOLET: Final = "#c4b5fd"
GREEN: Final = "#86efac"
AMBER: Final = "#fcd34d"
PINK: Final = "#fda4af"
MONO: Final = "DejaVu Sans Mono,ui-monospace,SFMono-Regular,Consolas,monospace"
SANS: Final = "DejaVu Sans,Arial,sans-serif"


class EvidenceRenderError(RuntimeError):
    """The evidence bundle is absent, malformed, inconsistent, or stale."""


@dataclass(frozen=True, slots=True)
class ArtifactFact:
    """One release artifact represented in both evidence documents."""

    filename: str
    kind: str
    sha256: str
    size_bytes: int
    member_count: int


@dataclass(frozen=True, slots=True)
class TraceFact:
    """Path-free normalized syscall evidence."""

    label: str
    sha256: str
    exec_count: int
    exit_count: int
    network_count: int
    child_count: int


@dataclass(frozen=True, slots=True)
class EvidenceFacts:
    """Validated facts used by every generated output."""

    source_commit: str
    source_date_epoch: int
    inventory_sha256: str
    artifacts: tuple[ArtifactFact, ...]
    checks: tuple[str, ...]
    interpreter: str
    platform: str
    launcher_mode: str
    launcher_sha256: str
    launcher_size_bytes: int
    record_mode: str
    record_sha256: str
    record_size_bytes: int
    selected_record_rows: int
    traces: tuple[TraceFact, ...]
    version_stdout: str
    receipt: dict[str, object]
    receipt_stdout: bytes
    endpoint_occurrences: int
    unique_endpoints: int
    physical_lines: int
    source_bytes: int
    ipv4_occurrences: int
    ipv6_occurrences: int
    documentation_occurrences: int
    duplicate_groups: int


def _fail(message: str) -> NoReturn:
    raise EvidenceRenderError(message)


def _canonical_json(document: object) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _json_bytes(document: object) -> bytes:
    return _canonical_json(document) + b"\n"


def _unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            _fail("JSON contains a duplicate object key")
        output[key] = value
    return output


def _load_canonical_json(payload: bytes, label: str) -> dict[str, object]:
    if (
        type(payload) is not bytes
        or not 0 < len(payload) <= MAX_INPUT_BYTES
        or not payload.endswith(b"\n")
        or payload.endswith(b"\n\n")
    ):
        _fail(f"{label} is not one bounded canonical JSON line")
    try:
        document = json.loads(
            payload.decode("ascii"),
            object_pairs_hook=_unique_object,
            parse_constant=lambda value: _fail(
                f"{label} contains invalid constant {value}"
            ),
        )
    except EvidenceRenderError:
        raise
    except (UnicodeError, json.JSONDecodeError, ValueError) as error:
        raise EvidenceRenderError(f"{label} is not valid ASCII JSON") from error
    if not isinstance(document, dict) or _json_bytes(document) != payload:
        _fail(f"{label} is not canonical")
    return cast(dict[str, object], document)


def _mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict):
        _fail(f"{label} must be an object")
    return cast(dict[str, object], value)


def _mapping_at(
    document: Mapping[str, object],
    key: str,
    label: str,
) -> dict[str, object]:
    if key not in document:
        _fail(f"{label} is missing {key}")
    return _mapping(document[key], f"{label}.{key}")


def _sequence(value: object, label: str) -> list[object]:
    if not isinstance(value, list):
        _fail(f"{label} must be an array")
    return cast(list[object], value)


def _sequence_at(
    document: Mapping[str, object],
    key: str,
    label: str,
) -> list[object]:
    if key not in document:
        _fail(f"{label} is missing {key}")
    return _sequence(document[key], f"{label}.{key}")


def _text(value: object, label: str, *, allow_newline: bool = False) -> str:
    if not isinstance(value, str) or not value.isascii():
        _fail(f"{label} must be ASCII text")
    forbidden = "\x00\r" if allow_newline else "\x00\r\n"
    if any(character in forbidden for character in value):
        _fail(f"{label} contains a forbidden control character")
    if any(
        ord(character) < 32 and (allow_newline is False or character != "\n")
        for character in value
    ):
        _fail(f"{label} contains a control character")
    return value


def _text_at(
    document: Mapping[str, object],
    key: str,
    label: str,
    *,
    allow_newline: bool = False,
) -> str:
    if key not in document:
        _fail(f"{label} is missing {key}")
    return _text(
        document[key],
        f"{label}.{key}",
        allow_newline=allow_newline,
    )


def _integer(value: object, label: str) -> int:
    if type(value) is not int or value < 0:
        _fail(f"{label} must be a non-negative integer")
    return value


def _integer_at(
    document: Mapping[str, object],
    key: str,
    label: str,
) -> int:
    if key not in document:
        _fail(f"{label} is missing {key}")
    return _integer(document[key], f"{label}.{key}")


def _false_at(document: Mapping[str, object], key: str, label: str) -> None:
    if document.get(key) is not False:
        _fail(f"{label}.{key} must be false")


def _hex(value: object, label: str, length: int) -> str:
    text = _text(value, label)
    if len(text) != length or any(character not in LOWER_HEX for character in text):
        _fail(f"{label} is not lowercase hexadecimal")
    return text


def _mode(value: object, label: str) -> str:
    text = _text(value, label)
    if len(text) != 4 or any(character not in "01234567" for character in text):
        _fail(f"{label} is not a four-digit mode")
    return text


def _parse_artifacts(
    artifacts: list[object],
) -> tuple[ArtifactFact, ...]:
    parsed: list[ArtifactFact] = []
    for index, item in enumerate(artifacts):
        artifact = _mapping(item, f"artifacts[{index}]")
        filename = _text_at(artifact, "filename", "artifact")
        kind = _text_at(artifact, "kind", "artifact")
        if kind not in ("wheel", "sdist"):
            _fail("artifact kind must be wheel or sdist")
        members = (
            _sequence_at(artifact, "members", "artifact") if kind == "sdist" else []
        )
        if kind == "wheel" and "members" in artifact:
            _fail("release inventory wheel must not claim sdist members")
        parsed.append(
            ArtifactFact(
                filename=filename,
                kind=kind,
                sha256=_hex(artifact.get("sha256"), "artifact.sha256", 64),
                size_bytes=_integer_at(artifact, "size_bytes", "artifact"),
                member_count=len(members),
            )
        )
    if (
        len(parsed) != 2
        or {artifact.kind for artifact in parsed} != {"wheel", "sdist"}
        or [artifact.filename for artifact in parsed]
        != sorted(artifact.filename for artifact in parsed)
    ):
        _fail("release artifacts are not the exact sorted wheel/sdist pair")
    return tuple(parsed)


def _parse_checks(raw_checks: list[object]) -> tuple[str, ...]:
    checks: list[str] = []
    for index, item in enumerate(raw_checks):
        check = _mapping(item, f"checks[{index}]")
        if set(check) != {"name", "status"} or check.get("status") != "pass":
            _fail("every evidence check must have exact pass status")
        name = _text_at(check, "name", "check")
        if not name or any(
            character not in "abcdefghijklmnopqrstuvwxyz_" for character in name
        ):
            _fail("check names must be lowercase identifiers")
        checks.append(name)
    required = {
        "coordinated_bootstrap_record_mutation_accepted",
        "public_demo_capture",
        "release_inventory_integrity",
        "source_commit_bound",
        "syscall_trace_offline",
        "tamper_fail_closed",
    }
    if (
        len(checks) < len(required)
        or len(checks) != len(set(checks))
        or not required.issubset(checks)
    ):
        _fail("verification check inventory is incomplete")
    return tuple(checks)


def _parse_traces(raw_traces: list[object]) -> tuple[TraceFact, ...]:
    traces: list[TraceFact] = []
    for index, item in enumerate(raw_traces):
        trace = _mapping(item, f"syscall_traces[{index}]")
        chain = [
            _text(value, "trace.exec_chain item")
            for value in _sequence_at(trace, "exec_chain", "trace")
        ]
        if chain != ["installed_launcher", "installed_python"]:
            _fail("trace exec chain is not the exact launcher/Python pair")
        traces.append(
            TraceFact(
                label=_text_at(trace, "label", "trace"),
                sha256=_hex(
                    trace.get("normalized_sha256"),
                    "trace.normalized_sha256",
                    64,
                ),
                exec_count=_integer_at(trace, "exec_count", "trace"),
                exit_count=_integer_at(trace, "exit_syscall_count", "trace"),
                network_count=_integer_at(
                    trace,
                    "network_syscall_count",
                    "trace",
                ),
                child_count=_integer_at(
                    trace,
                    "post_launch_process_count",
                    "trace",
                ),
            )
        )
    if {trace.label for trace in traces} != {"receipt", "version"} or any(
        trace.exec_count != 2
        or trace.exit_count < 1
        or trace.network_count != 0
        or trace.child_count != 0
        for trace in traces
    ):
        _fail("normalized trace evidence is incomplete")
    return tuple(sorted(traces, key=lambda trace: trace.label))


def _parse_demo(
    demo: Mapping[str, object],
) -> tuple[
    str,
    dict[str, object],
    bytes,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
    int,
]:
    if (
        demo.get("classification")
        != "synthetic_ietf_documentation_ranges_with_public_demo_key"
    ):
        _fail("public demo classification is not exact")
    corpus = _mapping_at(demo, "corpus", "public_demo")
    _hex(corpus.get("sha256"), "public_demo.corpus.sha256", 64)
    _integer_at(corpus, "size_bytes", "public_demo.corpus")
    physical_lines = _integer_at(corpus, "physical_lines", "public_demo.corpus")
    key = _mapping_at(demo, "public_demo_key", "public_demo")
    if (
        key.get("classification") != "public_non_secret_test_material"
        or key.get("source_constant") != "tools/verify_fresh_wheel.py:_PUBLIC_DEMO_KEY"
        or _integer_at(key, "size_bytes", "public_demo.public_demo_key") != 32
    ):
        _fail("public demo key classification is incomplete")
    _hex(key.get("sha256"), "public_demo.public_demo_key.sha256", 64)

    commands = _sequence_at(demo, "commands", "public_demo")
    if len(commands) != 2:
        _fail("public demo must contain exactly two commands")
    version = _mapping(commands[0], "public_demo.commands[0]")
    receipt_command = _mapping(commands[1], "public_demo.commands[1]")
    expected_version_argv = ["netveil-audit", "--version"]
    expected_receipt_argv = [
        "netveil-audit",
        "receipt",
        "documentation-corpus.txt",
        "--key-file",
        "public-demo.key",
    ]
    for command, expected_argv in (
        (version, expected_version_argv),
        (receipt_command, expected_receipt_argv),
    ):
        argv = [
            _text(value, "public demo argv item")
            for value in _sequence_at(command, "argv", "public demo command")
        ]
        if (
            argv != expected_argv
            or _integer_at(command, "exit_code", "public demo command") != 0
            or _text_at(
                command,
                "stderr",
                "public demo command",
                allow_newline=True,
            )
            != ""
        ):
            _fail("public demo command contract changed")
    version_stdout = _text_at(
        version,
        "stdout",
        "public demo version",
        allow_newline=True,
    )
    if version_stdout != "netveil-audit 0.3.0\n":
        _fail("public demo version output changed")

    receipt = _mapping_at(receipt_command, "stdout_json", "public demo receipt")
    receipt_stdout = _json_bytes(receipt)
    if hashlib.sha256(receipt_stdout).hexdigest() != _hex(
        receipt_command.get("stdout_sha256"),
        "public demo receipt stdout_sha256",
        64,
    ):
        _fail("public demo receipt stdout digest does not match")
    if receipt.get("schema") != "netveil.aggregate-receipt.v1":
        _fail("public demo receipt schema changed")
    report = _mapping_at(receipt, "report", "public demo receipt")
    counts = _mapping_at(report, "counts", "public demo report")
    by_version = _mapping_at(
        report,
        "endpoint_occurrences_by_ip_version",
        "public demo report",
    )
    by_scope = _mapping_at(
        report,
        "endpoint_occurrences_by_scope",
        "public demo report",
    )
    duplicates = _mapping_at(report, "duplicates", "public demo report")
    return (
        version_stdout,
        receipt,
        receipt_stdout,
        _integer_at(counts, "endpoint_occurrences", "receipt counts"),
        _integer_at(counts, "unique_endpoints", "receipt counts"),
        physical_lines,
        _integer_at(counts, "source_bytes", "receipt counts"),
        _integer_at(by_version, "ipv4", "receipt by version"),
        _integer_at(by_version, "ipv6", "receipt by version"),
        _integer_at(by_scope, "documentation", "receipt by scope"),
        _integer_at(duplicates, "group_count", "receipt duplicates"),
    )


def parse_evidence(
    verification_payload: bytes,
    inventory_payload: bytes,
) -> EvidenceFacts:
    """Validate the cross-document evidence contract and return renderable facts."""

    verification = _load_canonical_json(
        verification_payload,
        "fresh-wheel verification",
    )
    inventory = _load_canonical_json(inventory_payload, "release inventory")
    if (
        verification.get("schema") != VERIFICATION_SCHEMA
        or verification.get("status") != "pass"
        or inventory.get("schema") != INVENTORY_SCHEMA
    ):
        _fail("evidence schema or status is not publishable")
    source_commit = _hex(
        verification.get("source_commit"),
        "verification.source_commit",
        40,
    )
    if inventory.get("source_commit") != source_commit:
        _fail("verification and inventory source commits differ")
    source_date_epoch = _integer_at(
        inventory,
        "source_date_epoch",
        "release inventory",
    )
    inventory_artifacts = _sequence_at(
        inventory,
        "artifacts",
        "release inventory",
    )
    artifacts = _parse_artifacts(inventory_artifacts)

    integrity = _mapping_at(
        verification,
        "integrity_evidence",
        "verification",
    )
    if (
        integrity.get("artifacts") != inventory_artifacts
        or integrity.get("inventory_schema") != INVENTORY_SCHEMA
        or integrity.get("inventory_type") != "unsigned_sha256_manifest"
        or integrity.get("source_commit") != source_commit
        or integrity.get("source_date_epoch") != source_date_epoch
    ):
        _fail("verification does not embed the exact release inventory facts")
    _false_at(integrity, "signature_verified", "integrity evidence")
    _false_at(integrity, "attestation_verified", "integrity evidence")
    inventory_sha256 = _hex(
        integrity.get("inventory_sha256"),
        "integrity_evidence.inventory_sha256",
        64,
    )
    if inventory_sha256 != hashlib.sha256(inventory_payload).hexdigest():
        _fail("release inventory digest does not match its bytes")

    wheel = _mapping_at(verification, "wheel", "verification")
    wheel_artifact = next(
        artifact for artifact in artifacts if artifact.kind == "wheel"
    )
    if (
        wheel.get("sha256") != wheel_artifact.sha256
        or wheel.get("size_bytes") != wheel_artifact.size_bytes
        or not _sequence_at(wheel, "members", "verification wheel")
    ):
        _fail("wheel verification facts do not match the release inventory")

    installed = _mapping_at(verification, "installed", "verification")
    launcher = _mapping_at(installed, "launcher", "installed")
    record = _mapping_at(installed, "record", "installed")
    rows = _sequence_at(installed, "selected_record_rows", "installed")
    if not rows:
        _fail("installed RECORD evidence is empty")

    interpreter = _mapping_at(verification, "interpreter", "verification")
    platform = _mapping_at(verification, "platform", "verification")
    demo_values = _parse_demo(_mapping_at(verification, "public_demo", "verification"))
    (
        version_stdout,
        receipt,
        receipt_stdout,
        endpoint_occurrences,
        unique_endpoints,
        physical_lines,
        source_bytes,
        ipv4_occurrences,
        ipv6_occurrences,
        documentation_occurrences,
        duplicate_groups,
    ) = demo_values

    if any(
        endpoint.encode("ascii") in verification_payload for endpoint in RAW_ENDPOINTS
    ):
        _fail("public evidence unexpectedly contains raw endpoint text")

    return EvidenceFacts(
        source_commit=source_commit,
        source_date_epoch=source_date_epoch,
        inventory_sha256=inventory_sha256,
        artifacts=artifacts,
        checks=_parse_checks(_sequence_at(verification, "checks", "verification")),
        interpreter=(
            f"{_text_at(interpreter, 'implementation', 'interpreter')} "
            f"{_text_at(interpreter, 'version', 'interpreter')} · "
            f"{_text_at(interpreter, 'cache_tag', 'interpreter')}"
        ),
        platform=(
            f"{_text_at(platform, 'system', 'platform')} "
            f"{_text_at(platform, 'release', 'platform')} · "
            f"{_text_at(platform, 'machine', 'platform')}"
        ),
        launcher_mode=_mode(launcher.get("mode"), "installed launcher mode"),
        launcher_sha256=_hex(
            launcher.get("sha256"),
            "installed launcher sha256",
            64,
        ),
        launcher_size_bytes=_integer_at(
            launcher,
            "size_bytes",
            "installed launcher",
        ),
        record_mode=_mode(record.get("mode"), "installed RECORD mode"),
        record_sha256=_hex(
            record.get("sha256"),
            "installed RECORD sha256",
            64,
        ),
        record_size_bytes=_integer_at(record, "size_bytes", "installed RECORD"),
        selected_record_rows=len(rows),
        traces=_parse_traces(
            _sequence_at(verification, "syscall_traces", "verification")
        ),
        version_stdout=version_stdout,
        receipt=receipt,
        receipt_stdout=receipt_stdout,
        endpoint_occurrences=endpoint_occurrences,
        unique_endpoints=unique_endpoints,
        physical_lines=physical_lines,
        source_bytes=source_bytes,
        ipv4_occurrences=ipv4_occurrences,
        ipv6_occurrences=ipv6_occurrences,
        documentation_occurrences=documentation_occurrences,
        duplicate_groups=duplicate_groups,
    )


def _human_bytes(value: int) -> str:
    if value < 1_024:
        return f"{value} B"
    if value < 1_048_576:
        return f"{value / 1_024:.1f} KiB"
    return f"{value / 1_048_576:.1f} MiB"


def _svg_document(
    *,
    title: str,
    description: str,
    width: int,
    height: int,
    body: Sequence[str],
) -> bytes:
    escaped_title = html.escape(title)
    escaped_description = html.escape(description)
    lines = [
        (
            f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" '
            f'height="{height}" viewBox="0 0 {width} {height}" role="img" '
            'aria-labelledby="title description">'
        ),
        f'<title id="title">{escaped_title}</title>',
        f'<desc id="description">{escaped_description}</desc>',
        "<style>",
        f".bg{{fill:{BACKGROUND}}}",
        f".panel{{fill:{PANEL};stroke:{BORDER};stroke-width:1.5}}",
        f".panel-alt{{fill:{PANEL_ALT};stroke:{BORDER};stroke-width:1.5}}",
        f".title{{fill:{TEXT};font:700 30px {SANS}}}",
        f".subtitle{{fill:{MUTED};font:15px {SANS}}}",
        f".label{{fill:{TEXT};font:600 16px {SANS}}}",
        f".small{{fill:{MUTED};font:13px {SANS}}}",
        f".mono{{fill:{TEXT};font:13px {MONO}}}",
        f".mono-small{{fill:{MUTED};font:12px {MONO}}}",
        f".pass{{fill:{GREEN};font:600 13px {SANS}}}",
        f".warn{{fill:{AMBER};font:600 13px {SANS}}}",
        "</style>",
        f'<rect class="bg" width="{width}" height="{height}" rx="18"/>',
        *body,
        "</svg>",
    ]
    return ("\n".join(lines) + "\n").encode("utf-8")


def _terminal_transcript(facts: EvidenceFacts) -> str:
    receipt = facts.receipt_stdout.decode("ascii").rstrip("\n")
    return (
        "Netveil installed-wheel public demonstration\n"
        f"source commit: {facts.source_commit}\n"
        "input class: synthetic IETF documentation ranges\n"
        "key class: public non-secret test material\n\n"
        "$ netveil-audit --version\n"
        f"{facts.version_stdout}"
        "$ netveil-audit receipt documentation-corpus.txt "
        "--key-file public-demo.key\n"
        f"{receipt}\n"
    )


def _render_cli(facts: EvidenceFacts) -> bytes:
    wrapped: list[str] = []
    for line in _terminal_transcript(facts).rstrip("\n").splitlines():
        wrapped.extend(
            textwrap.wrap(
                line,
                width=126,
                subsequent_indent="  ",
                break_long_words=True,
                break_on_hyphens=False,
                replace_whitespace=False,
                drop_whitespace=False,
            )
            or [""]
        )
    line_height = 21
    height = 245 + len(wrapped) * line_height
    body = [
        '<text x="48" y="56" class="title">Installed CLI · captured stdout</text>',
        (
            '<text x="48" y="86" class="subtitle">Exact successful output '
            "captured by the fresh-wheel verifier; long canonical JSON is "
            "visually wrapped only.</text>"
        ),
        (
            f'<rect x="48" y="116" width="1344" height="{height - 160}" '
            'rx="14" fill="#020817" stroke="#29405e"/>'
        ),
        '<circle cx="76" cy="142" r="6" fill="#fb7185"/>',
        '<circle cx="97" cy="142" r="6" fill="#f59e0b"/>',
        '<circle cx="118" cy="142" r="6" fill="#34d399"/>',
    ]
    y = 180
    for line in wrapped:
        fill = CYAN if line.startswith("$ ") else TEXT
        body.append(
            f'<text x="72" y="{y}" class="mono" fill="{fill}">'
            f"{html.escape(line)}</text>"
        )
        y += line_height
    return _svg_document(
        title="Netveil installed CLI evidence",
        description=(
            "Terminal rendering of exact version and receipt standard output "
            "captured from the verified fresh wheel."
        ),
        width=1440,
        height=height,
        body=body,
    )


def _render_counts(facts: EvidenceFacts) -> bytes:
    metrics = (
        ("physical lines", facts.physical_lines, CYAN),
        ("endpoint occurrences", facts.endpoint_occurrences, VIOLET),
        ("unique endpoints", facts.unique_endpoints, GREEN),
        ("IPv4 occurrences", facts.ipv4_occurrences, "#38bdf8"),
        ("IPv6 occurrences", facts.ipv6_occurrences, "#f472b6"),
        ("duplicate groups", facts.duplicate_groups, AMBER),
    )
    maximum = max(value for _, value, _ in metrics)
    body = [
        '<text x="48" y="56" class="title">Public receipt · disclosed counts</text>',
        (
            '<text x="48" y="86" class="subtitle">Values parsed from the exact '
            "verifier-captured receipt; identifiers and raw endpoints are not "
            "used in this chart.</text>"
        ),
        '<rect x="48" y="120" width="1344" height="470" rx="14" class="panel"/>',
    ]
    y = 175
    for label, value, color in metrics:
        width = 820 * value / maximum if maximum else 0
        body.extend(
            (
                f'<text x="78" y="{y + 16}" class="label">{html.escape(label)}</text>',
                f'<rect x="310" y="{y}" width="860" height="24" rx="7" fill="#07111f"/>',
                f'<rect x="310" y="{y}" width="{width:.2f}" height="24" rx="7" fill="{color}"/>',
                f'<text x="1195" y="{y + 17}" class="mono">{value}</text>',
            )
        )
        y += 62
    body.extend(
        (
            '<rect x="48" y="620" width="660" height="160" rx="14" class="panel-alt"/>',
            '<text x="78" y="660" class="label">Scope result</text>',
            (
                f'<text x="78" y="695" class="mono">{facts.documentation_occurrences} / '
                f"{facts.endpoint_occurrences} occurrences · documentation ranges</text>"
            ),
            (
                '<text x="78" y="730" class="small">Synthetic corpus only; this '
                "is workflow evidence, not a claim about live infrastructure.</text>"
            ),
            '<rect x="732" y="620" width="660" height="160" rx="14" class="panel-alt"/>',
            '<text x="762" y="660" class="label">Disclosure boundary</text>',
            (
                f'<text x="762" y="695" class="mono">{facts.source_bytes} source bytes '
                "are summarized, not embedded</text>"
            ),
            (
                '<text x="762" y="730" class="small">Counts, equality and '
                "frequency remain public; pseudonymized does not mean anonymous.</text>"
            ),
        )
    )
    return _svg_document(
        title="Netveil public receipt count evidence",
        description=(
            "Bar chart of physical lines, endpoint counts, IP versions, and "
            "duplicate groups parsed from the committed public demo receipt."
        ),
        width=1440,
        height=830,
        body=body,
    )


def _render_matrix(facts: EvidenceFacts) -> bytes:
    columns = 3
    rows = (len(facts.checks) + columns - 1) // columns
    height = 500 + rows * 58
    body = [
        '<text x="48" y="56" class="title">Fresh-wheel verification matrix</text>',
        (
            f'<text x="48" y="86" class="subtitle">{len(facts.checks)} exact '
            "checks reported pass by the committed verifier JSON.</text>"
        ),
        '<rect x="48" y="120" width="1344" height="120" rx="14" class="panel"/>',
        (f'<text x="78" y="160" class="label">{html.escape(facts.interpreter)}</text>'),
        f'<text x="78" y="194" class="small">{html.escape(facts.platform)}</text>',
        (
            f'<text x="1360" y="160" text-anchor="end" class="mono">'
            f"{facts.source_commit}</text>"
        ),
        (
            '<text x="1360" y="194" text-anchor="end" class="warn">'
            "unsigned consistency evidence · not attestation</text>"
        ),
    ]
    for index, check in enumerate(facts.checks):
        column = index % columns
        row = index // columns
        x = 48 + column * 448
        y = 270 + row * 58
        body.extend(
            (
                f'<rect x="{x}" y="{y}" width="420" height="42" rx="10" class="panel-alt"/>',
                f'<circle cx="{x + 22}" cy="{y + 21}" r="7" fill="{GREEN}"/>',
                (
                    f'<text x="{x + 42}" y="{y + 26}" class="small">'
                    f"{html.escape(check.replace('_', ' '))}</text>"
                ),
                f'<text x="{x + 398}" y="{y + 26}" text-anchor="end" class="pass">PASS</text>',
            )
        )
    trace_y = 300 + rows * 58
    body.append(
        f'<text x="48" y="{trace_y}" class="label">Normalized offline syscall evidence</text>'
    )
    for index, trace in enumerate(facts.traces):
        x = 48 + index * 680
        body.extend(
            (
                f'<rect x="{x}" y="{trace_y + 24}" width="650" height="105" rx="12" class="panel"/>',
                (
                    f'<text x="{x + 24}" y="{trace_y + 58}" class="label">'
                    f"{html.escape(trace.label)}</text>"
                ),
                (
                    f'<text x="{x + 24}" y="{trace_y + 85}" class="mono-small">'
                    f"exec={trace.exec_count} · network={trace.network_count} · "
                    f"post-launch children={trace.child_count}</text>"
                ),
                (
                    f'<text x="{x + 24}" y="{trace_y + 110}" class="mono-small">'
                    f"normalized sha256 {trace.sha256}</text>"
                ),
            )
        )
    return _svg_document(
        title="Netveil fresh-wheel verification matrix",
        description=(
            "All verifier pass labels, interpreter and platform identity, and "
            "normalized path-free process and network trace evidence."
        ),
        width=1440,
        height=height,
        body=body,
    )


def _render_provenance(facts: EvidenceFacts) -> bytes:
    wheel = next(artifact for artifact in facts.artifacts if artifact.kind == "wheel")
    sdist = next(artifact for artifact in facts.artifacts if artifact.kind == "sdist")
    boxes = (
        (
            48,
            "1 · clean Git HEAD",
            facts.source_commit,
            f"SOURCE_DATE_EPOCH {facts.source_date_epoch}",
            CYAN,
        ),
        (
            390,
            "2 · bound release artifacts",
            f"wheel · {_human_bytes(wheel.size_bytes)} · {wheel.sha256[:20]}…",
            (
                f"sdist · {_human_bytes(sdist.size_bytes)} · "
                f"{sdist.member_count} members"
            ),
            VIOLET,
        ),
        (
            732,
            "3 · fresh installed state",
            (
                f"launcher {facts.launcher_mode} · "
                f"{_human_bytes(facts.launcher_size_bytes)}"
            ),
            (
                f"RECORD {facts.record_mode} · "
                f"{facts.selected_record_rows} selected rows"
            ),
            GREEN,
        ),
        (
            1074,
            "4 · executed evidence",
            f"{len(facts.checks)} checks pass",
            "2 traces · network 0 · children 0",
            AMBER,
        ),
    )
    body = [
        '<text x="48" y="56" class="title">Release evidence chain</text>',
        (
            '<text x="48" y="86" class="subtitle">Every displayed value comes '
            "from the canonical release inventory or fresh-wheel verifier JSON.</text>"
        ),
    ]
    for index, (x, title, line_one, line_two, color) in enumerate(boxes):
        body.extend(
            (
                f'<rect x="{x}" y="140" width="306" height="190" rx="14" class="panel"/>',
                f'<rect x="{x}" y="140" width="306" height="5" rx="3" fill="{color}"/>',
                f'<text x="{x + 22}" y="182" class="label">{html.escape(title)}</text>',
                f'<text x="{x + 22}" y="222" class="mono-small">{html.escape(line_one)}</text>',
                f'<text x="{x + 22}" y="252" class="mono-small">{html.escape(line_two)}</text>',
                (
                    f'<text x="{x + 22}" y="300" class="pass">BOUND IN EVIDENCE</text>'
                    if index
                    else f'<text x="{x + 22}" y="300" class="pass">BUILDER-OBSERVED</text>'
                ),
            )
        )
        if index < len(boxes) - 1:
            body.extend(
                (
                    f'<line x1="{x + 306}" y1="235" x2="{x + 336}" y2="235" stroke="{CYAN}" stroke-width="2"/>',
                    f'<path d="M{x + 336},229 L{x + 348},235 L{x + 336},241 Z" fill="{CYAN}"/>',
                )
            )
    body.extend(
        (
            '<rect x="48" y="380" width="1344" height="210" rx="14" class="panel-alt"/>',
            '<text x="78" y="425" class="label">Exact installed bindings</text>',
            (
                f'<text x="78" y="462" class="mono-small">launcher sha256  '
                f"{facts.launcher_sha256}</text>"
            ),
            (
                f'<text x="78" y="492" class="mono-small">RECORD sha256    '
                f"{facts.record_sha256}</text>"
            ),
            (
                f'<text x="78" y="540" class="mono-small">inventory sha256 '
                f"{facts.inventory_sha256}</text>"
            ),
            '<rect x="48" y="630" width="1344" height="145" rx="14" class="panel"/>',
            '<text x="78" y="674" class="warn">Claim boundary</text>',
            (
                '<text x="78" y="709" class="small">The manifest is unsigned. '
                "It shows internally consistent bytes and an executed test run; "
                "it does not prove publisher identity, an honest host, or an "
                "unmodified verifier.</text>"
            ),
            (
                '<text x="78" y="741" class="small">Authenticate the published '
                "artifact digests through a separate trusted channel.</text>"
            ),
        )
    )
    return _svg_document(
        title="Netveil release evidence chain",
        description=(
            "Source commit, artifact inventory, installed-file, and "
            "fresh execution evidence with an explicit unsigned non-claim."
        ),
        width=1440,
        height=825,
        body=body,
    )


def _render_cast(facts: EvidenceFacts) -> bytes:
    command_one = "$ netveil-audit --version\r\n"
    command_two = (
        "$ netveil-audit receipt documentation-corpus.txt "
        "--key-file public-demo.key\r\n"
    )
    receipt = facts.receipt_stdout.decode("ascii").replace("\n", "\r\n")
    header = {
        "env": {"SHELL": "/bin/sh", "TERM": "xterm-256color"},
        "height": 40,
        "timestamp": facts.source_date_epoch,
        "version": 2,
        "width": 120,
    }
    events: tuple[object, ...] = (
        [
            0.1,
            "o",
            (
                "Netveil verified public demo\r\n"
                "synthetic IETF documentation ranges · public non-secret key\r\n\r\n"
            ),
        ],
        [0.6, "o", command_one],
        [0.9, "o", facts.version_stdout.replace("\n", "\r\n")],
        [1.4, "o", command_two],
        [1.8, "o", receipt],
    )
    lines = [_canonical_json(header), *(_canonical_json(event) for event in events)]
    return b"\n".join(lines) + b"\n"


def render_bundle(
    verification_payload: bytes,
    inventory_payload: bytes,
    *,
    generator_payload: bytes,
) -> dict[str, bytes]:
    """Return every generated output, including the non-self-referential manifest."""

    facts = parse_evidence(verification_payload, inventory_payload)
    outputs = {
        CLI_SVG_PATH: _render_cli(facts),
        COUNTS_SVG_PATH: _render_counts(facts),
        MATRIX_SVG_PATH: _render_matrix(facts),
        PROVENANCE_SVG_PATH: _render_provenance(facts),
        CAST_PATH: _render_cast(facts),
    }
    manifest = {
        "claim_boundary": (
            "unsigned internally consistent build-and-execution evidence; "
            "not publisher authentication, host attestation, or a signature"
        ),
        "generator": {
            "path": "tools/render_evidence.py",
            "sha256": hashlib.sha256(generator_payload).hexdigest(),
            "size_bytes": len(generator_payload),
        },
        "inputs": [
            {
                "path": "docs/evidence/fresh-wheel-verification.json",
                "sha256": hashlib.sha256(verification_payload).hexdigest(),
                "size_bytes": len(verification_payload),
            },
            {
                "path": "docs/evidence/release-inventory.json",
                "sha256": hashlib.sha256(inventory_payload).hexdigest(),
                "size_bytes": len(inventory_payload),
            },
        ],
        "outputs": [
            {
                "path": path,
                "sha256": hashlib.sha256(outputs[path]).hexdigest(),
                "size_bytes": len(outputs[path]),
            }
            for path in sorted(outputs)
        ],
        "schema": VISUAL_MANIFEST_SCHEMA,
        "source_commit": facts.source_commit,
    }
    outputs[MANIFEST_PATH] = _json_bytes(manifest)
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
        raise EvidenceRenderError(f"{label} cannot be read") from error
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
    if path.exists():
        try:
            mode = path.lstat().st_mode
        except OSError as error:
            raise EvidenceRenderError("generated output cannot be inspected") from error
        if not stat.S_ISREG(mode):
            _fail(f"generated output is not regular: {relative.as_posix()}")


def _replace_file(path: Path, payload: bytes) -> None:
    _assert_safe_target(path)
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
        try:
            temporary.unlink(missing_ok=True)
        except (OSError, UnboundLocalError):
            pass
        raise EvidenceRenderError(f"cannot publish {path.name}") from error


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
        _fail("stale generated evidence: " + ", ".join(stale))


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Render deterministic SVG and terminal-cast views from committed "
            "Netveil release evidence."
        )
    )
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail unless every committed generated byte is current",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    namespace = _parser().parse_args(argv)
    try:
        verification_payload = _read_input(
            VERIFICATION_PATH,
            "fresh-wheel verification",
        )
        inventory_payload = _read_input(INVENTORY_PATH, "release inventory")
        generator_payload = _read_input(GENERATOR_PATH, "evidence renderer")
        outputs = render_bundle(
            verification_payload,
            inventory_payload,
            generator_payload=generator_payload,
        )
        if namespace.check:
            _check_outputs(outputs)
        else:
            for relative_path in VISUAL_OUTPUT_PATHS:
                _replace_file(ROOT / relative_path, outputs[relative_path])
            _replace_file(ROOT / MANIFEST_PATH, outputs[MANIFEST_PATH])
    except EvidenceRenderError as error:
        print(f"netveil-evidence-renderer: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
