#!/usr/bin/env python3
"""Render the code-derived Netveil execution-boundary diagram."""

from __future__ import annotations

import argparse
import ast
import html
from pathlib import Path
from typing import Final

ROOT: Final = Path(__file__).resolve().parents[1]
OUTPUT: Final = ROOT / "docs" / "assets" / "architecture.svg"


def _integer(expression: ast.expr) -> int:
    if isinstance(expression, ast.Constant) and type(expression.value) is int:
        return expression.value
    if isinstance(expression, ast.BinOp) and isinstance(expression.op, ast.Mult):
        return _integer(expression.left) * _integer(expression.right)
    raise ValueError("unsupported integer constant")


def _assignments(path: Path) -> dict[str, ast.expr]:
    tree = ast.parse(path.read_bytes(), filename=str(path))
    values: dict[str, ast.expr] = {}
    for node in tree.body:
        if isinstance(node, ast.Assign) and len(node.targets) == 1:
            target = node.targets[0]
            if isinstance(target, ast.Name):
                values[target.id] = node.value
        elif isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name):
            if node.value is not None:
                values[node.target.id] = node.value
    return values


def _source_contract() -> tuple[str, int, int, int, tuple[str, ...]]:
    launcher = (ROOT / "scripts" / "netveil-audit").read_text()
    handoff = 'exec "$netveil_script_directory/python" -IESB "$0" "$@"'
    if handoff not in launcher:
        raise ValueError("launcher isolation handoff changed")

    parser = _assignments(ROOT / "src" / "netveil" / "parser.py")
    cli = _assignments(ROOT / "src" / "netveil" / "cli.py")
    bootstrap = _assignments(ROOT / "src" / "netveil_bootstrap.py")
    source_modules = ast.literal_eval(bootstrap["_SOURCE_MODULES"])
    module_names = tuple(module for module, _, _ in source_modules)
    return (
        "-I -E -S -B",
        _integer(parser["MAX_INPUT_BYTES"]),
        _integer(parser["MAX_PHYSICAL_LINES"]),
        _integer(cli["_MAX_KEY_BYTES"]),
        module_names,
    )


def _text(
    x: int,
    y: int,
    value: str,
    *,
    size: int = 16,
    weight: int = 400,
    fill: str = "#d8e3f0",
    anchor: str = "start",
) -> str:
    return (
        f'<text x="{x}" y="{y}" text-anchor="{anchor}" '
        f'font-family="Inter,Segoe UI,Arial,sans-serif" font-size="{size}" '
        f'font-weight="{weight}" fill="{fill}">{html.escape(value)}</text>'
    )


def _box(
    x: int,
    y: int,
    width: int,
    height: int,
    *,
    fill: str,
    stroke: str,
    title: str,
    lines: tuple[str, ...],
) -> str:
    content = [
        (
            f'<rect x="{x}" y="{y}" width="{width}" height="{height}" rx="16" '
            f'fill="{fill}" stroke="{stroke}" stroke-width="2"/>'
        ),
        _text(x + 22, y + 34, title, size=18, weight=700, fill="#f8fbff"),
    ]
    for index, line in enumerate(lines):
        content.append(
            _text(
                x + 22,
                y + 64 + index * 24,
                line,
                size=14,
                fill="#c7d3e0",
            )
        )
    return "\n".join(content)


def render() -> bytes:
    flags, max_bytes, max_lines, max_key, modules = _source_contract()
    module_label = ", ".join(modules)
    mib = max_bytes // (1024 * 1024)
    svg = [
        (
            '<svg xmlns="http://www.w3.org/2000/svg" width="1440" height="1000" '
            'viewBox="0 0 1440 1000" role="img" '
            'aria-labelledby="title description">'
        ),
        '<title id="title">Netveil installed execution and trust boundary</title>',
        (
            '<desc id="description">Code-derived architecture from the installed '
            "polyglot launcher through pinned source loading to a pseudonymized "
            "receipt.</desc>"
        ),
        "<defs>",
        (
            '<linearGradient id="background" x1="0" y1="0" x2="1" y2="1">'
            '<stop offset="0" stop-color="#07111f"/>'
            '<stop offset="1" stop-color="#101c2f"/>'
            "</linearGradient>"
        ),
        (
            '<marker id="arrow" viewBox="0 0 10 10" refX="9" refY="5" '
            'markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
            '<path d="M 0 0 L 10 5 L 0 10 z" fill="#7dd3fc"/>'
            "</marker>"
        ),
        "</defs>",
        '<rect width="1440" height="1000" fill="url(#background)"/>',
        _text(70, 66, "Netveil installed execution boundary", size=34, weight=750),
        _text(
            70,
            99,
            "Generated from the 0.3.0 launcher, parser, CLI and bootstrap sources",
            size=16,
            fill="#8fa7bd",
        ),
        _box(
            70,
            145,
            390,
            170,
            fill="#33251a",
            stroke="#f59e0b",
            title="1  Trusted startup",
            lines=(
                "/bin/sh → sibling CPython",
                f"combined flags: {flags}",
                "no site hooks • env ignored • safe path",
                "launcher + installed RECORD are trust roots",
            ),
        ),
        _box(
            525,
            145,
            390,
            170,
            fill="#142a32",
            stroke="#22d3ee",
            title="2  Artifact drift guard",
            lines=(
                "launcher and bootstrap: installed hash + size",
                "bounded O_NOFOLLOW descriptor reads",
                "identity checked before and after read",
                "installed RECORD is not a signature",
            ),
        ),
        _box(
            980,
            145,
            390,
            170,
            fill="#17273a",
            stroke="#60a5fa",
            title="3  Closed source loader",
            lines=(
                f"{len(modules)} allowed modules",
                "pinned source bytes compiled in memory",
                "unknown netveil.* imports rejected",
                "package bytecode never executes",
            ),
        ),
        (
            '<path d="M 460 230 L 525 230" stroke="#7dd3fc" stroke-width="3" '
            'marker-end="url(#arrow)"/>'
        ),
        (
            '<path d="M 915 230 L 980 230" stroke="#7dd3fc" stroke-width="3" '
            'marker-end="url(#arrow)"/>'
        ),
        _box(
            70,
            395,
            600,
            205,
            fill="#1f2038",
            stroke="#a78bfa",
            title="4  Sensitive local inputs",
            lines=(
                f"corpus: regular file • ≤ {mib} MiB • ≤ {max_lines:,} lines",
                f"key: owner-only regular file • 32–{max_key:,} exact bytes",
                "same inode or byte-identical corpus/key rejected",
                "sensitive values omitted from handled output",
                "no DNS, socket or child-process workflow",
            ),
        ),
        _box(
            770,
            395,
            600,
            205,
            fill="#173126",
            stroke="#34d399",
            title="5  Public deterministic result",
            lines=(
                "parse → canonicalize → aggregate",
                "domain-separated HMAC-SHA256 identifiers",
                "fixed-schema sorted-key canonical JSON",
                "receipt digest binds the public report",
                "pseudonymized, not anonymous",
            ),
        ),
        (
            '<path d="M 720 315 L 720 350 L 370 350 L 370 395" '
            'stroke="#7dd3fc" stroke-width="3" marker-end="url(#arrow)" '
            'fill="none"/>'
        ),
        (
            '<path d="M 670 498 L 770 498" stroke="#7dd3fc" stroke-width="3" '
            'marker-end="url(#arrow)"/>'
        ),
        (
            '<rect x="70" y="665" width="1300" height="215" rx="16" '
            'fill="#0b1626" stroke="#334a62" stroke-width="2"/>'
        ),
        _text(94, 704, "Exact source inventory", size=18, weight=700, fill="#f8fbff"),
        _text(94, 739, module_label, size=14, fill="#9fb7cc"),
        _text(94, 792, "Trust-root legend", size=16, weight=700, fill="#fbbf24"),
        _text(
            94,
            823,
            "amber = executes before or supplies the mutable consistency boundary",
            size=14,
            fill="#c7d3e0",
        ),
        _text(760, 792, "Verified-byte legend", size=16, weight=700, fill="#67e8f9"),
        _text(
            760,
            823,
            "cyan / blue = checked before compilation by the supported installed path",
            size=14,
            fill="#c7d3e0",
        ),
        _text(
            70,
            935,
            "Reproduce: python3 tools/render_architecture.py --check",
            size=14,
            fill="#6f8aa3",
        ),
        _text(
            1370,
            935,
            "No network data or endpoint fixture is used by this diagram",
            size=14,
            fill="#6f8aa3",
            anchor="end",
        ),
        "</svg>",
    ]
    return ("\n".join(svg) + "\n").encode()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--check",
        action="store_true",
        help="fail when the committed SVG differs from generated bytes",
    )
    arguments = parser.parse_args()
    payload = render()
    if arguments.check:
        if not OUTPUT.is_file() or OUTPUT.read_bytes() != payload:
            raise SystemExit("architecture.svg is stale")
        return 0
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT.write_bytes(payload)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
