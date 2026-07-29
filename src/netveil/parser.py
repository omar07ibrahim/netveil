"""Fail-closed parser for local IP endpoint corpora."""

from __future__ import annotations

import ipaddress
import re
from enum import Enum
from typing import NoReturn

from netveil.model import (
    Endpoint,
    EndpointCorpus,
    _create_corpus,
    _create_endpoint,
)

MAX_INPUT_BYTES = 8 * 1024 * 1024
MAX_PHYSICAL_LINES = 100_000

_IPV4_ENDPOINT = re.compile(r"^(?P<address>[^:[\]]+):(?P<port>[0-9]+)$")
_IPV6_ENDPOINT = re.compile(r"^\[(?P<address>[^\[\]]+)\]:(?P<port>[0-9]+)$")
_NON_LF_LINE_SEPARATORS = frozenset(
    {
        "\v",
        "\f",
        "\x1c",
        "\x1d",
        "\x1e",
        "\x85",
        "\u2028",
        "\u2029",
    }
)


class EndpointParseErrorCode(Enum):
    """Stable public error codes that do not expose source values."""

    EMPTY_CORPUS = "empty_corpus"
    INPUT_TOO_LARGE = "input_too_large"
    INVALID_ADDRESS = "invalid_address"
    INVALID_LINE_ENDING = "invalid_line_ending"
    INVALID_PORT = "invalid_port"
    INVALID_SYNTAX = "invalid_syntax"
    INVALID_UTF8 = "invalid_utf8"
    NON_CANONICAL_PORT = "non_canonical_port"
    TOO_MANY_LINES = "too_many_lines"


class EndpointParseError(ValueError):
    """A redacted parse failure."""

    def __init__(
        self,
        code: EndpointParseErrorCode,
        *,
        line_number: int | None = None,
    ) -> None:
        self.code = code
        self.line_number = line_number
        location = "" if line_number is None else f" at line {line_number}"
        super().__init__(f"endpoint corpus rejected: {code.value}{location}")


def _fail(
    code: EndpointParseErrorCode,
    *,
    line_number: int | None = None,
) -> NoReturn:
    raise EndpointParseError(code, line_number=line_number)


def _parse_port(raw_port: str, *, line_number: int) -> int:
    if len(raw_port) > 1 and raw_port.startswith("0"):
        _fail(EndpointParseErrorCode.NON_CANONICAL_PORT, line_number=line_number)
    if len(raw_port) > 5:
        _fail(EndpointParseErrorCode.INVALID_PORT, line_number=line_number)
    port = int(raw_port)
    if not 1 <= port <= 65_535:
        _fail(EndpointParseErrorCode.INVALID_PORT, line_number=line_number)
    return port


def _parse_endpoint(raw_line: str, *, line_number: int) -> Endpoint:
    if raw_line != raw_line.strip() or any(
        character.isspace() for character in raw_line
    ):
        _fail(EndpointParseErrorCode.INVALID_SYNTAX, line_number=line_number)

    ipv6_match = _IPV6_ENDPOINT.fullmatch(raw_line)
    ipv4_match = _IPV4_ENDPOINT.fullmatch(raw_line)
    if ipv6_match is not None:
        match = ipv6_match
    elif ipv4_match is not None:
        match = ipv4_match
    else:
        _fail(EndpointParseErrorCode.INVALID_SYNTAX, line_number=line_number)

    raw_address = match.group("address")
    raw_port = match.group("port")
    if "%" in raw_address:
        _fail(EndpointParseErrorCode.INVALID_ADDRESS, line_number=line_number)
    try:
        parsed_address = ipaddress.ip_address(raw_address)
    except ValueError:
        _fail(EndpointParseErrorCode.INVALID_ADDRESS, line_number=line_number)

    if (ipv6_match is not None) != isinstance(
        parsed_address,
        ipaddress.IPv6Address,
    ):
        _fail(EndpointParseErrorCode.INVALID_SYNTAX, line_number=line_number)

    return _create_endpoint(
        parsed_address,
        port=_parse_port(raw_port, line_number=line_number),
    )


def parse_corpus(payload: bytes) -> EndpointCorpus:
    """Parse exact local bytes without resolving or contacting any endpoint."""

    if type(payload) is not bytes:
        raise TypeError("payload must be exact bytes")
    if len(payload) > MAX_INPUT_BYTES:
        _fail(EndpointParseErrorCode.INPUT_TOO_LARGE)
    if b"\r" in payload.replace(b"\r\n", b""):
        _fail(EndpointParseErrorCode.INVALID_LINE_ENDING)
    try:
        text = payload.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        _fail(EndpointParseErrorCode.INVALID_UTF8)
    if any(character in _NON_LF_LINE_SEPARATORS for character in text):
        _fail(EndpointParseErrorCode.INVALID_LINE_ENDING)

    normalized_text = text.replace("\r\n", "\n")
    if normalized_text:
        physical_lines = normalized_text.split("\n")
        if physical_lines[-1] == "":
            physical_lines.pop()
    else:
        physical_lines = []
    if len(physical_lines) > MAX_PHYSICAL_LINES:
        _fail(EndpointParseErrorCode.TOO_MANY_LINES)

    endpoints: list[Endpoint] = []
    for line_number, raw_line in enumerate(physical_lines, start=1):
        if not raw_line or raw_line.startswith("#"):
            continue
        endpoints.append(_parse_endpoint(raw_line, line_number=line_number))

    if not endpoints:
        _fail(EndpointParseErrorCode.EMPTY_CORPUS)

    return _create_corpus(
        payload=payload,
        physical_line_count=len(physical_lines),
        endpoints=tuple(endpoints),
    )
