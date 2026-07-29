"""Offline endpoint parsing with redacted failures and no network access."""

from netveil.model import (
    Endpoint,
    EndpointCorpus,
    EndpointScope,
    IPVersion,
)
from netveil.parser import (
    MAX_INPUT_BYTES,
    MAX_PHYSICAL_LINES,
    EndpointParseError,
    EndpointParseErrorCode,
    parse_corpus,
)

__all__ = [
    "MAX_INPUT_BYTES",
    "MAX_PHYSICAL_LINES",
    "Endpoint",
    "EndpointCorpus",
    "EndpointParseError",
    "EndpointParseErrorCode",
    "EndpointScope",
    "IPVersion",
    "parse_corpus",
]
