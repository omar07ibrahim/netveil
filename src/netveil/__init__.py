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
from netveil.privacy import (
    CANONICAL_JSON_PROTOCOL,
    MIN_PSEUDONYMIZATION_KEY_BYTES,
    PRIVACY_RECEIPT_SCHEMA,
    PRIVACY_REPORT_SCHEMA,
    PSEUDONYMIZATION_PROTOCOL,
    RUNTIME_PROFILE_SCHEMA,
    DuplicateGroup,
    PrivacyReceipt,
    PrivacyReport,
    RuntimeProfile,
    build_privacy_receipt,
    build_privacy_report,
)

__all__ = [
    "CANONICAL_JSON_PROTOCOL",
    "MAX_INPUT_BYTES",
    "MAX_PHYSICAL_LINES",
    "MIN_PSEUDONYMIZATION_KEY_BYTES",
    "PRIVACY_RECEIPT_SCHEMA",
    "PRIVACY_REPORT_SCHEMA",
    "PSEUDONYMIZATION_PROTOCOL",
    "RUNTIME_PROFILE_SCHEMA",
    "DuplicateGroup",
    "Endpoint",
    "EndpointCorpus",
    "EndpointParseError",
    "EndpointParseErrorCode",
    "EndpointScope",
    "IPVersion",
    "PrivacyReceipt",
    "PrivacyReport",
    "RuntimeProfile",
    "build_privacy_receipt",
    "build_privacy_report",
    "parse_corpus",
]
