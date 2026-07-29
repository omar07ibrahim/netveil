"""Privacy-preserving aggregate reports for endpoint corpora.

This module deliberately keeps raw endpoint models on the private side of the
report boundary. Public models contain only keyed identifiers and aggregate
counts.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import sys
from collections import Counter
from dataclasses import dataclass
from typing import Final, Self, final

from netveil.model import EndpointCorpus, EndpointScope, IPVersion
from netveil.parser import MAX_INPUT_BYTES, MAX_PHYSICAL_LINES, parse_corpus

MIN_PSEUDONYMIZATION_KEY_BYTES: Final = 32
PRIVACY_REPORT_SCHEMA: Final = "netveil.aggregate-report.v1"
PRIVACY_RECEIPT_SCHEMA: Final = "netveil.aggregate-receipt.v1"
PSEUDONYMIZATION_PROTOCOL: Final = "netveil.hmac-sha256-pseudonymization.v1"
CANONICAL_JSON_PROTOCOL: Final = "netveil.sorted-keys-json.v1"
RUNTIME_PROFILE_SCHEMA: Final = "netveil.python-runtime.v1"

_SOURCE_CONTENT_DOMAIN: Final = (
    b"netveil\x00hmac-sha256-pseudonymization\x00v1\x00source-content\x00"
)
_DUPLICATE_GROUP_DOMAIN: Final = (
    b"netveil\x00hmac-sha256-pseudonymization\x00v1\x00duplicate-group\x00"
)
_SOURCE_CONTENT_ID_PREFIX: Final = "nvs1_"
_DUPLICATE_GROUP_ID_PREFIX: Final = "nvd1_"
_HEX_DIGITS: Final = frozenset("0123456789abcdef")
_MIN_CANONICAL_ENDPOINT_BYTES: Final = len(b"[::]:1")

_IP_VERSION_LABELS: Final = ("ipv4", "ipv6")
_SCOPE_LABELS: Final = tuple(scope.value for scope in EndpointScope)
_PORT_BUCKET_LABELS: Final = (
    "system_1_1023",
    "registered_1024_49151",
    "dynamic_49152_65535",
)

CountPairs = tuple[tuple[str, int], ...]


@final
@dataclass(frozen=True, slots=True, init=False)
class RuntimeProfile:
    """The runtime whose stdlib defines endpoint parsing and classification."""

    schema: str
    python_implementation: str
    python_version: str
    endpoint_semantics: str

    def __new__(cls) -> Self:
        """Block construction outside the report factory."""

        raise TypeError("RuntimeProfile objects are created by build_privacy_report")


@final
@dataclass(frozen=True, slots=True, init=False)
class DuplicateGroup:
    """One pseudonymous endpoint value that occurs more than once."""

    group_id: str
    occurrences: int

    def __new__(cls) -> Self:
        """Block construction outside the validated report factory."""

        raise TypeError("DuplicateGroup objects are created by build_privacy_report")

    @property
    def extra_occurrences(self) -> int:
        """Return occurrences beyond the first instance."""

        return self.occurrences - 1


@final
@dataclass(frozen=True, slots=True, init=False)
class PrivacyReport:
    """Immutable public aggregates with no raw endpoint or source digest."""

    source_content_id: str
    runtime_profile: RuntimeProfile
    source_bytes: int
    physical_line_count: int
    endpoint_count: int
    unique_endpoint_count: int
    ip_version_counts: CountPairs
    scope_counts: CountPairs
    port_bucket_counts: CountPairs
    duplicate_groups: tuple[DuplicateGroup, ...]

    def __new__(cls) -> Self:
        """Block construction outside the validated report factory."""

        raise TypeError("PrivacyReport objects are created by build_privacy_report")

    @property
    def duplicate_group_count(self) -> int:
        """Return the number of distinct endpoint values with duplicates."""

        return len(self.duplicate_groups)

    @property
    def duplicate_occurrence_count(self) -> int:
        """Return total endpoint occurrences beyond each group's first."""

        return sum(group.extra_occurrences for group in self.duplicate_groups)

    def canonical_json_bytes(self) -> bytes:
        """Serialize the public report using Netveil's canonical JSON profile."""

        return _canonical_json_bytes(_report_document(self))


@final
@dataclass(frozen=True, slots=True, init=False)
class PrivacyReceipt:
    """A report plus a digest of the report's canonical public bytes."""

    report: PrivacyReport
    report_sha256: str

    def __new__(cls) -> Self:
        """Block construction outside the validated receipt factory."""

        raise TypeError("PrivacyReceipt objects are created by build_privacy_receipt")

    def canonical_json_bytes(self) -> bytes:
        """Serialize the receipt without including its digest input recursively."""

        document = {
            "canonicalization": CANONICAL_JSON_PROTOCOL,
            "protocol": PSEUDONYMIZATION_PROTOCOL,
            "report": _report_document(self.report),
            "report_digest": {
                "algorithm": "sha256",
                "value": self.report_sha256,
            },
            "schema": PRIVACY_RECEIPT_SCHEMA,
        }
        return _canonical_json_bytes(document)


def _canonical_json_bytes(document: object) -> bytes:
    return json.dumps(
        document,
        allow_nan=False,
        ensure_ascii=True,
        separators=(",", ":"),
        sort_keys=True,
    ).encode("ascii")


def _count_document(counts: CountPairs) -> dict[str, int]:
    return dict(counts)


def _report_document(report: PrivacyReport) -> dict[str, object]:
    return {
        "canonicalization": CANONICAL_JSON_PROTOCOL,
        "counts": {
            "endpoint_occurrences": report.endpoint_count,
            "physical_lines": report.physical_line_count,
            "source_bytes": report.source_bytes,
            "unique_endpoints": report.unique_endpoint_count,
        },
        "duplicates": {
            "extra_occurrences": report.duplicate_occurrence_count,
            "group_count": report.duplicate_group_count,
            "groups": [
                {
                    "extra_occurrences": group.extra_occurrences,
                    "id": group.group_id,
                    "occurrences": group.occurrences,
                }
                for group in report.duplicate_groups
            ],
        },
        "endpoint_occurrences_by_ip_version": _count_document(report.ip_version_counts),
        "endpoint_occurrences_by_port_bucket": _count_document(
            report.port_bucket_counts
        ),
        "endpoint_occurrences_by_scope": _count_document(report.scope_counts),
        "protocol": PSEUDONYMIZATION_PROTOCOL,
        "runtime": {
            "endpoint_semantics": report.runtime_profile.endpoint_semantics,
            "python_implementation": report.runtime_profile.python_implementation,
            "python_version": report.runtime_profile.python_version,
            "schema": report.runtime_profile.schema,
        },
        "schema": PRIVACY_REPORT_SCHEMA,
        "source_content_id": report.source_content_id,
    }


def _keyed_identifier(
    key: bytes,
    *,
    domain: bytes,
    value: bytes,
    prefix: str,
) -> str:
    framed_value = len(value).to_bytes(8, byteorder="big") + value
    digest = hmac.new(key, domain + framed_value, hashlib.sha256).hexdigest()
    return prefix + digest


def _validate_pseudonymization_key(key: bytes) -> None:
    if type(key) is not bytes:
        raise TypeError("pseudonymization_key must be exact bytes")
    if len(key) < MIN_PSEUDONYMIZATION_KEY_BYTES:
        raise ValueError(
            "pseudonymization_key must contain at least "
            f"{MIN_PSEUDONYMIZATION_KEY_BYTES} bytes"
        )


def _validate_identifier(value: str, *, prefix: str, field: str) -> None:
    if type(value) is not str:
        raise TypeError(f"{field} must be an exact str")
    suffix = value.removeprefix(prefix)
    if (
        not value.startswith(prefix)
        or len(suffix) != hashlib.sha256().digest_size * 2
        or any(character not in _HEX_DIGITS for character in suffix)
    ):
        raise ValueError(f"{field} must be a valid typed HMAC-SHA256 identifier")


def _validate_exact_nonnegative_int(value: int, *, field: str) -> None:
    if type(value) is not int:
        raise TypeError(f"{field} must be an exact int")
    if value < 0:
        raise ValueError(f"{field} must be non-negative")


def _validate_count_pairs(
    counts: CountPairs,
    *,
    field: str,
    labels: tuple[str, ...],
    expected_total: int,
) -> None:
    if type(counts) is not tuple:
        raise TypeError(f"{field} must be an exact tuple")
    for item in counts:
        if type(item) is not tuple or len(item) != 2:
            raise TypeError(f"{field} entries must be exact two-item tuples")
        label, count = item
        if type(label) is not str:
            raise TypeError(f"{field} labels must be exact strings")
        _validate_exact_nonnegative_int(count, field=f"{field} count")
    if tuple(label for label, _ in counts) != labels:
        raise ValueError(f"{field} labels or order are invalid")
    if sum(count for _, count in counts) != expected_total:
        raise ValueError(f"{field} must sum to endpoint_count")


def _create_duplicate_group(*, group_id: str, occurrences: int) -> DuplicateGroup:
    _validate_identifier(
        group_id,
        prefix=_DUPLICATE_GROUP_ID_PREFIX,
        field="group_id",
    )
    _validate_exact_nonnegative_int(occurrences, field="occurrences")
    if occurrences < 2:
        raise ValueError("duplicate group occurrences must be at least two")

    group: DuplicateGroup = object.__new__(DuplicateGroup)
    object.__setattr__(group, "group_id", group_id)
    object.__setattr__(group, "occurrences", occurrences)
    return group


def _create_runtime_profile() -> RuntimeProfile:
    version = sys.version_info
    profile: RuntimeProfile = object.__new__(RuntimeProfile)
    object.__setattr__(profile, "schema", RUNTIME_PROFILE_SCHEMA)
    object.__setattr__(profile, "python_implementation", sys.implementation.name)
    object.__setattr__(
        profile,
        "python_version",
        f"{version.major}.{version.minor}.{version.micro}",
    )
    object.__setattr__(
        profile,
        "endpoint_semantics",
        "python-stdlib-ipaddress",
    )
    return profile


def _validate_runtime_profile(profile: RuntimeProfile) -> None:
    if type(profile) is not RuntimeProfile:
        raise TypeError("runtime_profile must come from the validated factory")
    if profile != _create_runtime_profile():
        raise ValueError("runtime_profile does not match the active runtime")


def _create_privacy_report(
    *,
    source_content_id: str,
    runtime_profile: RuntimeProfile,
    source_bytes: int,
    physical_line_count: int,
    endpoint_count: int,
    unique_endpoint_count: int,
    ip_version_counts: CountPairs,
    scope_counts: CountPairs,
    port_bucket_counts: CountPairs,
    duplicate_groups: tuple[DuplicateGroup, ...],
) -> PrivacyReport:
    _validate_identifier(
        source_content_id,
        prefix=_SOURCE_CONTENT_ID_PREFIX,
        field="source_content_id",
    )
    _validate_runtime_profile(runtime_profile)
    for field, value in (
        ("source_bytes", source_bytes),
        ("physical_line_count", physical_line_count),
        ("endpoint_count", endpoint_count),
        ("unique_endpoint_count", unique_endpoint_count),
    ):
        _validate_exact_nonnegative_int(value, field=field)
    if endpoint_count == 0:
        raise ValueError("endpoint_count must be positive")
    if source_bytes == 0:
        raise ValueError("source_bytes must be positive")
    if source_bytes > MAX_INPUT_BYTES:
        raise ValueError("source_bytes exceeds the parser input bound")
    if physical_line_count > MAX_PHYSICAL_LINES:
        raise ValueError("physical_line_count exceeds the parser line bound")
    if not 1 <= unique_endpoint_count <= endpoint_count:
        raise ValueError("unique_endpoint_count must be in 1..endpoint_count")
    if physical_line_count < endpoint_count:
        raise ValueError("physical_line_count cannot be smaller than endpoint_count")
    minimum_source_bytes = (
        endpoint_count * _MIN_CANONICAL_ENDPOINT_BYTES + physical_line_count - 1
    )
    if source_bytes < minimum_source_bytes:
        raise ValueError("source_bytes is too small for the aggregate line counts")

    _validate_count_pairs(
        ip_version_counts,
        field="ip_version_counts",
        labels=_IP_VERSION_LABELS,
        expected_total=endpoint_count,
    )
    _validate_count_pairs(
        scope_counts,
        field="scope_counts",
        labels=_SCOPE_LABELS,
        expected_total=endpoint_count,
    )
    _validate_count_pairs(
        port_bucket_counts,
        field="port_bucket_counts",
        labels=_PORT_BUCKET_LABELS,
        expected_total=endpoint_count,
    )
    if type(duplicate_groups) is not tuple:
        raise TypeError("duplicate_groups must be an exact tuple")
    if any(type(group) is not DuplicateGroup for group in duplicate_groups):
        raise TypeError("every duplicate group must come from the validated factory")
    for group in duplicate_groups:
        _validate_identifier(
            group.group_id,
            prefix=_DUPLICATE_GROUP_ID_PREFIX,
            field="group_id",
        )
        _validate_exact_nonnegative_int(group.occurrences, field="occurrences")
        if group.occurrences < 2:
            raise ValueError("duplicate group occurrences must be at least two")
    group_ids = tuple(group.group_id for group in duplicate_groups)
    if group_ids != tuple(sorted(group_ids)) or len(group_ids) != len(set(group_ids)):
        raise ValueError("duplicate_groups must have unique IDs in sorted order")
    if len(duplicate_groups) > unique_endpoint_count:
        raise ValueError("duplicate_group_count cannot exceed unique_endpoint_count")
    expected_duplicate_count = endpoint_count - unique_endpoint_count
    if (
        sum(group.extra_occurrences for group in duplicate_groups)
        != expected_duplicate_count
    ):
        raise ValueError("duplicate_groups do not match aggregate uniqueness counts")

    report: PrivacyReport = object.__new__(PrivacyReport)
    object.__setattr__(report, "source_content_id", source_content_id)
    object.__setattr__(report, "runtime_profile", runtime_profile)
    object.__setattr__(report, "source_bytes", source_bytes)
    object.__setattr__(report, "physical_line_count", physical_line_count)
    object.__setattr__(report, "endpoint_count", endpoint_count)
    object.__setattr__(report, "unique_endpoint_count", unique_endpoint_count)
    object.__setattr__(report, "ip_version_counts", ip_version_counts)
    object.__setattr__(report, "scope_counts", scope_counts)
    object.__setattr__(report, "port_bucket_counts", port_bucket_counts)
    object.__setattr__(report, "duplicate_groups", duplicate_groups)
    return report


def _create_privacy_receipt(report: PrivacyReport) -> PrivacyReceipt:
    if type(report) is not PrivacyReport:
        raise TypeError("report must come from build_privacy_report")

    report_sha256 = hashlib.sha256(report.canonical_json_bytes()).hexdigest()
    receipt: PrivacyReceipt = object.__new__(PrivacyReceipt)
    object.__setattr__(receipt, "report", report)
    object.__setattr__(receipt, "report_sha256", report_sha256)
    return receipt


def _port_bucket(port: int) -> str:
    if port <= 1_023:
        return "system_1_1023"
    if port <= 49_151:
        return "registered_1024_49151"
    return "dynamic_49152_65535"


def _count_pairs(labels: tuple[str, ...], observed: Counter[str]) -> CountPairs:
    return tuple((label, observed[label]) for label in labels)


def _report_from_corpus(
    corpus: EndpointCorpus,
    *,
    pseudonymization_key: bytes,
    payload: bytes,
) -> PrivacyReport:
    version_counts: Counter[str] = Counter()
    scope_counts: Counter[str] = Counter()
    port_counts: Counter[str] = Counter()
    canonical_counts: Counter[str] = Counter()

    for endpoint in corpus.endpoints:
        version_counts["ipv6" if endpoint.version is IPVersion.IPV6 else "ipv4"] += 1
        scope_counts[endpoint.scope.value] += 1
        port_counts[_port_bucket(endpoint.port)] += 1
        canonical_counts[endpoint.canonical] += 1

    duplicate_groups = tuple(
        sorted(
            (
                _create_duplicate_group(
                    group_id=_keyed_identifier(
                        pseudonymization_key,
                        domain=_DUPLICATE_GROUP_DOMAIN,
                        value=canonical.encode("ascii"),
                        prefix=_DUPLICATE_GROUP_ID_PREFIX,
                    ),
                    occurrences=occurrences,
                )
                for canonical, occurrences in canonical_counts.items()
                if occurrences > 1
            ),
            key=lambda group: group.group_id,
        )
    )
    return _create_privacy_report(
        source_content_id=_keyed_identifier(
            pseudonymization_key,
            domain=_SOURCE_CONTENT_DOMAIN,
            value=payload,
            prefix=_SOURCE_CONTENT_ID_PREFIX,
        ),
        runtime_profile=_create_runtime_profile(),
        source_bytes=corpus.source_bytes,
        physical_line_count=corpus.physical_line_count,
        endpoint_count=corpus.endpoint_count,
        unique_endpoint_count=corpus.unique_count,
        ip_version_counts=_count_pairs(_IP_VERSION_LABELS, version_counts),
        scope_counts=_count_pairs(_SCOPE_LABELS, scope_counts),
        port_bucket_counts=_count_pairs(_PORT_BUCKET_LABELS, port_counts),
        duplicate_groups=duplicate_groups,
    )


def build_privacy_report(
    payload: bytes,
    *,
    pseudonymization_key: bytes,
) -> PrivacyReport:
    """Parse exact bytes locally and return only keyed IDs and aggregates."""

    if type(payload) is not bytes:
        raise TypeError("payload must be exact bytes")
    _validate_pseudonymization_key(pseudonymization_key)
    corpus = parse_corpus(payload)
    return _report_from_corpus(
        corpus,
        pseudonymization_key=pseudonymization_key,
        payload=payload,
    )


def build_privacy_receipt(
    payload: bytes,
    *,
    pseudonymization_key: bytes,
) -> PrivacyReceipt:
    """Build a public report and bind its canonical bytes in one pass."""

    report = build_privacy_report(
        payload,
        pseudonymization_key=pseudonymization_key,
    )
    return _create_privacy_receipt(report)
