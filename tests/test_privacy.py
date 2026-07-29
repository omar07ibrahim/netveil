from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import sys
import unittest
from dataclasses import FrozenInstanceError
from typing import Any, cast
from unittest.mock import patch

from netveil import (
    CANONICAL_JSON_PROTOCOL,
    MAX_INPUT_BYTES,
    MAX_PHYSICAL_LINES,
    MIN_PSEUDONYMIZATION_KEY_BYTES,
    PRIVACY_RECEIPT_SCHEMA,
    PRIVACY_REPORT_SCHEMA,
    PSEUDONYMIZATION_PROTOCOL,
    RUNTIME_PROFILE_SCHEMA,
    DuplicateGroup,
    EndpointParseError,
    EndpointParseErrorCode,
    PrivacyReceipt,
    PrivacyReport,
    RuntimeProfile,
    build_privacy_receipt,
    build_privacy_report,
)
from netveil.privacy import (
    _DUPLICATE_GROUP_DOMAIN,
    _SOURCE_CONTENT_DOMAIN,
    _create_duplicate_group,
    _create_privacy_receipt,
    _create_privacy_report,
    _create_runtime_profile,
    _keyed_identifier,
)

_KEY_A = bytes(range(32))
_KEY_B = bytes(range(32, 64))
_PAYLOAD = (
    b"# Synthetic special-use ranges only\n"
    b"192.0.2.1:80\n"
    b"192.0.2.1:80\n"
    b"[2001:db8::1]:443\n"
    b"[2001:0DB8:0:0:0:0:0:1]:443\n"
    b"10.0.0.1:1024\n"
    b"127.0.0.1:49152\n"
)
_RAW_VALUES = (
    "192.0.2.1:80",
    "[2001:db8::1]:443",
    "[2001:0DB8:0:0:0:0:0:1]:443",
    "10.0.0.1:1024",
    "127.0.0.1:49152",
)


def _json(payload: bytes) -> dict[str, Any]:
    document = json.loads(payload)
    if not isinstance(document, dict):
        raise TypeError("expected a JSON object")
    return cast(dict[str, Any], document)


class PrivacyReportTests(unittest.TestCase):
    def test_builds_expected_aggregates_without_network_or_process_calls(self) -> None:
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(
                socket,
                "getaddrinfo",
                side_effect=AssertionError("resolution"),
            ),
            patch.object(subprocess, "Popen", side_effect=AssertionError("process")),
            patch.object(subprocess, "run", side_effect=AssertionError("process")),
        ):
            report = build_privacy_report(
                _PAYLOAD,
                pseudonymization_key=_KEY_A,
            )

        document = _json(report.canonical_json_bytes())
        self.assertEqual(document["schema"], PRIVACY_REPORT_SCHEMA)
        self.assertEqual(document["protocol"], PSEUDONYMIZATION_PROTOCOL)
        self.assertEqual(document["canonicalization"], CANONICAL_JSON_PROTOCOL)
        self.assertEqual(
            document["runtime"],
            {
                "endpoint_semantics": "python-stdlib-ipaddress",
                "python_implementation": sys.implementation.name,
                "python_version": (
                    f"{sys.version_info.major}."
                    f"{sys.version_info.minor}."
                    f"{sys.version_info.micro}"
                ),
                "schema": RUNTIME_PROFILE_SCHEMA,
            },
        )
        self.assertEqual(
            document["counts"],
            {
                "endpoint_occurrences": 6,
                "physical_lines": 7,
                "source_bytes": len(_PAYLOAD),
                "unique_endpoints": 4,
            },
        )
        self.assertEqual(
            document["endpoint_occurrences_by_ip_version"],
            {"ipv4": 4, "ipv6": 2},
        )
        self.assertEqual(
            document["endpoint_occurrences_by_port_bucket"],
            {
                "dynamic_49152_65535": 1,
                "registered_1024_49151": 1,
                "system_1_1023": 4,
            },
        )
        scopes = document["endpoint_occurrences_by_scope"]
        self.assertEqual(scopes["documentation"], 4)
        self.assertEqual(scopes["private"], 1)
        self.assertEqual(scopes["loopback"], 1)
        self.assertEqual(sum(scopes.values()), 6)
        self.assertEqual(
            document["duplicates"]["extra_occurrences"],
            2,
        )
        self.assertEqual(document["duplicates"]["group_count"], 2)
        groups = document["duplicates"]["groups"]
        self.assertEqual([group["occurrences"] for group in groups], [2, 2])
        self.assertEqual([group["extra_occurrences"] for group in groups], [1, 1])
        self.assertEqual(
            [group["id"] for group in groups],
            sorted(group["id"] for group in groups),
        )

    def test_output_and_failures_do_not_reveal_raw_values_or_source_sha(self) -> None:
        receipt = build_privacy_receipt(
            _PAYLOAD,
            pseudonymization_key=_KEY_A,
        )
        rendered = (
            receipt.canonical_json_bytes().decode("ascii")
            + repr(receipt)
            + repr(receipt.report)
        )
        for raw_value in _RAW_VALUES:
            self.assertNotIn(raw_value, rendered)
        self.assertNotIn(hashlib.sha256(_PAYLOAD).hexdigest(), rendered)
        self.assertNotIn(_KEY_A.hex(), rendered)

        invalid_value = "invalid-sensitive-value"
        with self.assertRaises(EndpointParseError) as raised:
            build_privacy_report(
                f"{invalid_value}:443\n".encode(),
                pseudonymization_key=_KEY_A,
            )
        self.assertEqual(
            raised.exception.code,
            EndpointParseErrorCode.INVALID_ADDRESS,
        )
        self.assertNotIn(invalid_value, str(raised.exception))
        self.assertNotIn(invalid_value, repr(raised.exception))

    def test_report_and_receipt_are_deterministic_canonical_json(self) -> None:
        first = build_privacy_receipt(
            _PAYLOAD,
            pseudonymization_key=_KEY_A,
        )
        second = build_privacy_receipt(
            _PAYLOAD,
            pseudonymization_key=_KEY_A,
        )
        self.assertEqual(first, second)
        self.assertEqual(first.canonical_json_bytes(), second.canonical_json_bytes())

        report_bytes = first.report.canonical_json_bytes()
        receipt_document = _json(first.canonical_json_bytes())
        self.assertEqual(receipt_document["schema"], PRIVACY_RECEIPT_SCHEMA)
        self.assertEqual(
            receipt_document["report"],
            _json(report_bytes),
        )
        self.assertEqual(
            first.report_sha256,
            hashlib.sha256(report_bytes).hexdigest(),
        )
        self.assertEqual(
            receipt_document["report_digest"],
            {"algorithm": "sha256", "value": first.report_sha256},
        )
        self.assertNotIn("report_digest", _json(report_bytes))

        for canonical_bytes in (report_bytes, first.canonical_json_bytes()):
            self.assertFalse(canonical_bytes.endswith(b"\n"))
            self.assertEqual(
                canonical_bytes,
                json.dumps(
                    json.loads(canonical_bytes),
                    allow_nan=False,
                    ensure_ascii=True,
                    separators=(",", ":"),
                    sort_keys=True,
                ).encode("ascii"),
            )

    def test_key_rotation_and_domain_separation_change_typed_identifiers(self) -> None:
        first = build_privacy_report(
            _PAYLOAD,
            pseudonymization_key=_KEY_A,
        )
        rotated = build_privacy_report(
            _PAYLOAD,
            pseudonymization_key=_KEY_B,
        )
        self.assertNotEqual(first.source_content_id, rotated.source_content_id)
        self.assertTrue(first.source_content_id.startswith("nvs1_"))
        self.assertTrue(
            all(group.group_id.startswith("nvd1_") for group in first.duplicate_groups)
        )
        self.assertNotEqual(
            {group.group_id for group in first.duplicate_groups},
            {group.group_id for group in rotated.duplicate_groups},
        )

        same_value = b"same-framed-value"
        source_id = _keyed_identifier(
            _KEY_A,
            domain=_SOURCE_CONTENT_DOMAIN,
            value=same_value,
            prefix="nvs1_",
        )
        duplicate_id = _keyed_identifier(
            _KEY_A,
            domain=_DUPLICATE_GROUP_DOMAIN,
            value=same_value,
            prefix="nvd1_",
        )
        self.assertEqual(
            source_id,
            "nvs1_1835ed652ea947a88125064fad24a25b4cd3faa2c4f3e05878ce2bfe8fdd66c5",
        )
        self.assertEqual(
            duplicate_id,
            "nvd1_c5422fb8589253f084b16b227ba8fc7a8d1e2f69ec257f93a10f4a2544941750",
        )
        self.assertNotEqual(
            source_id.removeprefix("nvs1_"), duplicate_id.removeprefix("nvd1_")
        )
        self.assertNotEqual(source_id, duplicate_id)

    def test_equivalent_endpoints_have_stable_duplicate_ids_across_corpora(
        self,
    ) -> None:
        first = build_privacy_report(
            b"[2001:db8::1]:443\n[2001:0DB8:0:0:0:0:0:1]:443\n",
            pseudonymization_key=_KEY_A,
        )
        second = build_privacy_report(
            b"# another source\n[2001:db8::1]:443\n[2001:db8::1]:443\n",
            pseudonymization_key=_KEY_A,
        )
        self.assertNotEqual(first.source_content_id, second.source_content_id)
        self.assertEqual(
            first.duplicate_groups[0].group_id,
            second.duplicate_groups[0].group_id,
        )

    def test_single_endpoint_report_has_no_duplicate_identifier(self) -> None:
        report = build_privacy_report(
            b"192.0.2.1:443\n",
            pseudonymization_key=_KEY_A,
        )
        self.assertEqual(report.duplicate_groups, ())
        self.assertEqual(report.duplicate_group_count, 0)
        self.assertEqual(report.duplicate_occurrence_count, 0)

    def test_exact_types_key_length_and_parser_bounds_fail_closed(self) -> None:
        class BytesSubclass(bytes):
            pass

        for payload in (
            "192.0.2.1:443\n",
            bytearray(b"192.0.2.1:443\n"),
            BytesSubclass(b"192.0.2.1:443\n"),
        ):
            with (
                self.subTest(payload_type=type(payload).__name__),
                self.assertRaisesRegex(TypeError, "^payload must be exact bytes$"),
            ):
                build_privacy_report(
                    payload,  # type: ignore[arg-type]
                    pseudonymization_key=_KEY_A,
                )

        for key in (
            "x" * MIN_PSEUDONYMIZATION_KEY_BYTES,
            bytearray(_KEY_A),
            BytesSubclass(_KEY_A),
        ):
            with (
                self.subTest(key_type=type(key).__name__),
                self.assertRaisesRegex(
                    TypeError,
                    "^pseudonymization_key must be exact bytes$",
                ),
            ):
                build_privacy_report(
                    b"192.0.2.1:443\n",
                    pseudonymization_key=key,  # type: ignore[arg-type]
                )

        short_key = b"sensitive-but-too-short"
        with self.assertRaisesRegex(
            ValueError,
            "^pseudonymization_key must contain at least 32 bytes$",
        ) as raised:
            build_privacy_report(
                b"192.0.2.1:443\n",
                pseudonymization_key=short_key,
            )
        self.assertNotIn(short_key.decode(), str(raised.exception))

        with self.assertRaises(EndpointParseError) as oversized:
            build_privacy_report(
                b"x" * (MAX_INPUT_BYTES + 1),
                pseudonymization_key=_KEY_A,
            )
        self.assertEqual(
            oversized.exception.code,
            EndpointParseErrorCode.INPUT_TOO_LARGE,
        )

    def test_public_models_are_frozen_and_direct_construction_is_blocked(self) -> None:
        for model, message in (
            (
                RuntimeProfile,
                "RuntimeProfile objects are created by build_privacy_report",
            ),
            (
                DuplicateGroup,
                "DuplicateGroup objects are created by build_privacy_report",
            ),
            (
                PrivacyReport,
                "PrivacyReport objects are created by build_privacy_report",
            ),
            (
                PrivacyReceipt,
                "PrivacyReceipt objects are created by build_privacy_receipt",
            ),
        ):
            with (
                self.subTest(model=model.__name__),
                self.assertRaisesRegex(TypeError, f"^{message}$"),
            ):
                model()

        receipt = build_privacy_receipt(
            _PAYLOAD,
            pseudonymization_key=_KEY_A,
        )
        with self.assertRaises(FrozenInstanceError):
            receipt.report.endpoint_count = 0  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            receipt.report.duplicate_groups[0].occurrences = 99  # type: ignore[misc]
        with self.assertRaises(FrozenInstanceError):
            receipt.report_sha256 = "0" * 64  # type: ignore[misc]


class PrivacyModelInvariantTests(unittest.TestCase):
    def setUp(self) -> None:
        self.report = build_privacy_report(
            _PAYLOAD,
            pseudonymization_key=_KEY_A,
        )
        self.valid: dict[str, object] = {
            "source_content_id": self.report.source_content_id,
            "runtime_profile": self.report.runtime_profile,
            "source_bytes": self.report.source_bytes,
            "physical_line_count": self.report.physical_line_count,
            "endpoint_count": self.report.endpoint_count,
            "unique_endpoint_count": self.report.unique_endpoint_count,
            "ip_version_counts": self.report.ip_version_counts,
            "scope_counts": self.report.scope_counts,
            "port_bucket_counts": self.report.port_bucket_counts,
            "duplicate_groups": self.report.duplicate_groups,
        }

    def create(self, **changes: object) -> PrivacyReport:
        values = self.valid | changes
        return _create_privacy_report(
            source_content_id=cast(str, values["source_content_id"]),
            runtime_profile=cast(RuntimeProfile, values["runtime_profile"]),
            source_bytes=cast(int, values["source_bytes"]),
            physical_line_count=cast(int, values["physical_line_count"]),
            endpoint_count=cast(int, values["endpoint_count"]),
            unique_endpoint_count=cast(int, values["unique_endpoint_count"]),
            ip_version_counts=cast(
                tuple[tuple[str, int], ...],
                values["ip_version_counts"],
            ),
            scope_counts=cast(
                tuple[tuple[str, int], ...],
                values["scope_counts"],
            ),
            port_bucket_counts=cast(
                tuple[tuple[str, int], ...],
                values["port_bucket_counts"],
            ),
            duplicate_groups=cast(
                tuple[DuplicateGroup, ...],
                values["duplicate_groups"],
            ),
        )

    def test_duplicate_group_factory_rejects_invalid_models(self) -> None:
        with self.assertRaisesRegex(TypeError, "^group_id must be an exact str$"):
            _create_duplicate_group(group_id=cast(str, b"x"), occurrences=2)
        for group_id in (
            "wrong_" + "0" * 64,
            "nvd1_short",
            "nvd1_" + "G" * 64,
        ):
            with (
                self.subTest(group_id=group_id),
                self.assertRaisesRegex(ValueError, "^group_id must be a valid"),
            ):
                _create_duplicate_group(group_id=group_id, occurrences=2)
        with self.assertRaisesRegex(TypeError, "^occurrences must be an exact int$"):
            _create_duplicate_group(
                group_id="nvd1_" + "0" * 64,
                occurrences=True,
            )
        for occurrences in (-1, 0, 1):
            with (
                self.subTest(occurrences=occurrences),
                self.assertRaises(ValueError),
            ):
                _create_duplicate_group(
                    group_id="nvd1_" + "0" * 64,
                    occurrences=occurrences,
                )

    def test_report_factory_rejects_invalid_identifiers_and_scalar_counts(
        self,
    ) -> None:
        with self.assertRaisesRegex(TypeError, "^source_content_id must be"):
            self.create(source_content_id=cast(str, b"x"))
        with self.assertRaisesRegex(ValueError, "^source_content_id must be"):
            self.create(source_content_id="nvs1_" + "z" * 64)
        with self.assertRaisesRegex(TypeError, "^runtime_profile must come"):
            self.create(runtime_profile=object())

        forged_profile: RuntimeProfile = object.__new__(RuntimeProfile)
        object.__setattr__(forged_profile, "schema", RUNTIME_PROFILE_SCHEMA)
        object.__setattr__(
            forged_profile,
            "python_implementation",
            sys.implementation.name,
        )
        object.__setattr__(forged_profile, "python_version", "0.0.0")
        object.__setattr__(
            forged_profile,
            "endpoint_semantics",
            "python-stdlib-ipaddress",
        )
        with self.assertRaisesRegex(ValueError, "^runtime_profile does not match"):
            self.create(runtime_profile=forged_profile)

        self.assertEqual(self.report.runtime_profile, _create_runtime_profile())

        for field in (
            "source_bytes",
            "physical_line_count",
            "endpoint_count",
            "unique_endpoint_count",
        ):
            with (
                self.subTest(field=field),
                self.assertRaisesRegex(TypeError, f"^{field} must be an exact int$"),
            ):
                self.create(**{field: True})
        with self.assertRaisesRegex(ValueError, "^source_bytes must be non-negative$"):
            self.create(source_bytes=-1)
        with self.assertRaisesRegex(ValueError, "^source_bytes must be positive$"):
            self.create(source_bytes=0)
        with self.assertRaisesRegex(ValueError, "^source_bytes exceeds"):
            self.create(source_bytes=MAX_INPUT_BYTES + 1)
        with self.assertRaisesRegex(ValueError, "^physical_line_count exceeds"):
            self.create(physical_line_count=MAX_PHYSICAL_LINES + 1)
        with self.assertRaisesRegex(ValueError, "^endpoint_count must be positive$"):
            self.create(endpoint_count=0, unique_endpoint_count=0)
        for unique_count in (0, self.report.endpoint_count + 1):
            with (
                self.subTest(unique_count=unique_count),
                self.assertRaisesRegex(ValueError, "^unique_endpoint_count must be"),
            ):
                self.create(unique_endpoint_count=unique_count)
        with self.assertRaisesRegex(ValueError, "^physical_line_count cannot"):
            self.create(physical_line_count=self.report.endpoint_count - 1)
        with self.assertRaisesRegex(ValueError, "^source_bytes is too small"):
            self.create(source_bytes=1)

    def test_report_factory_rejects_invalid_count_tables(self) -> None:
        with self.assertRaisesRegex(TypeError, "^ip_version_counts must be"):
            self.create(ip_version_counts=list(self.report.ip_version_counts))
        with self.assertRaisesRegex(
            TypeError,
            "^ip_version_counts entries must be",
        ):
            self.create(ip_version_counts=(("ipv4", 4), ["ipv6", 2]))
        with self.assertRaisesRegex(
            TypeError,
            "^ip_version_counts entries must be",
        ):
            self.create(ip_version_counts=(("ipv4", 4, 0), ("ipv6", 2)))
        with self.assertRaisesRegex(
            TypeError,
            "^ip_version_counts labels must be",
        ):
            self.create(ip_version_counts=((cast(str, b"ipv4"), 4), ("ipv6", 2)))
        with self.assertRaisesRegex(
            TypeError,
            "^ip_version_counts count must be an exact int$",
        ):
            self.create(ip_version_counts=(("ipv4", True), ("ipv6", 5)))
        with self.assertRaisesRegex(
            ValueError,
            "^ip_version_counts count must be non-negative$",
        ):
            self.create(ip_version_counts=(("ipv4", -1), ("ipv6", 7)))
        with self.assertRaisesRegex(
            ValueError,
            "^ip_version_counts labels or order are invalid$",
        ):
            self.create(ip_version_counts=(("ipv6", 2), ("ipv4", 4)))
        with self.assertRaisesRegex(
            ValueError,
            "^ip_version_counts must sum to endpoint_count$",
        ):
            self.create(ip_version_counts=(("ipv4", 3), ("ipv6", 2)))

    def test_report_factory_rejects_invalid_duplicate_groups(self) -> None:
        with self.assertRaisesRegex(TypeError, "^duplicate_groups must be"):
            self.create(duplicate_groups=list(self.report.duplicate_groups))
        with self.assertRaisesRegex(TypeError, "^every duplicate group must"):
            self.create(duplicate_groups=(object(),))

        first, second = self.report.duplicate_groups
        invalid_id: DuplicateGroup = object.__new__(DuplicateGroup)
        object.__setattr__(invalid_id, "group_id", "invalid")
        object.__setattr__(invalid_id, "occurrences", 2)
        with self.assertRaisesRegex(ValueError, "^group_id must be a valid"):
            self.create(duplicate_groups=(invalid_id,))

        invalid_type: DuplicateGroup = object.__new__(DuplicateGroup)
        object.__setattr__(invalid_type, "group_id", first.group_id)
        object.__setattr__(invalid_type, "occurrences", True)
        with self.assertRaisesRegex(TypeError, "^occurrences must be an exact int$"):
            self.create(duplicate_groups=(invalid_type,))

        too_small: DuplicateGroup = object.__new__(DuplicateGroup)
        object.__setattr__(too_small, "group_id", first.group_id)
        object.__setattr__(too_small, "occurrences", 1)
        with self.assertRaisesRegex(ValueError, "^duplicate group occurrences"):
            self.create(duplicate_groups=(too_small,))

        with self.assertRaisesRegex(ValueError, "^duplicate_groups must have"):
            self.create(duplicate_groups=(second, first))
        with self.assertRaisesRegex(ValueError, "^duplicate_groups must have"):
            self.create(duplicate_groups=(first, first))

        too_many_groups = (
            _create_duplicate_group(group_id="nvd1_" + "0" * 64, occurrences=2),
            _create_duplicate_group(group_id="nvd1_" + "1" * 64, occurrences=2),
            _create_duplicate_group(group_id="nvd1_" + "2" * 64, occurrences=3),
        )
        with self.assertRaisesRegex(ValueError, "^duplicate_group_count cannot"):
            self.create(
                unique_endpoint_count=2,
                duplicate_groups=too_many_groups,
            )
        with self.assertRaisesRegex(ValueError, "^duplicate_groups do not match"):
            self.create(duplicate_groups=())

    def test_receipt_factory_rejects_nonfactory_report(self) -> None:
        with self.assertRaisesRegex(TypeError, "^report must come from"):
            _create_privacy_receipt(cast(PrivacyReport, object()))


if __name__ == "__main__":
    unittest.main()
