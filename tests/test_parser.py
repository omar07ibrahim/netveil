from __future__ import annotations

import hashlib
import ipaddress
import socket
import traceback
import unittest
from unittest.mock import patch

import netveil.model as model_module
from netveil import (
    MAX_INPUT_BYTES,
    MAX_PHYSICAL_LINES,
    EndpointParseError,
    EndpointParseErrorCode,
    EndpointScope,
    IPVersion,
    parse_corpus,
)


class SyntheticGlobalIPv4(ipaddress.IPv4Address):
    """Exercise the global branch without committing a live endpoint."""

    @property
    def is_unspecified(self) -> bool:
        return False

    @property
    def is_loopback(self) -> bool:
        return False

    @property
    def is_multicast(self) -> bool:
        return False

    @property
    def is_link_local(self) -> bool:
        return False

    @property
    def is_reserved(self) -> bool:
        return False

    @property
    def is_private(self) -> bool:
        return False


class DecodeOverridingBytes(bytes):
    def decode(
        self,
        encoding: str = "utf-8",
        errors: str = "strict",
    ) -> str:
        del encoding, errors
        return "192.0.2.1:443\n"


class EndpointParserHappyPathTests(unittest.TestCase):
    def test_parses_canonical_ipv4_and_ipv6_without_network_access(self) -> None:
        payload = (
            b"# Synthetic IETF documentation ranges only\n"
            b"192.0.2.10:443\n"
            b"[2001:0DB8:0:0:0:0:0:10]:8443\n"
        )
        with (
            patch.object(socket, "socket", side_effect=AssertionError("network")),
            patch.object(
                socket,
                "getaddrinfo",
                side_effect=AssertionError("resolution"),
            ),
        ):
            corpus = parse_corpus(payload)

        self.assertEqual(corpus.source_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(corpus.source_bytes, len(payload))
        self.assertEqual(corpus.physical_line_count, 3)
        self.assertEqual(corpus.endpoint_count, 2)
        self.assertEqual(corpus.unique_count, 2)
        self.assertEqual(corpus.duplicate_count, 0)
        self.assertEqual(corpus.endpoints[0].canonical, "192.0.2.10:443")
        self.assertEqual(corpus.endpoints[0].version, IPVersion.IPV4)
        self.assertEqual(corpus.endpoints[0].scope, EndpointScope.DOCUMENTATION)
        self.assertEqual(corpus.endpoints[1].canonical, "[2001:db8::10]:8443")
        self.assertEqual(corpus.endpoints[1].version, IPVersion.IPV6)
        self.assertEqual(corpus.endpoints[1].scope, EndpointScope.DOCUMENTATION)

    def test_accepts_crlf_and_preserves_exact_source_hash(self) -> None:
        payload = b"198.51.100.8:80\r\n203.0.113.9:443\r\n"
        corpus = parse_corpus(payload)
        self.assertEqual(corpus.physical_line_count, 2)
        self.assertEqual(corpus.source_sha256, hashlib.sha256(payload).hexdigest())

        without_final_newline = parse_corpus(b"192.0.2.10:443")
        self.assertEqual(without_final_newline.physical_line_count, 1)

    def test_equivalent_ipv6_spellings_are_duplicates(self) -> None:
        corpus = parse_corpus(b"[2001:db8::1]:443\n[2001:0DB8:0:0:0:0:0:1]:443\n")
        self.assertEqual(corpus.endpoint_count, 2)
        self.assertEqual(corpus.unique_count, 1)
        self.assertEqual(corpus.duplicate_count, 1)
        self.assertEqual(corpus.unique_endpoints[0].canonical, "[2001:db8::1]:443")

    def test_classifies_privacy_relevant_scopes(self) -> None:
        corpus = parse_corpus(
            b"10.0.0.1:1\n"
            b"127.0.0.1:2\n"
            b"169.254.1.1:3\n"
            b"224.0.0.1:4\n"
            b"0.0.0.0:5\n"
            b"100.64.0.1:6\n"
            b"240.0.0.1:7\n"
            b"[fec0::1]:8\n"
        )
        self.assertEqual(
            [endpoint.scope for endpoint in corpus.endpoints],
            [
                EndpointScope.PRIVATE,
                EndpointScope.LOOPBACK,
                EndpointScope.LINK_LOCAL,
                EndpointScope.MULTICAST,
                EndpointScope.UNSPECIFIED,
                EndpointScope.SHARED,
                EndpointScope.RESERVED,
                EndpointScope.SITE_LOCAL,
            ],
        )

    def test_global_scope_branch_uses_no_live_endpoint_fixture(self) -> None:
        address = SyntheticGlobalIPv4("192.0.2.1")
        with patch.object(model_module, "_DOCUMENTATION_NETWORKS", ()):
            self.assertEqual(
                model_module._scope(address),
                EndpointScope.GLOBAL,
            )


class EndpointParserFailureTests(unittest.TestCase):
    def assert_rejected(
        self,
        payload: bytes,
        code: EndpointParseErrorCode,
        *,
        line_number: int | None,
        forbidden: str | None = None,
    ) -> None:
        with self.assertRaises(EndpointParseError) as raised:
            parse_corpus(payload)
        self.assertEqual(raised.exception.code, code)
        self.assertEqual(raised.exception.line_number, line_number)
        if forbidden is not None:
            self.assertNotIn(forbidden, str(raised.exception))

    def test_rejects_empty_or_comment_only_corpora(self) -> None:
        for payload in (b"", b"\n", b"# no endpoints\n"):
            with self.subTest(payload=payload):
                self.assert_rejected(
                    payload,
                    EndpointParseErrorCode.EMPTY_CORPUS,
                    line_number=None,
                )

    def test_rejects_ambiguous_or_invalid_syntax(self) -> None:
        cases = (
            (b" 192.0.2.1:443\n", "192.0.2.1"),
            (b"192.0.2.1:443 # inline\n", "192.0.2.1"),
            (b"2001:db8::1:443\n", "2001:db8"),
            (b"[192.0.2.1]:443\n", "192.0.2.1"),
        )
        for payload, forbidden in cases:
            with self.subTest(payload=payload):
                self.assert_rejected(
                    payload,
                    EndpointParseErrorCode.INVALID_SYNTAX,
                    line_number=1,
                    forbidden=forbidden,
                )
        self.assert_rejected(
            b"example.invalid:443\n",
            EndpointParseErrorCode.INVALID_ADDRESS,
            line_number=1,
            forbidden="example.invalid",
        )

    def test_rejects_invalid_addresses_without_echoing_them(self) -> None:
        for payload, forbidden in (
            (b"999.51.100.7:443\n", "999.51.100.7"),
            (b"[fe80::1%eth0]:443\n", "eth0"),
        ):
            with self.subTest(payload=payload):
                self.assert_rejected(
                    payload,
                    EndpointParseErrorCode.INVALID_ADDRESS,
                    line_number=1,
                    forbidden=forbidden,
                )

    def test_invalid_address_creates_no_library_exception_context(self) -> None:
        payload = b"PRIVATE-ENDPOINT-VALUE:443\n"

        with self.assertRaises(EndpointParseError) as raised:
            parse_corpus(payload)

        error = raised.exception
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertEqual(error.code, EndpointParseErrorCode.INVALID_ADDRESS)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn("PRIVATE-ENDPOINT-VALUE", repr(error))
        self.assertNotIn("PRIVATE-ENDPOINT-VALUE", rendered)
        self.assertNotIn("AddressValueError", rendered)

    def test_rejects_invalid_and_noncanonical_ports(self) -> None:
        cases = (
            (b"192.0.2.1:0\n", EndpointParseErrorCode.INVALID_PORT),
            (b"192.0.2.1:65536\n", EndpointParseErrorCode.INVALID_PORT),
            (b"192.0.2.1:100000\n", EndpointParseErrorCode.INVALID_PORT),
            (b"192.0.2.1:0443\n", EndpointParseErrorCode.NON_CANONICAL_PORT),
        )
        for payload, code in cases:
            with self.subTest(payload=payload):
                self.assert_rejected(payload, code, line_number=1)

    def test_rejects_invalid_utf8_and_non_lf_line_endings(self) -> None:
        self.assert_rejected(
            b"\xff:443\n",
            EndpointParseErrorCode.INVALID_UTF8,
            line_number=None,
        )
        self.assert_rejected(
            b"192.0.2.1:443\r192.0.2.2:443\n",
            EndpointParseErrorCode.INVALID_LINE_ENDING,
            line_number=None,
        )
        for separator in (
            "\u000b",
            "\u000c",
            "\u001c",
            "\u001d",
            "\u001e",
            "\u0085",
            "\u2028",
            "\u2029",
        ):
            with self.subTest(separator=separator.encode().hex()):
                self.assert_rejected(
                    f"192.0.2.1:443{separator}192.0.2.2:443\n".encode(),
                    EndpointParseErrorCode.INVALID_LINE_ENDING,
                    line_number=None,
                )
                self.assert_rejected(
                    f"# comment{separator}hidden line\n192.0.2.1:443\n".encode(),
                    EndpointParseErrorCode.INVALID_LINE_ENDING,
                    line_number=None,
                )

    def test_invalid_utf8_creates_no_library_exception_context(self) -> None:
        payload = b"PRIVATE-CORPUS-\xff-DO-NOT-ECHO"

        with self.assertRaises(EndpointParseError) as raised:
            parse_corpus(payload)

        error = raised.exception
        rendered = "".join(
            traceback.format_exception(type(error), error, error.__traceback__)
        )
        self.assertEqual(error.code, EndpointParseErrorCode.INVALID_UTF8)
        self.assertIsNone(error.__context__)
        self.assertIsNone(error.__cause__)
        self.assertNotIn(repr(payload), repr(error))
        self.assertNotIn("PRIVATE-CORPUS", rendered)
        self.assertNotIn("UnicodeDecodeError", rendered)

    def test_enforces_resource_bounds(self) -> None:
        self.assert_rejected(
            b"x" * (MAX_INPUT_BYTES + 1),
            EndpointParseErrorCode.INPUT_TOO_LARGE,
            line_number=None,
        )
        self.assert_rejected(
            b"\n" * (MAX_PHYSICAL_LINES + 1),
            EndpointParseErrorCode.TOO_MANY_LINES,
            line_number=None,
        )

    def test_requires_exact_bytes_type(self) -> None:
        with self.assertRaisesRegex(TypeError, "^payload must be exact bytes$"):
            parse_corpus("192.0.2.1:443\n")  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "^payload must be exact bytes$"):
            parse_corpus(DecodeOverridingBytes(b"not an endpoint"))


if __name__ == "__main__":
    unittest.main()
