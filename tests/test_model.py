from __future__ import annotations

import hashlib
import ipaddress
import unittest
from typing import cast

from netveil import Endpoint, EndpointCorpus, EndpointScope, IPVersion
from netveil.model import _create_corpus, _create_endpoint


class ModelConstructionBoundaryTests(unittest.TestCase):
    def test_public_constructors_are_blocked(self) -> None:
        with self.assertRaisesRegex(
            TypeError,
            "^Endpoint objects are created by parse_corpus$",
        ):
            Endpoint()
        with self.assertRaisesRegex(
            TypeError,
            "^EndpointCorpus objects are created by parse_corpus$",
        ):
            EndpointCorpus()

        with self.assertRaises(TypeError):
            Endpoint(  # type: ignore[call-arg]
                "not-an-ip",
                0,
                IPVersion.IPV4,
                EndpointScope.DOCUMENTATION,
            )
        with self.assertRaises(TypeError):
            EndpointCorpus(  # type: ignore[call-arg]
                "not-a-sha256",
                -1,
                -1,
                (),
                (),
            )

    def test_endpoint_factory_enforces_exact_types_and_domains(self) -> None:
        address = ipaddress.IPv4Address("192.0.2.1")

        with self.assertRaisesRegex(TypeError, "^address must be an exact"):
            _create_endpoint("192.0.2.1", port=443)  # type: ignore[arg-type]
        with self.assertRaisesRegex(TypeError, "^port must be an exact int$"):
            _create_endpoint(address, port=True)
        for port in (0, 65_536):
            with (
                self.subTest(port=port),
                self.assertRaisesRegex(ValueError, "^port must be in"),
            ):
                _create_endpoint(address, port=port)
        with self.assertRaisesRegex(ValueError, "^scoped IPv6"):
            _create_endpoint(
                ipaddress.IPv6Address("fe80::1%eth0"),
                port=443,
            )

    def test_corpus_factory_derives_identity_counts_and_uniqueness(self) -> None:
        payload = b"192.0.2.1:443\n192.0.2.1:443\n"
        endpoint = _create_endpoint(
            ipaddress.IPv4Address("192.0.2.1"),
            port=443,
        )
        corpus = _create_corpus(
            payload=payload,
            physical_line_count=2,
            endpoints=(endpoint, endpoint),
        )

        self.assertEqual(corpus.source_sha256, hashlib.sha256(payload).hexdigest())
        self.assertEqual(corpus.source_bytes, len(payload))
        self.assertEqual(corpus.physical_line_count, 2)
        self.assertEqual(corpus.endpoints, (endpoint, endpoint))
        self.assertEqual(corpus.unique_endpoints, (endpoint,))
        self.assertEqual(corpus.duplicate_count, 1)

    def test_corpus_factory_rejects_impossible_inputs(self) -> None:
        endpoint = _create_endpoint(
            ipaddress.IPv4Address("192.0.2.1"),
            port=443,
        )

        with self.assertRaisesRegex(TypeError, "^payload must be exact bytes$"):
            _create_corpus(
                payload=cast(bytes, bytearray(b"x")),
                physical_line_count=1,
                endpoints=(endpoint,),
            )
        with self.assertRaisesRegex(
            TypeError,
            "^physical_line_count must be an exact int$",
        ):
            _create_corpus(
                payload=b"x",
                physical_line_count=True,
                endpoints=(endpoint,),
            )
        with self.assertRaisesRegex(TypeError, "^endpoints must be an exact tuple$"):
            _create_corpus(
                payload=b"x",
                physical_line_count=1,
                endpoints=cast(tuple[Endpoint, ...], [endpoint]),
            )
        with self.assertRaisesRegex(ValueError, "^physical_line_count must be"):
            _create_corpus(
                payload=b"x",
                physical_line_count=-1,
                endpoints=(endpoint,),
            )
        with self.assertRaisesRegex(ValueError, "^a corpus must contain"):
            _create_corpus(
                payload=b"",
                physical_line_count=0,
                endpoints=(),
            )
        with self.assertRaisesRegex(ValueError, "^physical_line_count cannot"):
            _create_corpus(
                payload=b"x",
                physical_line_count=1,
                endpoints=(endpoint, endpoint),
            )
        with self.assertRaisesRegex(TypeError, "^every endpoint must come"):
            _create_corpus(
                payload=b"x",
                physical_line_count=1,
                endpoints=cast(tuple[Endpoint, ...], (object(),)),
            )


if __name__ == "__main__":
    unittest.main()
