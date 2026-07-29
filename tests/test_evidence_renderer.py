from __future__ import annotations

import hashlib
import json
import unittest
from xml.etree import ElementTree

from tools import render_evidence
from tools import verify_fresh_wheel as verifier

SOURCE_COMMIT = "a" * 40
SOURCE_DATE_EPOCH = 1_700_000_000


def _receipt() -> dict[str, object]:
    report: dict[str, object] = {
        "counts": {
            "endpoint_occurrences": 5,
            "physical_lines": 6,
            "source_bytes": len(verifier._CORPUS),
            "unique_endpoints": 4,
        },
        "duplicates": {"group_count": 1},
        "endpoint_occurrences_by_ip_version": {"ipv4": 4, "ipv6": 1},
        "endpoint_occurrences_by_scope": {"documentation": 5},
        "source_content_id": "nvs1_" + "b" * 64,
    }
    return {
        "report": report,
        "report_digest": {
            "algorithm": "sha256",
            "value": hashlib.sha256(
                render_evidence._canonical_json(report)
            ).hexdigest(),
        },
        "schema": "netveil.aggregate-receipt.v1",
    }


def _documents() -> tuple[dict[str, object], dict[str, object]]:
    artifacts: list[object] = [
        {
            "filename": "netveil_audit-0.3.0-py3-none-any.whl",
            "kind": "wheel",
            "sha256": "c" * 64,
            "size_bytes": 24_000,
        },
        {
            "filename": "netveil_audit-0.3.0.tar.gz",
            "kind": "sdist",
            "members": [
                {
                    "kind": "directory",
                    "mode": "0755",
                    "path": "netveil_audit-0.3.0",
                    "size_bytes": 0,
                },
                {
                    "kind": "file",
                    "mode": "0644",
                    "path": "netveil_audit-0.3.0/README.md",
                    "sha256": "d" * 64,
                    "size_bytes": 100,
                },
            ],
            "sha256": "e" * 64,
            "size_bytes": 31_000,
        },
    ]
    inventory = {
        "artifacts": artifacts,
        "schema": render_evidence.INVENTORY_SCHEMA,
        "source_commit": SOURCE_COMMIT,
        "source_date_epoch": SOURCE_DATE_EPOCH,
    }
    inventory_payload = render_evidence._json_bytes(inventory)
    receipt = _receipt()
    receipt_payload = render_evidence._json_bytes(receipt)
    verification: dict[str, object] = {
        "checks": [{"name": name, "status": "pass"} for name in verifier._CHECKS],
        "installed": {
            "launcher": {
                "logical_path": "bin/netveil-audit",
                "mode": "0755",
                "sha256": "f" * 64,
                "size_bytes": 8_000,
            },
            "record": {
                "logical_path": ("site-packages/netveil_audit-0.3.0.dist-info/RECORD"),
                "mode": "0644",
                "sha256": "1" * 64,
                "size_bytes": 2_000,
            },
            "selected_record_rows": [
                {
                    "path": "../../../bin/netveil-audit",
                    "sha256": "f" * 64,
                    "size_bytes": 8_000,
                },
                {
                    "path": "netveil_audit-0.3.0.dist-info/RECORD",
                    "sha256": None,
                    "size_bytes": None,
                },
            ],
        },
        "integrity_evidence": {
            "artifacts": artifacts,
            "attestation_verified": False,
            "inventory_schema": render_evidence.INVENTORY_SCHEMA,
            "inventory_sha256": hashlib.sha256(inventory_payload).hexdigest(),
            "inventory_type": "unsigned_sha256_manifest",
            "signature_verified": False,
            "source_commit": SOURCE_COMMIT,
            "source_date_epoch": SOURCE_DATE_EPOCH,
        },
        "interpreter": {
            "cache_tag": "cpython-312",
            "implementation": "cpython",
            "version": "3.12.3",
        },
        "platform": {
            "machine": "x86_64",
            "release": "test-kernel",
            "sys_platform": "linux",
            "system": "Linux",
        },
        "public_demo": {
            "classification": (
                "synthetic_ietf_documentation_ranges_with_public_demo_key"
            ),
            "commands": [
                {
                    "argv": ["netveil-audit", "--version"],
                    "exit_code": 0,
                    "stderr": "",
                    "stdout": "netveil-audit 0.3.0\n",
                },
                {
                    "argv": [
                        "netveil-audit",
                        "receipt",
                        "documentation-corpus.txt",
                        "--key-file",
                        "public-demo.key",
                    ],
                    "exit_code": 0,
                    "stderr": "",
                    "stdout_json": receipt,
                    "stdout_sha256": hashlib.sha256(receipt_payload).hexdigest(),
                },
            ],
            "corpus": {
                "physical_lines": 6,
                "sha256": hashlib.sha256(verifier._CORPUS).hexdigest(),
                "size_bytes": len(verifier._CORPUS),
            },
            "public_demo_key": {
                "classification": "public_non_secret_test_material",
                "sha256": hashlib.sha256(verifier._PUBLIC_DEMO_KEY).hexdigest(),
                "size_bytes": 32,
                "source_constant": ("tools/verify_fresh_wheel.py:_PUBLIC_DEMO_KEY"),
            },
        },
        "schema": render_evidence.VERIFICATION_SCHEMA,
        "source_commit": SOURCE_COMMIT,
        "status": "pass",
        "syscall_traces": [
            {
                "exec_chain": ["installed_launcher", "installed_python"],
                "exec_count": 2,
                "exit_syscall_count": 1,
                "label": label,
                "network_syscall_count": 0,
                "normalized_sha256": digest * 64,
                "post_launch_process_count": 0,
                "process_count": 1,
            }
            for label, digest in (("receipt", "2"), ("version", "3"))
        ],
        "wheel": {
            "members": [
                {
                    "mode": "0644",
                    "path": "netveil/cli.py",
                    "sha256": "4" * 64,
                    "size_bytes": 7_000,
                }
            ],
            "sha256": "c" * 64,
            "size_bytes": 24_000,
        },
    }
    return verification, inventory


def _payloads() -> tuple[bytes, bytes]:
    verification, inventory = _documents()
    return (
        render_evidence._json_bytes(verification),
        render_evidence._json_bytes(inventory),
    )


class EvidenceRendererTests(unittest.TestCase):
    def test_renders_every_visual_from_cross_bound_evidence(self) -> None:
        verification, inventory = _payloads()

        outputs = render_evidence.render_bundle(
            verification,
            inventory,
            generator_payload=b"renderer source fixture\n",
        )

        self.assertEqual(set(outputs), set(render_evidence.ALL_OUTPUT_PATHS))
        for path in (
            render_evidence.CLI_SVG_PATH,
            render_evidence.COUNTS_SVG_PATH,
            render_evidence.MATRIX_SVG_PATH,
            render_evidence.PROVENANCE_SVG_PATH,
        ):
            ElementTree.fromstring(outputs[path])
        self.assertIn(b"captured stdout", outputs[render_evidence.CLI_SVG_PATH])
        self.assertIn(b"endpoint occurrences", outputs[render_evidence.COUNTS_SVG_PATH])
        self.assertIn(
            b"coordinated bootstrap record mutation accepted",
            outputs[render_evidence.MATRIX_SVG_PATH],
        )
        self.assertIn(
            SOURCE_COMMIT.encode(),
            outputs[render_evidence.PROVENANCE_SVG_PATH],
        )
        self.assertIn(
            b"netveil-audit receipt documentation-corpus.txt",
            outputs[render_evidence.CAST_PATH],
        )

        manifest = json.loads(outputs[render_evidence.MANIFEST_PATH])
        self.assertEqual(
            manifest["schema"],
            render_evidence.VISUAL_MANIFEST_SCHEMA,
        )
        self.assertEqual(manifest["source_commit"], SOURCE_COMMIT)
        self.assertEqual(
            {record["path"] for record in manifest["outputs"]},
            set(render_evidence.VISUAL_OUTPUT_PATHS),
        )
        for record in manifest["outputs"]:
            self.assertEqual(
                record["sha256"],
                hashlib.sha256(outputs[record["path"]]).hexdigest(),
            )

    def test_rendering_is_byte_deterministic(self) -> None:
        verification, inventory = _payloads()

        first = render_evidence.render_bundle(
            verification,
            inventory,
            generator_payload=b"same generator\n",
        )
        second = render_evidence.render_bundle(
            verification,
            inventory,
            generator_payload=b"same generator\n",
        )

        self.assertEqual(first, second)

    def test_rejects_noncanonical_or_cross_document_drift(self) -> None:
        verification, inventory = _documents()
        noncanonical = (
            json.dumps(verification, indent=2, sort_keys=True).encode("ascii") + b"\n"
        )
        with self.assertRaisesRegex(
            render_evidence.EvidenceRenderError,
            "not canonical",
        ):
            render_evidence.parse_evidence(
                noncanonical,
                render_evidence._json_bytes(inventory),
            )

        verification["source_commit"] = "b" * 40
        with self.assertRaisesRegex(
            render_evidence.EvidenceRenderError,
            "source commits differ",
        ):
            render_evidence.parse_evidence(
                render_evidence._json_bytes(verification),
                render_evidence._json_bytes(inventory),
            )

    def test_rejects_raw_endpoint_text_and_receipt_digest_drift(self) -> None:
        verification, inventory = _documents()
        verification["unexpected_raw_endpoint"] = "192.0.2.10"
        with self.assertRaisesRegex(
            render_evidence.EvidenceRenderError,
            "raw endpoint",
        ):
            render_evidence.parse_evidence(
                render_evidence._json_bytes(verification),
                render_evidence._json_bytes(inventory),
            )

        verification, inventory = _documents()
        demo = verification["public_demo"]
        assert isinstance(demo, dict)
        commands = demo["commands"]
        assert isinstance(commands, list)
        receipt_command = commands[1]
        assert isinstance(receipt_command, dict)
        receipt_command["stdout_sha256"] = "0" * 64
        with self.assertRaisesRegex(
            render_evidence.EvidenceRenderError,
            "receipt stdout digest",
        ):
            render_evidence.parse_evidence(
                render_evidence._json_bytes(verification),
                render_evidence._json_bytes(inventory),
            )


if __name__ == "__main__":
    unittest.main()
