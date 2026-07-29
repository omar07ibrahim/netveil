# Netveil

Netveil is being rebuilt as an offline, fail-closed audit tool for
network-endpoint corpora with an explicit privacy boundary.

## Current status

This repository is at **rehabilitation phase 2**. Its former working tree
contained unverified third-party IP address and port lists collected in 2022.
Those live endpoint lists have been removed from the current tree: they were
not suitable fixtures, did not include provenance or consent, and must not be
interpreted as working services.

The old values remain in Git history until a separately coordinated history
rewrite. Do not use them for connection attempts, availability checks, or
security testing.

The first layer is a dependency-free, offline parser with:

- strict UTF-8, line-ending, IP-address, and port validation;
- canonical IPv4 and bracketed IPv6 representations;
- deterministic duplicate detection across equivalent IPv6 spellings;
- explicit network-scope classification, including documentation ranges;
- content binding to the SHA-256 digest of the exact input bytes;
- bounded input and safe errors that never repeat endpoint values.

It does not import a networking client, resolve DNS, or open sockets.

Phase 2 adds an in-process aggregate-report boundary:

- an HMAC-SHA256 content ID bound to the exact source bytes;
- domain-separated HMAC IDs emitted only for endpoint values that repeat;
- occurrence counts by IP version, address scope, and IANA port-number range;
- explicit duplicate-group and extra-occurrence counts;
- deterministic, sorted-key JSON for the public report and receipt;
- an in-report Python runtime profile binding stdlib endpoint semantics;
- a SHA-256 digest of the canonical public report bytes, computed outside the
  report so the digest does not refer to itself.

The new API returns no raw address, canonical endpoint, secret key, or unkeyed
digest of the source. It has no file, network, or process API.

### Privacy and threat boundary

Parsed `Endpoint` and `EndpointCorpus` objects still retain raw canonical IP
addresses, and `EndpointCorpus` includes an ordinary SHA-256 source digest.
Treat parser models as sensitive: do not log, serialize, publish, or attach
them to issues when they came from a real corpus. Use the privacy-report API
when output must cross that boundary.

Privacy reports are **pseudonymized aggregates, not anonymous or
irreversible data**. HMAC-SHA256 makes offline enumeration impractical only
while a high-entropy key remains secret. Reusing a key intentionally makes
the exact source content and repeated endpoint groups linkable across reports.
Anyone who can submit chosen corpora to a report-generation service can test
candidates online, so access to that service is part of the key boundary.
The output also reveals source size, physical-line count, category totals,
duplicate equality, and duplicate frequency. Those signals may identify a
small or otherwise recognizable corpus.

The receipt's report SHA-256 is content integrity metadata, not a signature,
proof of origin, or substitute for an authenticated publication channel.
Python cannot reliably zeroize the caller's input, key, or intermediate
objects. The caller owns key generation, access control, versioning, rotation,
retention, and process isolation. Never hard-code or commit a production key.

Parser failures use bounded codes and line numbers. Their library-created
payload and exception context do not retain a rejected endpoint or undecodable
corpus. Caller-owned input objects, ambient exception context, traceback frame
locals, debuggers, and crash dump tooling remain outside that boundary and can
still retain sensitive bytes.

## Quick check

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The parser remains available for trusted local inspection:

```python
from netveil import parse_corpus

corpus = parse_corpus(b"192.0.2.10:443\n[2001:db8::10]:8443\n")
print(corpus.unique_count)
```

The addresses above are IETF documentation ranges, not live fixtures.

Build a public aggregate and deterministic receipt with a secret key of at
least 32 bytes:

```python
import secrets

from netveil import build_privacy_receipt

# For a real workflow, load a managed secret instead of generating an
# ephemeral key or embedding one in source code.
key = secrets.token_bytes(32)
receipt = build_privacy_receipt(
    b"192.0.2.10:443\n192.0.2.10:443\n",
    pseudonymization_key=key,
)
public_bytes = receipt.canonical_json_bytes()
```

With one key, equivalent endpoint spellings canonicalize before their
duplicate-group ID is calculated. Rotating the key changes the cryptographic
IDs. Source-content and duplicate-group IDs have different HMAC domains and
different typed prefixes, so they cannot be confused semantically.

Report bytes are deterministic for the same inputs and the same embedded
runtime profile. The profile records the Python implementation and exact
version because stdlib `ipaddress` parsing and classification can change
between Python releases; cross-profile byte identity is not claimed.

The exact framing, domains, ordering, port buckets, and canonicalization
profile are specified in
[docs/privacy-protocol.md](docs/privacy-protocol.md).

## Intended direction

The next incremental releases will add:

- richer schema-quality aggregates without weakening the privacy boundary;
- reproducible CLI evidence;
- source-derived diagrams, output examples, and short demonstrations;
- installed-artifact guards preserving the no-network boundary as reporting
  layers are added.

No scanner, proxy checker, or network probe is shipped.

## Safety boundary

Netveil operates on caller-supplied local bytes only and fails closed on
malformed input. Only synthetic or explicitly redistributable fixtures will be
committed.
Testing systems you do not own or lack permission to assess is out of scope.

See [SECURITY.md](SECURITY.md) for responsible-use and disclosure guidance.
