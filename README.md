# Netveil

Netveil is being rebuilt as an offline, fail-closed audit tool for
network-endpoint corpora with an explicit privacy boundary.

## Current status

This repository is at **rehabilitation phase 1**. Its former working tree
contained unverified third-party IP address and port lists collected in 2022.
Those live endpoint lists have been removed from the current tree: they were
not suitable fixtures, did not include provenance or consent, and must not be
interpreted as working services.

The old values remain in Git history until a separately coordinated history
rewrite. Do not use them for connection attempts, availability checks, or
security testing.

The first shipped layer is a dependency-free, offline parser with:

- strict UTF-8, line-ending, IP-address, and port validation;
- canonical IPv4 and bracketed IPv6 representations;
- deterministic duplicate detection across equivalent IPv6 spellings;
- explicit network-scope classification, including documentation ranges;
- content binding to the SHA-256 digest of the exact input bytes;
- bounded input and safe errors that never repeat endpoint values.

It does not import a networking client, resolve DNS, or open sockets.

### Phase-1 privacy boundary

Phase 1 keeps processing local and returns redacted parse failures, but parsed
`Endpoint` and `EndpointCorpus` objects intentionally retain raw canonical IP
addresses. Treat those objects as sensitive: do not log, serialize, publish, or
attach them to issues when they came from a real corpus.

Anonymisation is **not** implemented yet. Irreversible, domain-separated
identifiers for aggregate reports remain a future phase and are listed below.
The current code therefore claims locality and redacted errors, not anonymous
output.

## Quick check

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e .
.venv/bin/python -m unittest discover -s tests -v
```

The parser is a library boundary for now:

```python
from netveil import parse_corpus

corpus = parse_corpus(b"192.0.2.10:443\n[2001:db8::10]:8443\n")
print(corpus.unique_count)
print(corpus.source_sha256)
```

The addresses above are IETF documentation ranges, not live fixtures.

## Intended direction

The next incremental releases will add:

- aggregate duplicate, range, and schema-quality reports;
- irreversible, domain-separated anonymisation for reportable aggregates;
- content-addressed audit receipts and reproducible CLI evidence;
- installed-artifact guards preserving the no-network boundary as reporting
  layers are added.

No scanner, proxy checker, or network probe is shipped.

## Safety boundary

Netveil operates on caller-supplied local bytes only and fails closed on
malformed input. Only synthetic or explicitly redistributable fixtures will be
committed.
Testing systems you do not own or lack permission to assess is out of scope.

See [SECURITY.md](SECURITY.md) for responsible-use and disclosure guidance.
