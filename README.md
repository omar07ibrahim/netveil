# Netveil

Netveil is being rebuilt as an offline, privacy-preserving audit tool for
network-endpoint corpora.

## Current status

This repository is at **rehabilitation phase 0**. Its former working tree
contained unverified third-party IP address and port lists collected in 2022.
Those live endpoint lists have been removed from the current tree: they were
not suitable fixtures, did not include provenance or consent, and must not be
interpreted as working services.

The old values remain in Git history until a separately coordinated history
rewrite. Do not use them for connection attempts, availability checks, or
security testing.

## Intended direction

The next incremental releases will add:

- a strict offline parser and canonical endpoint representation;
- deterministic duplicate, range, and schema-quality checks;
- irreversible, domain-separated anonymisation for reportable aggregates;
- content-addressed audit receipts and reproducible CLI evidence;
- tests proving that the default workflow never opens a network socket.

No scanner, proxy checker, or network probe is currently shipped.

## Safety boundary

Netveil will operate on local files only and fail closed on malformed input.
Only synthetic or explicitly redistributable fixtures will be committed.
Testing systems you do not own or lack permission to assess is out of scope.

See [SECURITY.md](SECURITY.md) for responsible-use and disclosure guidance.
