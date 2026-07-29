# Security policy

## Supported state

Netveil is in rehabilitation phase 1. It ships an offline parser library but
no command-line scanner, network probe, or stable release. Security fixes
target the default branch and the latest open rehabilitation pull request.

## Data handling

Do not submit real credentials, access tokens, private-network inventories, or
third-party endpoint inventories in an issue or pull request. Use IETF
documentation ranges or clearly synthetic special-use addresses when
demonstrating the parser.

Phase-1 `Endpoint` and `EndpointCorpus` objects retain raw canonical addresses.
They are not anonymized and must not be logged, published, or attached to an
issue when created from a real corpus. Redacted exceptions protect error
messages only; irreversible report identifiers are a future phase.

The historical repository contains unverified public endpoint strings. Their
presence does not grant permission to connect to, probe, or test those systems.
The current tree intentionally contains none of those values.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository when
available. Include the affected commit, a minimal reproduction with synthetic
data, the expected safety boundary, and the observed behaviour. Do not include
secrets or personal data.
