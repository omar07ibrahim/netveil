# Security policy

## Supported state

Netveil is in rehabilitation phase 2. It ships an offline parser and
privacy-preserving aggregate-report library, but no command-line scanner,
network probe, or stable release. Security fixes target the default branch and
the latest open rehabilitation pull request.

## Data handling

Do not submit real credentials, access tokens, private-network inventories, or
third-party endpoint inventories in an issue or pull request. Use IETF
documentation ranges or clearly synthetic special-use addresses when
demonstrating the parser.

`Endpoint` and `EndpointCorpus` objects retain raw canonical addresses, and
the corpus model retains an unkeyed source SHA-256. They must not be logged,
published, or attached to an issue when created from a real corpus. Redacted
parser exceptions protect the library-owned payload and do not create a
`UnicodeDecodeError` or address-parser context retaining rejected input.
Caller objects, ambient exception context, traceback frame locals, debuggers,
and crash dump tooling remain outside that boundary.

`build_privacy_report` and `build_privacy_receipt` keep those raw values out of
their returned models. Their source-content and duplicate-group identifiers
use separate versioned HMAC-SHA256 domains and typed prefixes. The secret key
must be exact bytes containing at least 32 bytes.

The public report binds the Python implementation, exact interpreter version,
and its use of stdlib `ipaddress` semantics. Compare report bytes only within
the same runtime profile; scope classification can change between Python
releases.

These reports are pseudonymized, not anonymous. HMAC resists offline guessing
only while a high-entropy key remains secret. It does not prevent guessing by
an actor who can submit chosen corpora to a report-generation service, so
access to such a service must also be restricted. A reused key permits
equality linkage across reports. Published output exposes aggregate scope and
port counts, source and line sizes, and the equality and frequency of
duplicated endpoint values. Assess those disclosures against the size and
sensitivity of the input before publishing.

The receipt's SHA-256 binds the canonical public report bytes but is neither a
signature nor proof of provenance. Python cannot guarantee zeroization of the
source bytes, HMAC key, or intermediate canonical values. Callers must manage
key creation, storage, access, versioning, rotation, retirement, and process
isolation. Never place a production pseudonymization key in source control,
logs, command history, report metadata, or issue attachments.

The historical repository contains unverified public endpoint strings. Their
presence does not grant permission to connect to, probe, or test those systems.
The current tree intentionally contains none of those values.

## Reporting a vulnerability

Use GitHub's private vulnerability reporting feature for this repository when
available. Include the affected commit, a minimal reproduction with synthetic
data, the expected safety boundary, and the observed behaviour. Do not include
secrets or personal data.
