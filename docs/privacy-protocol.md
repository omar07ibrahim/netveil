# Privacy report protocol v1

This document makes the byte-level Netveil v1 privacy-report contract
reproducible. It describes pseudonymization and aggregation, not anonymization.

## Input boundary

`build_privacy_report` and `build_privacy_receipt` accept:

- an exact `bytes` endpoint corpus accepted by `parse_corpus`; and
- an exact `bytes` pseudonymization key containing at least 32 bytes.

Parser size, line-count, UTF-8, syntax, and canonicalization bounds apply
unchanged. The report layer has no path, file, network, DNS, or process API.

## Typed HMAC identifiers

Both identifiers use:

```text
HMAC-SHA256(key, domain || uint64be(value_length) || value)
```

`uint64be` is an unsigned eight-byte big-endian integer. Digest text is the 64
lowercase hexadecimal characters returned by `HMAC.hexdigest()`.

The exact, stable domains and values are:

| Identifier | Typed prefix | Domain bytes as a Python literal | Value |
|---|---|---|---|
| source content | `nvs1_` | `b"netveil\x00hmac-sha256-pseudonymization\x00v1\x00source-content\x00"` | exact source bytes |
| duplicate group | `nvd1_` | `b"netveil\x00hmac-sha256-pseudonymization\x00v1\x00duplicate-group\x00"` | canonical endpoint encoded as ASCII |

The HMAC domains cryptographically separate the purposes. The distinct typed
prefixes also prevent a source ID and duplicate-group ID from being
interpreted as the same semantic type.

An endpoint ID is emitted only when that canonical endpoint occurs at least
twice. Equivalent IPv6 spellings are canonicalized before grouping. Duplicate
groups are ordered lexicographically by typed ID, never by raw endpoint or
input order.

## Aggregate semantics

Every categorical count is an endpoint-occurrence count, not a unique-value
count. Zero-count categories remain present.

The fixed v1 scope labels are `documentation`, `global`, `private`,
`loopback`, `link_local`, `multicast`, `shared`, `site_local`, `unspecified`,
and `reserved`. Classification is inherited from the fail-closed parser.

Port buckets are fixed for v1:

- `system_1_1023`: ports 1 through 1023;
- `registered_1024_49151`: ports 1024 through 49151;
- `dynamic_49152_65535`: ports 49152 through 65535.

`extra_occurrences` is the sum of `occurrences - 1` across duplicate groups.
`unique_endpoints + extra_occurrences` therefore equals
`endpoint_occurrences`.

The public report also includes exact source byte size and parser physical-line
count. It never includes an ordinary digest of the source.

## Canonical JSON and receipt binding

`netveil.sorted-keys-json.v1` is the following restricted JSON profile:

- UTF-8-compatible ASCII output from `ensure_ascii=True`;
- object keys sorted lexicographically at every level;
- compact `,` and `:` separators;
- no NaN or infinity;
- no trailing newline.

The v1 schema contains integers, strings, objects, and arrays only, so number
or Unicode normalization ambiguity is not present.

The report binds the runtime profile that supplied endpoint parsing,
canonicalization, and scope classification:

- schema `netveil.python-runtime.v1`;
- `sys.implementation.name`;
- the exact Python `major.minor.micro` version; and
- endpoint semantics `python-stdlib-ipaddress`.

The same payload and key are byte-deterministic under the same runtime profile
and exact protocol implementation. Python's stdlib `ipaddress`
classifications have changed between interpreter versions, so reports with
different runtime profiles are not claimed to be byte-identical. The profile
is inside the report-digest boundary rather than being ambient metadata.

The receipt calculates:

```text
report_sha256 = SHA256(canonical_public_report_bytes)
```

It then embeds both the report object and that lowercase digest. The digest
input is the standalone public report, which has no digest field; this avoids
self-reference. The digest is content-addressing metadata, not a signature or
proof of provenance. The receipt schema does not identify a source commit,
wheel digest, distribution version, interpreter executable hash, or external
evidence manifest.

The public identifiers declare
`netveil.hmac-sha256-pseudonymization.v1`; the report and receipt declare
`netveil.aggregate-report.v1` and `netveil.aggregate-receipt.v1`. Any
incompatible change to domains, framing, canonicalization, aggregation, or
schema requires a new protocol/schema version.

## Threat boundary

HMAC prevents offline candidate testing only while the key remains secret. It
does not prevent guessing by someone who can submit chosen corpora to a report
generation oracle. Restrict access to both the key and any service that uses
it.

Reusing a key deliberately exposes equality of exact source content and
duplicate groups across reports. Counts, sizes, categories, equality, and
frequency remain public and may identify a small corpus. Key rotation changes
the typed cryptographic IDs for independently generated keys, but aggregate
patterns can still permit inference.

Python cannot guarantee zeroization of input bytes, keys, canonical endpoint
strings, or HMAC intermediates. Callers own key entropy, storage, access,
versioning, rotation, retirement, memory/process isolation, and output
disclosure decisions.
