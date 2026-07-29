# Installed CLI contract

This document specifies Netveil 0.3.0's local, wheel-installed command. It is
an interface contract, not a claim that mutable Python packaging metadata is a
signature. The exact artifact and trust boundary are documented in
[artifact-boundary.md](artifact-boundary.md).

## Supported command surface

The command grammar is deliberately small:

```text
netveil-audit --help
netveil-audit --version
netveil-audit receipt CORPUS --key-file KEY_FILE
```

`--version` is accepted only as the sole argument; mixing it with a receipt,
another option, or a second `--version` is a usage error. Top-level and
`receipt` help remain available through argparse's ordinary `-h`/`--help`
forms. Long options are not abbreviated, and `--key-file` must appear exactly
once in a receipt invocation.

The supported guarded path is the `netveil-audit` script installed from a
wheel into the standard `bin/` directory of a POSIX CPython virtual
environment. Netveil 0.3.0's recorded execution evidence uses CPython 3.12.3
on Linux x86-64. The package declares Python 3.11 or newer, but the guarded
launcher is not yet claimed as verified on every such interpreter or on
Windows, PyPy, Conda, editable installs, `pip --target`, or non-standard
environment layouts.

`python -m netveil` is intentionally unavailable. Running the source checkout,
the launcher through an ordinary non-isolated Python command, or an editable
install is not a substitute for the installed guard.

## Corpus file

`CORPUS` must resolve directly to one POSIX regular file. The command opens it
read-only with `O_CLOEXEC`, `O_NOCTTY`, `O_NOFOLLOW`, and `O_NONBLOCK`, then
checks the same descriptor's identity before and after a bounded read.
`O_NOFOLLOW` applies only to the final path component; symlinks in parent
directories are followed. Corpus owner, permission bits, and hard-link count
are not restricted.

The parser accepts at most 8 MiB and 100,000 physical lines. Input must be
strict UTF-8. Empty lines and lines beginning with `#` are ignored; other lines
must contain an IPv4 literal in `IPv4:port` form or an IPv6 literal in
bracketed `[IPv6]:port` form. Accepted addresses are canonicalized before
grouping. Ports are decimal integers from 1 through 65535 with no leading
zeroes. CRLF and LF are accepted; ambiguous or non-LF Unicode separators are
rejected.

No address is resolved or contacted. The file can contain private data, so its
path and rejected endpoint text are never repeated in Python-handled Netveil
diagnostics. The input paths remain process arguments and can be visible to the
operating system or process observers.

## Key file

`KEY_FILE` is read as exact bytes. It is not decoded, trimmed, or normalized;
a trailing newline is therefore part of the key. The file must satisfy every
condition below:

- one POSIX regular file, not a symlink, FIFO, socket, or directory;
- 32 through 4096 bytes inclusive;
- owned by the process's effective user ID;
- exactly one hard link;
- readable by the owner;
- no owner execute bit;
- no group or other permission bits;
- no set-user-ID, set-group-ID, or sticky bit.

Mode `0400` or `0600` is accepted. The corpus and key must not be the same
inode and must not contain byte-identical payloads. Those checks prevent a
corpus from being accidentally reused as its own pseudonymization key; they do
not assess entropy or operate a key-management system.

## Output

On success, `receipt` writes one canonical
`netveil.aggregate-receipt.v1` JSON document followed by exactly one LF to
standard output. Standard error is empty.

For the same exact code/artifact identity, corpus bytes, key bytes, and
embedded Python runtime profile, the output bytes are deterministic. Different
Python micro versions are not promised to be byte-identical because the
runtime profile and stdlib `ipaddress` semantics are inside the receipt's
digest boundary.

The receipt contains pseudonymized aggregate data, not anonymous data. It
reveals input size, physical-line count, category totals, duplicate equality,
and duplicate frequency. It contains neither raw endpoint strings, key bytes,
nor an unkeyed digest of the corpus. See
[privacy-protocol.md](privacy-protocol.md) for the byte-level schema and HMAC
domains.

Netveil writes the receipt only to stdout. Shell redirection, downstream pipe
behavior, destination permissions, atomic publication, and retention are the
caller's responsibility. The receipt does not embed the wheel SHA-256, source
commit, distribution version, or fresh-wheel evidence identity.

## Exit codes

Diagnostics are stable, one-line, and intentionally omit caller paths and
input values.

| Exit | Diagnostic or result |
|---:|---|
| 0 | receipt, help, or version completed |
| 2 | `netveil-audit: usage_error` |
| 10 | `netveil-audit: artifact_unverified` or `netveil-audit: platform_unsupported` from the bootstrap |
| 11 | `netveil-audit: corpus_unavailable` |
| 12 | `netveil-audit: key_unavailable` |
| 13 | `netveil-audit: corpus_rejected:<parser-code>[:line=N]` |
| 14 | `netveil-audit: key_rejected` |
| 15 | `netveil-audit: output_failed` |
| 70 | `netveil-audit: internal_error` or `netveil-audit: interrupted` |

If standard error itself cannot make bounded forward progress, the process
returns 15 and may be unable to emit the complete diagnostic.

Oversized, non-regular, symlinked, unavailable, or identity-changing corpus
files fail at the file boundary with exit 11. The equivalent key-file cases
use exit 12. A short or policy-insecure key, or a key that is the same inode or
byte-identical payload as the corpus, uses exit 14. Because the command's
8 MiB file read bound runs before parsing, an oversized installed-CLI corpus
does not reach the parser's library-level `input_too_large` code.

Treat stdout as valid only when the process exits 0. An output failure can
leave a partial stdout prefix before exit 15. Failures in `/bin/sh` or sibling
interpreter execution occur before Netveil's Python error boundary and can use
OS-defined exit codes and shell diagnostics, including an invocation path.

## Offline scope

Netveil package code exposes no DNS, socket, subprocess, or child-process path.
A publishable release-evidence bundle must exercise the exact installed
artifact under syscall tracing and hostile Python environment variables. Such
evidence describes the tested Linux run; it is not a mathematical guarantee
about a compromised interpreter, shell, operating system, debugger, or preload
mechanism outside the stated trust boundary.
