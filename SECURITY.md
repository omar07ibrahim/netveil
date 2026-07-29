# Security policy

## Supported state

Security work targets the default branch and the latest open rehabilitation
pull request. Netveil 0.3.0 is currently a release candidate, not a published
stable release.

The supported guarded execution path is narrow: install an exact wheel into a
fresh, standard POSIX CPython virtual environment and invoke the installed
`bin/netveil-audit` script. Recorded evidence currently covers CPython 3.12.3
on Linux x86-64. The library declares Python 3.11 or newer, but equivalent
launcher guarantees are not yet claimed for every interpreter or platform.

Editable installs, direct source execution, ordinary `import netveil` library
use, `python -m netveil`, Windows, PyPy, Conda, `pip --target`, renamed or
externally symlinked launchers, and non-standard environment layouts are
outside the guarded 0.3.0 command contract.

## Installed-command trust boundary

The wheel contains a real POSIX shell/Python polyglot launcher. `/bin/sh`
executes the sibling virtual-environment interpreter with `-I -E -S -B` before
launcher Python code. The launcher checks that isolated, no-site,
environment-ignoring, no-bytecode-write profile; verifies its installed bytes
and `netveil_bootstrap.py` against selected entries in the installed
`.dist-info/RECORD`; and compiles the already-read bootstrap source in memory.

The bootstrap checks a closed `netveil/` inventory, bounded file reads,
selected distribution metadata, and source hashes. It then installs a closed
finder that compiles pinned source bytes instead of importing source or
bytecode from disk. Preloaded and unknown `netveil.*` modules are rejected.

These checks reduce startup injection and uncoordinated installation drift.
They are not self-authentication:

- the launcher is already executing before its own later check;
- `/bin/sh`, sibling CPython, stdlib/import machinery, installer, OS,
  filesystem, standard virtual-environment layout, and launcher are trusted;
- installed `.dist-info/RECORD` is mutable, unsigned consistency metadata,
  can be rewritten by the installer, and is trusted;
- coherent changes to code and `RECORD` can pass;
- per-file identity rechecks do not form a transactionally atomic snapshot
  against a hostile concurrent filesystem mutator;
- a privileged hostile host, kernel, debugger, ptrace client, injected native
  code, malicious trusted stdlib, or memory/crash-dump collector is out of
  scope.

Verify a wheel SHA-256 through an authenticated channel before installation.
Netveil does not currently verify a package signature, publisher identity,
provenance attestation, or transparency-log entry. Full details and
unsupported paths are in
[docs/artifact-boundary.md](docs/artifact-boundary.md).

## Local file handling

After reading its installed launcher, metadata, and package files for
verification, the receipt workflow opens no caller data paths other than
`CORPUS` and `KEY_FILE`. Both must be direct POSIX regular files opened with
no-follow and nonblocking flags. `O_NOFOLLOW` applies to the final path
component; symlinks in parent directories are followed. The same descriptor's
identity is compared before and after each bounded read.

The key must contain 32–4096 exact bytes, be owned by the effective user, have
one hard link, be owner-readable, and expose no owner-execute, group, other, or
special permission bits. The corpus cannot be the same inode as the key or a
byte-identical copy. Netveil does not measure key entropy or replace a secret
manager. Never put a production key in source control, logs, shell history,
report metadata, issue attachments, screenshots, or demo recordings.

Corpus ownership, permission bits, and hard-link count are not restricted.
Input paths remain visible to the operating system and may be visible in a
process listing even though Netveil diagnostics do not repeat them. The caller
also controls stdout redirection, destination permissions, atomic publication,
and retention; Netveil writes receipt bytes to stdout rather than securely
creating an output file.

The full syntax, size, permission, and exit-code contract is in
[docs/cli-contract.md](docs/cli-contract.md).

## Privacy boundary

`Endpoint` and `EndpointCorpus` retain raw canonical addresses. The corpus
model also retains an unkeyed source SHA-256. Treat those library objects,
caller input bytes, traceback frame locals, debuggers, and crash dumps as
sensitive. Redacted library exceptions protect the library-created message
and context; they cannot erase caller-owned objects or ambient exception
state.

`build_privacy_report`, `build_privacy_receipt`, and the installed `receipt`
command keep raw endpoint strings, secret key bytes, and the ordinary source
digest out of their returned public models. Source-content and duplicate-group
identifiers use separate versioned HMAC-SHA256 domains and typed prefixes.

Reports are pseudonymized, not anonymous. HMAC resists offline guessing only
while a high-entropy key remains secret. It does not stop an actor who can
submit chosen corpora to a report-generation oracle. Reusing a key deliberately
links exact source content and repeated endpoint groups across reports.
Published output also reveals source size, line count, category totals,
duplicate equality, and duplicate frequency. Review those disclosures before
publication.

The report records `sys.implementation.name` and numeric Python
`major.minor.micro` whose stdlib `ipaddress` behavior supplied parsing and
classification. It does not hash the interpreter executable or stdlib.
Compare bytes only for the same trusted code artifact and runtime semantics.
Python cannot guarantee zeroization of source bytes, keys, canonical strings,
HMAC intermediates, or allocator copies.

The receipt's SHA-256 binds canonical public report bytes. It is not a
signature, MAC, proof of origin, or authenticated publication channel. The
receipt does not identify the source commit, wheel digest, distribution
version, or fresh-wheel evidence manifest. The
byte-level protocol and remaining disclosure surface are specified in
[docs/privacy-protocol.md](docs/privacy-protocol.md).

## Offline and authorization boundary

Netveil package code contains no intentional DNS, socket, subprocess, or
child-process operation. A publishable installed-artifact evidence bundle must
pair hostile Python environment-variable tests with Linux syscall tracing for
one exact artifact and runtime. That trace is evidence for the recorded run,
not a guarantee about a compromised trusted interpreter, shell, operating
system, or preload mechanism.

Release inventory and fresh-wheel verification JSON are unsigned. They bind a
builder-observed clean commit to exact artifact and executed-test facts, but
they do not authenticate the publisher, attest the build host, or prove that
Git, the verifier, build backend, installer, `strace`, OS, and filesystem were
honest. Obtain published artifact digests through a separately authenticated
channel.

Netveil is not a scanner or reachability tester. Historical Git commits
contain unverified public endpoint strings removed from the current tree.
Their existence does not grant permission to connect to, probe, or test those
systems. Use only caller-owned data, explicitly redistributable fixtures, or
IETF documentation ranges.

## Reporting a vulnerability

Use GitHub private vulnerability reporting for this repository when available.
Include:

- the affected commit and exact wheel SHA-256;
- interpreter, OS, install method, and invocation path;
- a minimal reproduction using synthetic data;
- the expected documented boundary and observed behavior;
- whether code and `RECORD` were changed independently or coherently.

Do not attach real endpoint inventories, private-network layouts, credentials,
access tokens, keys, personal data, memory dumps, or absolute private paths.
If private reporting is unavailable, open a minimal issue that contains no
sensitive reproduction material and asks the maintainer for a secure channel.
