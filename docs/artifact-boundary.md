# Installed artifact boundary

Netveil's installed guard reduces accidental drift and Python import-path
ambiguity. It is not package signing, sandboxing, or host attestation.

## Execution sequence

The supported wheel installs a real POSIX shell/Python polyglot script rather
than a generated `console_scripts` wrapper:

```text
wheel-installed netveil-audit
  -> /bin/sh
  -> sibling venv/bin/python -I -E -S -B
  -> static launcher checks startup and installed-RECORD-bound files
  -> installed-RECORD-bound netveil_bootstrap.py is compiled from pinned bytes
  -> package inventory and source records are checked
  -> netveil.* is compiled from pinned source bytes by a closed finder
  -> receipt command reads local corpus/key files
  -> canonical pseudonymized JSON
```

The combined Python flags take effect before launcher Python code:

- `-I`: isolated mode and safe import path;
- `-E`: ignore Python environment variables;
- `-S`: do not import `site` or `sitecustomize`;
- `-B`: do not write bytecode caches.

The launcher verifies those flags at runtime. It locates one exact standard
virtual-environment site directory, preflights installed `METADATA` and
`RECORD` as regular files of at most 1,048,576 bytes, checks the installed
script and `netveil_bootstrap.py` against their SHA-256/size entries in the
installed `.dist-info/RECORD`, and compiles the already-read bootstrap bytes
in memory. It never imports the top-level bootstrap by name.

`importlib.metadata` subsequently parses those trusted installed metadata
files and may reread them. The preflight is a resource bound, not an
authentication step or atomic snapshot. Selected metadata payloads and every
record-bound launcher/bootstrap/package file have the same 1,048,576-byte
per-file runtime ceiling.

The bootstrap then:

- requires the exact distribution name and version;
- requires no entry points and the exact `top_level.txt` bytes
  `netveil\nnetveil_bootstrap\n`;
- checks selected metadata and every allowed `netveil/` source record;
- opens files with bounded, no-follow descriptor reads and identity rechecks;
- rejects unknown files inside the package directory;
- treats allowed package bytecode as inert and rejects unknown package cache
  names;
- refuses a preloaded `netveil` package;
- installs a closed first-position finder;
- compiles only the pinned source bytes already held in memory;
- rejects imports of unlisted `netveil.*` modules.

## Trust table

| Layer | Status |
|---|---|
| authenticated wheel SHA-256 obtained before install | external trust root |
| installer and install-time environment | trust root |
| operating system and filesystem semantics | trust root |
| `/bin/sh` and sibling CPython interpreter | trust root |
| CPython stdlib and import machinery | trust root |
| installed static launcher | directly executed trust root |
| standard POSIX virtual-environment layout | required precondition |
| installed `.dist-info/RECORD` | installer-derived mutable consistency input and trust root |
| `netveil_bootstrap.py` bytes | checked against installed `RECORD` before execution |
| `netveil.*` source bytes | checked, pinned, and compiled in memory |
| corpus and key files | sensitive caller-controlled inputs |
| canonical receipt | public pseudonymized output, subject to disclosure review |

## Non-claims

The runtime never reads the wheel archive or verifies its SHA-256. It reads
the installer-produced `.dist-info/RECORD`, whose launcher path and bytes can
differ from the wheel archive's original record after installation.
`RECORD` is unsigned. A party able to change code and update it coherently can
make the consistency checks accept those new bytes. The guard therefore does
**not** prove authenticity, publisher identity, provenance, freshness, or
installation from a particular wheel. Verify a published wheel digest through
an authenticated channel before installing it.

The launcher is already executing when it checks its own current bytes. A
modified launcher can run code before its later mismatch is detected. The
launcher, `/bin/sh`, interpreter, stdlib, OS, filesystem, and `RECORD` remain
inside the trusted computing base.

The runtime does not hash the sibling Python interpreter, `/bin/sh`, installer,
or stdlib. It does not enforce owner or write-mode policy for installed
artifact files; the launcher checks only that the installed script is a
regular file. The separate release-evidence gate additionally requires the
wheel and installed launcher modes to be owner-executable. A compromised
installer or install-time host can coherently alter installed files and
`RECORD`.

`-B` prevents bytecode writes; it is not the reason existing bytecode is inert.
The top-level bootstrap is compiled directly from checked source bytes, and
package modules are served by the closed in-memory source finder. Unknown
package cache files are rejected.

The guard is not a sandbox and does not defend against a privileged hostile
host, kernel compromise, debugger, ptrace, process-memory reader, injected
native code, malicious trusted stdlib, crash-dump collector, or coherently
mutated trust roots. Per-file identity checks do not create a transactionally
atomic snapshot across the whole installation against a hostile concurrent
filesystem mutator. Python cannot guarantee secret-memory zeroization.

The runtime bootstrap verifies selected distribution records and the closed
`netveil/` package directory. It does not enforce the exact full wheel or sdist
inventory; that is a separate release gate.

The receipt schema itself contains no wheel digest, source commit,
distribution version, or evidence-manifest identifier. Those provenance
bindings remain external release evidence.

## Unsupported invocation paths

The following are deliberately outside the 0.3.0 guarded command contract:

- editable installs and direct source-checkout execution;
- ordinary `import netveil` library use, including from the installed wheel;
- `python -m netveil`;
- invoking the launcher with ordinary Python flags instead of its shell
  handoff;
- Windows, PyPy, Conda, `pip --target`, and non-standard install layouts;
- renamed launcher files or invocation through external symlinks;
- preloaded or embedded `netveil` module state.

A renamed or expected-name symlink is rejected once Python starts. An external
symlink without the expected adjacent interpreter can fail in the shell before
Netveil controls diagnostics; shell output may then include the invocation
path. Use the installed script in the environment's own `bin/` directory.

## Evidence standard

A publishable artifact must be checked from a clean source commit and fresh
wheel installation. The gate must bind:

- source commit, wheel SHA-256, interpreter version, and exact archive
  inventory;
- launcher bytes, mode, shebang, installed `RECORD`, and absence of
  `entry_points.txt`;
- isolated startup under hostile Python environment variables;
- inert bootstrap/package bytecode and rejection of unknown package files;
- fail-closed uncoordinated source and metadata tampering;
- deterministic receipt bytes from synthetic IETF documentation ranges;
- absence of raw endpoint and key material in public outputs;
- an offline syscall trace for the exact tested Linux execution.

Coordinated code-plus-`RECORD` mutations belong in negative trust-boundary
evidence: they must be shown as accepted, not misleadingly presented as
attacks the unsigned guard prevents.
