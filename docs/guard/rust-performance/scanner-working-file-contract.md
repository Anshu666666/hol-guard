# Working-file identity correction and RSP-071 coverage

This is a bounded offline-scanner correctness correction after the fifth CI
checkpoint. It does not activate the experimental Rust detector, qualify an
installed artifact, change a performance threshold, or replace a frozen
baseline. The implementation starts from source
`e3d64cb89b71563bd5b7e0c47e082b369452b556`.

## Concrete behavior change

Previously, the working-tree reader resolved a path, checked its size, and then
called unbounded `read_bytes()`. It did not compare the opened file's identity
with the admitted path or recheck identity after reading. An ordinary read error
returned `None`; the scanner skipped that input without marking coverage partial.
A file could also grow after its initial size check.

The new `working_file_reader.read_working_bytes` admits a regular file and reads
through one retained descriptor in chunks of at most 64 KiB. It consumes at most
the caller's per-file byte limit plus one overflow-detection byte. Before using
the bytes it checks the admitted/opened identity, exact original size, final
descriptor and path metadata, original candidate resolution and root identity.
The scanner never passes a failed or changed snapshot to the detector.

An open/read/identity failure after regular-file admission now produces the
finite error `working_tree_file_unavailable_or_changed`, `truncated=true`, and
the existing incomplete-scan exit code **2**. Findings from successfully read
inputs remain present. This deliberate correction changes the old silently
complete outcome for those failures. It does not invent a budget truncation
reason or publish paths, contents, or exception text in the error code.

POSIX opens retain the root and resolved ancestor descriptors, traverse with
`dir_fd`, and use no-follow, nonblocking regular-file admission. A FIFO substituted
after admission cannot block the open. Every descriptor is closed on success or
failure. Final directory identity checks ignore timestamps and size, since
sibling writes legitimately change those fields.

Windows reuses `open_windows_locked_regular_descriptor`, which opens a regular
non-reparse file while denying write/delete sharing. It retains that handle
through reading and validation. The helper's existing finite sharing retries are
unchanged; they are not a new wall-clock deadline. Final Windows path verification
opens a second compatible read handle and compares full descriptor snapshots,
including complete timestamps in that same metadata domain. POSIX final path
snapshots stay in the path-stat domain. The cross-source initial
identity check excludes `ctime` and Windows
attributes because CPython path-stat and CRT-fstat time domains can differ.
Windows ancestor resolution checks detect observed changes; this is not a claim
of retaining every Windows ancestor handle or preventing arbitrary ancestor ABA.

## Preserved input and output contracts

The default bounds remain 5,000 files, 2 MiB per file, 128 MiB total, 500 findings
and 500 commits. Normal finding ordering, suppression, per-path context, HMAC,
public schema and exit codes 0/2/3 are unchanged. A stable hardlinked regular file
is a legitimate input, with a separate finding occurrence for each scanned path;
the reader does not impose the private-authority single-link policy.

Initial missing, escaping, nonregular and already-oversized inputs retain their
declared skip behavior. The existing non-Git discovery excludes leaf symlinks;
Git working-tree discovery can scan a contained link's target under the link's
path. Escaping links remain omitted. Explicit target/root aliases are resolved
as before. Existing binary and malformed-UTF-8 source bytes remain omitted by
the original decoder before regex evaluation. Malformed bytes are not reported
as a valid-Unicode Python fallback. Staged content still comes from the immutable
Git index object rather than an unstaged working-tree edit.

This correction does not retroactively make all skipped inputs incomplete, change
Git object batching, alter archive parsing, or promote offline reads into the
resident hook. The new reader is a separate bounded module; the repository
scanner remains below the 500-line source limit.

## Literal RSP-071 audit and finite witnesses

The original acceptance names realistic/fixture credentials, unstaged changes,
hardlinks/symlinks, invalid encodings, mutation, archive bombs and incomplete
scans. Before this correction, retained rich-scanner source digest
`41b1d7cc163835ecb03653eeafd188c583d1122492bf3d5cbfbc0f7d4a882383`
matched the current twelve scanner files. That historical digest is unchanged
in its original report; this tranche changes the implementation and source set.

The fifth [actual scanner smoke](scanner-smoke-ci-96a697.md) executed four Rust
tests and 69 total selected Python tests with the real pilot executable. These
are not 69 distinct native parity cases. They cover the 17-rule/14-context
credential contract, HMAC, ASCII capture edges, valid Unicode fallback, staged
versus unstaged full-CLI behavior and typed protocol/resource failures. The
collector subsequently failed before offering any of its 24 timed attempts.
That failed experiment neither erases the executed correctness tests nor supplies
the missing experiment preflight or performance evidence.

The audit found three concrete gaps in the rich scanner's own coverage: malformed
UTF-8 source bytes, scanned filesystem link behavior, and deterministic admitted
working-file mutation/read failure. Toolchain hardlink admission, invalid protocol
JSON, and precommit-hook symlinks cover different boundaries. This tranche adds:

| Witness | Scope |
| --- | --- |
| 33 reader cases | Exact byte limits/EOF, malformed raw bytes, normal skips, legitimate hardlinks and contained links, regular/FIFO/symlink substitution before open, same-inode mutation, growth/shrink/read error, leaf/parent/root/alias replacement, descriptor cleanup, separate metadata time domains and compatible Windows final-path descriptor witnesses |
| Nine scanner/CLI cases | Working and staged malformed UTF-8, non-Git/Git link differences, and five admitted read failures; explicit expected findings, counts, privacy and exit codes |
| Five opt-in native cases | Four full source-CLI comparisons for malformed bytes and links, exact public/HMAC parity, plus admitted read failure preserving partial findings and exit 2 through the actual pilot |

Existing immutable staged-OID mutation and shared plugin-input snapshot tests
remain distinct witnesses. The [archive report](archive-worker-qualification.md)
covers archive links/mutation, invalid UTF-8 manifests, expansion bombs and
incomplete scans on its retained isolated Python implementation. Its current
five-source and two-harness hashes match the measured report. All 330 hostile
or bounded-failure calls remained non-clean, but two of 510 calls missed their
exact expected code through timeout; the measured exact-result gate remains
failed. No native archive implementation is selected or claimed.

## Verification and remaining qualification

The normal repository pytest environment passed **93** focused reader, scanner,
CLI and Git tests. A separate existing detector/precision/shared-input/bridge
selection passed **54**, with **16** explicitly skipped tests requiring a local
pilot executable. The five new native cases are among those skips and are included
in the already selected `test_guard_secret_native_pilot.py` CI file. The new
reader typechecks with zero errors and zero warnings; the three changed
production modules have zero errors (existing CLI warnings remain). Ruff,
formatting and diff checks pass.

These are Linux source correctness checks, without a Rust build, local performance
workload, new installed run or actual Windows execution. **RSP-071 remains OPEN**
until the new parity cases execute with the real pilot binary and relevant
platform-specific source checks have an observed result. The pending finite
smoke/full experiment remains a separate RSP-066/RSP-072 decision input. No local
skip, collector wiring or unoffered attempt counts as passing parity.
