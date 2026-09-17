# Installed offline Secrets qualification

The retained Python scanner now has a wheel-only qualification probe for
RSP-069 and the scanner portion of RSP-071. It invokes the actual installed
`hol-guard secrets` and `hol-guard-secrets` console launchers from a temporary
working directory. Its Python interpreter runs with `-I`; editable installs
and source-tree module substitutions are rejected. The probe compares each
relevant installed module byte-for-byte with the supplied wheel, records
wheel/module/launcher digests, and repeats the identity check after scanning.
Each launcher must match its installed distribution's `RECORD` SHA-256 and
size, contain a supported generated wrapper for the exact entrypoint, and
name the current installation's interpreter. Interpreter comparison uses
the absolute lexical path, because different virtual environments can share
one resolved base interpreter. The launcher is bounded to 4 MiB and its
Python wrapper to 8 KiB; symlinks and unexpected wrapper statements fail.
Wrapper parsing consumes the original bytes, including the POSIX shebang,
so Python's encoding-cookie rules and line positions match the actual loader.
A bundled native wheel must also have a manifest whose build SHA matches the
builder's candidate SHA. The scanner route remains Python.

On Windows the probe supports the pinned uv 0.9.26 launcher's PE resources
and the distlib appended ZIP wrapper. It reads uv's trampoline kind,
interpreter path and script ZIP with `LOAD_LIBRARY_AS_DATAFILE`; this does
not execute launcher code. Both formats require exactly one `__main__.py`
with a supported entrypoint wrapper. The uv format and wrapper are taken
from the pinned primary sources
([trampoline builder](https://github.com/astral-sh/uv/blob/0.9.26/crates/uv-trampoline-builder/src/lib.rs),
[wheel installer](https://github.com/astral-sh/uv/blob/0.9.26/crates/uv-install-wheel/src/wheel.rs)).
Unsupported launcher formats fail explicitly. Actual Windows execution is
still part of the hosted qualification below.

The probe constructs all 17 provider formats and independent context cases,
including generic entropy, documentation, fixture suppression, sensitive
fixture paths, public Google client configuration, references and Unicode
line positions. The rich repository contains 28 files and 22 independently
expected public occurrences. It compares every public result field across
both launchers and a repeated invocation. After staging the rich bytes, it
replaces all working files with safe text and verifies that the working scan
is clean while both staged entrypoints retain the original result. Comparing
working/staged results changes only the expected source label.

The fixed-count contracts cover exits 0, 2 and 3; incomplete coverage takes
precedence over findings. They exercise explicit file, file-byte, total-byte,
finding and history-commit bounds. A 501-finding fixture verifies the actual
default 500-finding limit and a larger explicit limit in both working and
staged modes. A file one byte above 2 MiB checks the actual default file limit
and explicit opt-in. All five parser defaults are independently specified and
checked from the installed module. Working-tree oversized files retain their
existing exclusion behavior; an oversized staged blob remains incomplete.

Additional cases cover hardlinks, internal/external/dangling symlinks, invalid
UTF-8, NUL input, caller-scoped HMACs, missing targets and non-Git staged
errors. An unsupported host link operation is recorded explicitly; storage
exhaustion is a setup failure rather than a skip. Three separate mutation
workers load the installed distribution's `hol-guard` entrypoint while
injecting a deterministic leaf replacement, symlink replacement or growth
between verification and opening. Each must trigger, return exit 2, preserve
the other finding and report `working_tree_file_changed`. These are labelled
as instrumented installed-entrypoint cases; the ordinary cases use unmodified
console launcher subprocesses.

Each scan command has a 25-second maximum within a 180-second command budget.
The parser reads at most 2 MiB plus one byte per output stream from temporary
capture files and rejects oversized output. Failure receipts retain output
lengths, digests and fixed reason codes without raw output or exception text.
Every generated provider candidate, including the shorter AWS and Google
values, is excluded from public output. Receipts checkpoint atomically after
each command. Oversized output digests are explicitly labelled as bounded
prefixes. These functional checks do not establish a performance benefit.
The 2 MiB limit applies after the child exits; it is not an active limit on
child output or temporary-file disk growth while the child is running. The
fixed fixtures and command deadline bound this probe's workload. A successful
subprocess is recorded as `command_completed` until its public contract passes;
semantic failures mark and checkpoint that same row as failed.

## Local evidence and hosted scope

The isolated Linux pure-wheel smoke completed all 28 cases. The
[final encoding-aware launcher receipt](evidence/rsp-scanner-installed-encoding-bound-linux.json)
records the final probe's source digest, start/end timestamps, supplied wheel
and unchanged installed module and launcher identities, including both
launchers' verified installation bindings. All link operations were available
on this host; no scanner case was skipped. The initial run's
[original receipt](evidence/rsp-scanner-installed-pure-wheel-attempt-linux.json)
is preserved separately from the final source-identified receipt. The local
wheel includes the corrected descriptor reader and optimized Python detector;
its module hashes identify those exact bytes. The fresh environment contains
only that wheel, with no dependency installation or reference to a source
tree. The [local validation record](evidence/rsp-scanner-installed-local-validation-linux.json)
binds both receipts to their probe revisions and records the build limitations.
The original raw receipt predates the additional probe-source timestamp
and digest metadata and is not presented as the final probe revision.
The [intermediate source-identified receipt](evidence/rsp-scanner-installed-pure-wheel-final-linux.json)
also remains unchanged. Root review identified that an intermediate command
row could say passed before public validation completed; the
[semantic status correction and replay](evidence/rsp-scanner-installed-semantic-validation-linux.json)
bind the [preceding receipt](evidence/rsp-scanner-installed-pure-wheel-semantic-status-linux.json)
to that fix. A subsequent independent review found that parent module
attestation and a stable launcher digest did not bind the actual launcher
to that installation. Every earlier raw receipt remains unchanged; it
establishes the observed results and parent module identity, without the
new launcher binding. The
[launcher validation record](evidence/rsp-scanner-installed-launcher-validation-linux.json)
binds the [first launcher-bound receipt](evidence/rsp-scanner-installed-launcher-bound-linux.json)
to the origin correction. Independent review then found that decoding a
wrapper as UTF-8 before parsing could disagree with Python's encoding-cookie
behavior. The final probe parses the original bytes and keeps the POSIX
shebang; the
[encoding validation record](evidence/rsp-scanner-installed-encoding-validation-linux.json)
records this correction and its parse-only regressions. The earlier receipt
remains unchanged and is not presented as the final parser revision.
All 28 cases pass again
with identical wheel, module and launcher bytes. No runtime scanner or CLI
behavior changed.

The local build first failed because one existing interpreter did not have
Hatchling. A second interpreter had Hatchling 1.32.0, outside the project's
`<1.31` constraint, so normal dependency checking correctly rejected it. The
development-only pure-wheel smoke used `--no-isolation` and
`--skip-dependency-check` with that existing tool. This is an explicit local
build limitation; it is not evidence that the normal locked native release
build passed. No existing interpreter, cache or native artifact was modified.

Fifty focused probe/builder tests pass, including installed-file and
source-origin substitution, independent expected occurrences, public-field
loss, candidate disclosure, oversized output and independent check execution
after failure. An earlier test stub omitted standard interpreter flags and
caused two test setup errors; the corrected stub preserves every original
flag except the isolated-mode value under test. These were harness setup
errors, not scanner failures. Three further regressions prove that successful
command exit alone never becomes a passed semantic result, and malformed or
incorrect public output checkpoints the same row as failed. Fifteen further
tests cover supported POSIX/Windows wrappers, wrong interpreter or entrypoint,
unexpected executed statements, launcher replacement against `RECORD`, uv's
resource kind and size bounds, and data-only resource loading and cleanup.
Windows tests use parser fixtures and simulated Win32 resource calls; they
are not Windows execution evidence. Seven further parse-only regressions
cover UTF-8 cookies and hidden statements under `unicode_escape` in POSIX,
distlib ZIP and uv resource ZIP wrappers, plus the original POSIX line
positions for an ignored third-line cookie. None of those witnesses is
executed. Ruff checks pass
for the probe, tests and builder.

The existing paired artifact builder now supplies its actual candidate wheel
and build SHA to this probe as a separate required check. A failed paired
sampling command does not prevent the installed scanner check from running.
The receipt is written to `aggregate/installed-offline-secrets.json` within
the existing qualification artifact. The first published attempt at
`abf319d5a345d761d88e26ba787026e98370c26f` completed on all four hosts in
[run 35229526455](https://github.com/hashgraph-online/hol-guard/actions/runs/35229526455).
The [hosted receipt manifest](evidence/rsp-scanner-installed-hosted-abf.json)
retains every scanner attempt and each original build-metadata file, with
artifact IDs and ZIP/JSON digests. All four overall jobs failed; the scanner
ran independently and passed on three hosts.

| Host | Candidate target | Installed scanner status |
| --- | --- | --- |
| Linux x86-64 | `x86_64-unknown-linux-musl` | [28 passed; no skips](evidence/rsp-scanner-installed-abf-linux.json) |
| macOS Intel | `x86_64-apple-darwin` | [28 passed; no skips](evidence/rsp-scanner-installed-abf-macintel.json) |
| macOS Apple Silicon | `aarch64-apple-darwin` | [28 passed; no skips](evidence/rsp-scanner-installed-abf-macarm.json) |
| Windows x86-64 | `x86_64-pc-windows-msvc` | [Failed before any scanner case](evidence/rsp-scanner-installed-abf-windows.json) |

All three passing hosts used actual native-bundled wheels from the published
build, the exact final probe, verified launcher bindings and the same final
scanner module bytes. Their 28 named cases, expected exits and semantic
dimensions match the local reference. Every public result digest except
host-generated Git-history commit IDs also matches. These are 84 completed
functional cases across three hosts, with no native detector activation.

Windows raised `PackageNotFoundError` during initial installed-distribution
attestation, before recording any identity or running a scan. Its probe hash
is the exact CRLF conversion of the published LF source, so the different
hash does not establish a source change. The preceding transition check also
lost access to an installed module. The common qualification environment
failure was corrected for the subsequent attempt below; this original
zero-case scanner failure remains preserved. No Windows launcher, finding,
mutation or CLI acceptance is inferred from this first failed attempt.

RSP-069's probe implementation and local installed Python coverage are
complete. Hosted qualification passes on Linux and both macOS architectures;
Windows remains incomplete until the corrected hosted check passes. RSP-071 combines this scanner
subset with the independent archive qualification. The
[standalone native regex NO-GO](rsp-scanner-regex-pilot.md) remains unchanged;
there is no native detector activation or inference of installed native
scanner parity from these retained-Python checks.

## Subsequent hosted attempt at 9db62e884

[Run 35239001782](https://github.com/hashgraph-online/hol-guard/actions/runs/35239001782)
used source `9db62e8844c2ba2627f55b6b00e58cb5b175185d`, tree
`47ba580366672b3b92cb46e6bb1d19c670444e94`. The
[new manifest](evidence/scanner-installed-9db/manifest.json) retains all four
original scanner receipts and build metadata, with exact API-verified ZIP
digests. This is a new source cohort: it includes the Windows path/descriptor
identity correction. The earlier 84 Unix passes remain attached to `abf`.

| Host | Raw scanner result at 9db |
| --- | --- |
| Linux x86-64 | [28 passed; no skips](evidence/scanner-installed-9db/linux-receipt.json) |
| macOS Intel | [28 passed; no skips](evidence/scanner-installed-9db/macintel-receipt.json) |
| macOS Apple Silicon | [28 passed; no skips](evidence/scanner-installed-9db/macarm-receipt.json) |
| Windows x86-64 | [23 passed rows; one failed row; four later cases unreached](evidence/scanner-installed-9db/windows-receipt.json) |

All four probes now attest an actual native-bundled candidate wheel and both
console entrypoints. Windows verifies the real uv PE resources, their exact
entrypoint wrapper and interpreter binding, and installed RECORD entries.
All eight scanner module hashes match the exact source: LF bytes on Unix and
the exact CRLF conversion on Windows. The probe source itself is unchanged
from the earlier attempt. Every observed public-result digest except the
generated history commit identity matches the earlier independent reference.
The three complete probes retain all 28 case expectations, including links,
invalid encodings, mutation and incompleteness. These results do not turn the
four overall paired-job failures into successful jobs.

Windows has progressed beyond the prior missing-distribution failure. Its
23 passing rows include both real console entrypoints, rich working/staged
findings, unstaged divergence, installed defaults and caller HMAC, explicit
limits, and exits 0/2/3. It then records `fixture_git_setup`. Source tracing
shows that the history bounds and occurrence-source checks had already
completed: their validation marker and public digest are present. The old
catch-all subsequently marked that last completed row failed when a later
fixture setup raised. The raw status is preserved and remains a failed row
in the reported totals: **107 passed rows, one failed row and four unreached
cases across this attempt**. No missing case is counted as a skip or pass.

The following links fixture used `nul.ts`, which Python's Windows path rules
classify as a reserved device name. This is a concrete fixture portability
defect and a source-supported likely trigger for the Git setup failure.
The original probe did not retain the failing Git operation or stderr, so
that exact operating-system cause is not proven by this receipt. The links,
invalid-encoding and mutation cases need a fresh corrected Windows run.

Probe-only correction `0e2d560cc` changes that binary fixture's filename while
preserving its NUL bytes, adds an explicit failed setup row with an allowlisted
Git operation and hash-only diagnostics, and preserves already completed
cases when later setup or final attestation fails. Scan expectations,
timeouts and limits are unchanged. **54 source tests passed in 0.60 seconds**
under the shared lock; Ruff, formatting and whitespace checks passed. No
installed execution or performance measurement was repeated for this repair.
The new source checks do not amend the original hosted result. RSP-069's
four-host installed gate remains incomplete pending corrected Windows coverage.

```sh
/absolute/installed/python -I ci/native_runtime/probe_installed_offline_secrets.py \
  --wheel /absolute/actual-candidate.whl \
  --source-sha <candidate-build-sha> \
  --json /absolute/installed-offline-secrets.json
```
