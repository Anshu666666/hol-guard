# Rich offline scanner qualification

This extends the initial safe-text algorithm benchmark with finding-heavy
source files and explicit correctness gates. It also removes an unnecessary
allocation in the Python detector: ordinary provider matches no longer split
the entire input into surrounding lines when neither fixture nor placeholder
suppression uses those lines. Suppression order, provider rules, confidence,
entropy, finding positions, HMACs and public output remain unchanged.

The tested baseline is `fb8d57a8efc364068860f74ea41414d595ee976c`, which already
contains bounded Git object batching, scan-local finding reuse and shared
plugin traversal. The candidate is
`5ea667e15fdeada0a25533fe2d098119cea0dde8`. Both complete source digests are in
the [raw evidence](evidence/rsp-scanner-rich-linux.json). The earlier
comparison against the original `2e672d2d` implementation remains in the
[initial scanner report](rust-performance-scanner-review.md).

## Correctness and coverage

The runner evaluates all 17 ordered provider/context rules and 14 additional
context examples with independently specified expected rule sets. These cover
high-entropy assignments, unrelated random values, low-entropy values,
indirect source and shell references, documentation, fixtures, sensitive
files, public client configuration, Unicode and fine-grained GitHub tokens.
It verifies caller-keyed HMACs against an independent HMAC calculation and
checks that changing caller keys changes the fingerprint. All serialized
finding fields are compared across the two implementations.

The existing Anthropic/OpenAI pattern overlap is preserved. The lexical
detector can return both rules for an Anthropic-format candidate; repository
deduplication retains its existing provider choice. Catalog coverage and final
repository finding counts are checked separately, so overlapping rules do not
inflate claims about the number of reported occurrences.

The workflow matrix includes 10 and 1,000 staged files, repeated Git blobs,
eight 256 KiB files, working-tree and plugin controls, 17 and 510 provider
source files, four 256 KiB finding-heavy source files, staged bytes whose
working-tree versions have been replaced with safe text, and repeated history.
The largest history fixture preserves 4,046 findings across 238 file versions
and six commits. Every timed Secrets CLI result equals the corresponding
instrumented scanner result, including files/bytes covered, completeness,
finding order and commit/path occurrences.

CLI contracts exercise complete accepted scans (0), findings with
`--fail-on-findings` (3), and incomplete/error scans (2). Incomplete coverage
takes precedence over findings. Explicit file/byte bounds and missing targets
are tested in the recorded matrix. A separate [CLI contract replay](evidence/rsp-scanner-cli-contracts-linux.json)
passes both implementations on rich working-tree, divergent staged and repeated
history workloads, including the explicit finding bound and default
500-finding bound. Large working-tree and history scans return incomplete (2)
at the default bound; the smaller staged scan remains complete (0).
The default limits and production CLI entrypoint are unchanged.

The focused detector, assignment, fixture, Git-object, redaction, Secrets CLI
and qualification suite passed 106 tests before measurement. The added tests
prove that ordinary provider scans avoid whole-file context materialization,
while neighboring fixture markers, sensitive fixture paths, Unicode line
separators and explicit placeholders retain their previous behavior. The
expanded runner suite passed 21 tests after adding atomic checkpoints and
per-workload locking, including failure-path lock release and preservation of
the previous checkpoint when serialization fails.

## Measurement boundaries

The run used Linux 6.18.44, x86-64, nine visible logical CPUs, Python 3.12.14 and
Git 2.51.1. Five fresh-process trials per implementation alternate execution
order for each workload/cache state. Instrumented scanner wall/CPU, detector
CPU/call counts, Git object-I/O wall time, Git child CPU, source import time,
serialization time, subprocess counts and coverage are recorded separately.
The full CLI measurement includes a fresh interpreter, command dispatch,
scanning, Git children, public JSON serialization and process exit. Its CPU
measurement includes the reaped process tree. Bytes/sec uses the actual
covered byte counter divided by full CLI wall time.

The source dispatch uses `codex_plugin_scanner.cli.main` with the
`hol-guard` program name. It is not an installed-wheel or native-consumer
measurement. The worker process envelope includes imports, instrumentation,
serialization and validation overhead; it must not be interpreted as pure
interpreter startup time.

For prewarmed trials the runner reads every generated fixture file. For
eviction trials it flushes generated regular files with `fsync`, requests
`POSIX_FADV_DONTNEED` and verifies zero resident data pages with `mincore`
before each worker and full CLI sample. This controls fixture file data only.
Interpreter/code caches and directory/inode metadata remain uncontrolled.
Global machine caches are never dropped.

The matrix contains **21 measured equivalent rows and five unavailable
eviction rows**. Eviction could not be verified for repeated small/large staged
safe files, the plugin control, or the small/many provider working-tree cases.
Those rows have no timing samples and no cold-cache claim. Verified eviction
did succeed for the large finding-heavy source workload, staged provider
divergence and repeated provider history, among other rows. No ENOSPC error
occurred in the scanner run.

## Observed results and limits

These are local diagnostic medians, not release performance acceptance.
Nearest-rank p95 with five trials is also included in the raw report; it is not
a defensible release tail estimate.

| Workload and cache state | Findings | Full CLI wall, baseline → candidate | Full process-tree CPU, baseline → candidate | Candidate detector CPU / full CLI CPU |
| --- | ---: | ---: | ---: | ---: |
| 17 provider source files, prewarmed | 17 | 743.7 → 747.2 ms | 510.2 → 538.0 ms | 2.3% |
| 510 provider source files, prewarmed | 510 | 1,880.8 → 1,256.2 ms | 1,092.0 → 1,027.6 ms | 24.1% |
| Four 256 KiB rich source files, prewarmed | 680 | 1,426.5 → 2,486.1 ms | 1,029.5 → 1,099.9 ms | 70.5% |
| Four 256 KiB rich source files, verified eviction | 680 | 3,094.0 → 3,066.7 ms | 1,938.3 → 1,464.2 ms | 53.7% |
| 34 staged provider files with safe unstaged edits, verified eviction | 34 | 1,589.6 → 1,199.1 ms | 533.1 → 454.5 ms | 4.8% |
| 170 repeated staged provider files, prewarmed | 2,890 | 1,219.4 → 1,023.4 ms | 463.1 → 514.8 ms | 0.8% |
| Repeated provider history, verified eviction | 4,046 | 2,474.5 → 1,320.5 ms | 896.7 → 616.8 ms | 19.4% |

Even unchanged controls vary materially. Individual full CLI CPU measurements
within an arm vary by factors of two to four, and control median CPU changes
range from about -20% to +40%. The late repeated-provider staged/history
cohorts may also overlap removal of unrelated regenerable build caches to
restore free disk space. All raw samples are retained. These conditions
prevent claiming the required 30% full-command improvement with at most 5%
regression in the other primary metric from this run.

The removed allocation is established independently by the code path and
tests: it previously materialized every line for each ordinary provider match
and now performs zero such materializations. The broad local timing matrix
does not establish a stable end-to-end speedup for that change.

## Native detector investigation

There is no qualified native cutover in this evidence. Small staged scans,
finding reuse and the 17-file provider workload spend little of the complete
command in detection. Even eliminating all measured detector CPU could not
deliver a 30% CPU reduction on those observed workloads. A separate native
process would add startup and input/output serialization costs.

The large-source workload is different: detection still accounts for roughly
54–71% of full-command CPU in this diagnostic. This leaves a plausible native
kernel opportunity. A blanket conclusion that a richer native detector cannot
help would be unsupported. That finding justified the subsequent
[native regex extraction pilot](rsp-scanner-regex-pilot.md), which preserves
Python context/suppression/HMAC work and the complete public result while
including the actual boundary in full CLI measurements. Its separate final
comparison used the corrected descriptor reader at commit `66d86b3c9`, not the
older source measured in this report. It reduced mean full-command CPU by
31.6%, but increased p95 wall time by 13.5%; the allowed regression is 5%.
The scoped decision is NO-GO for activating that standalone subprocess.

RSP-062 now has a broader Linux workflow baseline. RSP-066 and RSP-072 have
explicit historical evidence for retained scopes and remaining native
opportunity. The subsequent pilot report maps its implementation, NO-GO and
installed/platform limitations to the conditional RSP-067–069 acceptances.
The existing hook `guard-scanner` contract is not used
as a substitute for the richer offline detector. Archive workers, third-party
scanners, network intelligence and report orchestration remain in their
existing separately bounded routes.

## Reproduce

Use clean frozen source trees and the same locked development interpreter for
both arms. The runner now supports per-workload shared locking and atomically
checkpoints completed workloads. A checkpoint has `run_complete: false` until
the entire requested matrix and final source-identity checks finish.

```sh
uv run python scripts/bench_guard_secret_scans.py \
  --baseline-root /absolute/path/to/frozen-baseline \
  --source-root /absolute/path/to/frozen-candidate \
  --measurement-lock /absolute/path/to/performance-measurement.lock \
  --output /absolute/path/to/scanner-qualification.json \
  --repeats 5
```

Use repeated `--case` and `--cache-state` options for a declared subset, and
`--contracts-only` for correctness qualification without timed samples.
`--measurement-lock` uses POSIX `flock`; on other platforms an external
platform-appropriate timing lock can be used instead. Verified eviction is
Linux-specific and fails explicitly elsewhere. macOS, Windows and release
hardware performance remain separately unqualified by this Linux evidence.
