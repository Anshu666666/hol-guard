# Rich offline regex pilot

The measured decision is **NO-GO for activating this standalone extraction
subprocess**. The final corrected-reader comparison reduced mean complete
process-tree CPU by 31.6%, but regressed p95 full CLI wall time by 13.5%, beyond
the permitted 5%. All 60 calls preserved the same 680 public findings. The
optimized Python implementation remains the offline CLI route; this decision
does not reject unmeasured Rust boundaries or in-process bindings.

This is an explicit benchmark experiment for RSP-066 and RSP-072. It is not
imported by any installed production entrypoint and does not change the
Secrets CLI default implementation. It addresses the remaining large-source
opportunity identified in the [rich workflow baseline](rsp-scanner-qualification.md).

## Measured boundary

The [residual CPU profile](evidence/rsp-scanner-detector-profile-linux.json)
measures one 256 KiB source file containing all 17 provider formats, ten times
each. Across five process-CPU trials, regex iteration accounts for 73–76% of
detector CPU (144–153 ms of 192–206 ms). Timing each iterator advancement
excludes Python finding consumers. An independent cProfile pass is included;
these instrumented values are attribution diagnostics, not CLI acceptance. A
separate [source-identified replay](evidence/rsp-scanner-detector-profile-replay-linux.json)
retains all five samples and shows a wider 61–78% regex CPU share, reinforcing
the host variability already observed in full-command controls.

The pilot moves those provider regex scans and generic assignment candidate
extraction into a separate `guard-offline-regex-pilot` executable. It sends
one complete logical file per request, amortizes process startup across files
within one CLI invocation, and never crosses the boundary once per rule or
finding. The existing Python detector owns all suppression, scoring, entropy,
line calculation, candidate deduplication, ordering, public fields and HMACs.
Repository traversal, staged object identity, Git batching/reuse, explicit
user limits and exit handling remain the existing Python implementation.

## Experimental protocol

The NDJSON schema is `guard-offline-regex-pilot.v1`. Initialization contains
`schema`, a SHA-256 `catalog` identity and an ordered `patterns` array. Each
pattern carries its ID, regex text, case/multiline flags and assignment marker.
The child compiles the catalog once and acknowledges the same schema and
catalog with `ready: true`. Compilation has explicit regex/DFA size limits.

A scan request contains `schema`, a monotonic request `id`, and owned `text`.
The complete response contains the same schema, catalog and ID,
`complete: true`, and one ordered result for every rule. Each capture contains
half-open `whole` and `secret` spans. Assignment captures additionally contain
`name` and `quote` spans. An absent assignment quote has its existing empty
span at the secret start. Responses never contain candidate strings, context
or caller HMAC keys. Python validates identity, completeness, rule order,
fields, span bounds, capture containment and nonoverlap before consuming any
candidate. Duplicate response keys are rejected.

Native support is deliberately limited to ASCII text at most 4 MiB per logical
file. ASCII offsets are simultaneously UTF-8 byte and Python character offsets.
Non-ASCII or larger text follows the original Python patterns for the entire
file and increments an explicit fallback counter. This preserves Unicode word
boundaries, case folding, line counting and decoding behavior without claiming
a complete Unicode regex port. Python's four extra ASCII whitespace control
characters are translated explicitly. The generic assignment backreference is
represented by separate double-quoted, single-quoted and unquoted branches;
ordered captures are compared against Python at length and delimiter edges.

Both frame directions are bounded at 64 MiB, initialization at 32 rules and
4 KiB per pattern, and extraction at 100,000 total raw candidates per logical
file. The child rejects unsupported input, excess captures, malformed JSON and
unterminated frames with a fixed non-sensitive reason and exit 2. It never
returns a partial result as complete. The Python bridge has one 30-second
remaining request deadline across writing and reading, closes the input and
reaps the child, and kills/reaps a child that does not exit. Protocol or native
failures abort benchmark qualification. This experimental failure mode is not
a claim of production fallback or installed-CLI integration.

The child does not preserve lexical overlap between requests. Every file is a
separate input. The bridge clears per-file capture state after every detector
call, restores patched functions when the experiment ends, and reports native
and Python fallback counts separately from the public CLI JSON.

## Qualification and activation

The release binary passes four Rust tests and release Clippy with warnings
denied. The Python boundary and runner suite passes 45 tests, including the
actual staged CLI with worktree bytes that differ from the index. Ordered
capture parity covers 510 assignment edge/random documents, every provider
format, rich large sources, independent context/HMAC expectations, Unicode
fallback, native and bridge limits, EOF/deadlines and function restoration.

The runner compares the complete public CLI result and independently expected
finding counts, file occurrences and byte coverage. Both arms execute the real
`codex_plugin_scanner.cli.main` dispatch in fresh Python processes. The pilot
arm includes bridge imports, child startup, catalog compilation, request and
response JSON, all retained Python work, public JSON output and child cleanup.
Process-tree CPU includes the reaped Rust child and Git children. The runner
also exercises exits 0/2/3, explicit file/byte/finding limits, the default
500-finding bound and missing targets.

Every workload/cache state has its own measurement lock and checkpoint. A
failed case retains already completed samples. Only verified fixture-data
eviction earns an evicted label; cache preparation failures remain explicit.
Ratios compare nearest-rank p95 wall time and mean complete process-tree CPU.
The report includes 2,000 paired bootstrap resamples and central 95% intervals.
Passing local point thresholds alone does not establish release readiness.

Build and validate with existing locked workspace dependencies:

```sh
CARGO_INCREMENTAL=0 cargo build --manifest-path rust/Cargo.toml \
  --locked --offline --release -p guard-offline-regex-pilot
cargo test --manifest-path rust/Cargo.toml --locked --offline --release \
  -p guard-offline-regex-pilot
GUARD_OFFLINE_REGEX_PILOT_BINARY=/absolute/path/to/guard-offline-regex-pilot \
  uv run pytest -q tests/test_guard_secret_native_pilot.py
uv run python scripts/bench_guard_secret_native_pilot.py \
  --native-pilot-binary /absolute/path/to/guard-offline-regex-pilot \
  --measurement-lock /absolute/path/to/performance-measurement.lock \
  --output /absolute/path/to/native-regex-comparison.json --repeats 30
```

The final comparison below records exact source and binary identities and
declares supported workload/platform scopes. Its failed gate leaves production
activation deferred. Installed/platform qualification is separate. The hook `guard-scanner`
contract is never used to stand in for the richer offline findings.

## Preserved measurement interruption

The [initial matrix](evidence/rsp-scanner-native-regex-initial-linux.json)
retains seven complete 30-pair workload/cache states and three cache states
whose fixture-data eviction could not be verified. The next working-tree
state retains 17 complete pairs and a failed native call in pair 18. During
that state, the shared release target was moved from overlay storage to
executable tmpfs without acquiring the common measurement lock. The binary
digest was unchanged. The failed state cannot qualify a performance benefit.

The [incident record](evidence/rsp-scanner-native-relocation-incident-linux.json)
preserves the original report digest, observed filesystem timestamps and
failure. A temporarily missing executable is a plausible explanation for exit
2, but the original runner did not retain failure output; the exact cause is
unproven. Subsequent cohorts record the executable's resolved path and device,
retain per-command UTC timestamps, and save bounded output lengths, SHA-256
digests and fixed diagnostic categories for unexpected exits or timeouts.
They do not pool samples from the affected state. The short
[boundary profile](evidence/rsp-scanner-native-boundary-profile-linux.json)
also retains its timestamp limitation and does not establish a CLI benefit.

The [test evidence](evidence/rsp-scanner-native-regex-tests-linux.json) records
49 combined boundary/runner tests and one additional repository parity test.
The latter covers hardlinks, internal/external/dangling symlinks, invalid UTF-8,
NUL input, Unicode fallback and changed working bytes. A separate provider
boundary replay covers 425 additional length/ASCII word-edge documents.
Overlapping test invocations are reported explicitly.

The first run of 87 existing Secrets tests installed the pilot for detector and
repository entrypoints, but left the public package's previously imported
function alias unchanged. Its 102 native file scans prove some native use, not
that every direct detector test used the pilot. The
[corrected replay](evidence/rsp-scanner-native-regex-legacy-replay-linux.json)
also patches that public alias before collecting tests: all 87 pass, with 110
native file scans, no fallback and successful child cleanup. This test setup
correction does not change the measured CLI path, which already uses the
patched repository entrypoint.

## Complete attempted matrix and withdrawn result

The [matrix summary](evidence/rsp-scanner-native-regex-matrix-summary-linux.json)
combines the initial report with the separately completed
[post-relocation cohorts](evidence/rsp-scanner-native-regex-post-relocation-linux.json).
All 12 planned workloads and both cache states were attempted. Seventeen states
completed 30 alternating pairs each, covering 1,020 full CLI calls with exact
public finding and coverage equivalence. Seven requested eviction states could
not be verified and do not qualify as cold measurements. The earlier failed
state's 34 successful calls and one failed native call remain separate.

Only the older-reader warm four-file, 1 MiB rich-source workload passed the numerical point
and interval gates. Its mean process-tree CPU ratio is 0.578 (95% paired
bootstrap interval 0.498–0.668); its p95 wall ratio is 0.785 (0.455–0.810).
Both arms preserve all 680 findings. Other measured workloads do not establish
the required full-command benefit from this subprocess boundary.

That passing cohort ended at 11:47:04 UTC. A later disclosure placed an
unlocked 57 MB cleanup of completed package fixtures sometime after 11:46:54,
without an exact deletion timestamp. Overlap with the final ten seconds cannot
be excluded. The numerical result is preserved, but its qualifying status is
withdrawn. The separate complete confirmation below used a coordinated lock
window and the final corrected Python reader. Unknown cleanup timing also
limits attribution of later historical cohorts. The confirmation was justified
by the disclosed intervention, not by selecting a better result.
No production or installed native route is activated by this evidence.

A separate [controlled reader diagnostic](evidence/rsp-scanner-working-reader-race-replay-linux.json)
confirmed two pre-existing working-tree reader defects: replacing a checked
leaf with a symlink before its binary open can read a file outside the root,
and growing a checked file before open can exceed the byte bound. It used only
generated temporary files. The initial diagnostic hook failed to trigger and
is explicitly excluded; the corrected hook triggered both interventions.
The working-tree scanner now uses the shared byte reader through one bounded
descriptor. It compares file identity, mode, size and mutation timestamps at
open and after reading, and verifies the path still names the same file. Reads
stop at the observed size plus one byte; that detects growth without reserving
the whole configured budget for each small file. A detected mutation marks the
scan incomplete with `working_tree_file_changed`, preserves other findings,
and produces CLI exit 2. Existing canonical paths, hardlink occurrences, UTF-8
and binary exclusions and explicit/default bounds remain covered.

The [reader tests](evidence/rsp-scanner-working-reader-tests-linux.json) record
214 affected Python tests, then 62 final boundary/reader tests after the bounded
allocation refinement. A separate 95-test run enables native extraction for
the legacy Secrets tests and new reader regressions before collection; it
passes with 111 native files and successful child cleanup. These invocations
overlap and are not an additive distinct-test count. The final large-rich
confirmation uses this corrected reader for both arms and records a new source
identity, rather than pooling its results with the earlier reader.

## Final corrected-reader confirmation and decision

The [complete confirmation](evidence/rsp-scanner-native-regex-final-reader-confirmation-linux.json)
contains 30 alternating full CLI pairs on four 256 KiB rich source files.
Its measurement window was 2026-09-17 12:23:14.936779–12:24:05.448348 UTC.
Both arms use Python source commit
`66d86b3c9cc1d755878ad0649b618504bf4f5133`, including the final descriptor reader;
the scanner source digest is
`14dea3727ed74a622c4024be018d069a8c76b7306ec1ebd71715d7418a2a22e8`.
The frozen native binary digest is
`bda6936a350d361b0de0422c54ea57842c9353d9e7de11c554880532bdcebe35`.
These samples are separate from every older-reader or interrupted cohort.

| Complete command metric | Optimized Python | Native extraction pilot | Native / Python | Paired bootstrap 95% interval |
| --- | ---: | ---: | ---: | ---: |
| Mean process-tree CPU | 934.048 ms | 639.111 ms | 0.684 | 0.511–0.912 |
| p95 wall time | 1,812.231 ms | 2,056.465 ms | 1.135 | 0.289–2.084 |

The adopted gate requires at least 30% lower CPU or p95 wall and no more than
5% regression in the other metric. The 13.5% p95 wall regression fails the
point gate; the wide intervals also fail the conservative gate. Every call
returns exit 3 with all 680 findings across four files and 1,048,576 bytes.
The complete public result digest is identical across all 60 calls; every
native call uses four native file extractions and zero Python fallbacks.
The [decision record](evidence/rsp-scanner-native-regex-decision-linux.json)
preserves these values and the exact source identities.

The host was Linux 6.18.44 on x86-64 with nine visible logical CPUs and Python
3.12.14. Later inventory identifies an Intel Xeon Platinum 8370C at 2.80 GHz
and 22,568,256 KiB visible memory. The executable records Rust 1.88.0 and was
built in release mode with locked offline dependencies and incremental
compilation disabled. This was a shared host; power mode was not controlled,
and process-tree RSS was not measured. Fixture data was prewarmed; code and
metadata caches were uncontrolled. There is no global cold-cache claim or
cross-platform performance acceptance.

A [separate provenance correction](evidence/rsp-scanner-native-executable-provenance-linux.json)
preserves the raw reports unchanged. Their free-text notes described the
executable as tmpfs-backed, but both reports recorded device 28 and a resolved
workspace path. Read-only inspection after the confirmation found that target
was a real overlay directory; a separate copy remained on tmpfs device 27.
The actor and time of any restoration are unknown. Recorded path/device/hash
take precedence over the unsupported notes. Because device 28 was recorded at
cohort start, this inspection does not establish an intervention during the
confirmation and does not justify repeating it to seek a pass.

The retained production work is the Python context-allocation correction and
the bounded working-file reader. Suppression, context, entropy, Unicode,
HMACs, public findings, traversal, Git reuse, completeness and CLI defaults
remain in Python. Native protocol failures are experimental aborts, so this
report makes no claim that production native fallback semantics are qualified.

## Original task acceptance mapping

These statuses are scoped to the original PRD and TODO. Conditional production
work can be deferred by the measured NO-GO; source invocation alone does not
establish installed qualification.

| Original task | Evidence and proposed status | Explicit remaining scope |
| --- | --- | --- |
| RSP-062 | Complete Linux source-workflow baseline: startup/import, Git I/O, detector CPU, files/bytes, small/large/repeated blobs. | Installed and other-platform performance are separate. |
| RSP-066 | Complete actual boundary comparison and scoped subprocess NO-GO. | Other native boundaries and in-process bindings were not measured. |
| RSP-067 | Complete experimental capture/span schema, exact rich findings and caller HMAC preservation. | This is not a production-native rich-output schema. |
| RSP-068 | Pilot implementation and bounded parity complete; production port deferred by NO-GO. | ASCII at most 4 MiB is supported; Unicode/oversized input uses Python. Protocol failures abort qualification. |
| RSP-069 | Source CLI verified; the [installed retained-Python probe](rsp-scanner-installed-qualification.md) passes all 28 local cases and 28 actual native-bundled-wheel cases on each of Linux and both macOS architectures. | Windows failed at initial distribution attestation after a common environment failure and needs a corrected hosted attempt. No native detector route is activated. |
| RSP-071 | Scanner adversarial subset complete, including staged divergence, credentials, links, invalid encoding, mutation and incomplete scans. | Archive bombs/isolation use separate archive evidence; installed/platform coverage is explicit. |
| RSP-072 | Complete scoped NO-GO and coverage publication against final optimized Python source. | No installed-native or cross-platform release-performance claim. |
