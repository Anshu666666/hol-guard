# Rich offline regex pilot

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

The final comparison must record exact source and binary identities, declare
supported workload/platform scopes, and justify its go/no-go decision against
the optimized Python baseline. Production activation remains gated on that
evidence and installed/platform qualification. The hook `guard-scanner`
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
unproven. Subsequent cohorts identify the new executable backing explicitly,
retain per-command UTC timestamps, and save bounded output lengths, SHA-256
digests and fixed diagnostic categories for unexpected exits or timeouts.
They do not pool samples from the affected state. The short
[boundary profile](evidence/rsp-scanner-native-boundary-profile-linux.json)
also retains its timestamp limitation and does not establish a CLI benefit.

The [test evidence](evidence/rsp-scanner-native-regex-tests-linux.json) records
87 existing Secrets tests run with the pilot installed in the test process,
102 native file scans with no fallback, and successful child cleanup. A
separate provider boundary replay covers 425 additional length/ASCII word-edge
documents. Overlapping test invocations are reported explicitly.
