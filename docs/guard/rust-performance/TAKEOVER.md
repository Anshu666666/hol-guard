# Rust migration takeover evidence

The continuation reviewed the exact ChatGPT conversation
[Rust Migration PRD Review](https://chatgpt.com/c/6aab4df1-1bec-83ea-9203-010d1c05f2e1),
including its linked PRD, TODO, and Takeaway. The conversation title, URL, and
implementation PR #2954 were checked together. The original PRD and all 144 TODO
acceptance conditions and dependencies are preserved. The target remains
`release/3.2`.

This checkpoint covers implementation through `b3569bc10`; it precedes the final
execution-ledger reconciliation and remaining workstream measurements. It does
not establish a qualified release or change any performance threshold.

## Retained installed attempt

The [paired smoke run at 42579f046ac](https://github.com/hashgraph-online/hol-guard/actions/runs/35210168801)
failed on all four targets before complete paired sampling. Its 14 available
aggregate/build JSON records are retained under
[evidence/takeover-42579](evidence/takeover-42579/manifest.json). The manifest
records the GitHub artifact IDs and both original and retained byte hashes.

| Target | Paired baseline failure | Separate candidate lifecycle observation |
| --- | --- | --- |
| Linux x64 | Approval-persistence fault witness absent | Native Ollama passed 22 lifecycle cases and Builder passed; the outer identity check failed. |
| macOS x64 | HTTP server construction stalled in `socket.getfqdn` | Native Ollama readiness failed; Builder passed. |
| macOS arm64 | HTTP server construction stalled in `socket.getfqdn` | Native Ollama passed 22 lifecycle cases and Builder passed; the outer identity check failed. |
| Windows x64 | Existing secure opener refused the source-reference fixture | Native Ollama readiness failed; Builder passed. |

The Linux fault fixture accepted only keyword arguments while production passes
the approval request and timestamp positionally. A caught `TypeError` preceded
the intended failure witness. The fixture now accepts the actual call shape;
a regression traverses the public approval path and real store. Semantic failure
reports retain the bounded observed verdict when setup validation fails.

The outer Ollama check lost `source_sha` during generic privacy sanitization and
then compared the stripped identity with its expected contract. Its typed
identity now uses a canonical 40-character `build_sha`, with a complete sanitized
child-to-driver-to-report regression. Readiness failures retain their actual
phase, unchanged 400 ms budget, elapsed time, snapshot state, and allowlisted
publisher error. These repairs require a new installed run.

Both baseline and candidate deliberately refuse secure file opening on Windows
until an equivalent handle-bound path walk exists. Qualification now verifies
the exact refusal separately, excludes it from successful review timings, and
continues supported work. Full source-content review and source-identity
verification remain unqualified. See the
[platform contract](windows-reference-qualification.md).

The macOS experiment installs an exact loopback PTR resolver only on the
disposable runner and keeps it active around both complete build/measurement
arms. It records bounded resolver probes and removes its own exact configuration.
It does not patch the baseline or runtime or extend startup/readiness budgets.
Actual runner behavior remains to be observed.

The separate [native wheel run](https://github.com/hashgraph-online/hol-guard/actions/runs/35210168835)
passed on both macOS architectures and Windows. Linux failed its concurrency-64
gate: overlapping snapshots of shared route counters incorrectly attributed
successful requests to fail-safe routing. The new capacity report conserves
whole-wave route totals and keeps exact pre-dispatch overload attempts separate.
It preserves every accepted request and all terminal failures. This is a
measurement correction, not evidence that the stricter PRD c16 threshold passed.

The main CI pytest shards passed; coverage XML generation failed on invented
source filenames used by startup tests. Those frames now point to real test
source. The ownership gate's 500-line module limit is preserved by extracting
the unchanged private-file regression to an enrolled sibling module.

## Local validation and limits

The combined platform/corpus/acceptance/capacity/Ollama integration passed 98
focused tests. The component commits retain their independent validation:
139 platform/capacity tests, 64 route-conservation tests, 56 resolver/workflow
tests, 44 Ollama identity tests, 13 startup tests with real coverage XML export,
and nine approval-fault/diagnostic tests. These counts overlap and are not added
into a fabricated unique test total.

This local host rejects creation of an `AF_UNIX` stream socket with `EPERM`.
The actual resident runtime uses that transport on Unix. Installed resident
attempts were stopped after that capability was isolated; loopback TCP being
available does not qualify the Unix runtime. GitHub runners must supply installed
daemon, registered launcher, recovery, and platform evidence.

The foundation [PR #2951](https://github.com/hashgraph-online/hol-guard/pull/2951)
remains open at `e449594e86c717e66e14598a4130475de79c536f`, with normal auto-merge
enabled and independent code-owner approval still required. Implementation
[PR #2954](https://github.com/hashgraph-online/hol-guard/pull/2954) remains a draft.
Neither protected merge, canary deployment, nor release completion is claimed.
