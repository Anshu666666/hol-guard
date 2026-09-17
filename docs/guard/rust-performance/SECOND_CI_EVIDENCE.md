# Second finalization CI: exact 24ba checkpoint

Observed 2026-09-17. [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970)
candidate `24ba2d130a90f36b676139f03cabea98a2c3b00e`, tree
`01bbfefb3702a091788bd59bc6f616193527a9a8`, has **39 terminal workflows: 32 successful
and seven failed**. The release is not qualified. The
[normalized exact-head workflow observation](evidence/second-ci-24ba/workflow-status.json)
includes the invalid native-performance YAML push run, which created no jobs and
was absent from the PR-only workflow wrapper.

The seven failures are [native wheel](https://github.com/hashgraph-online/hol-guard/actions/runs/35228365075),
[package](https://github.com/hashgraph-online/hol-guard/actions/runs/35228365019),
[Security Gates](https://github.com/hashgraph-online/hol-guard/actions/runs/35228364982),
[MCP](https://github.com/hashgraph-online/hol-guard/actions/runs/35228364816),
[Windows resident](https://github.com/hashgraph-online/hol-guard/actions/runs/35228364933),
[main CI](https://github.com/hashgraph-online/hol-guard/actions/runs/35228364797), and
[the invalid native-performance workflow](https://github.com/hashgraph-online/hol-guard/actions/runs/35228359387).
This report analyzes the package and MCP component artifacts. Other failures and
later source corrections remain outside its measured conclusions.
Main CI completed 114 jobs: 110 successful, three skipped and one failed
[Sonar Quality Gate](https://github.com/hashgraph-online/hol-guard/actions/runs/35228364797/job/105227738372).
The Sonar analysis completed; its reliability and security ratings failed the
gate. This report does not resolve or reclassify those findings.

The [evidence manifest](evidence/second-ci-24ba/manifest.json) identifies every
retained public file, its exact bytes and SHA-256, downloaded artifact members and
verified ZIP hashes. Both component experiments compare frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` with `24ba2d130...`. Do not attribute their
measurements to a later integration commit or pool them with
[the first checkpoint](FIRST_CI_EVIDENCE.md), whose environment and candidate differ.

The original [MCP public artifact](evidence/second-ci-24ba/mcp-original-failed.json)
remains **incomplete**, with `aggregate_invalid_or_outside_bound` and no published
measurements. All 30 worker log records and the measurement controller passed,
but the public finalizer rejected two fixed fields newly emitted by the shared
resource collector: `cpu_accounting_scope` and `cpu_unavailable_samples`.

The [corrected offline projection](evidence/second-ci-24ba/mcp-corrected-offline.json)
was reconstructed from the authenticated retained archive using correction
`b19bd59069db01a72ada9f3d93417f2ebfcb1866`, integrated as
`1498e226432a3731c982fb545ab9bb746848c86d`. The correction admits only
`observed_process_tree`, a nonnegative integer unavailable count, and equality
with the existing unavailable-snapshot count. Unknown fields, alternate job
scope, missing provenance and inconsistent counts still fail. No collector,
measurement, estimator, workload, denominator or production behavior changed.
The strict finalizer also ran successfully with `python -I -S`; 81 focused tests
passed and an independent source review found no privacy or completeness defect.
**This is a corrected reconstruction of the original observations, not a new
measurement or a green original GitHub workflow.**

The reconstructed MCP v2 experiment passed **30 workers, 240 child sessions and
10,080 tool calls**, with zero retained failures. It contains 48 comparison
groups, 240 independent-run trace summaries, 364 diagnostic phase rows, eight
paired comparisons and 181 raw-evidence commitments. Each source has five
independent runs in each of three separate modes. Plain and diagnostic traces
have one first call plus 12 warm calls; resource traces have one first call plus
99 warm calls. The original seven trace commitments are preserved, with one
additional actual loopback TCP trace.

The table reports candidate/baseline ratios. Its 95% intervals use 2,000 paired
run-block bootstrap resamples of the **five independent plain-run pairs**; lower
is better. The 60 warm calls per aggregate are not 60 independent runs.

| Trace | Warm wall p50 ratio [95% interval] | Mean parent process CPU ratio [95% interval] |
| --- | ---: | ---: |
| `catalog10` | 0.9660 [0.9227, 1.0266] | 0.9565 [0.8445, 1.0398] |
| `catalog100` | 0.9076 [0.8645, 0.9570] | 0.8859 [0.8393, 0.9512] |
| `catalog1000` | 0.5380 [0.5288, 0.5648] | 0.4468 [0.4380, 0.4770] |
| `payload16k` | 0.6746 [0.6654, 0.7254] | 0.6152 [0.6011, 0.6668] |
| `catalog_refresh` | 0.9019 [0.8539, 0.9629] | 0.8911 [0.8327, 0.9641] |
| `child_delay10ms` | 0.9221 [0.9148, 0.9699] | 0.8792 [0.8512, 0.9465] |
| `inline_approval10ms` | 0.9744 [0.9495, 1.0197] | 0.9612 [0.9380, 0.9953] |
| `loopback_tcp10ms` | 0.9378 [0.9003, 0.9543] | 0.9023 [0.8618, 0.9278] |

Large-catalog and 16 KiB improvements are clear within this experiment; the
smallest-catalog wall and CPU intervals cross one. There is no universal gain
claim. The full artifact also retains construction, first-call, session and
per-run p95 comparisons. With only 12 warm observations per plain run, these
tails remain descriptive: `tail_qualified=false`. The plain CPU numerator is
the proxy worker's process CPU, not a process-tree CPU qualification claim.

Separate instrumented observations attribute large-catalog fingerprint exclusive
thread CPU of **1,528.843 → 79.691 ms across 130 invocations**. For `payload16k`,
category-classification exclusive CPU is **867.002 → 45.016 ms**, with 195 → 130
invocations across 65 tool calls. Candidate residual work includes policy-store
lookup, policy evaluation and receipt/inventory/event persistence. Nested
inclusive phases overlap; instrumented timings are not substituted for plain
headline observations or added together as independent costs.

The final quiet barrier remains approximately **5.11 ms per call**. The actual
child-owned loopback TCP trace records median round-trip wall time of
**10.495 → 10.517 ms**, service wall time **10.078 → 10.077 ms**, client thread CPU
**0.295 → 0.326 ms**, and service thread CPU approximately **0.023 ms**. The service
includes the fixed synthetic 10 ms delay. External network latency and actual
human approval time are not measured; the inline approval trace uses a synthetic
callback delay. Construction, child startup and serialization are separately
observed. The measured source boundary is production `run_session` with real
child stdio; outer installed CLI ingress and bootstrap are excluded.

All **80 fixed warm resource windows** are complete, with **134–331 snapshots per
window**, zero missing samples, zero required-metric errors, and verified root
and child identities at both barriers. The sampler takes its final snapshot
before the end ACK releases child teardown. No padding sleeps or adaptive work
were added to reach the sample minimum. Linux handles remain explicitly
unsupported and are not a required Linux metric.

| Warm trace | Median sampled peak RSS, baseline → candidate (MiB) | Median sampled private peak, baseline → candidate (MiB) |
| --- | ---: | ---: |
| `catalog10` | 104.527 → 108.051 | 82.676 → 86.160 |
| `catalog100` | 106.078 → 109.516 | 84.172 → 87.559 |
| `catalog1000` | 111.969 → 114.738 | 90.000 → 92.770 |
| `payload16k` | 112.391 → 115.340 | 90.473 → 93.383 |
| `catalog_refresh` | 112.488 → 115.266 | 90.457 → 93.348 |
| `child_delay10ms` | 112.398 → 115.215 | 90.492 → 93.277 |
| `inline_approval10ms` | 114.203 → 117.156 | 92.305 → 95.164 |
| `loopback_tcp10ms` | 115.734 → 118.703 | 93.508 → 96.484 |

These are medians of five observed peaks per arm/trace. Sampled peaks remain
lower bounds and RSS includes shared pages. Traces execute in a fixed order in
each worker, so later windows include that worker's preceding allocations.
The separate ten startup/churn lifecycle records are all **incomplete**, retaining
16 missing snapshots in total and descriptor-access errors in nine records.
Their incomplete reads are not erased or relabeled as warm measurements. Warm
completeness therefore does not establish complete lifecycle memory accounting.

The [package diagnostic](evidence/second-ci-24ba/package-diagnostic.json) preserves
the real local npm `protect --dry-run` function at 1,000 dependencies and 1,000
bundle entries. All five alternating independent pairs completed with matching
fixture, entry, semantic and evidence commitments and 1,000 package/evidence rows.
The interval includes the local protect function; imports, fixture preparation,
preverified bundle admission and postvalidation are outside it.

| Package protect measure | Frozen Python median | Optimized Python median | Median paired reduction |
| --- | ---: | ---: | ---: |
| Local wall time | 8,773.536 ms | 318.011 ms | 96.3751% |
| Local process CPU | 7,732.300 ms | 310.481 ms | 95.9846% |

These are source-route paired medians, not installed CLI, qualified p95 or native
measurements. The candidate exact evaluator's individual 100/100, 1,000/1,000
and 10,000/10,000 dependency/bundle cells recorded respectively
43.703/40.593, 148.816/144.093 and 1,405.236/1,385.221 ms wall/CPU. Each is one
uncached exploratory observation, not an independently qualified latency tail.

All 72 offered cardinality observations remain accounted for: **36 candidate
completions, 24 baseline completions and 12 baseline censored attempts**. For all
four match modes, baseline dependency/bundle combinations (1,000,10,000),
(10,000,1,000) and (10,000,10,000) reached the **15-second whole-worker** containment
limit, including setup and postvalidation. That limit is neither the production
evaluator deadline nor a measured evaluator lower bound. Censored pairs have no
speedup ratio. The unversioned matrix rows remain bundle-kernel observations,
distinct from the full evaluator/protect routes. Both unresolved full-route
witnesses completed validation with their explicit credential-unavailable
outcomes; they carry no timing-benefit comparison.

The [format preflight](evidence/second-ci-24ba/package-format-preflight.json)
completed all **20 candidate cases**. The baseline completed 18 and failed its
two Composer `package_count` checks, which remain noncomparable. These are the
same baseline coverage defect and cardinality censoring pattern as the first
checkpoint. Corresponding fixture/semantic/evidence/entry hashes, package and
entry counts, and terminal statuses match the earlier reports for every offered
arm/case. Environment commitments differ, so timings are not pooled across runs.

The package public reports record complete private staging: 102 preflight files
and 189 diagnostic files, with no required files missing. Preflight retained
2,865,050 bytes and diagnostic groups retained 126,882,307 bytes. Their six
retained public archive receipts report successful encryption. This review did
not download or decrypt the package ciphertext, so archive recovery is not
claimed for these package runs.

MCP ciphertext artifact `10499739444` was downloaded with exact size and ZIP
SHA-256 verification, checked for its single permitted member, authenticated and
recovered with the existing archive tool. The
[recovery receipt](evidence/second-ci-24ba/mcp-recovery-receipt.json) confirms
182 recovered files. Existing limits remained 256 files, 32 MiB per file and
128 MiB total; all recovered directories were 0700 and files 0600. The archive
includes the aggregate plus its 181 committed raw records. Only closed-schema
public projections, fixed receipts, normalized workflow metadata and hashes are
retained here; private observations, ciphertext, keys and download credentials
are excluded. The original failed public file is retained byte-for-byte.

The evidence supports the following acceptance recommendations without changing
the [TODO](TODO.md), [execution ledger](execution-ledger.json) or PRD thresholds:

| Criterion | Evidence supported at this checkpoint | Remaining boundary |
| --- | --- | --- |
| RSP-098: measure startup, catalog hashing, classification, policy, barrier, child/network/human wait and serialization with identical synthetic traces | The corrected v2 artifact supplies these source-component measurements, separate modes, an actual loopback service and five independent paired runs. Its bounded source-component measurement criterion can be recorded as complete with this exact provenance. | Human delay is synthetic; network is loopback; installed ingress/bootstrap is outside scope. The original workflow finalizer failed. |
| RSP-103: measure optimized proxy overhead and memory, separating deliberate/remote waits from local CPU before selecting Rust | The corrected artifact supplies plain CPU/wall, separate phase attribution and 80 complete warm process-tree resource windows. Its bounded source-component rebaseline criterion can be recorded as complete with explicit lifecycle limitations. | Ten lifecycle records remain incomplete; no installed, cross-platform or qualified-tail claim follows. Native selection requires its own decision and measured pilot evidence. |
| RSP-050 / RSP-054: package cardinality and optimized-Python port decision | The reports retain every offered outcome and reproduce the large algorithm-first Python gain. | Censored baseline cells, bundle-only unversioned scope and residual attribution still constrain the decision. These criteria remain open; no native package pilot or permanent no-port decision is established. |

Any new Rust hot-path candidate must be compared with this optimized Python
baseline at the PRD's actual end-to-end boundary: at least 30% improvement in the
selected primary measure with no more than 5% regression in the other. The
observed Python improvement is not evidence that a native candidate meets that
threshold. No native MCP/package activation or release qualification is
authorized by this report.
