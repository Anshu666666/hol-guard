# MCP request-facts reuse and its measured limits

This is the retained measurement of candidate C, not the current runtime selection.
C regresses its 128-KiB route; the later structural-binding candidate D also has
material dense-container regressions within the supported frame limit. Commit
`88d815e2d` restores the better Python runtime wiring. The explicit facts API and
tests remain available for controlled experiments; RSP-100 remains OPEN. The
frozen C measurements below are unchanged, and D's separate campaign remains
distinct.

Measured candidate C derives ordered risk categories once per unchanged supported authority preparation and reuses them for approval identity, current policy, signals, and summary. The change preserves fresh preparation after approval, claim, catalog, or input changes. It does not promise one classification for an entire interactive lifecycle. This report is a separate follow-up to the frozen [prefilter rebaseline](rust-performance-mcp-rebaseline.md); none of that earlier evidence was replaced.

## Exact input binding and current authority

Measured candidate commit `1dbfdbb8e` introduces a request-local immutable facts value. Its private binding includes every GuardArtifact field, nested metadata/schema and private metadata, arguments, scalar types, and dictionary insertion order. Snapshot construction accepts exact built-in dictionaries with string keys, lists, immutable JSON scalar values, and finite floats. Declared artifact argument tuples must contain exact strings. Unsupported/custom containers, non-finite numbers, cycles, and excessive recursion retain the existing uncached path; the change does not coerce them into reusable identities.

The preparer derives categories from its owned snapshot. A hash or policy consumer constructs an owned current snapshot, compares its exact encoding, and uses that same owned copy only when it matches. Current policy resolves the configured override before checking the match. Policy lookup, temporary grants, saved-approval claims, and post-claim revalidation remain current operations. The facts object is not attached to returned authority, exported to receipts or logs, or carried through an approval wait. Its repr hides the exact private binding. The existing request ownership and final revalidation contract continues to own alias mutation beyond each consumer; this change does not replace that contract.

The tests exercise changed nested arguments, schema, descriptions, catalog/environment/tool/server identities, private metadata, browser context, key ordering, scalar types, mutation during preparation, mutation after snapshot matching, and mutation from current-policy resolution. Actual pipe tests observe one category derivation per ordinary call and retain catalog refresh, approval accept/cancel/invalidation, and the 5 ms final quiet barrier. The broader suite passed 212 tests in 139.22 seconds; the updated memory harness passed 7 tests in 34.29 seconds. A separate source review found no new correctness blocker in the fixed production revision.

## Frozen source comparison

Baseline B is `d811b08f0`, including the previously measured exact regex prefilters. Candidate C is `1dbfdbb8e`. Harness commit `5bbd22e69` measures the same real client → CodexMcpGuardProxy.serve() → child → client pipe route, with a temporary real GuardStore, stable warn-policy provider, 100-tool catalog, and complete response/notification/ID checks. The installed CLI bootstrap, a large real policy database, and configuration-file reload cost are outside this boundary. The independent frozen-module oracle checks 3,008 cases for exact ordered categories, approval hashes and complete current-policy decisions, explicitly using prepared facts on every candidate case.

Five fresh-process blocks alternate source order for 1, 16 and 128 KiB text. Each process has one first-call warmup and 100 measured calls; six additional processes have 20 measured calls for phase attribution. Every case acquires/releases the shared flock independently, cleans its temporary store before releasing, and records UTC start/end times inside the lock. A checkpoint retains every completed case, and failures retain attempted/completed outcome counts. No failed attempt is discarded or overwritten. The [complete paired evidence](../../release-metadata/mcp-request-facts-comparison.json) contains source and harness digests.

The host is Linux x86_64 with Python 3.12.14. It is shared, and measured workloads are serialized. The ranges below describe the five observed process blocks; they are not confidence intervals. Negative percentage changes are improvements. These samples remain below the release tail-gate minima and are not installed, c16/c64, Windows, or long-soak qualification.

| Text | Baseline median p95, ms | Candidate median p95, ms | Paired p95 change, median (range) | Paired tree CPU change, median (range) |
| --- | --- | --- | --- | --- |
| 1 KiB | 137.20 | 159.38 | 20.24% (-29.61% to 152.44%) | -5.16% (-17.63% to 65.23%) |
| 16 KiB | 221.91 | 149.39 | -33.36% (-55.01% to 244.16%) | -19.18% (-39.24% to 62.12%) |
| 128 KiB | 209.72 | 324.50 | 47.79% (41.58% to 101.51%) | 17.22% (-2.62% to 61.97%) |

The ordinary controls and every adverse block remain in the evidence. In particular, 128 KiB p95 was worse in all five uninstrumented blocks, and its paired median tree CPU increased 17.22%. Removing one category pass is a structural correctness result; these route measurements determine its net cost. The separate phase profiles below show reduced classification and different policy/state costs, but do not establish the cause of those uninstrumented regressions or erase them. No general performance or non-regression pass is inferred from selected improvements or from phase timings.

## Separate CPU and memory attribution

The following are mean exclusive main-thread CPU milliseconds per call from separate instrumented processes. The snapshot column excludes its nested JSON work, which appears in all-JSON serialization. Parent CPU includes the worker’s other threads. Facts/identity includes classification, snapshot work, catalog hashing and request identity; the generous share additionally includes all JSON and other Guard computation, including costs a pure facts kernel cannot remove.

| Source / text | Parent CPU | Classification | Snapshot excluding JSON | All JSON | Policy/state | Receipt/result | Facts/identity share | Generous share |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| baseline / 1 KiB | 58.67 | 0.68 | 0.00 | 0.66 | 26.19 | 21.74 | 2.31% | 7.48% |
| candidate / 1 KiB | 108.96 | 0.51 | 0.50 | 2.15 | 68.76 | 30.11 | 2.52% | 6.50% |
| baseline / 16 KiB | 45.44 | 1.65 | 0.00 | 0.80 | 23.97 | 15.91 | 4.45% | 8.71% |
| candidate / 16 KiB | 54.59 | 0.99 | 0.32 | 1.28 | 31.38 | 17.69 | 3.16% | 7.73% |
| baseline / 128 KiB | 86.40 | 13.61 | 0.00 | 3.95 | 38.02 | 20.69 | 16.96% | 26.29% |
| candidate / 128 KiB | 58.80 | 6.04 | 0.27 | 3.26 | 24.38 | 18.83 | 12.18% | 23.15% |

All six profiles retain the exact configured 0.005-second barrier; observed mean barrier wall time ranges from 5.17 to 6.54 ms. Each ordinary candidate profile records 20 classifications for 20 measured calls, versus 40 in the baseline, and 60 snapshot constructions across preparation and the two consumers. Deliberate barrier and child waits remain included in complete-route latency. Earlier separate approval and loopback HTTP controls remain linked in the historical report; this follow-up adds no remote transport or human-wait claim.

| Text | Baseline worker peak RSS range, MiB | Candidate worker peak RSS range, MiB | Baseline sampled tree USS range, MiB | Candidate sampled tree USS range, MiB |
| --- | --- | --- | --- | --- |
| 1 KiB | 83.64–84.26 | 83.47–84.01 | 75.92–76.11 | 76.17–76.47 |
| 16 KiB | 83.62–84.01 | 83.65–83.91 | 75.98–76.45 | 76.26–76.56 |
| 128 KiB | 84.37–85.00 | 84.68–85.29 | 77.36–78.82 | 78.46–78.91 |

Worker peak RSS is the operating system’s RUSAGE_SELF high-water mark across the whole worker, including imports and transient request allocations. It is not process-tree private memory or an incremental allocation counter. Process-tree USS is sampled after catalog delivery and each response; its observed peak can miss transient allocations. Both retain benchmark observation/storage costs and establish no leak or growth-gate pass.

## Near-frame-ceiling memory and remaining large-input candidate

A separate [four-cell memory diagnostic](../../release-metadata/mcp-request-facts-memory-boundary.json) sends 4,193,792-byte ASCII or UTF-8 Unicode text in 4,193,908-byte request frames, below the unchanged 4,194,304-byte line ceiling. Child replies contain the verified complete-arguments SHA-256, payload byte count, generation, ID and metadata, keeping responses compact enough for the same frame ceiling. Each source/shape uses one warmup and three instrumented calls in a fresh process. All 16 forwards and both source pairs match exactly. These cells are not a latency or native-speedup qualification.

| Shape | Baseline peak worker RSS, MiB | Candidate peak worker RSS, MiB | Candidate parent CPU, ms | Residual classification, ms (share) |
| --- | --- | --- | --- | --- |
| ascii | 113.97 | 118.40 | 484.50 | 190.57 (39.33%) |
| unicode | 129.99 | 133.25 | 599.34 | 367.06 (61.24%) |

The existing [framing contract](../mcp-framing-bounds.md) explicitly bounds retained encoded frames and queues, not decoded heap size or exact RSS. This correction does not enlarge any wire, queue, unmatched-response, nested-operation or deadline limit. It traverses and owns containers three times per supported authority preparation, reuses immutable scalar/string values, and serializes an exact binding each time. The prepared binding lives through the hash and current-policy consumers; matching temporaries are released after use, and no facts value is retained across authority preparations. Auxiliary storage grows with the serialized inputs and container nodes rather than accumulating across requests. Unicode escaping can make the private exact binding larger than the incoming UTF-8 frame. Large schema, high-cardinality container, concurrent and long-soak memory behavior are outside these two string-shape probes; no exact maximum RSS is inferred from them.

The near-limit result is material to selection: residual classification is still a large CPU share for these shapes. It prevents extending an ordinary/128 KiB no-port decision to all accepted MCP inputs. This large-input scope remains an open candidate for a narrow facts pilot or further measured algorithm work. Three instrumented samples establish neither a native benefit nor p95/p99, installed, platform, concurrency or long-soak qualification.

## Conditional tranche status

RSP-100's candidate implementation was exercised through the real proxy route,
but its measured cost does not justify production selection. RSP-100 therefore
remains OPEN. RSP-098/RSP-103 have this separate rebaseline including snapshot
cost and transient worker memory. The original PRD §6 still requires at least
30% lower end-to-end p95 or process-tree CPU, with no more than 5% regression in
the other primary metric, before declaring the selected performance tranche
qualified. Neither removing duplicate work nor counting a pure phase as
theoretically removable satisfies that gate.

The completed source scope retains optimized Python. A broad native no-go is not established: RSP-104/RSP-105/RSP-107 remain conditional and the newly observed near-limit workload is an open candidate. Original PRD §12 F6 does not require a full proxy rewrite merely because one local facts phase is expensive. The current authority, approval, credential, remote-session and final-write boundaries remain owned by the existing control path. No installed or Windows performance pass is claimed.

Reproduce in frozen baseline and candidate checkouts, using fresh output paths:

```bash
PYTHONPATH=/path/to/candidate/src .venv/bin/python scripts/compare_guard_mcp_risk.py --baseline-src /path/to/d811b08f0/src --candidate-src /path/to/candidate/src --comparison-name request-facts --samples 100 --lock-file /tmp/hol-guard-performance.lock --json release-metadata/new-mcp-request-facts-comparison.json
PYTHONPATH=/path/to/candidate/src .venv/bin/python scripts/compare_guard_mcp_risk.py --baseline-src /path/to/d811b08f0/src --candidate-src /path/to/candidate/src --comparison-name request-facts --memory-boundary --samples 3 --lock-file /tmp/hol-guard-performance.lock --json release-metadata/new-mcp-request-facts-memory.json
```
