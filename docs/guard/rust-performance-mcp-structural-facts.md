# MCP structural-facts correction: frozen comparison and decision

Do not select the structural-facts candidate D for universal runtime activation. Its exact owned-input binding is functionally correct in the exercised scope, but ordinary controls and large containers fail the nonregression requirement. Retain optimized Python B as the runtime default and keep RSP-100 OPEN. This report does not supersede or relabel the adverse [B→C results](rust-performance-mcp-request-facts.md).

## Frozen inputs and completion

The baseline is `d811b08f081d72c348b95f0cf9e45349fb1787e6` (B, exact risk prefilters); the candidate is `1dbc20f31b5cc7a0b6402afaa6a0b9127131771c` (D, structural facts binding). The complete source and harness used by every worker were frozen before measurement. Workers verified their imported risk/runtime source hashes, and each case checked source identities before and after execution. The raw reports now include the frozen commit IDs and harness hashes.

The five alternating process blocks each ran 100 measured calls per source at 1, 16 and 128 KiB, with one first-call warmup. Six separate 20-call profiles bring the ordinary campaign to 36 cases and 3,156 successful forwards. Ten separate near-frame-ceiling diagnostic cells each ran one warmup and three instrumented calls. Across all 46 cells there were 3,196 successful forwards, exact complete-response/forwarding parity in all 23 pairs, and no timeout substitutions, hidden retries, or discarded failed cases. Each campaign independently passed 3,008 frozen-source full category, approval-hash and policy-decision comparisons.

Cases ran from `2026-09-17T12:55:34.548782+00:00` through `2026-09-17T13:14:04.991316+00:00` on the recorded Linux source-route host. The shared flock covers one case at a time, including temporary-store cleanup, then releases for other bounded work. Independent process blocks alternate source order. The host remains noisy; all qualification flags stay false. This is not installed CLI, Windows, macOS, live remote, concurrent-session, or release-tail qualification.

## What changed and what remains fresh

C serialized the complete artifact and arguments into a private JSON string at preparation and at both consumers. D instead makes the owned strict-JSON copy and an immutable structural binding in one traversal. A private byte string records distinct scalar/key/container tags and nesting; an ordered immutable tuple records exact string/integer leaves. Finite floats use `float.hex()` so signed zero remains distinct. Large immutable strings are shared by reference. There is no per-scalar tagged tuple and no policy decision in the binding.

Every matching consumer still uses its own matching copy. Artifact fields, private metadata, tuple command arguments, nested values, dictionary order and exact built-in JSON types remain bound. Current policy resolution still precedes policy matching. Custom containers/scalars, non-finite values, cycles and unsupported shapes use the prior uncached path. Facts remain local to one authority preparation; they do not survive into saved-approval claims, waits or later authority preparations. The final 5 ms quiet/freshness barrier, catalog invalidation ordering, transport limits and approval outcomes are unchanged.

Validation at the frozen D source: 51 focused facts/actual-pipe tests and 176 additional proxy/framing/identity/policy regressions passed; Ruff and diff checks passed. Independent source review found no concrete binding/ownership defect. The new witnesses include signed zero, bool/int/float/string distinctions, nesting and insertion-order collisions, immutable text sharing, dense scalar structure, input mutation, policy callbacks and actual stdio container payloads. These establish correctness of the candidate API in the tested scope, not production performance selection.

## Uninstrumented paired results

Positive change means slower. Each value is the median of the five paired percentage changes, with the complete observed range; instrumented cells are excluded.

| Request text | Client p95 change | Process-tree CPU per call change |
| --- | --- | --- |
| 1 KiB | +18.44% (-35.61% to +51.27%) | +20.12% (-14.90% to +29.22%) |
| 16 KiB | +7.47% (-17.85% to +225.10%) | -1.82% (-23.96% to +80.41%) |
| 128 KiB | -57.22% (-64.47% to +48.43%) | -35.53% (-45.77% to +8.87%) |

Four of five 128 KiB pairs improve materially, but the remaining pair is adverse (+48.43% p95, +8.87% tree CPU). The 1 KiB median regresses in both measures, and the 16 KiB results are inconsistent. The result cannot be turned into a universal pass by selecting only favorable sizes or blocks. CPU for the synthetic child and proxy is included; the first-call CPU is included in the existing tree-CPU average, while the parent warm-profile summaries exclude that first call.

## Near-limit memory and CPU diagnostics

These are three instrumented samples per source/shape. Compact replies contain a digest of all arguments, byte counts, generation, request identity and metadata, so no large result is dropped to evade the response ceiling. Complete result and forwarding parity passed. The largest text request line is 4,193,908 bytes; the dense/nested lines are 4,193,652–4,193,680 bytes, all below the unchanged 4,194,304-byte external line limit.

| Shape | Source | Mean parent CPU ms | Exclusive classification CPU ms | Exclusive snapshot CPU ms | Whole-worker peak RSS MiB |
| --- | --- | ---: | ---: | ---: | ---: |
| ascii | B | 2198.67 | 662.55 | 0.00 | 113.75 |
| ascii | D | 475.71 | 204.02 | 1.39 | 113.54 |
| unicode | D | 512.78 | 332.26 | 0.64 | 125.20 |
| unicode | B | 1069.20 | 709.19 | 0.00 | 130.13 |
| dense-integers | B | 10841.20 | 2886.03 | 0.00 | 435.15 |
| dense-integers | D | 15487.91 | 1617.99 | 5042.54 | 484.92 |
| nested-records | D | 12399.64 | 2299.40 | 3364.59 | 437.35 |
| nested-records | B | 10755.26 | 4557.16 | 0.00 | 426.62 |
| nested-text | B | 1052.76 | 598.26 | 0.00 | 114.18 |
| nested-text | D | 1204.35 | 617.51 | 7.12 | 114.18 |

Dense integers spend 5,042.54 ms per call in D's snapshot traversal and binding, and peak worker RSS rises from 435.15 to 484.92 MiB (+49.77 MiB). Nested records spend 3,364.59 ms in snapshots. These costs are material even though the frame and operation limits remain intact. The dense D p95 diagnostic reaches 25.62 seconds under the unchanged 30-second response deadline. The nested-text control is also adverse; it is not omitted because the top-level text examples are favorable.

The external 4 MiB encoded-frame bound is not a 4 MiB decoded-heap or RSS guarantee. Existing framing, JSON objects and outgoing encoded fragments already amplify memory in high-cardinality inputs. D adds owned container copies and immutable binding storage proportional to the node count; it does not impose a new global RSS budget. The measured OS peak is whole-worker `RUSAGE_SELF`, including transient allocations and imports. Sampled process-tree USS/RSS is recorded separately and must not be described as an absolute process-tree peak. These C=1 probes do not establish aggregate concurrency or long-soak memory qualification.

Top-level ASCII/Unicode text shows much lower snapshot/serialization cost with D, but residual classification is still material (42.89% and 64.80% of parent CPU respectively). This supports testing a bounded four-predicate native experiment using D as the applicable Python comparator for this declared text scope. Ordinary/container comparisons must use B where D is already known to regress. No native gain may be credited to avoiding D's regression or to the prior B→D change.

## Evidence and bounded decision

- [Ordinary five-block raw comparison](../../release-metadata/mcp-structural-facts-comparison.json)
- [Near-limit ASCII/Unicode raw diagnostics](../../release-metadata/mcp-structural-facts-memory-boundary.json)
- [Dense and nested raw diagnostics](../../release-metadata/mcp-structural-facts-container-boundary.json)
- [Prior B→C route and memory result](rust-performance-mcp-request-facts.md)
- [Optimized-compiler component provenance](../../release-metadata/mcp-near-limit-component-provenance.json), [ASCII](../../release-metadata/mcp-near-limit-ascii-component.txt), [Unicode](../../release-metadata/mcp-near-limit-unicode-component.txt)

The original PRD permits a measured decision about a narrow pure-facts boundary; it does not require a full Rust proxy rewrite. D's universal activation is rejected, RSP-100 remains OPEN, and the near-limit native text experiment remains separate and explicit. No policy/trust result moves to Rust, and no release/installed/platform qualification is inferred from these source-route measurements.
