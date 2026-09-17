# MCP native text-facts experiment: completed comparison and decision

Do not select this native helper for runtime activation on the completed
evidence. The real proxy comparison includes Python normalization, private
encoding, both IPC directions and the helper's CPU. Its five-block medians miss
the original 30% benefit gate, individual blocks regress, ordinary controls are
unstable, and an early positive Unicode control is adverse. Retain optimized
Python B as the runtime default. The compiled four-predicate prototype remains
available for a different, separately justified experiment; this is not a claim
that every possible native MCP boundary is unhelpful.

## Frozen scope and complete attempts

The Rust example is commit 3e1e8bdabe2943848dccd60b982cd5862ee39c78; the main
adapter and runner are 49ea9db7edb50a2cb9b1a4b4de845ee672270471. The separate
positive-marker runner is 525d2f0ef. The ordinary 1/16/128 KiB controls use B
(d811b08f081d72c348b95f0cf9e45349fb1787e6). Near-limit top-level text uses D
(1dbc20f31b5cc7a0b6402afaa6a0b9127131771c), its stronger applicable Python
comparator. Both arms of each pair load exactly the same runtime. No native gain
is credited to the prior B-to-D change or to avoiding D's dense-container
regression. Neither C nor universal D activation is selected.

Five independent process blocks alternate Python/native order, with 30 timed
calls after one cold first call in every cell. Ten separate ten-call profiles
follow. All 60 main cells completed: 1,660 successful forwards and 30 exact
paired traces. Eight separate three-call instrumented positive-marker controls
add 32 forwards and four exact pairs. All 68 cells, 1,692 forwards and 34 pairs
are retained. There are no failed cells, timeout substitutions, hidden retries,
replays or dropped attempted decisions. Every imported runtime, frozen harness
and requested/actually executed helper identity passed its checks.

The main campaign ran from 2026-09-17 13:50:14.699595 UTC through
14:09:50.203013 UTC on Linux x86_64 and Python 3.12.14. Each complete case,
including temporary-store cleanup, owns the shared measurement lock separately.
The recorded host has nine visible logical CPUs, an eight-CPU cgroup quota and
20 GiB memory limit; one during-campaign load observation was 7.10/6.20/6.36.
The CPU power governor was unavailable. These facts describe a shared source
host, not declared release hardware or continuous background-load monitoring.

Two forced-native full semantic oracles each matched all 3,008 attempted cases
against frozen B for exact categories, approval hashes and complete policy
decisions. They exercise the same 3,008 distinct cases, not 6,016 distinct
fixtures. B made 9,024 native predicate requests across its public consumers;
D made 3,008 through prepared reuse. Every request completed. The forced oracle
threshold is zero, so ordinary-input fallback cannot masquerade as native parity.

## Uninstrumented real-route comparison

Positive change means slower. Each table value is the median of the five
within-block percentage changes, followed by their complete observed range.
These are not confidence intervals. Percentiles use nearest rank. The cold
first call is excluded from warm latency; the process-tree CPU average includes
it and the helper's startup. The CPU boundary includes the proxy, synthetic
server and live helper after catalog delivery through the final response. It
excludes the benchmark client's CPU and post-session cleanup. Complete client
latency includes client frame encoding and all proxy/server work through the
verified response; no deliberate wait is silently subtracted.

| Input and Python source | Client p95 change, median (range) | Tree CPU/call change, median (range) |
| --- | ---: | ---: |
| 1 KiB ASCII, B | -77.75% (-85.22% to -32.49%) | -64.34% (-71.94% to -6.88%) |
| 16 KiB ASCII, B | -4.63% (-46.21% to +68.13%) | -8.89% (-36.52% to +76.88%) |
| 128 KiB ASCII, B | +57.63% (-35.63% to +149.62%) | +31.54% (-25.90% to +73.44%) |
| Near-limit ASCII, D | -24.95% (-75.93% to +196.38%) | -14.65% (-61.80% to +16.06%) |
| Near-limit U+20AC Unicode, D | -22.75% (-40.56% to +121.41%) | -29.71% (-40.66% to +28.47%) |

All three ordinary sizes select Python and start zero native processes. Their
large swings therefore cannot be described as native speedups. In particular,
the adverse 128 KiB control remains visible. This experiment does not isolate
the cause of the shared-host variation or establish a general nonregression
pass. There is no repeat campaign chosen to obtain a more favorable result.

Neither large-input median reaches 30% lower p95 or process-tree CPU. Unicode's
unrounded CPU improvement is 29.711838%, strictly below that threshold. ASCII's
fourth block regresses 196.38% in p95 and 16.06% in CPU; Unicode's third block
regresses 121.41% and 28.47%. Positive individual blocks do not override these
results or the original requirement that the other primary metric regress by
no more than 5%.

## Attribution, waits and positive-marker controls

The following separate profile values are mean main-thread CPU milliseconds
per warm call. Classification includes retained Python normalization; JSON
serialization and facts snapshots are separate nested phases. Native IPC
includes Python chunk encoding, protocol work and diagnostic RSS sampling.
Child/helper CPU is included in the separate process-tree measure, not in the
parent classification/IPC columns.

| Sparse near-limit shape | Arm | Parent CPU | Classification | Private IPC CPU | JSON serialization | Policy/state | Receipt/result |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| ASCII | Python | 362.11 | 186.83 | 0.00 | 45.15 | 20.56 | 15.08 |
| ASCII | Native | 592.54 | 80.16 | 6.32 | 166.99 | 61.32 | 41.93 |
| Unicode | Python | 1094.03 | 647.16 | 0.00 | 77.21 | 105.94 | 51.75 |
| Unicode | Native | 213.78 | 39.73 | 10.56 | 32.12 | 25.38 | 13.88 |

The broad variation also appears in unchanged phases, so these instrumented
observations are attribution diagnostics, not a replacement for the alternating
uninstrumented comparison. The configured 5 ms final prewrite barrier remains
exact; observed means across these profiles are 5.13–5.75 ms. Child startup,
child wait, pipe writes, catalog capture/hash, request identity and other Guard
work are retained in the raw phase data. Earlier completed child-delay,
elicitation-delay and loopback HTTP controls remain in the
[source benchmark audit](mcp-source-benchmark-acceptance.md); the private helper
does not own network or human approval orchestration.

The separate positive-marker controls place synthetic process/network/secret/
privilege markers at the beginning or end of a byte-equivalent near-limit text.
Both arms still use D, a real warn-policy proxy/store, complete compact response
verification and the same helper. Three instrumented samples per cell establish
neither a tail percentile nor a stable speedup; they preserve an input-shape
concern that the sparse negative fixture alone cannot resolve.

| Shape / marker position | Tree CPU/call change | Diagnostic p95 change | Python classification CPU ms | Native classification + parent IPC CPU ms |
| --- | ---: | ---: | ---: | ---: |
| ASCII / early | -36.41% | -48.26% | 19.61 | 13.67 + 4.99 |
| ASCII / late | -54.43% | -54.85% | 261.08 | 11.49 + 3.24 |
| Unicode / early | +115.61% | +154.23% | 37.34 | 40.95 + 41.52 |
| Unicode / late | -71.73% | -69.74% | 871.70 | 20.75 + 6.84 |

When markers occur early, Python can finish the text predicates quickly. The
helper still incurs encoding and IPC, while other classification work remains
in Python. The early Unicode regression is retained, and the favorable early
ASCII total cannot be attributed solely to removing its small predicate phase.
There is no evidence here for universal activation based only on text length,
nor for dense/nested inputs, arbitrary tool schemas, concurrent sessions or all
Unicode content distributions.

## Bounds, memory and functional validation

The [boundary contract](mcp-native-text-pilot-boundary.md) specifies the 16 MiB
whole private packet, 16-byte request header, exact 13-byte reply, increasing
sequence, one admitted packet, inherited absolute operation deadline, terminal
failure and bounded kill/reap behavior. Python retains current policy, all
identity and mutation checks, approval claims, catalog freshness and final
forwarding. The original 4 MiB external frame and existing queue ceilings are
unchanged. The largest main-campaign external request line is 4,193,910 bytes.

ASCII's largest helper packet is 4,193,851 bytes. The U+20AC fixture expands to
8,387,641 bytes after Python JSON normalization, and that expansion is charged
to the actual route. Both observed Linux pipe capacities are 65,536 bytes.
Across the main native arms there are 332 admitted/attempted/completed requests,
12 helper starts and 12 reaps, 2,088,527,552 request bytes and 4,316 response bytes.
The ordinary controls record 996 small-text Python selections and no helper
starts. No raw arguments or normalized text are exported.

| Sparse near-limit shape / arm | Sampled tree private USS range, MiB | Whole-worker OS peak RSS range, MiB | Sampled helper RSS range, MiB |
| --- | ---: | ---: | ---: |
| ASCII / Python | 116.09–116.84 | 114.04–114.55 | none |
| ASCII / Native | 121.59–123.43 | 114.36–115.03 | 6.64–6.81 |
| Unicode / Python | 150.06–150.77 | 125.02–125.64 | none |
| Unicode / Native | 160.24–161.99 | 125.28–126.15 | 10.67–10.81 |

These ranges are from the five uninstrumented blocks. Worker OS peak includes
imports and transient requests but excludes its children. Tree/helper samples
are observations after catalog/responses or helper replies, not absolute
whole-tree allocation peaks. The source C=1 experiment does not establish
aggregate c4/c16/c64 admission, long-soak growth, release memory budgets or
installed startup/recovery limits.

Six Rust release tests, the normal release build and Clippy with warnings denied
passed on pinned Rust 1.88.0. The actual executable digest is
4a3a021d2b92c7e2a46530ab92bca280d6f11a4d5aac9c6659910d937dbc1b45,
on observed tmpfs device 27. All 30 compiled-native/adapter/stdio tests passed,
with no skips, in 72.85 seconds; Ruff and whitespace checks passed. They include
1,108 direct native regex probes, invalid/partial/surplus replies, exact IDs,
original-deadline trickling and delayed RSS sampling, single admission under four
callers, real catalog refresh and approval accept/cancel/invalidation, and zero
child forwards after terminal helper failure. This is finite source correctness
evidence, not actual Windows/macOS or installed native qualification.

## Acceptance and retained decision

The [RSP-098 audit](mcp-source-benchmark-acceptance.md) maps every named source
phase and wait to completed evidence. RSP-103's actual optimized proxy CPU,
overhead and memory comparison is also complete for the declared source scope;
its earlier wording that the residual rerun was still active is obsolete. The
separate RSP-100 requirement remains unmet in the retained runtime, which derives
categories for both identity and fresh policy. Its failed C/D activation and
remaining ownership work are recorded in the
[request-facts ownership audit](mcp-request-facts-ownership-audit.md).

The conditional RSP-104 prototype contract and implementation experiment are
concrete and reviewed. RSP-105 production integration/activation and RSP-107
positive native qualification are deferred for this tested boundary after its
benefit gate failed; the prototype must not be labeled a shipped kernel. The
existing RSP-106 current-proxy correctness result and new finite helper parity
remain valid within their stated scopes. Record RSP-108's full-proxy rewrite
decision as continued deferral: these measurements do not justify transferring
policy, approvals and complete transport orchestration to Rust. A future positive
rewrite selection still needs its separate ADR and protocol rollout plan.

All qualification/activation flags remain false. PRD section 5's installed
platforms, confidence intervals, 10,000 warm decisions per priority route,
100 cold starts/recoveries, concurrency and soak requirements are not supplied
by this source experiment. The completed experiment supports a scoped no-go;
it does not erase the remaining work or relax the 30%/5% gate.

- [Full native comparison](../../release-metadata/mcp-native-text-comparison.json), SHA-256 75d5fa394b53b5e6027c1e74af8d418fb67161881386aa123c41005a0051ed5a
- [Separate positive-marker controls](../../release-metadata/mcp-native-positive-markers.json), SHA-256 ce59866e848137130f6f297e56b6f457f44983acdf611abdb3f97ad345fec154
- [Build, test and host provenance](../../release-metadata/mcp-native-text-build.json)
- [Earlier frozen B-to-D decision](rust-performance-mcp-structural-facts.md) and [B-to-C evidence](rust-performance-mcp-request-facts.md)
