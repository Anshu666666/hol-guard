# Release/3.2 implementation addendum

This addendum applies the original [Rust Performance PRD](PRD.md) to
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970), targeting
`release/3.2`. The original requirements, all 144 [task IDs](TODO.md), acceptance
conditions, dependencies and numerical thresholds remain unchanged. The user
has authorized implementation; the initial proposal's read-only scope does not
limit that work.

**Product outcome:** reduce the time and CPU HOL Guard adds to real developer
tool calls while preserving decisions, delivered responses, approval authority
and artifact trust. Rust conversion must earn its place through a comparable
real-route result. This work does not prove optimal performance or complete
release acceptance.

Implementation source cutoff: `872b0517b5596f8c19abd0fce185c7e14983cc20`, tree
`581e5cb30bd0082abf0356b5931b26d5ef204903`. The [ledger](execution-ledger.json) records the evidence
for each original criterion.

83 DONE / 24 OPEN / 29 BLOCKED / 8 DEFERRED

## Users, scope and observable behavior

Developers should receive the same enforcing decision, Watch response or
availability continuation through their installed harness, with lower ordinary
latency. Approval must still resolve only the original live request under
current policy. Maintainers must be able to identify, update and roll back the
installed artifact without stale authorization. Operators need bounded queues,
resource use and recovery, private evidence, and truthful health under load.

Keep four timing boundaries explicit: named Rust **KERNEL**, **NATIVE_CLIENT**,
authenticated **DAEMON_INGRESS**, and actual registered **INSTALLED_LAUNCHER**.
The last includes process startup, stdin, stdout and exit validation. Cold
launcher, cold resident, daemon readiness and recovery remain separate series.
The [current contract](CURRENT_CONTRACT.md) defines the boundaries. A source
component or kernel result cannot qualify an installed route.

## Current evidence and conversion decisions

The [fourth CI checkpoint](FOURTH_CI_EVIDENCE.md) measured PR head
`2ebb01ff356101aea8d658ce639fe2c87188bd0d`, tree
`1c41bef1979ead9e50ee406a60505ce6894aa461`.
Explicit candidate checkouts and ordinary PR merge checkouts remain distinct:
merge `d769f9722d34e98cadea058e01575b48ab24f053` has the same tree but a different
build identity. The checkpoint has 40 terminal workflow instances: 35 successful
and five failed. Later repairs do not inherit its results. Earlier
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md) and
[third](THIRD_CI_EVIDENCE.md) reports retain their own sources and outcomes.

| Area | Implemented behavior or measured evidence | Release decision and remaining acceptance |
| --- | --- | --- |
| Existing native decision core | Typed results, canonical identity reuse, immutable compiled policy/command state and bounded output work are integrated. | Preserve semantic/adversarial parity and prove actual installed CPU and latency benefit. Do not introduce Python semantic fallback. |
| Native command extensions | The shipped v1 program translates the reviewed declarative families and records compatibility ownership/uncertainty. Linux, ARM and Windows installed Ollama/Builder scenarios passed at the fourth checkpoint. | Publish exact artifact/catalog coverage and native route receipts. The 42 null-matcher compatibility identities are not a claim of full Python classifier parity; Intel readiness and overall installed qualification remain open. |
| Runtime identity and posture | Verified live-process reuse and acknowledged posture snapshots remove demonstrated duplicate work within supported scopes. | Preserve process/image, current authority and generation checks; unsupported proof retains full validation. Final installed mutation, replacement, recovery and posture transitions remain required. |
| Native launcher | Dormant source implementation exists for four targets. All 20 fourth-checkpoint experiment jobs failed target-domain preparation before any measurement offer. Exact manifest Cargo-target/runtime-label bindings are now corrected. | Production activation remains off. Execute the repaired experiment, retain failures, and require comparable installed parity, lifecycle and optimized-Python/native benefit. The Windows baseline ranking does not establish Claude as uniformly most expensive. |
| Package parsing/evaluation | Verified indexes, one parse per exact-content evaluation and evidence batching are implemented. Five fourth-checkpoint protect pairs show median wall 8,785.843 → 327.344 ms and CPU 7,739.458 → 319.842 ms. All ten phase/validation/registry workers completed. | RSP-054 records no package Rust selection for this release. Guard Python still owns 37.31%/51.75% of instrumented exclusive CPU; no native benefit or impossibility is established. Preserve format, censoring and None-version kernel limitations. A future coarse immutable model/identity/result boundary must pass the original real-route threshold. |
| Offline scanner and archive | Retained source-CLI and archive profiles identify actual costs. RSP-070 profiling is complete; the archive exact-result gate retained two fail-closed timeouts among 510 inspections. | Retain the isolated Python archive worker and defer a parser-only archive port. Rich scanner selection remains open pending the finite finding-heavy experiment: 24 planned smoke or 840 full attempts in the integrated [opt-in collector](scanner-regex-pilot-ci.md); execution remains pending. No scanner or archive native activation follows. |
| MCP proxy | The corrected 24ba source-component cohort has five independent pairs, 10,080 calls and 80 complete warm resource windows. Larger catalogs improve; tiny pure phases, store/composition work and the existing barrier remain distinct. | Retain optimized Python and the recorded conditional native-kernel/full-proxy deferrals. The successful d0e cohort is separate; fourth CI supplies a completion check only. No Rust candidate failure, installed target or complete lifecycle qualification is claimed. |
| Transport, ingress and installed delivery | Bounded framing, scheduler/header ownership and native helper contracts are integrated. Fourth daemon-edge and Windows resident workflows passed their actual workloads. | Installed wheel probes still failed on Linux, Windows and Intel. Capacity and stdout witnesses now preserve bounded rejection facts without retrying, changing authority or expanding deadlines. Select further changes from those actual boundaries. |
| Evidence, inventory and resources | Durable journals, batching, SQL freshness and private encrypted recovery are implemented. The new Darwin reader binds Mach counters, root/member identities and reaped-child CPU without psutil double counting. | Complete mixed-load/mutation/recovery and receipt durability evidence. Actual Darwin checks on both Mac targets are still required; source tests do not establish installed resource completeness. |

The [package decision](package-native-selection-decision.md),
[MCP decision](mcp-native-selection-decision.md), and
[scanner/archive decision](scanner-current-decision.md) state their evidence and
reopening gates. A measured release deferral is distinct from an unbuilt
implementation. Conditional native schemas, implementations and activation are
not marked DONE merely because Python is retained. Package format parity and
installed acceptance remain separate, and original dependencies stay intact.

The integrated [acknowledged posture contract](acknowledged-posture-contract.md)
makes local Watch effective only after the correct resident ACK. Ordinary native
requests sample one authenticated binding for evaluation, command-control lease
and final delivery; local configuration cannot weaken an enforcing result while
an update awaits ACK. Native receipts retain the intrinsic decision. Missing or
expired authority follows the unchanged availability path, not inferred Watch
authority. Source transition tests passed; RSP-034's actual mixed-transition and
installed qualification remain open.

## Requirements for every selected change

1. Preserve authority from admission through finalization: authenticated peer,
   current process/image, exact source content, policy/program/catalog identity,
   generation, expiry, mutation fencing and receipt/replay binding. Cached API
   definitions and metadata hints never replace those checks.
2. Preserve native verdict, posture transformation, availability outcome and
   delivered harness response separately. An availability continuation is not
   a native-evaluated allow. Do not replace ordinary unavailability with blanket
   denial or a Python semantic fallback.
3. Preserve the original waiter, request identity and deadline through approval.
   Revalidate native Codex completion under current authority. Unsigned terminal
   state and ambiguously delivered MCP writes cannot authorize replay.
4. Compare identical intended work and retain semantic differences explicitly.
   Unsupported reads, omitted dependencies and incomplete scans cannot count as
   successful performance observations.
5. Bind evidence to source, artifact, rule/runtime/program, platform,
   interpreter, dependency and workload identities. Install measured wheels
   outside source checkouts and keep the controller environment separate.
6. Retain every offer, outcome and failed observation. Reconstruct bounded
   public fields and authenticate encrypted private evidence. Missing CPU,
   memory, numeric or archive evidence stays missing.
7. Validate update and rollback as artifact transitions. Stopped replacement or
   settings rollback cannot substitute for live replacement, signed/frozen
   packaging or changed-program rollback.

## Performance acceptance and execution

The original PRD is normative where this table abbreviates a requirement.

| Gate | Required evidence |
| --- | --- |
| Priority warm, concurrency 1 | Installed p95 ≤50 ms and p99 ≤100 ms |
| Priority warm, concurrency 16 | Installed p99 ≤200 ms, zero errors |
| Native client / cold native launcher | p95 ≤20 ms / p95 ≤150 ms |
| Readiness | Existing 400 ms barrier; no retry extending the original budget |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU benefit; at most 5% regression in the other primary metric |
| Optional ingress | At least 25% private-memory or 30% concurrency-16 p99 benefit |
| Package/offline native kernel | At least 30% benefit against optimized Python at the real route, including serialization/startup amortization and original parity safeguards |
| Resources | At least 30 valid samples; unchanged 12% short-run and 50% long-soak RSS growth gates |
| Statistical coverage | At least five independent alternating pairs, required confidence intervals, 10,000 warm priority/1,000 other samples and 100 cold/recovery observations per required scope |

The [indexed qualification](indexed-pair-qualification.md) uses five same-runner
pairs on Linux x64, macOS Intel, macOS ARM and Windows x64. Each block receives
2,000 priority, 200 other and 20 cold/recovery observations; scopes and routes
retain their own denominators. Two 60-minute workers fit a 125-minute collection
step, with separate encryption/upload budgets inside the 200-minute pair job.
These containment budgets do not change a product deadline or sample minimum.

The [nonpriority companion](nonpriority-installed-tails.md) now has an explicit
four-platform, single-route smoke selection: four collection jobs plus four
aggregators, two observations per arm after semantic preflight. No completed
observations are claimed. Its full 16-route × four-platform × five-pair plan is
320 collection jobs and remains deliberate opt-in. Smoke cannot satisfy the
1,000-observation minimum or qualify host activation, other loads or resources.

## Delivery order and release exit

Execute the coherent repaired source before extending a migration. Fourth Main
CI uploaded all 96 duration artifacts, but only 95 pytest shards passed;
shard 54 and its aggregate gate failed, and Sonar was skipped. The fresh-worker
collector test preserves all oracles and strict negative-total rejection; the
original negative cause remains unknown. New required CI and an actual quality
gate are still needed.

All four immutable qualification builds passed. Linux, ARM and Windows
Ollama/Builder scenarios passed, while Intel readiness was 403.453 ms against
400 ms. All four pair jobs failed, as did their aggregators. Both Mac frozen
baselines still stopped in resolver work; candidate delivery failures retained
narrower witnesses. The 20-job Claude experiment offered no measurements.
Target-domain corrections and bounded capacity/stdout witnesses need fresh
execution; they do not turn those attempts into successful comparisons.

Complete selected nonpriority smoke and the finite scanner experiment before
opting into expensive full collections or choosing a native boundary. Preserve
all failures, original sample minima and exact artifacts. Qualify the Darwin
reader on actual Mac runners. Then complete supported installed comparisons,
signed/frozen artifacts, live update/rollback, mixed offered-load/mutation/
recovery, durable receipts and the canary/rollback plan.

Source inventory, boundary documentation and this handoff can close their own
literal criteria. They do not close RSP-012, final-head validation (RSP-134),
independent latest-push approval (RSP-142), or dependent installed benefit.
The [release review](RELEASE_REVIEW.md) and [ledger](EXECUTION_LEDGER.md) distinguish
those states. Protected merge, canary and release remain incomplete.
