# Release/3.2 implementation addendum

This addendum applies the original [Rust Performance PRD](PRD.md) to the work in
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970), targeting
`release/3.2`. The original requirements, 144 task IDs, acceptance conditions,
dependencies and numerical thresholds remain unchanged. The user authorized
implementation after the initial proposal; the proposal's earlier read-only
scope does not limit the authorized implementation.

**Product outcome:** reduce the time and CPU HOL Guard adds to real developer
tool calls while preserving the decision, delivered response, approval and
artifact trust contracts. Language conversion is a means to that outcome.
Completion requires measured installed behavior on supported platforms.

## Users and observable behavior

Developers should receive the same enforcing decision, Watch response or
availability continuation through the same installed harness integration, with
lower ordinary latency. Approval prompts must still resolve only the original
live request under current policy. Maintainers must be able to identify the
installed artifact, explain its route, update it and restore the previous
artifact without stale authorization. Operators must retain bounded queues,
resource use, private evidence and truthful health under overload and recovery.

Keep four timing boundaries explicit: named Rust **KERNEL**, **NATIVE_CLIENT**,
authenticated **DAEMON_INGRESS**, and actual registered **INSTALLED_LAUNCHER**.
The last includes process startup, stdin, stdout and exit validation. Cold
launcher, cold resident, daemon readiness and resident recovery are distinct
series. The [current contract](CURRENT_CONTRACT.md) defines their exact scope.

## Conversion decisions and next evidence

The [first finalization CI report](FIRST_CI_EVIDENCE.md) retains source-specific
measurements. It is evidence for prioritization, not a passing release.

| Area | Implemented behavior or measured observation | Release decision and acceptance still needed |
| --- | --- | --- |
| Existing Rust decision core | Typed results, canonical identity reuse, immutable compiled policy/command state and bounded output work are integrated. | Preserve semantic/adversarial parity; qualify actual installed CPU and latency benefit. No additional semantic fallback. |
| Runtime identity and posture | Verified live-process identity reuse and acknowledged Watch posture remove demonstrated duplicate work within their supported scopes. | Run mutation, replacement, recovery and posture transitions on final installed artifacts. Unsupported platforms retain complete validation. |
| Native launcher | Dormant Claude source-feature correctness passed on all four targets. Current Python launcher smoke still measured roughly 283–344 ms with only two observations per target. | Prepare an explicit feature-enabled comparison against optimized Python in the same installed wheel. Require real registration, parity, package binding and sufficient paired samples before activation. |
| Package parsing/evaluation | Five actual local protect pairs at 1,000 dependencies/bundle entries show median CPU 5,923.255 → 242.241 ms after Python optimization. | Attribute the remaining optimized cost. A Rust parser/evaluator must beat optimized Python on a real route and meet format, malformed-input and coverage requirements. Censored baseline cells remain incomplete evidence. |
| Offline scanner/archive work | Source/CLI baselines and a separate hostile-archive experiment exist; timeouts and incomplete cache scopes remain recorded. | Select ports using the required full-route finding-heavy and adversarial evidence. A kernel experiment or source-only clean-file result cannot activate a native scanner/worker. |
| MCP proxy | The first stdio component run reduced the 1,000-tool catalog's mean parent CPU from 51.886 to 24.455 ms per call. | Remeasure later prefilters with paired run-level intervals, separate network/service wait and complete warm resource windows. Select only demonstrated pure-kernel opportunities; a complete proxy rewrite is not selected. |
| Hook transport/ingress | Bounded framing, scheduler/header ownership and persistent native helper contracts are implemented. | Attribute discovery/connect/authentication cost and prove the selected connection or ingress change against the existing path. Preserve Unix and Windows ownership/replacement guarantees. |
| Evidence/inventory | Foreground submission, durable journals, batching and SQL freshness work are implemented. Linux legacy soak completed 100,000 requests and 250,000 receipts. | Qualify the distinct mixed offered-load/mutation/recovery workload and receipt durability. Select a native spool/compiler only if residual cost meets the PRD criterion. |

No unbuilt conditional component is marked DONE or DEFERRED. A deferred port
needs the measured go/no-go record specified in its original task. Source tests
can close a source criterion; they cannot close a dependent installed gate.

## Requirements that apply to every selected change

1. Preserve authority from admission through finalization: authenticated peer,
   current process/image, exact source content, policy/program/catalog identity,
   generation, expiry, mutation fencing and receipt/replay binding. Cached API
   definitions or metadata hints must never replace these checks.
2. Preserve native verdict, posture transformation, availability outcome and
   delivered harness response separately. An availability continuation is not
   a native-evaluated allow. Do not turn ordinary unavailability into blanket
   denial or add a Python semantic fallback.
3. Preserve the original waiter, request identity and deadline through approval.
   Revalidate native Codex completion under current authority. Unsigned terminal
   state and ambiguously delivered MCP writes cannot authorize replay.
4. Validate both measurement arms on identical intended work. Record differing
   supported semantic scopes explicitly, especially frozen Windows source
   refusals. An unsupported read supplies no successful content-scan timing.
5. Bind every result to immutable source, artifact, rule/runtime/program,
   platform, interpreter, dependency and workload identities. Install measured
   wheels outside source checkouts. Keep the measurement controller separate.
6. Retain all offers, outcomes and failed samples. Public evidence consists of
   bounded reconstructed fields; private observations use authenticated
   encryption. Missing CPU, memory, numeric or archive evidence stays missing.
7. Validate update and rollback as artifact transitions. A settings rollback or
   stopped-process replacement has a narrower scope than live replacement,
   signing, frozen packaging and changed-program rollback.

## Performance acceptance and execution

The original PRD is normative where a row below abbreviates it.

| Gate | Required evidence |
| --- | --- |
| Priority warm, concurrency 1 | Installed p95 ≤ 50 ms and p99 ≤ 100 ms |
| Priority warm, concurrency 16 | Installed p99 ≤ 200 ms, zero errors |
| Native client and cold launcher | Native-client p95 ≤ 20 ms; cold-native p95 ≤ 150 ms |
| Readiness | Existing 400 ms barrier, with no extra retry that extends the original budget |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU benefit; no more than 5% regression in the other metric |
| Optional ingress | At least 25% private-memory or 30% concurrency-16 p99 benefit |
| Native package/offline kernel | At least 30% benefit against the optimized Python real route, with its original parity and regression safeguards |
| Resources | At least 30 valid samples; existing 12% short-run and 50% long-soak RSS growth gates remain |
| Statistical coverage | At least five independent alternating pairs, required confidence intervals, 10,000 warm priority/1,000 other samples and 100 cold/recovery observations per required scope |

Full indexed qualification uses five same-runner pairs on each of Linux x64,
macOS Intel, macOS ARM and Windows x64. Each worker receives the original
five-run plan: 2,000 priority, 200 other and 20 cold/recovery observations per
block. Both 60-minute workers fit a 125-minute collection step; encryption and
upload have separate budgets within the 200-minute pair job. This repairs
orchestration capacity without changing a product deadline or sample minimum.
The [indexed-pair contract](indexed-pair-qualification.md) specifies exact
numeric commitments, sealed-byte verification and strict cohort aggregation.

Smoke exercises collection and correctness with small counts. It cannot qualify
performance. A successful legacy soak also cannot substitute its broader
latency allowance for the installed-priority thresholds above.

## Delivery order and exit criteria

First publish the reconciled source and pass actual repaired smoke/component
runs. Diagnose remaining failure boundaries without discarding offers or
weakening fixture/production trust. Then run full indexed qualification and the
bounded optimized-Python/native experiments that justify remaining ports.
Integrate only supported, independently reviewed routes. Finally verify exact
signed/frozen artifacts, updates, rollback and the concrete canary/rollback plan.

The current ledger is **67 DONE, 36 OPEN and 41 BLOCKED, with zero DEFERRED**.
The [release review](RELEASE_REVIEW.md) and [machine ledger](execution-ledger.json)
identify what the latest source implements and what evidence remains. Final
independent code-owner approval is a protected-branch requirement. No merge,
canary or release is complete at this checkpoint.
