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

This addendum reflects source `6c7c3097d566da35812d087d1dadae1fba8823de`, tree `87828bda11b356fa9ba982f3d47fffc96a05451c`,
before these documentation edits. The [third observed CI checkpoint](THIRD_CI_EVIDENCE.md)
is PR head `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`; native-wheel and
daemon-edge jobs identify merge `c855bae3e83579587d229c83b597dc1cbc1d4bb6`.
Later fixes do not inherit those results. The immutable [first](FIRST_CI_EVIDENCE.md)
and [second](SECOND_CI_EVIDENCE.md) reports retain their earlier measurements,
failed attempts and artifact identities. None qualifies the release.

| Area | Implemented behavior or measured observation | Release decision and acceptance still needed |
| --- | --- | --- |
| Existing Rust decision core | Typed results, canonical identity reuse, immutable compiled policy/command state and bounded output work are integrated. | Preserve semantic/adversarial parity; qualify actual installed CPU and latency benefit. No additional semantic fallback. |
| Runtime identity and posture | Verified live-process identity reuse and acknowledged Watch posture remove demonstrated duplicate work within their supported scopes. | Run mutation, replacement, recovery and posture transitions on final installed artifacts. Unsupported platforms retain complete validation. |
| Native launcher | Dormant four-target source correctness exists. The first opt-in installed experiment failed before measurement in all 20 jobs; canonical uv interpreter admission and Windows evidence metadata corrections are prepared. One retained Windows baseline block ranks actual Claude/Codex routes descriptively, with Codex PostToolUse slower at c16. | Rerun the repaired `native-claude-launcher-experiment`. Do not select Claude by claiming it is uniformly the slowest route. Require actual parity, package binding, lifecycle and comparable optimized-Python/native benefit before activation; production remains off. |
| Package parsing/evaluation | The d0e five-pair local protect medians at D=B=1,000 are 5,828.384 → 215.214 ms wall and 4,571.890 → 195.921 ms CPU. All eight candidate attribution/validation workers and two explicit-`*` resolver workers completed; 82–86% of exclusive calling-thread CPU remains unnamed. | Execute the bounded residual-origin projection on the same inputs/intervals before selecting a coarse native boundary. Parser-only benefit is not established. Preserve the two baseline Composer failures, 12 censored cardinality workers and None-version kernel scope; a native candidate must beat optimized Python under the original gates. |
| Offline scanner/archive work | Source/CLI baselines and a separate hostile-archive experiment exist; timeouts and incomplete cache scopes remain recorded. | Select ports using the required full-route finding-heavy and adversarial evidence. A kernel experiment or source-only clean-file result cannot activate a native scanner/worker. |
| MCP proxy | Corrected second-checkpoint v2 evidence contains five independent run pairs, 10,080 calls, separate loopback/service/approval waits and 80 complete warm resource windows. Large-catalog wall/parent-CPU ratios are 0.5380/0.4468; smallest-catalog intervals cross one and sampled peak memory increases. | RSP-098/103 source-component acceptance is complete. The measured release decision defers native kernels (RSP-104/105/107) and records the full-proxy deferral (RSP-108). Tiny pure residuals, store/composition/persistence work and the unchanged barrier justify scope deferral; no Rust candidate or native benefit failure was measured. Installed/platform/lifecycle acceptance remains separate. |
| Hook transport/ingress | Bounded framing, scheduler/header ownership and persistent native helper contracts are implemented. The d0e daemon-edge and Windows resident workflows passed their actual workloads, while installed Windows launcher and Mac source proofs failed. | Use the finite bridge/launcher diagnostics to identify the actual failed stage without changing authority or deadlines. Attribute discovery/connect/authentication cost and prove any selected connection/ingress change against the existing path. |
| Evidence/inventory | Foreground submission, durable journals, batching and SQL freshness work are implemented. Linux legacy soak completed 100,000 requests and 250,000 receipts. | Qualify the distinct mixed offered-load/mutation/recovery workload and receipt durability. Select a native spool/compiler only if residual cost meets the PRD criterion. |

An unbuilt implementation is not marked DONE. A conditional port may be
DEFERRED only with the measured go/no-go record specified in its original task.
The [MCP selection decision](mcp-native-selection-decision.md) records that
bounded choice and the evidence needed to reopen it. Source tests can close a
source criterion; they cannot close a dependent installed gate.

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
block. Actual registered priority/nonpriority routes retain their own denominators;
the separate [16-route/320-job nonpriority-tail companion](nonpriority-installed-tails.md)
is integrated but has no completed observations. It requires explicit selection
and cannot yet supply the other-route requirement. Both
60-minute workers fit a 125-minute collection step; encryption and
upload have separate budgets within the 200-minute pair job. This repairs
orchestration capacity without changing a product deadline or sample minimum.
The [indexed-pair contract](indexed-pair-qualification.md) specifies exact
numeric commitments, sealed-byte verification and strict cohort aggregation.

Smoke exercises collection and correctness with small counts. It cannot qualify
performance. A successful legacy soak also cannot substitute its broader
latency allowance for the installed-priority thresholds above.

## Delivery order and exit criteria

First publish the coherent source and verify the actual next-CI results for
canonical interpreter admission, Windows evidence identity, duration artifact
retention and the new native bridge/launcher diagnostics. All 96 d0e pytest
jobs passed, but Main CI failed its missing duration artifact and Sonar gate.
The earlier storage-burst/backfill investigation remains historical source
evidence; it does not replace exact-head CI or justify changed limits.

Read the retained qualification attempt-2 POSIX failures and resolver evidence
before choosing a production correction. Linux and Mac ARM candidate
Ollama/Builder scenarios succeeded independently; failed pairs, missing Windows
bundles and skipped transitions still prevent qualification. The first Claude
experiment produced no measurements, so native launcher benefit remains unknown.
Run the bounded package residual projection and repaired installed experiment;
start nonpriority collection with one selected route smoke before explicitly
opting into its 320-job full plan. Preserve every failed attempt and required
upload. Then complete full indexed qualification and the optimized-Python/native
comparisons needed for conditional ports. Finish exact signed/frozen artifacts,
update/rollback, mixed-load evidence and the canary/rollback plan.

The current ledger is **77 DONE, 30 OPEN, 34 BLOCKED and 3 DEFERRED**.
RSP-024 closes the recorded technical contract review, RSP-073 the bounded
installed baseline ranking/inventory, and RSP-074 the package-bound launcher
design contract. Their original dependencies remain;
RSP-012, RSP-134 final-head validation and RSP-142 independent final-head approval
are separate. Earlier source/component closures and measured MCP deferrals do
not close dependent installed benefit.
The transition scenario's five stopped phases and ten registered cases remain
separate from live updates, signing, frozen packaging and downgrade support.
The [release review](RELEASE_REVIEW.md) and [machine ledger](execution-ledger.json)
identify what the latest source implements and what evidence remains. Final
independent code-owner approval is a protected-branch requirement. No merge,
canary or release is complete at this checkpoint.
