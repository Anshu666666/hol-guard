# Release/3.2 Rust performance review

**Implementation and measured conversion decisions are reviewable; installed
qualification and release acceptance remain incomplete.** This review covers
source `872b0517b5596f8c19abd0fce185c7e14983cc20`, tree `581e5cb30bd0082abf0356b5931b26d5ef204903`. Later source repairs
must earn their own CI results. The original [PRD](PRD.md), all 144 [TODO](TODO.md)
titles, acceptance conditions, dependencies and thresholds remain unchanged.
The [release addendum](RELEASE_3_2_PRD.md) defines current scope; the
[execution ledger](EXECUTION_LEDGER.md) records criterion-level evidence.

83 DONE / 24 OPEN / 29 BLOCKED / 8 DEFERRED

The latest observed publication is [PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970)
head `2ebb01ff356101aea8d658ce639fe2c87188bd0d`, tree
`1c41bef1979ead9e50ee406a60505ce6894aa461`. GitHub merge
`d769f9722d34e98cadea058e01575b48ab24f053` has that same tree but a distinct
build identity. The [fourth checkpoint](FOURTH_CI_EVIDENCE.md) retains exact
run, artifact and source identities: **40 terminal workflow instances,
35 successful and five failed**. Job-level skips are separate. The
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md) and
[third](THIRD_CI_EVIDENCE.md) checkpoints remain independent historical cohorts.

## What actual CI establishes

| Scope | Fourth-checkpoint observation | Remaining requirement or integrated response |
| --- | --- | --- |
| Main CI | 114 jobs: 106 successful, six skipped, two failed. All 96 duration artifacts uploaded, but only 95 pytest shards passed. Shard 54 failed one package attribution test; the aggregate gate failed. Duration aggregation and Sonar were skipped. | The attribution correctness test now executes the actual fresh worker CLI. Signed fixture, semantic oracle, one-parse and journal assertions remain; negative totals are still rejected with bounded field/value diagnostics. The original negative cause remains unknown. Artifact presence does not establish aggregate content validation. Fresh required CI and an actual quality gate are needed. |
| Security, daemon edge and Windows resident | Security passed all four jobs, including 15 Gitleaks fixture controls and a 1,259-commit scan with no leaks. Daemon edge passed its five required jobs; optional soak skipped. Both Windows resident jobs passed. | These validate their actual source, lifecycle and security scopes. They do not qualify installed latency or every resource workload. |
| Native wheel | ARM passed. Linux and Windows failed resident-route/conservation or coverage gates. Intel's c16 maximum was 1,014.141 ms against the unchanged 1,000 ms adapter gate. | Fixed capacity witnesses now retain facts on original failed calls without extra requests, retries, authority reads or extended budgets. A delivered availability continuation still cannot count as native-evaluated allow. The failures do not establish an underlying scheduler or counter cause. |
| Immutable qualification | All four wheel builds passed. Linux, ARM and Windows candidate Ollama/Builder scenarios passed; Windows completed all 22 native cases. Intel completed two cases before 403.453 ms enabled-control readiness exceeded the unchanged 400 ms barrier. | All four indexed pair jobs and all four aggregators failed. Partial scenario success and a later ACK do not qualify a pair or excuse the readiness limit. Optional transitions and nonpriority collection skipped. |
| Installed Claude experiment | All 20 jobs reached registration preparation, then failed the same manifest/runtime target-domain comparison. No measurement request was offered. Each encrypted a failure summary, but no measurement journals existed and final retention correctly failed. | Exact Cargo-target/runtime-label bindings are corrected, with Rust architecture/OS/ABI checks preserved. Production activation remains off. Repaired preparation, retention, semantic parity and optimized-Python/native comparison need actual execution. |
| Package component | All ten phase/validation/registry workers completed. Five plain protect pairs completed. Overall diagnostic and format jobs still failed on 12 censored baseline cardinality workers and two baseline Composer coverage failures. | Retain successful observations and failures together. The actual residual evidence now supports a release-scoped no-selection decision; it does not establish a failed Rust benchmark or full format parity. |
| MCP component | The source-stdio job and all its steps passed. | This checkpoint is a completion check only. The measured native-selection decision remains bound to the corrected 24ba cohort; the successful d0e cohort is separate. |

Pair failures retain their narrower boundaries. Linux and Windows compared a
Cargo distribution triple with the runtime's `ARCH-OS` label; the
[association correction](qualification-target-identity.md) keeps both fields
and every artifact/dependency commitment. Linux's baseline completed while its
candidate remained unattempted. Both Mac frozen baselines timed out at
`socket.getfqdn` during daemon construction. These failures do not justify
patching the frozen baseline or inventing a completed pair.

ARM's candidate completed 386 daemon and 62 registered corpus cases before a
c16 Codex PostToolUse stdout-schema rejection. All 16 calls were offered, but
only three returned latencies were retained; the rejected stdout was absent.
Intel's candidate Pi mismatch case returned an error object before receipt
validation with an admitted runtime and about 2,980 ms of budget remaining.
Neither record identifies a production cause. The
[failure-only stdout witness](fourth-installed-failure-observations.md) and
[capacity witness](native-capacity-none-witness.md) now preserve bounded failure
facts while retaining the original acceptance schemas and failure outcomes.
The [Claude target diagnosis](claude-launcher-target-identity-diagnosis.md)
likewise corrects the witnessed association error without claiming a native
performance result.

The [native command program](../../../contracts/extensions/native-command-program.v1.json)
retains schema `guard.native-command-program.v1` and reference profile
`cpython-3.12-ucd15`, program digest
`4df5208d0dc05ceaadb1de6a6d8f6d3f9e5395dffcf992640fed87b82a0df1c9` and catalog
digest `232ff389ca607b805118a02bd9560e972453f9a406188237037138f4834faf11`.
Its [translation contract](../adr/0013-native-command-extension-program.md) and
[compatibility inventory](../native-command-compatibility-admission.md) distinguish
249 declarative rules from 42 null-matcher identities; owned uncertainty is not
successful empty matching. The fourth Linux, ARM and Windows scenario receipts
supply actual installed production-route proof for their declared cases. They do
not certify every matcher family, Intel readiness or a measured compatibility
speedup. This is the scope of RSP-120's coverage and diagnostics publication.

## Measured decisions and their limits

The [package decision](package-native-selection-decision.md) retains optimized
Python and selects **no package Rust implementation or activation for release
3.2**. Five independent alternating pairs of the exact npm protect source route
at D=B=1,000 report median wall **8,785.843 → 327.344 ms** and CPU
**7,739.458 → 319.842 ms**. Median paired reductions are **96.2752% wall and
95.8662% CPU**. Imports, fixture setup, pre-admitted signed bundle and
postvalidation remain outside that interval; serialization and evidence
persistence remain inside. These observations are neither installed CLI tails
nor a Rust comparison.

All 36 candidate cardinality cells completed, against 24 baseline completions
and 12 censored baseline attempts. Format preflight retained 20 candidate and
18 baseline completions plus two baseline Composer failures. Censoring has no
invented route latency, and the Composer coverage correction is not an
equivalent speedup. None-version highest-risk matching remains a bundle-kernel
scope. The separate explicit npm `*` pair makes exactly 100 admitted GETs per
arm and uses the real JSON, retry, semver, evaluator and protect path to select
2.0.0 over higher-risk 1.0.0. Its synthetic transport does not measure external
HTTPS latency or change the existing bare-`latest` shortcut.

The six instrumented route invocations each retain one parse, one immutable
index construction and one evidence batch, with commitments matching separate
uninstrumented validations. The disjoint function-origin projection assigns
**37.31% protect / 51.75% evaluator** exclusive calling-thread CPU to Guard
Python; Pydantic Python and Pydantic-core recorded zero calls. Existing hash,
byte and SQLite primitives already use native libraries. Function origin is
not exact language attribution, inclusive spans overlap, and profiling perturbs
tiny repeated calls. These fractions cannot establish an attainable speedup
bound. The authenticated private projection identifies repeated validation,
normalization and model/result identity work without publishing private records.

RSP-054 can record this measured release decision. Conditional package native
schemas, implementation and activation remain unselected; unbuilt work is not
called a failed comparison or a completed implementation. A reopened candidate
must cover a coarse immutable model/identity/result operation, first account
for removable Python duplication, preserve original semantics, and demonstrate
at least 30% real-route p95 or complete process-tree CPU benefit over optimized
Python with at most 5% regression in the other metric. RSP-050's censored and
kernel-only limits and RSP-059's parity requirements remain explicit.

The [MCP decision](mcp-native-selection-decision.md) retains optimized Python on
its corrected **24ba** evidence: five independent pairs, 30 workers, 240
sessions, 10,080 calls and 80 complete warm resource windows. Catalog1000 wall
ratio 0.5380 has 95% interval 0.5288–0.5648; mean parent CPU ratio 0.4468 has
interval 0.4380–0.4770. Smallest-catalog intervals cross one and sampled peak
memory increases. Ten lifecycle records remain incomplete, with 16 missing
samples and descriptor errors in nine records. Its fingerprint/classification
residuals are about 0.130/0.173 ms exclusive thread CPU per invocation, alongside
larger store/composition work and the unchanged approximately 5.11 ms barrier.
This supports the recorded conditional kernel/full-proxy deferrals, not a
failed native benefit test, formal upper bound or installed target claim.

The separate successful **d0e** cohort reports large-catalog wall ratio
0.533961 (95% interval 0.508358–0.555922) and mean parent CPU ratio 0.444666
(0.419106–0.468266). Its 80 warm windows are complete, with 129–326 samples and
zero missing readings; all ten lifecycle windows remain incomplete, with 18
missing samples and nine descriptor-error rows. Do not pool those observations
with the decision cohort or substitute the fourth completion check for them.

The [scanner/archive decision](scanner-current-decision.md) retains the
isolated Python archive worker. RSP-070's literal profiling evidence is present:
510 unmodified inspections and 60 diagnostic children identify interpreter,
integrity-read, expansion and member-processing costs. The exact-result gate
still failed at 508/510, with two fail-closed timeouts and one separate warmup
timeout; all 330 hostile/bounded-failure calls remained non-clean. A parser-only
archive Rust port is deferred. No equivalent native worker has been measured,
and no hostile parsing moves into the resident.

Rich-scanner selection remains open. The earlier native experiment runs the
actual fresh source CLI with Rust startup, serialization and child CPU included;
its seven completed timed states are all clean, and none passes the benefit
gate. No finding-heavy timed state completed. The integrated [finite collector](scanner-regex-pilot-ci.md) plans
**24 smoke attempts or 840 full attempts**, with frozen finding,
context/HMAC, fallback, cache and failure-retention expectations. It does not
activate native detection or support a blanket no-port conclusion.

## Source ready to execute and release exit

The [baseline launcher ranking](installed-launcher-baseline-ranking.md) remains
one descriptive Windows block with 80 actual registered invocations. Ordering
changes by event and load; Claude is not established as uniformly most expensive.
No installed usage weighting, missing-platform ranking or qualified tail follows.
The dormant launcher and its repaired experiment therefore still need an actual
comparable benefit result before activation.

The [nonpriority companion](nonpriority-installed-tails.md) now exposes an
explicit four-platform smoke for `cursor.beforeShellExecution.global`: four
collection jobs plus four aggregators, two timed observations per arm after
separate benign/block preflight. That is 16 timed and 16 preflight invocations
if every arm completes. No observations are claimed. Full 16-route ×
four-platform × five-pair collection remains deliberate opt-in at 320 jobs;
smoke cannot satisfy the original 1,000-observation route minimum. Existing
priority, cold/recovery, resource and offered-load minima remain unchanged.

The new Darwin reader binds Mach counters to exact root/member identities and
separates reaped-child rollup from live descendant CPU. Sticky read failures,
identity changes and missing samples prevent completeness; no psutil double
counting or zero fallback supplies a pass. Source tests and peer review are
complete, but actual checks on both Mac targets are still required. This does
not close installed resource qualification or RSP-011.

The integrated [ACK-only posture correction](acknowledged-posture-contract.md)
samples one authenticated request binding for native evaluation, the shared
command-control lease and final Watch delivery. Local Watch becomes effective
only after the correct resident ACK; a pending local update cannot weaken an
enforcing result. Native decisions/receipts and unchanged availability responses
remain separate. The source run passed 24 new and 153 adjacent tests, with one
platform skip. This supports RSP-031's authenticated visibility contract, while
RSP-034's actual mixed-transition and installed qualification remain open.
Historical measurements do not qualify this new behavior.

Run the coherent corrected source and inspect exact admission, retention and
failure witnesses. Restore required Main CI and the actual quality gate;
execute the repaired Claude experiment, selected nonpriority smoke, Darwin
correctness checks and finite scanner experiment. Preserve every offered or
failed attempt and all original timing, resource and sampling thresholds.
A successful diagnostic advances only its declared scope.

Final acceptance still requires comparable installed performance, exact signed
and frozen artifacts, live update/rollback, mixed offered-load/mutation/recovery,
durable receipts, complete final-head validation and independent latest-push
approval. Source inventory, the recorded package/archive decisions and this
handoff can close their literal criteria while dependent work stays open or
conditionally deferred. Original dependencies remain intact; RSP-012 and the
latest-head release gates do not close through a status refresh. PR #2970 targets
`release/3.2`; protected merge, canary and release remain incomplete.
