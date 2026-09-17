# Release/3.2 Rust performance implementation PRD

Reduce the latency, CPU and memory HOL Guard adds to real developer tool calls
while preserving its decisions, delivered responses, approval authority, artifact
trust and evidence. A Rust conversion must earn selection through comparable
real-route measurements. Optimal performance and release qualification remain
unestablished.

The original [PRD](PRD.md) and all [144 TODO criteria](TODO.md) remain normative.
This addendum specifies the current implementation, priority decisions and exit
work without changing their IDs, titles, acceptance conditions or dependencies.
The [execution ledger](EXECUTION_LEDGER.md) records **89 DONE / 20 OPEN / 27 BLOCKED / 8 DEFERRED**.
Four criteria close at their original scopes: RSP-034 concurrent transition correctness, RSP-066 selective scanner comparison/deferral, RSP-072 published full-CLI scanner evidence and RSP-118 installed command.ollama lifecycle. Their original definitions and dependencies remain unchanged. These closures do not establish native activation, complete installed performance/resources, signing, package downgrade or release qualification.

## Users and observable outcomes

Developers receive the same enforcing, Watch or availability response through
their installed harness with lower overhead. An approval resolves only its
original live request under current authority. Maintainers can identify, update
and roll back the exact installed artifact. Operators receive bounded queues,
resources and recovery with truthful health and private evidence under load.

## Source and evidence

The [eighth CI evidence](EIGHTH_CI_EVIDENCE.md) records **41 terminal first-attempt workflows: 36 successful and 5 failed**
at PR head `a933921372ddb3772eff8a9d86771fe15da063b1`, tree `3db430b618fe63cc1b85b8037e5de700cc3378c9`. GitHub tested merge
`e54cf7732f61a6a7e609250a4e17344b5e92039d` has the same tree and a distinct build identity.
The later implementation checkpoint `8ddf86494e8bb4da50be83d849603195b6b77976`, tree `566d910caaa29b0ec3585803a9f4095b11a5651d`,
requires its own published-source CI. The four additional label-triggered runs,
including full scanner, remain separate from the original 41. All eight historical cohorts remain
separate; failed, censored and unoffered work retains its original denominator.

| Workstream | Eighth observation and practical limit |
| --- | --- |
| Main CI and security | All 96 pytest shards pass. Main has 114 jobs: 110 successful, one failed and three skipped. Actual Windows ordinary packaged bootstrap passes; Sonar analysis succeeds and its unchanged quality gate fails. No fresh numeric gate conditions were queried. All four security jobs and both ownership workflows pass. All 195 Main artifacts are present and unexpired; this is artifact metadata, not a download/recovery claim. |
| Installed native launcher | Fifteen POSIX jobs complete 1,320 attempts, including 1,200 timed observations. Linux native PostToolUse p95 is 31.028–41.522 ms across five series; PreToolUse is 40.817–71.519 ms, with four of five above 50 ms. Both Mac sets remain above 50 ms. All five Windows jobs fail the existing-parent child-ACL preservation regression before offers: 440 planned attempts remain unoffered. Fifteen observation archives and five explicit no-observation receipts remain distinct. Production selection stays off. |
| Dormant native source pilot | All four actual target jobs pass the source fixture and Python/Rust gates, including 32 Python and 17 Rust pilot cases per target plus feature-off/on smokes. This is actual platform build/source evidence; production registration and qualification stay off. |
| Scanner smoke and separate full experiment | Original smoke completes 24/24 attempts and passes source/identity/retention gates, but alone has only one of five required runs. The separate full experiment completes all 840 attempts across 35 shards, five independent runs per 14 case/cache-state cohorts, with zero missing/invalid shards. Both arms use the same optimized a933 source and locked environment, not the frozen 3.0.1 baseline. Complete finding/stdout commitments agree between matched arms within each shard; cross-run fixture/history identities may differ and remain retained. Only the large provider-credential case passes the original gate in both cache states (2/14); the other 12 fail. Large-case p95 ratios are 0.467884/0.379151 and CPU ratios 0.461275/0.458187, with required bootstrap intervals. All 420 native observations have zero fallback. This is Linux source-CLI evidence; production CLI remains Python, without an invented input-size cutoff or installed/platform qualification. |
| Package | Five comparable Python protect pairs retain wall medians 8,864.682061 → 326.475958 ms and CPU medians 7,774.195 → 316.916 ms; median paired reductions are 96.3336902129%/95.9413386466%. All ten phase workers complete; Guard-Python exclusive origin medians are 41.9452820% protect and 53.7612411% evaluator. Cardinality retains 36 candidate and 24 baseline completions plus twelve censored baseline workers; formats retain 20/18 completions plus two frozen Composer failures. The original keep-Python decision remains unchanged; these are separate Python cohorts, not Rust speedups. |
| MCP | 30 workers and 10,080 outcomes complete with zero failures across eight five-block comparisons. All 80 warm resource windows complete with 149–352 snapshots; ten lifecycle rows remain incomplete with 14 missing samples and 38 descriptor denials. The existing decision remains unchanged; no installed/cross-platform qualification or native selection is inferred. |
| Installed native wheel | Linux and ARM pass all 14 installed smoke gates; qualification remains false. Intel fails c16 p99 at 1,430.876 ms and resident recovery p95 at 1,913.911 ms against separate 1,000 ms smoke bounds. Each POSIX report retains 146 observations, 21 installed routes across 13 harnesses and 42 warm values. Linux c16 completes 16 native results; c64 accounts for 58 native results plus six explicit overloads, with zero fail-safe/None/error results. Its soak completes 100,000 logical stress calls and responses against 250,000 preseeded receipts, with zero errors, 19,961 successful health checks, stable PID and one daemon. RSS rises 614,137,856 → 635,490,304 bytes (3.4768%); p95 472.61 ms is judged against the 4,500 ms diagnostic bound. The soak helper may retry and does not prove a native route for every request. Windows returns 21 corpus responses but reports only 19 native-resident plus one fail-safe route, failing aggregate conservation; no complete probe or SLO report follows. No missing per-request route or cause is inferred. These runtime artifacts bind equal-tree merge e54cf773, separately from a933 head identity. |
| Indexed qualification and nonpriority tails | The qualification workflow has 27 jobs: 15 successful, ten failed and two skipped. All four wheels and all four installed extension-scenario jobs pass. Linux indexed smoke completes one block per arm, each with 38 series and 136 numeric observations; its aggregate is comparable but unqualified. Both Mac candidates complete the same numeric scope, while frozen baselines fail fixture construction in getfqdn. Windows baseline fails qualification_warmup_changed_semantic_route in the numeric block; candidate fails native policy not ready during session startup. Neither outer worker times out or fails containment. Windows baseline retains 386 normalized and 62 registered preflight cases plus two startup/readiness journal values. Candidate retains 290 normalized cases, then the next fixture fails before any further offer; 96 declared normalized cases remain unoffered. No finer timeout/authentication/control cause is inferred. Linux and Windows tail comparisons complete; both Mac candidates complete, while frozen baselines fail before a public block. Twelve of 16 planned timed tail values are retained; four Mac baseline values are unoffered. All four completed indexed c64 offered-load contracts fail and all mixed/registered/approval/input/UTF8 side scenarios remain failed; successful block collection does not pass those gates. General Darwin CPU remains unavailable and Linux resource samples number only 11 baseline/ten candidate against 30 required. Full sample, resource and five-pair qualification remains incomplete; exact failure witnesses are in QUALIFICATION_EIGHTH_CI_EVIDENCE.md. |
| Installed command.ollama | All four declared platform jobs pass: each retains 22 native-resident cases and 22 durable receipts through installed contribution, Builder/build identity, authenticated daemon HTTP, enable, policy review, approved retry, disable, update, settings rollback and stale-write rejection. Revisions progress 0→4; contribution/program hashes match a933 and observed installed identities match expected identities. This closes RSP-118 at its literal lifecycle scope. It does not execute an Ollama process or establish package downgrade, native v3/v4 approval consumption, interactive enrollment, signing or performance. |
| Packaging and release | Original PyPI authorization and build/verify pass with 14 downstream jobs skipped. Desktop feed jobs validate only; actual publication skips. The separate label-triggered PyPI run performs authorization only and skips 15 jobs. Neither cohort publishes a release. |

## Conversion decisions and priorities

| Priority / component | Release 3.2 decision | Exit requirement |
| --- | --- | --- |
| P0 / native client and existing decision path | Measure remaining identity/discovery/connect/auth cost, then select a coarse Rust change only where installed evidence shows a bottleneck. | Complete RSP-025/RSP-085 observations, preserve trust/expiry/peer identity and demonstrate original ordinary-hook benefit and resource gates. |
| P0 / dormant native launcher | Keep activation off; complete actual Windows preservation and correct the remaining PreToolUse/Mac latency. | Four-target installed parity/registration/lifecycle plus unchanged absolute/relative latency and CPU gates. |
| P1 / large finding-heavy scanner | The four × 256 KiB dense provider fixture earns further targeted native work on Linux. Retain Python in production and for the other six tested workloads; do not invent a universal cutoff from one fixture. | A justified selection rule needs representative size/content sweep, complete findings/limits/exits, required platforms and installed packaging evidence. No blanket rewrite. |
| P1 / package path | Retain optimized Python under the original measured decision; preserve current large Python improvements and censored baseline work. | Reopen only a coarse native model/identity/result boundary that beats the optimized full real route with comparable work. |
| P1 / installed qualification and lifecycle | Keep distinct indexed/tail/sample/resource deficits visible and restore comparable frozen arms without changing baseline semantics. | Original warm/cold/recovery minima, approval/source/alias cases, complete resources, signed/frozen live update and changed-program rollback. |
| Conditional / MCP and archive | Retain measured Python boundaries and original conditional native deferrals. | Any selected port must meet the original same-work benefit, parity, containment, resources and installed requirements. |

The [package decision](package-native-selection-decision.md),
[MCP decision](mcp-native-selection-decision.md) and
[scanner/archive decision](scanner-current-decision.md) retain their exact
historical evidence and reopening conditions. A measured deferral is a decision;
it does not implement an optional port or satisfy its conditional native parity.
The full source map and ownership boundaries remain in [CURRENT_CONTRACT](CURRENT_CONTRACT.md).

## Functional and trust requirements

1. Keep the Rust resident responsible for the ordinary semantic decision.
   Preserve exact policy/program/catalog binding, authenticated peer and process
   identity, generation, expiry, mutation fences and replay protection through
   finalization. Metadata hints cannot confer content authority.
2. Record native verdict, resident-acknowledged posture, availability and the
   delivered harness response separately. Preserve the existing response matrix.
3. Bind approval to its original waiter, request and deadline; re-evaluate current
   authority before atomic consumption. Never replay an ambiguously delivered MCP write.
4. Preserve strict parsing, Unicode/CRLF behavior, limits, complete findings,
   source references, HMAC, suppression, provenance and exits 0/2/3. An incomplete
   scan or omitted dependency cannot become a successful benchmark observation.
5. Bind source, artifact/runtime/program, interpreter, dependencies, workload and
   host cohort. Execute measured wheels outside source checkouts using the actual
   registered executable and argv with development overrides cleared.
6. Retain offered, failed, late, censored and unoffered work, bounded private
   evidence and complete resources. Missing counters remain missing.
7. Prove signed/frozen installation, live update and rollback on the tested
   artifacts. Source tests and stopped replacement cannot supply that proof.

## Performance acceptance

| Scope | Unchanged acceptance |
| --- | --- |
| Ordinary installed priority hooks, 1–16 KiB, warm c1 | p95 ≤50 ms and p99 ≤100 ms |
| Ordinary installed priority hooks, c16 | p99 ≤200 ms, zero errors and correct decisions |
| Native client / cold native / daemon readiness | p95 ≤20 ms / p95 ≤150 ms / 400 ms barrier |
| Independent comparisons | At least five alternating independent pairs and required confidence intervals |
| Per required qualification scope | 10,000 warm priority, 1,000 other, 100 cold/recovery observations and at least 30 valid resource samples |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU reduction; at most 5% regression in the other primary metric |
| Optional native ingress | At least 25% private-memory or 30% c16 p99 reduction with equivalent decisions and containment |
| Optional package/offline conversion | At least 30% benefit over optimized Python on the same real route including startup/boundary costs |
| Resource growth | Existing 12% short-load and 50% long-soak RSS limits at their original scopes |

The original PRD resolves any abbreviated requirement. Keep KERNEL,
NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER separate; registered process
startup is included in the last boundary. Cold launcher, cold resident,
readiness and recovery are distinct series. Exercise Linux x64, macOS Intel,
macOS ARM and Windows x64, with 1 KiB, 16 KiB, 256 KiB, 1 MiB and maximum
payloads at c1/c4/c16/c64 and offered-rate load. Include generator/queue delay
and all terminal outcomes. Bounded c64 overload remains visible in conservation.
General Darwin process-tree CPU remains unavailable where reaping is ambiguous.

## Implementation and acceptance work

| Later source change | Resulting behavior | Required next evidence |
| --- | --- | --- |
| Windows parent ACL preservation | Explicit provisioning uses NtSetSecurityObject on the retained exclusive directory handle with DACL/protection flags only. Missing API or nonzero status fails explicitly; owner, child/key bytes and existing strict readers are untouched. The actual eighth SetSecurityInfo child-descriptor failure is preserved; the original Windows regression is unchanged. | Actual Windows parent/child identity and ACL regression, ordinary bootstrap and installed launcher on the later source. Local ctypes contracts do not prove platform behavior. |
| Failed installed-corpus delivery context | Retains up to 32 finite delivery rows using the original single is_allowed result and emits only on the original aggregate validation failure. Missing/invalid counts stay null; original assertion and exception remain. No request, wait, retry, deadline, successful receipt or native-route predicate changes. | A later Windows report distinguishing delivered outcomes from aggregate routing; no per-request native route or root cause is inferred from the observer. |
| Evaluated-hook identity diagnostic (RSP-025) | Counts actual executable status lookups, validation/hash bytes, live proof and capability calls separately on three unchanged hooks in a normally prepared resident. Records dispatch and missingness without clearing caches or fabricating cold state; separate from headline timing. | Actual retained installed observations on each target, then literal cold-hook attribution. RSP-025 remains open. |
| Native-client phase diagnostic (RSP-085) | Separate default-off Cargo feature instruments the existing persistent helper and resident-client calls, preserving operation/result/order/deadlines. Correlates exact request digest, actual native route and frozen semantic proof; socket counts become incomplete on unobservable failures. Public fixed-schema phases are inclusive and must not be summed. Four-target explicit opt-in workflow requires bounded private capture and successful encrypted retention. | Actual full feature builds and installed 20 benign + 20 blocked observations per target under rust-native-client-profile. These diagnostics cannot supply uninstrumented headline benefit; RSP-085 remains open until observations exist. |
| Policy/posture transitions (RSP-034) | Eighteen concurrent source cases cover Watch/enforce, stricter workspace overlays, signed expiry/renewal, missing/digest/epoch/stale-generation ACK and generation-file replacement. Real worker/compiler/signed publisher/ACK decoder retain in-flight response bindings; native edge/lease are injected. Thread-start failure cleanup preserves the original error. | Closes literal source transition-testing scope alongside retained installed restart evidence. Full installed mutation/recovery, mixed-load, resources and release gates remain separate. |

1. **Execute the later published source.** Run the complete required native/Python ownership, security and platform checks on the exact next publication. Select rust-native-client-profile only after its reviewed workflow is published; inspect all four source-bound diagnostic artifacts and encrypted-retention gates. Keep eighth terminal failures, the separate full scanner cohort and new instrumented observations distinct.

2. **Prove Windows parent preservation and corpus routing.** Execute the unchanged child/key ACL and identity assertions against the direct handle-based setter, ordinary frozen bootstrap and installed launcher. Retain all 440 unoffered eighth Windows launcher attempts. Inspect the bounded corpus observer for the separate 21-delivery/20-route assertion. Do not infer that this observer fixes the runtime or change deadlines, failure policy, keys or child security to make the checks pass.

3. **Attribute and reduce ordinary native overhead.** Read actual RSP-025 hook identity/cache reports and RSP-085 platform spans and socket counts. Prepared-resident first-hook is not a cold resident or cold cache. Establish the missing cold-hook series and prioritize the demonstrated repeated work; exclude instrumentation from headline comparison. Keep native verdict, acknowledged posture, availability and delivered response separate. Retain failed PreToolUse/Mac launcher and Intel concurrency/recovery values.

4. **Apply the scanner decision without broad activation.** The completed 840-attempt same-source experiment satisfies the comparison/report criteria. Only the large provider fixture passes both cache-state benefit gates. Use its retained complete finding and full-CLI wall/CPU evidence to design any next targeted size/content/platform comparison. Keep Python selected for all production CLI routes and the twelve failing cohorts. Preserve cross-run workload identities; do not pool source-CLI results with installed hooks or frozen-baseline experiments.

5. **Complete installed qualification and resources.** Use the eighth qualification and native-wheel evidence to diagnose Windows partial indexed failures separately from corpus aggregate conservation, and Mac frozen getfqdn construction separately from candidate performance. The prior disposable-runner PTR experiment did not restore libc reverse lookup; do not repeat it unchanged or patch the frozen baseline. Complete original independent-pair/sample/resource minima and literal installed source/alias/approval/availability cases. General Darwin reaped process CPU remains unavailable where attribution is ambiguous. Full tails need deliberate 320-job selection after comparable arms.

6. **Preserve component decisions and complete lifecycle.** Keep original package/MCP/archive decisions and all earlier cohorts. Preserve twelve censored package workers, two baseline Composer failures and incomplete MCP lifecycle resources. RSP-118 now proves the declared four-platform installed control-settings lifecycle, not package/program downgrade or signing. Complete live update, in-flight generations, changed-program rollback, durable receipts and mixed offered load with exact artifacts.

7. **Finish release acceptance.** Keep all 144 definitions and dependencies intact. Require complete same-source performance/semantic/resource evidence, final-head CI, independent latest-push human/code-owner approval and tested signed/frozen rollback. Prepare a concrete qualified canary and stop conditions before final release approval. Approval of the pending Sonar request is required for its proposed custom lookups/dispositions; do not bypass it through CI.

Full nonpriority tails still require their deliberate 320-job selection.
The separate [full scanner experiment](SCANNER_FULL_CI_EVIDENCE.md) has completed
all 840 attempts across 35 shards, seven fixtures, five runs, two cache states,
six pairs and two arms under the unchanged 120-second CLI and 30-second native
deadlines. Only the large provider-credential case passes both cache-state gates;
production selection remains Python. Its label was removed after completion.
This full source-CLI experiment does not qualify installed hooks or other platforms.

## Validation and release decision

At local integration `019600668a2248c75099910a6ac77d5ebb2fc2c9`, the final combined 27-module correctness suite passes **521 tests**, with **nine explicit Windows/platform skips**. The first combined run retained 520 passes, nine skips and one scheduler-dependent test failure; its actual finite ledger showed correct generator rejection under a one-slot fixture. The reviewed test-only correction uses three bounded queue slots and synchronized workers to assert all three intended outcomes while preserving separate one-slot overload coverage. All 30 changed Python files pass Ruff and formatting; all 14 changed source/protocol modules pass CI-level typing after an annotation/cast-only fixture cleanup. The exact a933 fixture reproduces the original ten type errors, and the cleanup preserves runtime values, readiness and request calls. Rust 1.88 formatting, four-source Claude fixture freshness, same-base authority ownership and privacy gates pass. Full collection succeeds with **22,725 cases and 24 protected invariants**. All **394 frozen evaluator source commitments** still match, without corpus re-evaluation or regeneration. Five tests of the exact Rust instrumentation module passed under Rust 1.88.0; this is a standalone module build, not a complete native runtime or platform build. Subsequent evidence-only commits do not change this tested source. No local performance workload ran. Actual direct-parent Windows execution, complete native feature builds and installed diagnostic/performance/resource results require the newly published source's own CI. Gitleaks 8.24.2 scans the exact release-base-to-immutable-source range: **1,269 commits and 55.33 MB, zero findings**.

The [release review](RELEASE_REVIEW.md) and [takeaway prompt](TAKEAWAY.md) define
the remaining execution. Require complete comparable performance/semantic/resource
evidence, final-source CI, independent latest-push human/code-owner approval,
tested signed/frozen live rollback and a concrete canary with stop conditions.
The PR remains a draft; merge, production activation and release are incomplete.

The 42 [individually reviewed Sonar findings](../security/sonar-release-32-review.md)
remain unapplied. Eighth ordinary analysis succeeds, then its unchanged quality
gate fails. Seventh service HTTP 500 remains a distinct historical failure.
No fresh numeric gate conditions have been queried or inferred from prior runs.
Automatic approval review rejected the project-specific external lookup because
it would disclose private project, PR and issue identifiers without explicit
authorization. The specific permission request for fresh checks and verified
individual false-positive dispositions remains pending. Do not retry that action
through CI or another route without approval. No comments, exclusions, severity
changes or quality-threshold changes are authorized by that pending request.
