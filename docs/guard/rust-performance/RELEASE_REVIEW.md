# Release/3.2 Rust performance review

Reviewed 2026-09-17. **The next source checkpoint is implemented and reviewable;
installed qualification and the release remain incomplete.** This review covers
source `599509be545b9992076d7f9f71dd19ecfd34bbc2`, tree
`55b05ef94f1f379fd0cf2762e3f1f394a2771b24`, before these documentation edits.
The second measured publication is PR #2970 head
`24ba2d130a90f36b676139f03cabea98a2c3b00e`. Later source corrections do not inherit
its measurements or change its failed workflow conclusions.

Validation-only follow-up `a86ee973647c742baa795e3871582eb53aff8f6f`
subsequently fixes a tautological MCP trace assertion and adds six real signed
authority-marker regressions. Seven focused tests pass. The
[source-bound Sonar review](../security/sonar-release-32-review.md) identifies
42 remaining false positives individually, with exact analyzed source hashes.
Their remote dispositions are unapplied; fresh analysis and authenticated Sonar
review remain required. Production code, detector rules, thresholds, fixture
URLs and deterministic seeds are unchanged by this follow-up.

The original [PRD](PRD.md) and all 144 [TODO](TODO.md) titles, acceptance conditions
and dependencies remain unchanged. The [release addendum](RELEASE_3_2_PRD.md)
connects them to implementation and conversion priorities. The reconciled
[ledger](EXECUTION_LEDGER.md) records **74 DONE, 30 OPEN, 37 BLOCKED and 3 DEFERRED**. RSP-007 closes the actual registered-launcher measurement implementation,
RSP-047 the applicable core parity/adversarial suite work, RSP-015 the frozen
Watch/availability fixtures, RSP-140 the evidence/privacy checks, and RSP-098/103
the source-bound MCP overhead/optimized-Python rebaseline. The measured MCP
selection record defers RSP-104/105/107 and completes RSP-108's full-proxy decision. These literal criteria do
not close dependent installed benefit, final-head validation, rollout or approval.

## Second CI checkpoint: 32 successes and seven failures

All 39 workflows at `24ba2d130...` are terminal. The separate
[second-CI report](SECOND_CI_EVIDENCE.md) records exact public artifacts and the
recovered component evidence. Seven failed workflows are not seven failed tests:
the native-wheel workflow itself contains four failed platform jobs, and the
invalid qualification workflow executed no jobs.

| Workflow | Actual second-checkpoint failure and current source response |
| --- | --- |
| Main CI | Of 114 jobs, 110 passed, three skipped and one Sonar Quality Gate failed. Analysis completed; reliability/security ratings failed the gate while 82.4% source coverage passed its check. The validation-only follow-up fixes one test assertion and documents 42 individual false positives. Their dispositions and fresh analysis remain outstanding; passing source suites cannot replace that gate. |
| Native wheel | All four jobs failed. Linux lacks a qualifying RSS warmup route proof; Mac ARM `cursor/5m` and Mac Intel `pi/1m` source witnesses saw one native edge call without an admitted result. Windows failed its RSS process-tree fixture before wheel construction. `7e2739fc4` adds finite failure diagnostics and corrects Windows binary-LF/base-interpreter fixture topology, without relaxing route, count, memory or timing assertions. The Linux/Mac causes remain unestablished. |
| Package component | Frozen-baseline coverage failures remain incomplete comparisons. Candidate completions and retained pairs keep their exact source and route scope; they are not a native-selection or tail result. The separate phase-attribution and explicit-range resolver job is implemented for the next CI. |
| MCP component | Collection completed, but strict public finalization rejected two newly emitted resource fields. `1498e2264` admits exactly Linux `observed_process_tree` CPU scope and an integer unavailable count consistent with existing missing-sample accounting. Reprojection of the retained authentic data supplies component evidence; it does not turn the original workflow green. |
| Windows resident | The child-exit CPU fixture assumed one process per Python invocation. Actual Job counts included venv redirectors. `8bab03d5f` witnesses exact PID/parent/creation chains and checks exact total/active counts plus the original exited-child CPU lower bound. Actual corrected Windows execution remains required. |
| Security | Pinned `go install` did not stamp the Gitleaks version required by the fixture regression. `ca772a069` supplies the upstream version linker symbol for the same 8.24.2 module. The exact-version check, detector rules, exceptions and full scan scope remain unchanged. |
| Native performance qualification | Invalid job-level `runner.temp` environment expressions prevented any job from starting. `a886a89bc` moves those paths to supported consuming-step contexts. No second-checkpoint installed pair or performance result exists. |

The recovered MCP v2 component is a real five-run baseline/candidate observation,
with **30 workers, 240 child sessions, 10,080 calls and 80 complete warm resource
windows**. It separates eight synthetic traces, first-call/startup work,
classification/catalog/policy/serialization, the unchanged 5 ms freshness barrier,
child/service work and controlled approval/network waits. Paired run-level
intervals and complete warm-window accounting support the local Python
rebaseline. They do not establish remote-service latency, installed CLI overhead,
Windows transport, whole-lifecycle resources or a native kernel advantage.
For `catalog1000`, the candidate/baseline wall ratio is 0.5380 (95% interval
0.5288–0.5648) and parent-process CPU ratio 0.4468 (0.4380–0.4770); the smallest
catalog's intervals cross one. Sampled peak memory increased. All ten separate
startup/churn lifecycle records remain incomplete, with 16 missing snapshots
and descriptor-access errors in nine records. Warm-window completeness does
not erase those failures or establish whole-lifecycle CPU/memory coverage.

The second package run completed five comparable local protect pairs at
D=B=1,000: median wall time 8,773.536 → 318.011 ms and process CPU
7,732.300 → 310.481 ms, with median paired reductions of 96.3751% and 95.9846%.
All 72 cardinality offers remain accounted for: 36 candidate completions,
24 baseline completions and 12 baseline censored workers. Format preflight
completed 20 candidate and 18 baseline cases, retaining two baseline Composer
coverage failures. Imports, setup/admitted bundle and postvalidation are outside
the measured local protect interval. These are neither full installed CLI
measurements nor a Rust comparison.

The [MCP selection decision](mcp-native-selection-decision.md) retains optimized
Python for release 3.2 and defers a new native MCP kernel and full proxy rewrite.
Across the eight instrumented traces, remaining catalog fingerprint/category
classification cost about 0.130/0.173 ms of exclusive thread CPU per invocation,
compared with larger store lookup, policy composition and persistence spans.
The approximately 5.11 ms quiet barrier is an ordering requirement, not removable
CPU. This supports a measured scope decision; it is not a failed Rust benchmark,
a formal upper bound on native speedup or proof that installed goals are met.
A new residual or justified coarse kernel can reopen the conditional work under
the original benefit/parity/resource requirements. RSP-106 remains unchanged.

## Implemented since that publication

| Tranche | Implemented scope and next evidence |
| --- | --- |
| Indexed qualification and diagnostics | Same-run immutable wheel bundles, independent alternating pairs, exact numeric archive commitments and unchanged sample minima are wired. Failure envelopes now retain finite route-wave and client-context observations. The corrected YAML and diagnostic paths require actual new-head execution. |
| Package residual attribution (`4a1349d57`) | Eight candidate-only validation/profile workers use the original two fixture inputs; a separate two-worker pair exercises 100 explicit npm `*` requests through the actual resolver/protect route with fixed registry bytes. No change to the original 567-case manifest, ordinary route timings or production semantics. CI must supply attribution before a Rust package decision. |
| Installed Claude experiment (`a416c1cbb`, `d7069e65b`) | An opt-in feature wheel compares optimized Python and native registered Pre/Post argv inside the same installed artifact. Exact response/route identity, offered/terminal outcomes and mandatory encrypted/public retention are implemented. Apply `native-claude-launcher-experiment` to the same-repository PR for the next publication. Production registration and the default feature remain off. No installed experiment result exists yet. |
| Stopped artifact transitions (`6509b59c8`) | A separate four-platform job consumes indexed bundles and exercises five stopped phases/ten registered cases in a third environment. It binds the candidate dependency lock/inventory and exact Python patch, keeps every 180-second command cap, and requires exact-snapshot encrypted checkpoints plus both uploads. This qualification-label scenario has not executed; it does not prove live replacement, signing or downgrade support. |
| Compatibility foreground/startup (`d0069a1a9`, `599509be5`) | Static harness lookup avoids cold adapter imports during admission, foreground observations delegate resource probes to the supervisor, and compatibility work consumes its existing cap from ingress. Admitted oracle code and immutable manifest preparation precede evaluator readiness; authority/config/store work remains request-local. Original deadlines, aliases and delivery semantics remain. |

The separate 16-route, 320-job nonpriority-tail companion is still under
implementation. It is not integrated at this cutoff and supplies no observations.
The existing nonpriority 1,000-sample requirement remains; a later companion
must retain all offers and exact route/platform denominators.

## Source validation and remaining uncertainty

The original 24-request locked-storage burst now passes its unchanged 1.75-second
client timeout, 1.6-second response and 0.5-second health assertions, including
all 24 deliveries and post-unlock recovery. It also passed the consolidated run.
Earlier failures remain historical; they are no longer the current unresolved
burst blocker. [The source investigation](locked-storage-burst-correctness.md)
records the actual import/admission/resource-probe boundaries and intermediate
failures.

The subsequent [evaluator preparation](evaluator-bootstrap-correctness.md)
correction passed the original direct fan-in and state-readiness cases together.
Its broader four-module run recorded **91 passes and one failure**:
`test_deferred_runner_bounds_backfill_deferral_during_active_reviews` missed its
unchanged eight-second capacity wait. An instrumented isolated rerun passed,
but did not explain that broader-run failure. The final deterministic bootstrap,
import and harness batch passed 46 tests, and all 15 semantic-gate roots passed.
This is not a fully passing combined runner suite or an installed timing proof.

Root integration validation at `599509be5` passed 119 source tests covering the
transition controller/workflow, qualification workflow, evaluator preparation,
selected harness imports, admission identity/deadlines and MCP public projection.
The authority gate passed 66 changed files, I/O ownership passed with 435 reachable
functions and 3,861 inventory entries, and seven dynamic privacy probes passed.
These narrower checks do not reclassify the broader backfill failure.

RSP-134 remains distinct from RSP-047: applicable core parity work is complete,
while exact integrated-head Rust/Python validation and the remaining CI failures
must still be resolved. The transition tranche passed 179 source tests and the
Claude experiment tranche 60; their related helper totals overlap and must not
be summed. Independent review closed the transition archive validation/read
race by checking the exact bytes passed to encryption. Source correctness does
not establish Windows execution, artifact activation or performance acceptance.

## Historical evidence and release decision

The [first-CI checkpoint](FIRST_CI_EVIDENCE.md) remains unchanged: 39 workflows,
33 successes, six failures and 19 exact public reports at `107606388...`.
Its native-wheel evidence identifies merge build `a806a38...`, a different
artifact from the paired head. Linux completed 100,000 requests, 250,000 receipts
and 17,888 health checks without request/health errors, with 3.9683% sampled RSS
growth. Its 528.06 ms legacy-soak p95 does not meet or replace the PRD's 50 ms
installed-priority target. Two-observation Python launcher smokes and Mac Ollama
successes remain narrower historical observations.

The first package five-pair protect result reduced median CPU from 5,923.255 to
242.241 ms at 1,000 dependencies/bundle entries after Python optimization.
Those values remain first-checkpoint evidence, not measurements of the later
phase collector. Censored 15-second whole-worker cells are not evaluator lower
bounds. The kernel's None-version highest-risk lookup, bare `latest` shortcut
and real explicit-`*` resolver route remain distinct workloads.

Publish and inspect corrected CI, run the opt-in installed experiments, diagnose
Linux/Mac failures and the unresolved backfill deadline, then complete the full
indexed and nonpriority sample requirements. Select remaining Rust tranches only
from comparable optimized-Python/native evidence. Complete signed/frozen artifact,
update/rollback, mixed-load and canary evidence before release acceptance.

[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970) targets
`release/3.2` on `codex/release-3.2-rust-finalization`. PR #2954 has another writer;
review selective reuse without overwriting its work. Foundation PR #2951's
reported approvals and CI are historical. Independent latest-push code-owner
approval remains a protected-branch gate. No protected merge, canary or release
is complete.
