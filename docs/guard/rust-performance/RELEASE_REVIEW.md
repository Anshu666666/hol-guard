# Release/3.2 Rust performance review

Reviewed 2026-09-17. **The current source is implemented and reviewable; installed
qualification and release acceptance remain incomplete.** This fourth handoff
refresh covers `6c7c3097d566da35812d087d1dadae1fba8823de`, tree `87828bda11b356fa9ba982f3d47fffc96a05451c`, before these
handoff edits. The latest observed publication is PR #2970 head
`d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`. Its native-wheel and daemon-edge
jobs tested merge `c855bae3e83579587d229c83b597dc1cbc1d4bb6`. Later source
corrections do not inherit those measurements or rewrite failed conclusions.

The original [PRD](PRD.md) and all 144 [TODO](TODO.md) titles, acceptance conditions
and dependencies remain unchanged. The [release addendum](RELEASE_3_2_PRD.md)
connects them to current implementation. The [ledger](EXECUTION_LEDGER.md)
records **77 DONE, 30 OPEN, 34 BLOCKED and 3 DEFERRED**. RSP-024 now records the
[technical contract review](technical-contract-review.md), RSP-073 the bounded
[installed baseline ranking](installed-launcher-baseline-ranking.md), and RSP-074
the [package-bound launcher design](native-claude-launcher-design.md). Original
dependencies and RSP-012 remain unchanged. Source criteria, measured conditional deferrals,
installed benefit, final-head validation and protected approval remain separate.
The original [first](FIRST_CI_EVIDENCE.md) and [second](SECOND_CI_EVIDENCE.md)
checkpoint reports remain immutable historical evidence.

## Latest actual CI and source response

The [third-CI report](THIRD_CI_EVIDENCE.md) binds the d0e publication, individual
run attempts, artifact bytes and observation cutoff. The 15:00 UTC snapshot
records **43 terminal workflow instances: 36 successful, five failed and two
skipped**. Label events account for additional instances; these are not unique
workflow definitions or a count of failed tests.
Qualification attempt 1 and its rerun must not be collapsed into one outcome.

| Scope | Actual observation | Current source response and remaining evidence |
| --- | --- | --- |
| Main CI, `35233473529` | 114 jobs: 109 passed, three skipped, two failed. All 96 pytest jobs passed. Duration aggregation received 95 artifacts, missing shard 91; Sonar retained a C gate with 42 individually reviewed false positives. | The duration reporter now binds its output destination at session start, before installed-proof tests clear environment overrides. Individual authenticated Sonar dispositions remain unapplied. Fresh complete telemetry and the actual quality gate are still required. |
| Native wheel, `35233473553` | Linux passed its installed SLO step and separate enforced legacy soak. Mac ARM failed OMP/5 MiB and Mac Intel failed Kimi/250 KiB source witnesses. Windows passed 30 memory tests and the 21-decision default-auto native corpus, then failed registered Claude PostToolUse native-route proof. No completed Mac/Windows SLO aggregate was written. | New bounded bridge-stage and launcher failure diagnostics retain the missing admission/response/route evidence. They do not choose a production correction, turn continuation into native allow, or relax limits. A returned earlier measurement function is not proof that its gates passed. |
| Daemon edge, `35233473122` | Contracts, low-descriptor, Linux, macOS and Windows jobs passed; optional soak skipped. | This validates its actual source/lifecycle workload, separately from the failed installed launcher/source matrix. |
| Windows resident, `35233473530` | The job passed 13 FFI tests, 45 Job CPU tests including immediate-exit/nested witnesses, 22 related resource/fixture tests, locked Rust checks and four authenticated resident tests; two additional platform cases skipped. | Actual cumulative exited-child CPU and the tested Windows ownership/lifecycle assertions have evidence. They do not qualify installed launcher latency, every resource workload or a production native benefit. |
| Package component, `35233473461` | All ten phase/validation/registry workers passed. The overall workflow still failed on two frozen-baseline Composer coverage failures and 12 censored baseline cardinality workers. | Retain completed comparisons and failures by route. A bounded residual-origin diagnostic projection is prepared; the 82–86% unnamed calling-thread share has not yet been classified by an actual new run. No parser/native boundary is selected. |
| MCP component, `35233473439` | The workflow and both public/encrypted uploads succeeded: 30 workers and all 10,080 calls completed without call failures. | Preserve the independent source/artifact identity and earlier failed finalizer. This does not broaden the measured release decision into installed, cross-platform, remote-service or complete lifecycle qualification. |
| Installed Claude experiment, `35233552830` | All 20 jobs failed before measurement: 15 POSIX jobs at interpreter alias admission, five Windows jobs in journal/archive contracts. | The builder now prepares and uses the canonical private interpreter behind admitted uv aliases. Windows evidence now compares path, descriptor and inventory in one handle metadata domain. Both fixes await actual next-CI validation; there is no optimized-Python/native launcher comparison yet. |
| Indexed qualification, `35233473603` | Attempt 1 was cancelled during build by an unrelated label event. Attempt 2 executed three POSIX builds and collection despite the Windows build/export failure: all four pair jobs failed, Linux and Mac ARM candidate Ollama/Builder scenarios passed, Mac Intel Builder passed but enabled-control Ollama readiness failed at the original 400 ms limit, and Windows lacked its bundle. Four aggregators failed. Artifact transitions skipped. | Unique run/attempt concurrency prevents unrelated labels or later pushes cancelling retained work. Windows evidence metadata correction addresses the observed unchanged-file rejection. Actual POSIX failure logs and resolver reports determine the next correction; partial scenario success is not paired qualification. |

The Mac [source-bridge diagnosis](macos-source-bridge-diagnostics.md) records
one refused raw-edge call per case: 30 ms with 2,938 ms remaining on ARM, and
108 ms with 2,927 ms remaining on Intel. Both client contexts were
`not_recorded`. This does not establish deadline exhaustion. The fixture now
observes actual status, snapshot/envelope, client, decode and receipt boundaries
with fixed labels and no extra authority I/O or retries. Observer errors remain
finite partial diagnostics; overlapping observers do not wait or disturb patch
ownership. The [Windows launcher diagnosis](windows-installed-launcher-diagnosis.md)
similarly adds the previously missing response/route evidence without asserting
that home resolution or a particular native failure caused the refusal.

The attempt-2 POSIX pairs retained their actual failing boundaries. Linux
baseline completed 386 daemon cases and 26 registered cases before the next
registered case failed reviewed-output digest equality. Both Mac baselines
stopped in daemon construction at `socket.getfqdn`; candidate arms reached
real daemon cases before `native_post_tool_unavailable` with no native result.
None supplies a completed timing comparison, and availability continuation
cannot count as native-evaluated allow. These observations guide the next
bounded witness; they do not establish an underlying runtime cause.

The [registered-host fixture correction](registered-host-workspace-fixture.md)
addresses a concrete context omission in Linux's frozen-baseline Codex benign
1 MiB case: global registration and the payload both omitted workspace, while
the real host should supply `cwd`. Both benchmark arms now receive the same
actual host context; explicit conflicting context remains intact. Source
tracing supports this narrow correction, but no corrected installed result is
claimed. It does not explain other candidate, Windows or macOS failures.

The [raw UTF-8 fixture](installed-raw-utf8-fixture.md) now sends exact malformed
bytes through four registered launchers using the existing containment
primitives. It retains private capture prefixes and separate delivery, exit,
I/O and native-route facts. These untimed observations remain unqualified until
actual platform codec/delivery expectations are reviewed; the original sixteen
text cases and their acceptance gates remain unchanged.

Linux's d0e legacy soak retained 100,000 responses, 250,000 receipts, zero request
errors, 20,128 error-free health checks and 5.5121% sampled RSS growth. Its
495.90 ms p95 and 583.38 ms maximum passed that workload's 4,500 ms ceiling.
That success does not meet or replace the PRD's 50 ms installed-priority target
or mixed-mutation requirements.

The original 24-request storage burst passed its unchanged 1.75-second client,
1.6-second response and 0.5-second health assertions. The older 91-pass/one-failed
backfill run remains in its source investigation; it is not a new failure in the
d0e pytest matrix, whose 96 jobs all passed. Exact next-head validation remains
RSP-134, and complete duration evidence must still be restored. Earlier source
suite totals overlap and must not be summed into a new test denominator.

## What the measurements support

The [actual package phase report](PACKAGE_PHASE_CI_EVIDENCE.md) now establishes
one parse, one evidence batch and one immutable index construction per tested
route, with exact semantic/evidence commitments matching separate uninstrumented
validations. Signed-bundle admission occurred before the measured route; zero
in-route RSA/verification calls do not erase that admission cost. Six profiled
candidate invocations cover two original inputs, and two separate explicit npm
`*` workers exercise real resolution/protect behavior using synthetic transport
bytes. Each makes 100 GETs and emits 100 packages/evidence rows, selecting
lower-risk 2.0.0 over the higher-risk 1.0.0 record. Bare `latest` and the kernel's
None-version highest-risk lookup remain distinct unchanged boundaries.

Only about 14–18% of exclusive calling-thread CPU is assigned to the finite
phase names; 82–86% is measured but unnamed. The parser's inclusive share is
4.65%/6.48% in the instrumented protect/evaluator profiles, with larger bundle
reconstruction and evidence spans. Inclusive spans overlap and are not additive,
and profiler perturbation prevents a formal native-speedup bound. The prepared
fixed-origin partition and encrypted top-50 projection retain the same attempts
and interval; they are a collector extension, not newly observed phase results.

The d0e uninstrumented protect comparison at D=B=1,000 retains five independent
alternating pairs: median wall 5,828.384 → 215.214 ms and CPU
4,571.890 → 195.921 ms; median paired reductions are 96.2766% and 95.7711%.
All 72 cardinality offers remain accounted for: 36 candidate completions,
24 baseline completions and 12 baseline censored workers. Format preflight
retains 20 candidate and 18 baseline completions plus two baseline Composer failures.
These intervals exclude imports, setup/admitted bundle and postvalidation;
they are source-route diagnostics, not installed CLI tails or a Rust comparison.
RSP-050 retains its documented kernel/censored-baseline limitations; RSP-054
still needs a justified port/no-port decision against the original 30% criterion.

The [MCP selection decision](mcp-native-selection-decision.md) retains optimized
Python for release 3.2. Its corrected second-checkpoint v2 evidence supplies
five independent pairs, 30 workers, 240 sessions, 10,080 calls and 80 complete
warm resource windows. For catalog1000, wall ratio 0.5380 has 95% interval
0.5288–0.5648 and parent CPU ratio 0.4468 has interval 0.4380–0.4770. Smallest-
catalog intervals cross one; sampled peak memory increased. Ten lifecycle
records remain incomplete, with 16 missing samples and descriptor errors in
nine records. These facts retain their second-checkpoint identity even though
the newer MCP workflow passed.

The separate successful d0e MCP cohort reports large-catalog wall ratio
0.533961 (95% interval 0.508358–0.555922) and mean parent CPU ratio 0.444666
(0.419106–0.468266). All 80 warm windows are complete with 129–326 samples and
zero missing readings. All ten lifecycle windows remain incomplete, with
18 missing samples and nine descriptor-error rows. Its 182-file encrypted
archive is retained; no new decryption test is claimed. These results remain
bound to d0e and are not pooled with the earlier decision cohort.

Pure fingerprint/classification residuals are about 0.130/0.173 ms of exclusive
thread CPU per invocation, beside larger store/composition/persistence spans
and an unchanged approximately 5.11 ms ordering barrier. This supports the
measured release deferral of RSP-104/105/107 and RSP-108's recorded full-proxy
decision. It is not a failed Rust benefit test, a formal upper bound or evidence
that installed targets are met. RSP-106 remains separate.

The [installed baseline ranking](installed-launcher-baseline-ranking.md) is
now explicit: one retained Windows block contains 80 actual registered Claude
and Codex invocations across four routes and three load/start conditions.
For the same PostToolUse c16 workload, observed p50 is 3,233.690 ms for Claude
and 4,065.828 ms for Codex. Serial PostToolUse differs by only 1.319 ms; the
ordering changes by event/load. This descriptive ranking does not show Claude
as uniformly most expensive, isolate launcher-only CPU, supply qualified tails
or fill missing platforms/surfaces. No installed usage-frequency weighting exists.

## Source ready for the next execution

The [nonpriority command-tail companion](nonpriority-installed-tails.md) is now
integrated: 16 distinct registrations × four targets × five pairs = 320 full
collection jobs, plus four aggregators. Each route retains its original
1,000-observation minimum. Normal smoke and scheduled runs do not trigger this
plan; full PR collection requires both `rust-performance-qualification` and
`rust-nonpriority-tails`. Start with an explicitly selected route smoke. The
64,000 runner-minute aggregate job-limit reservation is a capacity bound, not
measured spend or duration. No observations are supplied by source wiring.

The installed Claude experiment stays default-off in production. Its admitted
uv-alias and Windows evidence corrections need actual execution before any
launcher benefit can be assessed. The independent artifact-transition scenario
retains exact indexed wheels, candidate-locked dependencies and a third
installation: five stopped phases, ten registered cases, unchanged 180-second
command caps. It skipped in the observed qualification attempts. Stopped
replacement cannot qualify live update, signing, frozen packaging or changed-
program rollback.

Next, publish the coherent reviewed source and inspect actual admission, evidence
retention and diagnostics before selecting another production fix. Restore
complete required CI and authenticated quality-gate dispositions; classify the
retained POSIX pair/scenario failures; run the bounded package residual
projection and the repaired opt-in Claude experiment. Execute selected route
smoke before deliberate full indexed/nonpriority collection. Preserve five
independent alternating pairs, original sample/resource minima, all offers and
failed observations. Choose remaining native work only from comparable
optimized-Python/native evidence at its real route boundary.

Complete exact signed/frozen artifacts, first-hook update/rollback, mixed offered
load/mutation/recovery and durable receipts before release acceptance. Historical
first-checkpoint Linux 100,000-request/250,000-receipt soak evidence retains its
528.06 ms p95; it does not meet or replace the 50 ms priority target. Foundation
PR #2951's approvals and PR #2954's separate writer do not approve this head.
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970) remains the
owned publication targeting `release/3.2`; independent latest-push code-owner
approval, protected merge, canary and release are incomplete.
