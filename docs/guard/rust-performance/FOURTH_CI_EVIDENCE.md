# Fourth finalization CI checkpoint

This report records candidate `2ebb01ff356101aea8d658ce639fe2c87188bd0d`,
tree `1c41bef1979ead9e50ee406a60505ce6894aa461`, on
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970).
The release base remains `4b89e0d2d496a85f04922b2e019a4aea15326bb9`.
GitHub's PR merge `d769f9722d34e98cadea058e01575b48ab24f053` has that base and
candidate as parents and the same tree. Explicit candidate checkouts and
ordinary merge checkouts remain distinct build identities despite equal trees.
Main was reverified as `05fa4760df8401b9710bf098adb4fbb2dc4ff389`.

The terminal API snapshot on 2026-09-17 contains **40 workflow instances:
35 successful, five failed, none active or skipped**. Job-level skips are
separate. The [manifest](evidence/fourth-ci-2ebb/manifest.json) records every
run/attempt and hashes the retained public evidence. The
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md) and
[third](THIRD_CI_EVIDENCE.md) checkpoints remain separate, immutable cohorts.
Later corrections do not inherit this checkpoint's results.

**Installed performance qualification and release remain incomplete.**

## Required source and platform checks

| Scope | Actual result and practical limit |
| --- | --- |
| [Main CI](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794078) | 114 jobs: 106 successful, six skipped, two failed. 95 of 96 pytest shards passed. Shard 54 failed one package attribution test; the aggregate CI job failed its dependency gate. Duration-manifest, Sonar and Sonar guard jobs were skipped. |
| [Security](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794239) | All four jobs passed. Actual Gitleaks v8.24.2 completed all 15 fixture controls and scanned the release-base-to-candidate range: 1,259 commits, no leaks found. |
| [Windows resident](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794142) | Both jobs passed. These are the workflow's actual FFI, Job CPU, resource and authenticated resident tests, not full installed performance qualification. |
| [Daemon edge](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794163) | Five jobs passed: contract, low-descriptor, Linux, macOS and Windows. The optional soak was skipped. |
| [MCP component](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794173/job/105268400723) | The source-stdio job and all its steps passed. This checkpoint records completion only; it does not pool or recompute the earlier measured MCP selection cohort. |

Main shard 54, job `105268872659`, retained 227 passing tests and one failure:
`test_actual_instrumented_protect_preserves_oracle_and_single_parse` raised
`package_phase_total_invalid`. The prior validator did not retain which
non-residual total was negative. An isolated local coverage execution passed;
the original negative value and cause remain unknown. The later test correction
uses the real fresh worker CLI, matching production attribution isolation, and
retains the signed-fixture, oracle, single-parse, evidence and private-journal
assertions. Negative totals remain rejected, with a bounded field/value witness.
That source correction requires a new Main CI result.

All **96 distinct duration artifacts**, indices 0–95, are present, nonempty
and unexpired in the complete artifact enumeration. Shard 91 now uploads its
report successfully (artifact `10505975276`, 7,996 bytes). The
[retained job/artifact facts](evidence/fourth-ci-2ebb/main-jobs-and-duration-artifacts.json)
establish presence. Their contents were not all independently downloaded, and
the aggregate duration-manifest job was skipped, so aggregate validation is
not claimed. The earlier 42 individually reviewed Sonar dispositions remain
unapplied; no new Sonar result exists for this checkpoint.

## Installed native-wheel failures

[Native-wheel run 35240794111](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794111)
passed on macOS ARM. Linux, Windows and macOS Intel failed.

| Target / job | Retained failure |
| --- | --- |
| Linux / `105268400561` | The c16 wave had 16 resident routes and zero errors. At c64, all 64 responses returned: 48 delivered allows and 16 explicit overloads. Engine route counters recorded 32 native-resident and 16 native-fail-safe decisions; the native-overload counter delta was zero. Resident count, overload route and conservation gates failed. |
| Windows / `105268400450` | One ordinary 1 KiB safe case continued through native unavailability; resident share was 0.97619 and safe-corpus coverage failed. At c64, 35 allows and 29 overloads differed from 34 resident routes plus one fail-safe route; native-overload count was zero. |
| macOS Intel / `105268400552` | The c16 maximum was 1,014.141 ms against the unchanged 1,000 ms adapter gate. Its 16 resident routes and c64 conservation (36 resident plus 28 explicit bypasses, zero errors) were otherwise intact. |

The [Linux](evidence/fourth-ci-2ebb/linux-installed-slo.json),
[Windows](evidence/fourth-ci-2ebb/windows-installed-slo.json) and
[Intel](evidence/fourth-ci-2ebb/intel-installed-slo.json) reports retain their
original gates and measurement boundaries. A delivered allow is not evidence
of a native-evaluated allow. These observations do not prove a counter bug,
pool-sizing cause or scheduler defect. The later
[capacity-only failure witness](native-capacity-none-witness.md) captures
bounded existing failure facts on original `None` returns. It adds no request,
retry, deadline or authority operation, and explicitly treats unchanged
thread-local failure codes as potentially stale. Its callbacks remain inside
the original failed-request budget.

## Immutable qualification and installed launcher experiment

[Qualification run 35240794284](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794284)
completed with eight successful, nine failed and four skipped jobs. All four
immutable-wheel builds passed, including Windows bundle export. Candidate
Ollama/Builder scenarios passed on Linux, macOS ARM and Windows. The Windows
scenario completed all 22 native cases with their receipt/control checks.
Intel completed two cases, then enabled-control readiness took **403.453 ms**,
exceeding the unchanged **400 ms** barrier. Receiving a later generation does
not make that timing pass. The
[finite scenario and job evidence](evidence/fourth-ci-2ebb/qualification-jobs-and-scenarios.json)
retains those results.

All four indexed pair jobs and all four aggregators failed. Optional
transitions and nonpriority collection were skipped in this smoke plan.

- Linux and Windows failed pair recording because the validator compared a
  Cargo distribution triple with the runtime's `ARCH-OS` label. Linux's frozen
  baseline worker completed and its candidate remained unattempted. The
  [exact association correction](qualification-target-identity.md) preserves
  both identities and every artifact/dependency commitment. The old manifests
  remain failed; no completed pair is retroactively manufactured.
- Both Mac frozen baselines timed out during daemon construction in
  `socket.getfqdn`. The retained evidence does not establish an application
  correction or justify changing the frozen baseline.
- ARM's candidate completed 386 daemon and 62 registered corpus cases, then
  failed the c16 Codex PostToolUse stdout schema. All 16 invocations were
  offered; only three returned latencies were retained before the batch failed.
  The rejected stdout itself was not retained. The validator's failure branch
  establishes unexpected top-level fields after a valid PostToolUse event,
  but not their exact names or the underlying native cause.
  The later [failure-only stdout witness](fourth-installed-failure-observations.md)
  retains fixed key-presence and outcome facts while preserving the original
  rejection and every accepted schema.
- Intel's candidate failed a Pi source-digest-mismatch case. The stage witness
  observed returned bytes containing an error object, rejected before receipt
  validation, with an admitted runtime, positive snapshot generation and about
  2,980 ms of original budget remaining. Its reason was mapped to `other`.
  That does not identify a supported production fix.

The [Claude experiment](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794149)
ran all 20 jobs. Each reached registration preparation and failed the same
manifest/runtime target comparison. None offered a measurement request.
All 15 POSIX jobs passed 48 contract tests with one skip; each Windows job
passed 43 with six skips. All 20 encrypted one failure-summary file. None
reached measurement journals, and the final retention gates correctly failed.
The [complete cohort and correction](claude-launcher-target-identity-diagnosis.md)
bind separate manifest and capability targets while independently enforcing
the compiled Rust architecture/OS/ABI. The prior interpreter and Windows
archive-admission failures did not recur in this cohort; installed measurement
retention, parity and native benefit remain unproven. Production activation
remains off.

## Package residual evidence and decisions

[Package run 35240794034](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794034)
failed its overall diagnostic/cardinality finalization, while phase collection,
the five-pair plain hot-route step and both evidence uploads succeeded.
All ten phase workers completed with semantic parity. The public phase artifact
is `10505750914`; encrypted artifact `10505720965` was authenticated and
recovered as 34 private files with private filesystem permissions.

The disjoint origin projection assigns median exclusive calling-thread CPU to
Guard Python at **37.31% for protect and 51.75% for evaluator**, JSON Python at
5.37%/6.44%, byte primitives at 8.75%/11.66%, and other C primitives at
17.60%/15.38%. Pydantic Python/core had zero observed calls in both scopes.
Repeated validation, normalization and result/identity construction remain
material. Instrumented fractions establish attribution; they do not establish
a Rust speedup, an attainable upper bound or a native benefit failure.
The [source-bound package decision](package-native-selection-decision.md)
retains optimized Python and selects no package Rust activation for this
release. Its five uninstrumented protect pairs at D=B=1,000 record baseline
wall/CPU medians of 8,785.843/7,739.458 ms and candidate medians of
327.344/319.842 ms; median paired reductions are 96.2752%/95.8662%. These are
local source-route comparisons, not installed tails or a Rust benefit. All
36 candidate cardinality and 20 format cases completed; 12 baseline cardinality
attempts remained censored and two baseline Composer cases failed. The decision
requires any future native candidate to include the coarse immutable
model/identity/result boundary, preserve semantics and beat optimized Python
under the original 30%/5% gate. No unbuilt native implementation is called a
failed benchmark. The exact 15-file manifest and six authenticated profile
commitments were independently checked, along with the reported medians.

This checkpoint supplies no completed full performance comparison. Corrected
target admission, fresh-worker testing, failure witnesses and bounded follow-up
experiments need new execution. Signing/frozen identities, full installed
tails, live update/rollback, mixed-load evidence, final required CI and
independent latest-push approval remain release gates.
