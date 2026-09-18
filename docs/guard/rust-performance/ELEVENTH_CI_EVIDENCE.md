# Eleventh CI evidence

This report binds published source `23bef02c5edd2fb24dbfec768a9dbd5e80c2b31d`,
tree `e3fa69336ff37d8e91add1ecd0a5a89b5cca35d9`, and tested merge
`fb6112dd964df5b88e90e43e04229a4d6914f7e6`. Independently retrieved GitHub Git
commit metadata confirms that the merge has the same tree and parents release
base `4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the published head.
The preceding implementation checkpoint is
`224cca37a57ea4e068c0c586d2354c15abd887f0`, tree
`7c4322a4c243c900bedf1365aa2194d888023f7b`. Its parent is the tenth publication
`095074cda6a751ffaf12b070ecc46a3091f12471`. These identities remain distinct.

The exact terminal census, observed at **00:16:45 UTC on 2026-09-18**, is
**42 workflows: 37 success and five failure**. Main CI, Installed Claude,
Package Python rebaseline, Native wheel CI and Native performance qualification
fail. Every original workflow is terminal; each failure remains recorded at
its actual scope.

All 42 original workflows are first attempts created at **23:42:00–01 UTC on
2026-09-17**. No supplemental label events or reruns are pooled into this cohort.
The [tenth report](TENTH_CI_EVIDENCE.md) and earlier evidence remain unchanged.
The [manifest](evidence/ci-23bef02c/manifest.json) records exact source identities,
workflow/job metadata, finite public observations and component commitments.
Passing source checks or bounded smoke does not establish full release
qualification, activation, signing or live rollback.

## Main CI, security and ownership

[Main run 35287995154](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995154)
finishes with **106 successful, two failed and six skipped jobs out of 114**.
All 96 pytest shards finish: **95 pass and one fails**. The other failed job is
the dependent CI aggregate `105425941491`.

Shard 60, job `105424751569`, retains **237 passed, one failed and one skipped**
in 169.84 seconds. The failed case is
`test_guard_daemon_claude_hook_endpoint_accepts_guard_home_symlink_alias` at
`tests/test_guard_surface_server.py:2158`. It receives the expected
`UserPromptSubmit` event plus the availability fields `continue=true`,
`policy_action=allow` and `reason_code=daemon_hook_process_not_ready`, instead
of the expected normal response shape. The request therefore reached admitted
hook handling; the log does not identify which readiness condition emitted the
fallback. Daemon startup already requires initial capacity, and a transient
evaluator failure can emit the same reason. Neither a symlink defect, a missing
initial wait nor a specific production cause is established.

The later [test-only correction](symlink-path-admission-test.md) uses the
neighboring deterministic runner-capacity/reviewer seam while retaining real
authenticated HTTP, canonical path admission, the original 200/normal-shape
assertions, and an exact one-call check of canonical guard home, harness,
workspace and payload. Thirteen selected existing endpoint tests pass with
102 deselected; Ruff check/format and diff checks pass. Independent source
review is clear. Local commit `dcffe48ca9` changes the fixture and its explanatory
note; shipping runtime and benchmark instrumentation remain unchanged. This
later source check neither reclassifies the failed eleventh test nor identifies
the original readiness emitter.

Main Windows `105424489426` passes **246 tests with five skips**, two Codex
process-tree cases with fourteen deselected, and the original packaged
bootstrap regression in **51.72 seconds**. This is separate from the installed
launcher preservation test and does not assign a cause to the ninth bootstrap
failure. Scheduling-sensitive, compatibility, quality and dashboard checks pass.

Duration aggregation `105425942417`, `sonar-guard` `105425942552` and Sonar
`105425943238` skip after the dependency failure. **There is no eleventh Sonar
analysis or quality-gate result.** The tenth analyzed gate failure remains
historical. No custom Sonar lookup or disposition is performed.

The Main artifact API contains **194 unique, unexpired artifacts** across
100+94 entries: all **96 coverage and 96 duration artifacts**, plus the dashboard
bundle and shard plan. No aggregate duration artifact is present. These are
paginated API commitments, not independently downloaded artifact bytes.

[Security run 35287995023](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995023)
passes all four jobs: Gitleaks, Semgrep, Trivy and workflow policy. Rust authority
ownership `35287994893`, job `105424487916`, and decision-critical I/O
`35287995146`, job `105424488940`, also pass. These successes preserve their
source-validation scope.

## Scanner smoke and dormant pilot

[Scanner run 35287994957](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994957)
passes all three jobs and actual-binary correctness: **four Rust and 192 Python
tests**. All **24 planned observations are offered and complete**, with zero
failed or unoffered work. Twelve native observations each report four native
files and zero fallback. The four arm/cache cells contain six observations
each; preflight and final identity verification pass. All observations share
one complete-result digest and one stdout digest.

Two independently downloaded public ZIPs match GitHub size/SHA-256 and retain
**3,530 bytes and four members**. Summary/receipt retention bindings match.
Encrypted artifact `10525470182` is metadata-only here; its producer receipt
reports 113 files. No ciphertext download, authentication or private drain
recomputation is claimed. One independent run does not meet five-run selection
or replace the eighth 840-attempt experiment. Comparison is null, benefit and
installed qualification false, and production selection remains Python.

[Dormant run 35287994980](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994980)
passes all four platforms. Each passes the bound source fixture, **32 Python
and 17 Rust tests**, and explicit feature-off/on smokes. Capability and command
presence match the feature state; registration remains unchanged and installed
qualification false. These counts are parsed from complete decoded job logs;
no installed artifact qualification is inferred.

## Installed Claude and Windows preservation

[Installed Claude run 35287995010](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995010)
finishes with **19 successful jobs and one failed job**. All five Windows
contract suites pass **108 tests with six skips** before wheel construction.
The revised native-descriptor preservation oracle therefore executes successfully
on Windows; strict legacy-key rejection remains asserted. The historical
failed invocations retain their original outcomes. The
[Windows evidence note](windows-discovery-producer.md#eleventh-attempt-native-preservation-passes-launcher-ambiguity-retained)
separates preservation from the later launcher results.

Across all 20 jobs, **1,760 planned = 1,750 attempted + 10 unattempted**;
**1,749 completed + one failed = 1,750 attempted**. All fifteen POSIX jobs and
Windows runs 0–3 complete their 88 requests. Windows run 4, job `105424489054`,
completes 77 of 78 attempted requests. Its optimized-Python `PreToolUse` sample
17 returns allow and exit status 0 after 5,249.2177 ms, but `native_resident`
increases from 77 to 79. The unchanged route gate rejects this ambiguous delta;
the unique route and cause of the extra evaluation remain unknown. This is not
an established retry, ACL defect or native decision failure.

The 19 complete reports retain **1,520 timed observations**. Authenticated
recovery of the failed run retains **70 additional observed durations**, of
which 69 accompany completed requests and one accompanies the failed attempt.
All four partial timing batches remain failed/incomplete, with no accepted
latency aggregate. The total 1,590 observed durations is distinct from 1,589
completed timed requests and 160 completed preflights. Registration restoration
is recorded. The failed-run public summary matches its authenticated private
summary; two ZIPs and the six-member archive commitment were verified. The
manifest preserves that narrow recovery scope, without implying independent
recovery of all twenty jobs or changing their qualification flags.

## Native-client attribution

[Native-client run 35287994878](https://github.com/hashgraph-online/hol-guard/actions/runs/35287994878)
passes all four targets. Each target passes 125 Python and nine runtime Rust
tests; Windows additionally passes two actual companion tests. Each records
40 offers and 40 completions, zero failed or unoffered work, one helper, 42
client records, 43 resident records and 40 successful hook socket opens. The
total is **160 offered and completed requests**.

The [profile evidence](native-client-profile-eleventh-ci.md) independently
verifies four public ZIPs and their exact summaries. Producer receipts report
five encrypted files per target. **No eleventh ciphertext authentication or
private raw-span recomputation is claimed.** The tenth authenticated and
independently recomputed attribution remains separate. Complete diagnostic
capture does not establish a release latency win, activation or full resource
qualification.

## Installed wheels and indexed qualification

[Native-wheel run 35287995035](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995035)
finishes with Linux and both Macs successful, Windows failed. The
[wheel report](NATIVE_WHEEL_ELEVENTH_CI_EVIDENCE.md) preserves seventeen finite
JSON reports reconstructed from complete decoded GitHub logs. Its archive
identities are API/upload metadata; no wheel ZIP, executable or ciphertext
bytes were independently downloaded for that report.

Linux and both Macs pass all fourteen bounded smoke gates. Windows passes
thirteen, including c16 p99 665.333 ms, and fails only c64 conservation:
**64 responses, zero transport errors = 37 resident + 23 explicit overloads +
four unclassified responses**. The coarse overloaded count of 27 is a different
projection from 23 explicit overloads. All 146 SLO observations remain, while
route counters total 142. The raw-bridge None witness records zero None returns;
no cause is inferred for the four unclassified responses. The Windows ordinary
probe accepts/processes all 21 receipts with zero drops/pending while retaining
one writer-failure counter; Linux and both Macs retain zero writer failures.

The corrected Darwin privacy assertion executes successfully: each Mac
prebuild suite passes 117 tests with one skip. These source-check results do
not reclassify the prior ARM failed invocation. All wheel SLO reports keep full
qualification false; their 1,000 ms smoke thresholds are distinct from the
release latency targets.

Linux soak completes **100,000 logical calls and 100,000 responses**, zero
errors, and **17,706 health checks with zero failures**, after preseeding
250,000 receipt rows. Each logical call permits the fixture's bounded transport
tries, so this is not an exact wire-request or native-decision count. It reports
p95 518.09 ms and maximum 585.38 ms against 4,500 ms; RSS grows from 619,708,416
to 636,317,696 bytes (**2.6802%**). Maximum threads/descriptors are 71/195, one
daemon PID remains stable, and the lifecycle includes the stopped marker.
Both soak flags pass. Passing this Linux soak scope does not qualify
all platforms, missing resource dimensions or full installed tails.

[Qualification run 35287995187](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995187)
finishes with **14 successful, eleven failed and two skipped jobs out of 27**.
All four immutable builds pass. The
[qualification report](QUALIFICATION_ELEVENTH_CI_EVIDENCE.md) keeps ordinary
indexed arms, diagnostic identity/configuration observations, settings scenarios
and nonpriority tails separate.

Three indexed arms complete: Linux baseline and candidate, plus ARM candidate.
They retain **408 numeric observations** in three complete blocks; five arms
fail with no partial observed numeric block values. Across all corpus-reached
arms, **1,598 normalized cases and 228 registered validations complete**.
Both frozen Mac baselines fail in daemon construction. Intel candidate completes
26 normalized cases before a later fixture-start deadline; Windows baseline
completes 386 normalized and 42 registered cases before unavailable setup fails,
while Windows candidate completes 28 normalized cases before a request-wrapper
failure. These partial corpus counts do not become complete arm comparisons.
Failure frames or sampled stacks do not establish a narrower production cause.

The early diagnostic placement independently permits **18 validated cold hooks
and eighteen separate prepared/warm hooks** across six arms, including all four
candidates. Each candidate also completes eight instrumented phase hooks. Across eight
finished candidate phase groups, the 32 configuration-binding windows retain
their zero-call observations. Both frozen
Mac baselines retain partial cold preparation with three planned cold hooks unoffered
per arm. These measurements do not reclassify later failed indexed collection,
prove an implementation speedup or supply complete process-tree resources.

All three completed arms still retain failed load and mixed, priority-approval,
priority-input and registered-surface gates. The raw-UTF8 observations stop at
registration; that failure is separate from the diagnostic's intentionally
unqualified design. Linux baseline/candidate steady-state resource windows
retain 19/13 samples against the original minimum of 30. ARM retains ten samples
and unavailable general tree CPU; missing CPU is not zero. Failed work,
generator drops, overloads and unavailable resource samples remain in the
qualification report rather than being removed from denominators.

Linux, ARM and Intel settings scenarios each pass all 22 native cases and
Builder. Windows completes twelve native cases before an updated-control
readiness miss at 406 ms; Builder passes. The 400 ms readiness gate is unchanged.
The previous cohort's different scenario outcomes remain separate.

Nonpriority tails complete six of eight arms: **twelve of sixteen planned timed
observations plus twelve separate preflights**, with four planned frozen Mac baseline
timed hooks unoffered. Authenticated failed-Mac diagnostics retain the
`getfqdn`/HTTP-server constructor boundary before corpus or numeric offers.
Linux and Windows pair/aggregate comparisons complete; both Mac comparisons
remain incomplete. Even the passing two-sample smoke comparisons keep sampling,
ordinary-scope and full qualification false.

Qualification custody verifies **24 ZIPs, 6,950,754 bytes and 86 members**,
including four small build-provenance artifacts. All four indexed archives are
authenticated and cover 127 private members. All four tail ciphertext hashes
are verified; only the two failed Mac tail archives are authenticated/recovered,
covering sixteen private members. Complete numeric commitments and recovered
journal sequences agree. Linux/Windows tail ciphertexts remain undecrypted;
these scoped recoveries do not imply recovery of every artifact in the cohort.

## Package and MCP components

The [package/MCP report](PACKAGE_ELEVENTH_CI_EVIDENCE.md) binds four independently
verified public ZIPs with fourteen members and twenty retained public files. Package run
`35287994987` fails its format and diagnostic jobs while phase attribution
passes. All three jobs pass 132 correctness tests. Cardinality retains
**36 candidate and 24 baseline completions plus twelve censored baseline
workers**; formats retain **20 candidate and 18 baseline completions plus two
frozen Composer package-count failures**. The unresolved pair, five independent
protect pairs and ten phase/registry workers all complete. Candidate
`complete-v3` and frozen `complete-v1` remain distinct.

For the five protect pairs, baseline/candidate median wall time is
8,891.829135/322.712215 ms and process CPU is 7,764.455/315.085 ms. Median paired
reductions are 96.3795421272% and 95.9479804460%; these are separate estimators
from ratios of arm medians. Guard-Python exclusive origin medians are
41.4738694% protect and 52.9679542% evaluator. These source-route observations
do not replace the earlier keep-Python decision or establish a Rust comparison.

MCP run `35287995008` passes 126 correctness tests and completes **30 workers,
10,080 outcomes and zero failures**, with 48 groups, 240 run/trace summaries,
364 phase rows and eight five-block comparisons. All 80 warm resource windows
complete with 132–341 snapshots and zero missing samples. Ten separate
lifecycle rows remain incomplete, retaining sixteen missing samples and 38
descriptor denials across all ten rows. Warm completeness does not repair those
lifecycle gaps. The 331 package and 182 MCP encrypted-file counts are producer
receipts; no eleventh component ciphertext recovery is claimed.

## Release and custody boundaries

PyPI `35287995112` passes authorization and Build + Verify, then skips all
fourteen downstream release jobs. Desktop Linux `35287994984` and stable feed
`35287994946` each pass validation and skip publication. No release, canary,
signing, live update or rollback follows from their workflow names.

The manifest distinguishes API metadata, finite JSON reconstructed from decoded
logs, independently verified public ZIPs, ciphertext commitments and narrowly
authenticated recoveries. Each scope retains its own denominator. Producer
receipts alone are not private authentication, and failed or absent work is not
replaced by a later passing source check or changed test fixture.

No original task definition, dependency, semantic rule, deadline, sample minimum
or acceptance threshold changes in this report. Later current-ledger decisions
must retain the literal acceptance scope and the remaining qualification gaps.
