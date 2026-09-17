# Tenth CI evidence

This report binds published source `095074cda6a751ffaf12b070ecc46a3091f12471`,
tree `04d79da9c1cf212cce263c202bfdd5b4350007e3`, and tested merge
`9e85de6f42910785e7ba4b53198ddcc05672607c`. Independently retrieved GitHub
commit metadata confirms the merge has that same tree and parents release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the published source.
The implementation checkpoint is `6da76bc591d7bb9c498918673305d7074b2b9b60`,
tree `d1391c030154398144a549fd4685facddd69e937`; source, publication and merge
remain distinct identities. Frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` remains unchanged where used.

At **2026-09-17 23:13:35 UTC**, all 42 original workflows are terminal:
**37 successful and five failed**, with none skipped. Main CI, native-wheel CI,
native performance qualification, the installed Claude experiment and the
package component workflow fail. Their component/job outcomes remain distinct
below; a passing Linux soak or correctness suite does not override another
failed gate.

All original workflows are first attempts created at **22:40:30–31 UTC on
2026-09-17**. There are no supplemental label events in this cohort. The
native-client diagnostic is one of the original 42 workflows, unlike the
separate ninth label-triggered run. Historical failures are neither pooled
with this cohort nor replaced by later source corrections.

The [manifest](evidence/ci-095074cd/manifest.json) retains the census, source
proofs, bounded job/artifact metadata and commitments to the component reports.
The [ninth report](NINTH_CI_EVIDENCE.md) remains unchanged. Full installed
performance qualification, production activation and release acceptance remain
incomplete.

## Main CI, security and ownership

[Main run 35283194145](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194145)
finishes with **110 successful, one failed and three skipped jobs**. All
**96 pytest shards pass**, including the two shard positions that failed in
the ninth cohort. Aggregate CI `105411714386`, duration aggregation
`105411714393` and `sonar-guard` `105411714407` pass. Windows compatibility
`105409585814` also passes; it is separate from the installed Claude experiment's
child-security assertion failures.

The sole failed job is ordinary Sonar `105411736272`. Its decoded log records
analysis success at **22:54:09.668 UTC**, execution success at **22:54:13.851 UTC**,
then a failed quality gate at **22:54:25.217 UTC** and action exit 1. No new
numeric gate conditions were queried or inferred. This is a tenth analysis/gate
result; the ninth analysis was skipped. No custom Sonar lookup, disposition or
gate change was performed.

The Main artifact API lists **195 unexpired artifacts**, including all 96
coverage and 96 pytest-duration files, the aggregate duration result, dashboard
bundle and shard plan. This is exact paginated metadata, not independent
artifact-byte verification or private recovery.

[Security run 35283194263](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194263)
passes Semgrep, Trivy, Gitleaks and workflow policy. Decision-critical I/O
`35283194179` and Rust authority ownership `35283194264` pass. Windows resident
`35283193473` passes both jobs; daemon edge `35283193941` passes five jobs and
skips its separate soak. These successes do not supply installed performance
qualification.

## Scanner smoke and dormant source pilot

[Scanner smoke 35283193763](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193763)
passes all three jobs. Actual-binary correctness passes four Rust and 192
selected Python tests. It completes **24 planned/offered observations**, with
zero failed or unoffered work: twelve observations per arm, six per cache
state/arm. Every native observation reports four native files and zero fallback.
The same-source arms retain one complete-result digest and one stdout digest;
preflight and post-run identity checks pass.

Two bounded public ZIPs are independently downloaded and verified against
GitHub sizes and SHA-256: **3,520 bytes and four members** in total. Public
summary/receipt retention bindings match. Encrypted artifact `10523021329`
remains metadata-only; its producer receipt reports **113 files and 10,851,515
ciphertext bytes**. No ciphertext download, independent ciphertext hash check
or authenticated private recovery is claimed. Each state has one independent
run against five required, and benefit/installed/default-activation flags remain
false. This smoke is not pooled with the eighth 840-attempt full experiment.

[Dormant pilot 35283193507](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193507)
passes all four platform jobs. Each passes the bound fixture, 32 Python tests,
17 Rust tests, and explicit feature-off/on source smokes. Capability and command
presence match the feature state; registration remains unchanged and installed
qualification false.

## Installed Claude experiment and Windows preservation

[Installed Claude run 35283193497](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193497)
has **15 successful POSIX jobs and five failed Windows jobs**. The POSIX jobs
complete 1,320 attempts, including 1,200 timed observations. Windows fails the
existing child-preservation assertion before measurements, with 107 tests
passing and six skipping in every job. Its **440 planned attempts remain
unoffered** out of 1,760 planned overall.

| Platform | Native PreToolUse p95 range, ms | Native PostToolUse p95 range, ms | Series within 50 ms |
| --- | ---: | ---: | --- |
| Linux | 41.048–51.696 | 41.475–53.556 | Pre 1/5; Post 2/5 |
| macOS ARM | 119.325–188.568 | 136.322–179.435 | None |
| macOS Intel | 202.568–420.056 | 208.314–439.638 | None |

These are independently instantiated experimental registered-launcher series
with a prepared resident, not full release tail qualification. All successful
jobs restore fixture registration and keep production selection and qualification
false. Fifteen six-file encrypted producer receipts and five explicit
`no_observations`/zero-file receipts remain distinct. Their decoded public logs
and producer receipts do not establish archive ZIP verification or decryption.

The new failure-only Windows witnesses observe exact native descriptor bytes
unchanged across four stages and around the higher-level reads for three fixed
children, while the `GetSecurityInfo`-derived inheritance projection changes.
This observed representation difference does not establish undocumented API
internals. The later test-only correction compares the exact native
self-relative owner/group/DACL bytes, identity and payload, retains the
higher-level diagnostic, and preserves strict legacy-key rejection. No bits,
padding or fields are masked. It neither changes production provisioning nor
turns this failed tenth attempt into a pass; actual corrected Windows execution
remains separate evidence.

## Same-request native-client attribution

The [tenth native-client profile](native-client-profile-tenth-ci.md) is part of
the original cohort. All four target jobs in run `35283193998` pass actual
feature builds, 125 Python and nine Rust tests per target; Windows additionally
passes two companion capture/isolation tests. **160 hooks are offered and
completed with zero failures or unoffered work.**

Each target retains 42 client and 43 resident records, 89 journal rows, one
helper with clean EOF and two relay EOFs. Every selected request has one exact
authenticated frame-digest join and successful socket opening. All eight ZIPs
are verified and four private archives authenticate and recover. Owner and
independent review recompute all selected joins, record counts, final EOF
coverage and phase aggregates.

The resident edge and dispatch/encoding spans are separately observed on the
same request. They are inclusive instrumented wall spans: the edge includes
validation, snapshot acquisition, control fencing, evaluation and receipt
encoding. They are not pure matcher CPU, ordinary feature-off latency or a
connection-reuse comparison. Client response-read is not substituted or
subtracted to predict benefit. Full process-tree cost and the selection of a
transport alternative remain separate requirements.

## Installed wheels and indexed qualification

The [tenth native-wheel report](NATIVE_WHEEL_TENTH_CI_EVIDENCE.md) retains
**two successful and two failed platform jobs**. Linux and Intel pass all
fourteen smoke gates. Windows completes its corpus but fails the c16 latency
gate: **1,282.125 ms against the 1,000 ms smoke threshold**, with sixteen
resident responses and zero errors; its other thirteen gates pass. This
threshold is separate from the stricter release SLO and request deadlines.

ARM stops before its build: 111 tests pass, one fails and one skips. The privacy
test searches a serialized report for the PID text `321`, which also occurs in
a legitimate elapsed value `338.413213`. This source-proven assertion defect
is corrected separately; no ARM wheel, installed SLO or artifact is offered in
this invocation, and its failure remains recorded.

The three completed installed platforms each retain 21 default-auto resident
decisions and 146 SLO numeric observations. Receipt counts reconcile at 21
accepted/processed with no drops or pending records; Windows also retains a
separate writer-failure counter of **three**. At c64, Linux reports 63 resident
responses plus one explicit overload, Intel 39 plus 25, and Windows 42 plus 22;
each has 64 responses and zero errors. These normalized ingress checks do not
constitute 21 distinct registered-launcher executions or full release
qualification.

Linux's separate soak completes **100,000 logical calls and responses**, with
zero final errors and **17,367 health checks** without failure or transient
unavailability. Its p95 is **503.43 ms**, maximum **581.21 ms**, against 4,500 ms;
RSS grows **615,759,872 → 638,566,400 bytes (3.7038%)**, below its 50% limit.
Maximum threads/FDs are 71/199, one daemon PID remains stable, and the lifecycle
retains `start_requested`, `ready` and `stopped`. The 250,000 receipt rows are
preseeded. A logical call permits up to three transport tries, so this is not
an exact count of wire attempts or native authorizations. These lifecycle and
resource facts do not replace prior cohort outcomes.

Wheel evidence reconstructs thirteen complete public JSON values from exact
decoded-log spans. Artifact identities remain upload/API metadata; no wheel,
binary, artifact ZIP or private ciphertext download is claimed.

The [tenth indexed qualification](QUALIFICATION_TENTH_CI_EVIDENCE.md) finishes
**12 successful, thirteen failed and two skipped jobs out of 27**. All four
immutable wheels build. Five indexed arms complete **680 numeric values**:
both Linux arms, both Mac candidates and the Windows baseline. Both frozen
Mac baselines fail constructor `getfqdn` before numeric offers. Windows
candidate retains **66 partial values: 50 validated and sixteen returned but
unvalidated**. Those sixteen belong to its first registered Claude PreToolUse
c16 wave, whose route-count validation fails. The precise mismatch or
native/transport cause is unobserved; no timeout is inferred.

All six corpus-reached arms complete **2,316 normalized cases and 372 registered
validations**. Windows baseline's 55 declared source-reference denials remain
unsupported content review, not successful reviews. Only Linux completes both
indexed arms and a comparison; the one-pair smoke remains unqualified.

The new pre-constructor observer reaches those five completed arms, with **15
validated cold-lifecycle hooks and fifteen separate prepared-resident hooks**.
Its calls, ownership/phase boundaries, child exit, original startup and cleanup
outcomes, and retained private journals pass their completeness checks. The
interval begins after imports and private-journal admission, and ordinary
preparation may ready the resident before the first hook. It is not a cold
OS-cache/import measurement or exclusive identity cost. Linux candidate's
three hooks each reuse verified live proof and hash zero executable bytes;
preparation still performs four full validations plus one reuse. The other
observed platforms retain full validation. **Windows candidate reaches neither
identity scenario**, so this attempt does not complete the candidate's
four-platform cold-hook scope.

All five completed arms retain failed mixed, priority-approval, input,
raw-UTF8 and registered-surface scopes. The UTF8 registration interruption is
additional to its deliberately diagnostic/unqualified design. Windows candidate
does not reach those later scopes. c64 offered load conserves generator drops,
admitted failures, explicit overloads and native decisions separately; it does
not pass full load qualification. Darwin process-tree CPU remains unavailable
where ambiguous, and no platform/resource completion is inferred from numeric
block completion.

Settings/Builder scenarios pass 22 native cases each on Linux, ARM and Windows.
Intel completes two cases, then misses enabled-control readiness at **400.736 ms**
against the unchanged 400 ms deadline. A later cached revision is still
unacknowledged; the sampled store/catalog stack does not identify a cause. All
four Builder subchecks pass. Earlier all-platform settings exercise evidence
does not turn this failed tenth scenario into a pass.

Nonpriority tails complete **ten of sixteen planned timed observations and ten
separate preflights**. Six timed hooks are not journaled as offered: both frozen
Mac baselines fail construction and the Windows candidate fails before its case
and numeric journals. Only Linux has a complete comparison. The Windows
diagnostic records Python `BrokenPipeError` with raw Win32 code **32**, a sharing
violation; the wrapper feeds `GetLastError()` to `OSError`, while the Windows
broken-pipe code is 109. The failed caller, operation and conflicting handle
remain unknown, and no pipe disconnect or resident failure is inferred.

The qualification report verifies **twenty ZIPs, 9,587,454 bytes and 81 members**.
Its owner authenticates all four indexed ciphertexts with 142 private members;
three tail archives authenticate with 21 private members. The Linux tail
ciphertext has verified commitments but is not decrypted. Complete numeric
sequences, partial journals and cold/prepared observations keep their separate
custody and acceptance boundaries. No full sampling, release latency, resource,
signing, live-update or rollback qualification follows.

## Package and MCP components

The [tenth package/MCP report](PACKAGE_TENTH_CI_EVIDENCE.md) retains all original
failures and same-route boundaries. Package cardinality has 36 candidate and
24 baseline completions plus twelve censored baseline workers; formats have
20/18 completions and two frozen Composer package-count failures. All ten phase
workers complete. All three jobs pass 132 source correctness tests.

Five complete protect pairs retain wall medians **8,760.358205 → 319.871925 ms**
and CPU medians **7,730.081 → 311.412 ms**. Median paired reductions are
**96.3541685537% wall / 95.9764129901% CPU**, distinct from ratios of arm medians.
Instrumented Guard-Python exclusive origin shares are **41.6229614% protect /
53.0125243% evaluator**. These are optimized-Python versus frozen-Python
observations, not Rust gains or attainable native savings.

MCP completes **30 workers and 10,080 outcomes with zero failures**, across
eight five-block comparisons; its 126 correctness tests pass. All 80 warm
resource windows complete with 145–357 samples and zero missing readings.
Ten lifecycle rows remain incomplete, with fourteen missing samples and 35
descriptor denials across nine rows. Warm completeness does not repair
lifecycle missingness.

The four component public ZIPs total 116,807 independently verified bytes.
Producer receipts report 331 package and 182 MCP encrypted files; no tenth
component ciphertext download or recovery is claimed. The original package and
MCP selection decisions remain unchanged, with no native, installed or
cross-platform qualification inferred.

## Release and evidence boundaries

PyPI authorization and Build + Verify pass, while all fourteen downstream
release jobs skip. Both Desktop feeds validate and skip publication. No release,
canary, signing or live rollback is inferred from these workflow names.

The manifest distinguishes API metadata, finite JSON reconstructed from decoded
logs, verified public ZIPs, verified ciphertext commitments and authenticated
private recovery. Each component retains its exact source and denominator.
Failed or absent observations remain failed or absent; producer receipts alone
do not authenticate private records. Later source/test corrections do not
reclassify original results.

No original task definition, dependency, timeout, semantic rule, sample minimum
or acceptance threshold is changed by this report. The separate current ledger
records literal task acceptance; completed attribution or source tests do not
qualify dependent installed performance, platform behavior or release artifacts.
