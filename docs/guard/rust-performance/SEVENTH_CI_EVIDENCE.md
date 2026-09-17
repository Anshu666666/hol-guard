# Seventh CI evidence

This report records published source `79cb6921ff722a597b545350485864dcd9310bdc`,
tree `f158652293b1e10931122db6ccf48e33f5dd3c38`, and PR merge
`b06b8db2f6fbd9d8f87e5e724e117748f57aea75`. Independent GitHub commit metadata
confirms the merge has the same tree and parents release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the published source. Source
and merge remain distinct build identities. Frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` remains unchanged.

At **2026-09-17 19:55:57 UTC**, the exact source query contains **41 unique,
first-attempt workflow instances, all terminal: 34 successful and seven failed**.
The [public manifest](evidence/ci-79cb6921/manifest.json) records that census,
job conservation and bounded evidence commitments. The [sixth report](SIXTH_CI_EVIDENCE.md)
and its [supplement](sixth-indexed-followup.md) remain historical. Later fixes
do not replace any original failed result. Full installed qualification,
production native selection and release acceptance remain incomplete.

## Observed workflow scopes

| Scope | Run | Observed result and limit |
| --- | --- | --- |
| Main CI | 35264203675 | 109 successful, two failed and three skipped jobs; all 96 pytest shards pass. Windows packaged bootstrap and Sonar analysis fail. |
| Security Gates | 35264203435 | All four declared jobs pass. |
| Decision-critical I/O ownership | 35264203553 | Success on this source. |
| Rust authority ownership | 35264203275 | Success on this source. |
| Native wheel | 35264203634 | Linux and both Macs pass; Windows fails during an installed corpus HTTP response. |
| Dormant native source pilot | 35264203587 | All four jobs fail the bound reference-fixture check before intended pytest/Rust execution. |
| Installed Claude experiment | 35264203611 | All 15 POSIX jobs pass; five Windows jobs fail fixture teardown before experiment offers. |
| Offline scanner experiment | 35264203650 | Correctness tests pass; executable identity admission fails before all 24 planned offers. |
| Package Python component | 35264203583 | Phase passes; format and cardinality retain frozen-baseline failures and censoring. |
| MCP Python component | 35264203282 | Component job passes; lifecycle resource missingness remains separate. |
| Native performance qualification | 35264203851 | 13 successful, 12 failed and two skipped jobs; Linux's one indexed smoke pair and aggregate pass without qualification. |
| Windows resident | 35264203635 | Both declared jobs pass. |
| Daemon edge | 35264203577 | Five jobs pass; optional soak is skipped. |

Publish-named workflow success does not establish a release. PyPI Build + Verify
executed and uploaded distributions and associated evidence. Actual native-wheel
assembly, canary, reservation, publication, GitHub release and container jobs
were skipped. Both Desktop-feed workflows validated and skipped publication.
The PyPI result is therefore not described as authorization-only.

## Main CI, security and ownership

Main's 114 terminal jobs conserve as **109 success + two failure + three skip**.
All 96 pytest shards pass. Aggregate CI job `105349617233` and duration
aggregation `105349617273` pass. GitHub lists **195 unexpired artifacts**:
96 coverage, 96 duration, one duration-manifest candidate, one shard plan and
one dashboard bundle. These identities are API metadata, not independently
rehash-verified downloads.

Windows cross-platform job `105347153134` fails its packaged Core daemon gate
when bootstrap encounters a pre-existing Guard directory that does not satisfy
private Windows ACL requirements. This failure is distinct from the synthetic
Claude fixture teardown described below; later source repairs do not constitute
a rerun of either job.

Sonar job `105349644776` fails during **analysis**, after the scanner's project
repository request receives HTTP 500 at 19:28:51 UTC. The action exits with code
3. No successful analysis or new quality-gate conclusion was produced. The
sixth cohort's quality-gate failure remains a separate observation; older ratings
or coverage percentages must not be presented as seventh-cohort measurements.

Security's Trivy, Semgrep, privileged-workflow policy and Gitleaks jobs all pass.
I/O ownership job `105347149701` and authority job `105347148641` pass their
source, compiled and explicitly exercised installed checks. Their artifacts are
`10515798589` and `10516087111`; exact API sizes and SHA-256 digests are retained
in the manifest. Passing these checks does not establish full installed SLOs.

## Native wheel and bounded soak

The native-wheel workflow has **three successful jobs and one failed job**.
Linux `105347153339` and both Macs pass all 14 declared installed-smoke gates;
all three reports retain `qualification_complete=false`.

Linux's c16 wave has 16 native responses; c64 conserves 64 responses as 62
native plus two explicit overloads, with zero errors, fail-safe responses,
unclassified responses or raw bridge None returns. The later soak completes
**100,000 requests and responses, 250,000 receipts, zero errors and 17,765
health checks with no failed or transient checks**. One daemon retains a stable
PID. RSS grows from 616,984,576 to 637,190,144 bytes, a reported fraction of
0.032749 (about 3.2749%); maxima are 71 threads and 195 file descriptors.
Soak p95 is 522.36 ms and maximum is 589 ms, below its unchanged 4,500-ms bound.
Both `passed` and `soak_passed` are true. These are the soak's own observations,
not a claim that every installed latency or platform requirement is satisfied.

Each Mac prebuild selection passes 112 tests and skips one Linux-only resource
collector test. Its finite known-child witnesses distinguish waited-once from
doubled ignored-child accounting. **General Darwin process-tree CPU remains
unavailable**. Intel's c64 conserves 42 native plus 22 explicit-overload responses,
with zero errors, unknown routes or raw None returns.

Windows `105347152805` passes **47 prebuild tests and skips 25 POSIX-only tests**.
That includes 17 scanner reader/route passes and all 25 corresponding POSIX
skips; the large-byte test now runs without the prior oversized-node-ID fixture
error. Four independent Windows control-lock cases pass. A prior normalized
21-case default-auto probe records 21 resident decisions and 21 accepted and
processed receipts, while its separate receipt failure counter is five; those
facts are not replaced with a clean-receipt claim.

The later Windows installed corpus fails while waiting for an HTTP response
under its existing five-second client timeout. The exact harness/event and
underlying cause are unestablished, and no final installed-SLO report is emitted.
A passing prebuild or normalized probe does not repair this failure.

The four wheel artifact identities in the manifest come from Actions upload
logs, not independently downloaded ZIPs. Linux artifact `10517133571` is
13,214,589 bytes with SHA-256
`ea7e3642aa4a3b4d215d1f768cd2490506bef74ebbb7468d5a90a00205171c30`.

## Scanner admission and dormant-pilot fixture

Scanner run `35264203650` passes its plan, then fails its shard and aggregate.
It executes **four Rust and 174 Python correctness tests**. Those are test
counts, not 174 independent native parity scenarios. The original executable
identity read now exposes the finite reason **`metadata_writable`** at
`python_executable_identity_failed`. All **24 planned attempts are unoffered**;
zero measurement attempts complete. This seventh observation does not identify
the unobserved identity subcheck of earlier cohorts.

Two private files are sealed. Public and encrypted uploads pass while collection
and final retention acceptance fail. The three independently downloaded and
SHA-256-verified ZIPs are public `10515423776` (1,526 bytes), encrypted
`10515843401` (4,185 bytes), and aggregate `10515478858` (573 bytes). The
manifest records the exact ZIP and retained-member commitments. No scanner
ciphertext recovery is claimed.

The separate dormant-pilot workflow fails all four jobs at its bound fixture
`--check`, before the intended pytest/Rust gates. Linux and Windows log inspection
identifies a stale four-source reference fixture following the Windows discovery
producer change. This is distinct from the unchanged 394-file command evaluator
commitment. Later exact regeneration and the scanner's reviewed private-interpreter
fixture repair are source changes awaiting their own execution; neither changes
these original outcomes or establishes native benefit.

## Installed Claude experiment

Linux, ARM and Intel each complete five of five jobs; Windows completes zero of
five. The 15 POSIX jobs finish **1,320 attempts, including 1,200 timed
observations**. Each complete job has eight preflight and 80 timed attempts.
Windows' **440 planned attempts remain unoffered**, so the combined experiment
conserves 1,760 planned = 1,320 completed + 440 unoffered.

All five Windows jobs fail the signature-case synthetic fixture's teardown in
contract validation, before any installed experiment preflight or numeric offer.
Each records 78 passed tests, six skipped and one teardown error. The separate
new producer contract tests pass. These results do not repeat the sixth cohort's
native-request ACL observation and do not prove the seventh installed Windows
experiment itself passed.

The encryption/upload wrapper steps run successfully in all 20 jobs. The five
Windows receipts explicitly say `no_observations`, with zero files and no
created archive; their final retention gates fail. The 15 POSIX archives are
created and pass retention. Producer receipts and upload identities are retained
from public job logs; no experiment ZIP download or private recovery is claimed
here. All reports retain default registration unchanged, fixture restored,
production selection false and qualification false. Every completed native
PostToolUse p95 series remains above 50 ms.

## Indexed pairs, scenarios and nonpriority smoke

Qualification's 27 jobs conserve as **13 success + 12 failure + two skip**.
The plan and all four immutable-wheel builds pass. Linux indexed pair
`105350663555` and aggregate `105354576115` pass: each arm completes **38 numeric
series and 136 observations**, and a 41-file encrypted archive is produced.
The aggregate explicitly records **SMOKE, one pair**, collection and comparison
complete, but sampling, program and full qualification false. The pair producer
keeps its own `comparison_available=false`; the later aggregate performs and
records the one-pair comparison. These are distinct scopes. This completed
comparison is not a qualified tail estimate or release-wide benefit result.

ARM `105350663502` and Intel `105350663393` indexed baselines fail during daemon
construction in `socket.getfqdn` / `HTTPServer.server_bind`. Both candidate
public reports complete 38 series and 136 observations. Their public reports
match the pair-manifest hashes and both downloaded ZIP hashes are independently
verified; private numeric bytes have not been decrypted and rehashed. Each
producer reports 26 encrypted files. The failed baseline prevents either paired
comparison. Windows `105350663412` fails both arms. Authenticated recovery of its six-file
archive shows the baseline first completed 386 daemon and 62 registered cases.
It retained 66 numeric values across 27 offered batches, 26 validated; the failed
27th batch offered and observed all 16 Claude PreToolUse c16 samples, then failed
route validation. Those failed-batch values are retained evidence, not accepted
measurements. The candidate offered 29 daemon cases, completed 28 and failed
`claude-code/PreToolUse/review/small` during delivery, with no returned HTTP status,
no bridge witness and zero numeric values. The failure originates in
`native_slo_session._request`; neither timeout nor a narrower cause is proved.
The three corresponding aggregates fail.

Candidate scenario jobs pass on Linux and ARM and fail on Intel and Windows.
Builder passes in both failed jobs. Intel completes two native cases, then
readiness for enabled control revision one returns no snapshot at **469.786 ms**,
beyond the unchanged **400-ms** budget. The retained snapshot is revision zero,
ACK is false and failure count is zero. A sampled publisher stack is in store
connection/control projection; it does not identify a lock holder or prove a
root cause. Windows completes ten native cases, including same-binding approval
reuse and independent block checks, then disabled revision two readiness returns
no snapshot immediately, with retained revision one, ACK false, retry pending
and failure count one. The bounded redacted error does not establish its cause.

The first nonpriority route is `cursor.beforeShellExecution.global`. Linux and
Windows workers and aggregates pass their smoke collection; both Mac workers
and aggregates fail. Six arms each complete two semantic preflights plus two
timed observations, with zero errors and checked native allow/stdout/exit.
**Twelve of 16 planned timed observations are accepted; four are unattempted.**
Authenticated private recovery proves both Mac baselines stop at daemon
construction in `socket.getfqdn:808` / `HTTPServer.server_bind:138`, before any
corpus or numeric offers. Both candidate arms complete. All eight outer ZIPs and
four ciphertext/manifest commitments are independently verified. Private recovery
is claimed for those two Mac diagnostics only. All sampling, ordinary-route and
full-qualification flags remain false, including the passing Linux and Windows
smoke aggregates. Artifact transitions and the second tail group are skipped.

## Package and MCP components

The [package and MCP evidence note](PACKAGE_SEVENTH_CI_EVIDENCE.md) retains their
exact public components, source identities, producer receipts and download proofs.
The package phase job passes while format and cardinality jobs fail their full
criteria. Each job's overlapping 132-test correctness selection passes; the
counts are not added together. Candidate package semantics are `complete-v3`;
the frozen baseline is `complete-v1`.

Format covers 20 completed candidate cells versus 18 completed baseline cells
and two baseline Composer package-count failures. Cardinality covers 36 completed
candidate cells, 24 completed baseline cells and 12 baseline cells censored by
the unchanged 15-second whole-worker bound. The baseline's Composer identity
filter defect remains a limit, with no rewritten baseline or repaired workload.
Two unresolved-version workers and all ten hot-route workers complete.

Across five independent hot-route pairs, median wall time is
8,904.153534 → 326.290654 ms and median CPU time is 7,808.830 → 318.823 ms.
Median paired reductions are 96.335523% wall and 95.920132% CPU. These remain
source component diagnostics; they neither pool earlier cohorts nor establish
new native selection or installed performance. Ten phase workers complete;
the reported Python function-origin shares are about 42.3529% of protect and
54.2616% of evaluator time, with Pydantic at zero. Nine package staging groups
report zero missing records and producer receipts report 331 encrypted files.
No package ciphertext recovery is claimed.

MCP's separate 126-test correctness selection passes. Its component completes
30 workers, **10,080 outcomes with zero failures**, 48 groups, 240 run/trace
summaries, 364 phase rows and eight complete five-block comparisons. All 80
warm resource windows complete, with 139–361 samples and zero missing samples.
The ten lifecycle rows remain incomplete with 13 missing samples and 39
descriptor denials across all ten. Successful warm windows do not erase those
lifecycle limits. The exact public ZIP is independently verified; 181 raw
commitments and a producer receipt for 182 encrypted files are retained, without
ciphertext recovery. Installed, cross-platform and tail qualification remain false.

## Evidence boundary

The manifest distinguishes GitHub API metadata, parsed public logs, independently
verified downloads and authenticated diagnostic recovery. Passing an upload is
not equivalent to proving all expected observations exist. Censoring, unoffered
work, unavailable resource measurements and failed gates remain explicit.
This report changes no original task definition, deadline, gate, ledger status,
release selection or frozen historical evidence.
