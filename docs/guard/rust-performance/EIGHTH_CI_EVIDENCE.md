# Eighth CI evidence

This report freezes published source `a933921372ddb3772eff8a9d86771fe15da063b1`,
tree `3db430b618fe63cc1b85b8037e5de700cc3378c9`, and merge
`e54cf7732f61a6a7e609250a4e17344b5e92039d`. Independently retrieved GitHub
commit metadata confirms the merge has the same tree and parents release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the published source. Source
and merge remain distinct runtime build identities. Frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` remains unchanged where used;
the scanner comparison instead runs both arms from the same eighth source.

At **2026-09-17 20:49:00 UTC**, the original **41 first-attempt synchronize
workflow instances are all terminal: 36 success and five failure**. The
[manifest](evidence/ci-a9339213/manifest.json) retains those exact IDs, source
proofs, bounded job and artifact metadata, and links to the separate evidence
records. The failed workflows are Main CI, native-wheel CI, native performance
qualification, the installed Claude experiment, and the package rebaseline.
The [seventh report](SEVENTH_CI_EVIDENCE.md) remains historical; later repairs
do not replace either cohort's original results. Full installed qualification
and release acceptance remain incomplete.

Four later label-triggered workflows on the same source are **separate** from
the original 41: the full scanner experiment succeeds, two experiments skip,
and a PyPI authorization workflow succeeds with all 15 downstream jobs skipped.
Their results are not folded into the original census or pooled with scanner
smoke observations.

## Observed scopes

| Scope | Run | Terminal result and limit |
| --- | --- | --- |
| Main CI | 35270079331 | 110 successful, one failed and three skipped jobs; all 96 pytest shards pass. Sonar analysis succeeds but its quality gate fails. |
| Security Gates | 35270079969 | All four jobs pass. |
| Decision-critical I/O ownership | 35270079817 | Success on this source. |
| Rust authority ownership | 35270079957 | Success on this source. |
| Native wheel | 35270079893 | Linux and ARM pass; Intel fails two smoke latency gates; Windows fails default-auto route conservation before SLO execution. |
| Dormant native source pilot | 35270079311 | All four jobs pass their fixture, Python/Rust and explicit feature-off/on checks. |
| Installed Claude experiment | 35270079884 | All 15 POSIX jobs pass; five Windows jobs fail a direct-child ACL preservation assertion before experiment offers. |
| Offline scanner smoke | 35270079985 | Three jobs pass; all 24 observations complete after admitted interpreter setup. One independent run supplies no qualified benefit comparison. |
| Package Python component | 35270079970 | Phase passes; format and cardinality retain frozen-baseline failures/censoring. |
| MCP Python component | 35270080057 | Component passes; lifecycle resource missingness remains separate. |
| Native performance qualification | 35270080155 | 15 successful, ten failed and two skipped jobs. All four installed settings scenarios pass; full qualification remains false. |
| Windows resident | 35270079888 | Workflow succeeds. |
| Daemon edge | 35270080114 | Workflow succeeds. |
| Supplemental full scanner | 35270748894 | All 37 jobs and 840 planned observations complete; only two of fourteen benefit cohorts pass. |

Publish-named success does not establish a release. Original PyPI run
`35270079995` executes authorization and Build + Verify; all 14 downstream
jobs skip, including publication, reservations, native-wheel assembly,
GitHub releases and container publication. Both Desktop feeds validate and
skip sidecar publication. Supplemental PyPI run `35270748898` executes only
authorization; its Build + Verify also skips.

## Main CI and security

Main's 114 jobs conserve as **110 success + one failure + three skips**. All
96 pytest shards, aggregate CI `105369329175`, and duration aggregation
`105369329160` pass. GitHub lists **195 unexpired artifacts**: 96 coverage,
96 duration and three other artifacts. These are API identities, not
independently downloaded or rehashed artifact contents.

Sonar job `105369568437` reports successful analysis at 20:32:17 UTC and
successful scanner execution at 20:32:21 UTC, followed by **quality-gate
failure at 20:32:32 UTC**. Current numeric conditions are not available in
this evidence. No custom Sonar lookup was performed. The seventh cohort's
HTTP 500 analysis failure and older ratings or percentages do not describe
this new quality-gate result.

The Windows Main job `105366900597` passes its 246-test selection with five
skips, two Codex process-tree tests with 14 deselections, and the ordinary
packaged bootstrap test in 52.63 seconds. This bootstrap success is distinct
from both the installed-Claude child-preservation failure and the native-wheel
default-auto failure below. Security's Semgrep, Gitleaks, Trivy and privileged
workflow-policy jobs all pass.

## Native-wheel scope

The [native-wheel record](NATIVE_WHEEL_EIGHTH_CI_EVIDENCE.md) preserves all four
platform results and decoded-log provenance. Linux and ARM pass all emitted
adapter smoke gates. Intel fails exactly c16 concurrency p99
**1,430.876 ms** and resident-recovery p95 **1,913.911 ms**, each against the
unchanged **1,000 ms** smoke bound. Its remaining emitted gates pass. These
smoke thresholds do not replace the release's ordinary-priority targets or
independent-run/tail requirements. All emitted SLO reports retain
`qualification_complete=false`.

Windows fails the earlier default-auto aggregate: **19 resident + one fail-safe
= 20 routes**, where 21 were expected. Reaching that assertion after delivery
checks supports a source-control-flow inference about delivery completion;
it does not identify the missing route or the fail-safe request. No completed
Windows default-auto receipt report or Windows SLO report is emitted. The
underlying cause remains unlocalized.

Linux's separate soak passes **100,000 requested/completed logical stress
calls**, zero final errors, **19,961 health checks** without failed or transient
checks, one stable daemon, maxima of 71 threads and 198 descriptors, and
**3.4768% reported RSS growth**. Its p95 is 472.61 ms and maximum 556.14 ms,
under the unchanged 4,500 ms bound. The fixture preloads and verifies
**250,000 receipt rows**; these are not 250,000 new hook receipts. The helper
permits up to three transport attempts per logical call and checks bounded
JSON-object responses, so neither exact wire-attempt counts nor per-request
native decision/receipt identity follows from the logical-call denominator.

All four wheel artifact uploads succeed. The side note retains their API
identities and fifteen complete JSON values reconstructed from decoded logs;
it does not claim independently verified artifact-member bytes. A successful
Linux soak does not repair Intel or Windows results.

## Scanner smoke and separate full comparison

Original scanner smoke executes four Rust and 192 Python correctness tests,
then completes all **24/24** offers. These are test counts, not 192 distinct
native parity scenarios. Interpreter admission, preflight and after-run identity
checks pass. Every native observation reports four native files and zero
fallbacks; all 24 complete-result/stdout commitments agree. Public ZIP
`10518023671` and aggregate `10517748970` were independently downloaded and
matched to GitHub's size/SHA-256 metadata. The producer reports 113 encrypted
files; this audit downloaded no scanner ciphertext. The smoke has only one
independent run, so both benefit comparisons remain unqualified.

The separately requested [full scanner report](SCANNER_FULL_CI_EVIDENCE.md)
freezes run `35270748894`: **35 shards / 840 complete observations / zero
failed or unoffered observations**, across seven workloads, five independent
runs, two cache states and six alternating pairs per state. All 35 public ZIPs
and their 105 members were independently verified; all fourteen original
bootstrap and pooled-point benefit gates were independently recomputed.

Only `working_provider_large`—four 256 KiB, finding-dense files—passes both
cache cohorts. All twelve other cohorts fail the original **30% reduction /
no more than 5% regression** rule. The report keeps optimized Python as the
default and identifies only a narrow large-input candidate; it establishes
no production routing threshold, installed activation, platform extrapolation
or archive benefit. Complete matched-arm finding/stdout commitments agree
within each shard; independently created Git/history commitments remain
distinct across runs. The earlier smoke's 24 observations are not pooled
into these 840.

## Dormant and installed Claude experiments

All four dormant jobs pass the bound fixture check, 32 Python tests, 17 Rust
tests, and the explicit feature-off/on source checks. This establishes that
source scope and leaves the installed experiment's separate limits intact.

The installed experiment completes **1,320 of 1,760 planned attempts**:
15 POSIX jobs × 88 attempts, including **1,200 timed observations**. All five
Windows jobs stop before offers, retaining **440 unoffered** attempts. Each
records 101 passing tests, six skipped and one direct-child ACL preservation
assertion failure, with no synthetic teardown error. This is distinct from
the seventh cohort's teardown failure and from Main's passing Windows bootstrap.

Encryption/upload wrappers run in all 20 jobs. The five Windows receipts say
`no_observations`, zero files and no created archive; their strict completeness
gates fail. The 15 POSIX archives are created and pass retention. Those
receipts are decoded-log producer evidence, not downloaded/verified ZIPs.
All experiment qualification/production-selection flags remain false. Native
p95 values vary across event/run/platform; some Linux series are below 50 ms,
so the earlier cohort's statement that every native p95 exceeds 50 ms is not
reused here. Passing or favorable individual series do not establish the full
release requirement.

## Package, MCP and installed settings evidence

The [package/MCP record](PACKAGE_EIGHTH_CI_EVIDENCE.md) retains candidate
`complete-v3` against frozen baseline `complete-v1`. Format observations
conserve as **20 candidate + 18 baseline complete + two baseline Composer
failures**. Cardinality observations conserve as **36 candidate + 24 baseline
complete + twelve censored baseline workers**. Every candidate observation
completes, but noncomparable or censored baseline cells are not speedups.
All ten phase workers complete; all five real protect-route pairs complete.
The existing keep-Python/no-package-native-selection decision remains unchanged.

MCP records **30 workers / 10,080 outcomes / zero failures** and eight complete
five-block comparisons. All 80 warm resource windows complete; the ten separate
lifecycle rows remain incomplete with **14 missing samples and 38 descriptor
denials**. Package and MCP producer receipts commit 331 and 182 encrypted
files respectively, without ciphertext recovery. Their four public ZIPs were
independently verified. No installed or full tail qualification follows from
these component results.

All four installed settings/Builder scenarios in qualification run
`35270080155` pass, each at exact source a933 with **22 native route/durable
cases plus Builder success**. Their finite reports retain the command-program,
package and wheel identities. The scope is authenticated daemon HTTP with
an isolated generated-key authority. Package downgrade, native one-time
approval consumption, interactive enrollment and signing are not established
by these passing settings scenarios.

## Indexed and tail qualification

The [qualification record](QUALIFICATION_EIGHTH_CI_EVIDENCE.md) retains all
**27 jobs: 15 success, ten failure and two skips**. Its indexed and nonpriority
tail scopes remain separate from the four passing settings scenarios. Failed
arms, partial numeric journals and missing comparisons are retained; smoke
mode and its small sample sizes do not become full qualification.

Four indexed arms complete—both Linux arms and the two Mac candidates—each
retaining 136 observations across 38 series, **544 completed aggregate values**
in total. Windows baseline completes its 386 normalized and 62 registered
preflight cases before a warm-up route failure, retaining only two validated
startup/readiness journal values. Windows candidate completes 290 normalized
cases, then fails readiness before the next offer: 96 declared cases remain
unoffered and no numeric values are retained. The frozen Windows baseline's
source-reader refusal profile is not described as candidate-equivalent content
review. Both Mac indexed baselines fail construction before preflight.

Completed collection is distinct from acceptance: all four completed blocks
fail their offered-load concurrency-64 contracts, and mixed contention,
registered surfaces, approval continuation and malformed-input side scenarios
remain failed. Raw-UTF8 also encounters a registration interruption, separate
from that diagnostic's deliberately unqualified final state. No exact cause
is inferred for the Windows warm-up/readiness failures or the unproved Codex
continuation. General Darwin daemon CPU remains unavailable; Linux resource
sample counts also do not meet the unchanged resource minimum. The detailed
record preserves offered, admitted, failed and generator-dropped counts.

The nonpriority tails retain six completed arms: Linux and Windows both arms,
plus each Mac candidate. Each completed arm validates two semantic preflights
and two timed observations. Both Mac baselines fail in the frozen daemon's
`getfqdn` constructor path before offers, confirmed by authenticated private
recovery. Thus **12 of 16 planned timed observations complete and four are
unoffered**. Linux and Windows pair comparisons complete without passing the
sampling/ordinary/full-qualification flags; both Mac comparisons remain
incomplete. The detailed note distinguishes successful numeric commitments,
authenticated recovery, failed stages and aggregate results.

## Preservation and practical limits

The manifest distinguishes direct GitHub metadata, decoded public log reports,
independently verified artifact ZIPs, producer encryption receipts and the
qualification owner's authenticated recovery. Verification at one level is
not assigned to another. The full-scanner label event is separate from the
41-workflow synchronize cohort, and component/launcher/soak counts are not
summed into a fictional end-to-end qualification population.

This evidence commit changes no original task definition, dependency, threshold,
production behavior or task status. All five failed workflows, twelve failed
scanner benefit cohorts, skipped jobs and explicit unoffered denominators
remain visible. Later source corrections require their own observations.
