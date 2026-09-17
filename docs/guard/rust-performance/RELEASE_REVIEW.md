# Release/3.2 Rust performance review

**Implementation and measured conversion decisions are reviewable; installed
qualification and release acceptance remain incomplete.** This review covers
source `d06d8093bb1744ff22fcaf65fcfd1e908c989c2d`, tree `9b2caee188ace6c0bc97379e08708f7f4019d4e0`. Later source repairs
must earn their own CI results. The original [PRD](PRD.md), all 144 [TODO](TODO.md)
titles, acceptance conditions, dependencies and thresholds remain unchanged.
The [release addendum](RELEASE_3_2_PRD.md) defines current scope; the
[execution ledger](EXECUTION_LEDGER.md) records criterion-level evidence.

84 DONE / 23 OPEN / 29 BLOCKED / 8 DEFERRED

The [fifth CI checkpoint](FIFTH_CI_EVIDENCE.md) records measured PR head
`96a69725eab018674174dabc6f205a4087d6ff4b`, tree `7da3dcf25df5dc75b61f773c40a3a4dd96bbf2fa`.
Its merge `c9a4b508ec5e9f5e6526990f9a3fad8c8b97646d` has the same tree and distinct build identity.
All 41 workflow instances are terminal: **33 successful and eight failed**.
Successful authorization-only publish workflows did not publish a release.
Later source corrections require new CI; earlier
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md),
[third](THIRD_CI_EVIDENCE.md) and [fourth](FOURTH_CI_EVIDENCE.md)
cohorts retain their original identities and failed observations.

## What actual CI establishes

| Scope | Fifth-checkpoint observation | Integrated correction or remaining proof |
| --- | --- | --- |
| Main CI | 19 jobs: nine successful, three failed and seven skipped. Collection failed before any of the 96 pytest shards ran; aggregate CI failed its dependency check. Duration aggregation and Sonar skipped. | Restored the test's temporary helper import path so it no longer shadows the repository ci namespace. Full local collection and 24 protected invariants pass; actual new-source Main CI and quality gate remain required. |
| Ownership | Both decision-critical I/O and Rust-authority workflows failed because the experimental regex crate was absent from the ownership manifest. | Added a precise benchmark-only owner for its two source files, with no production decision or installer authority. The same-base authority gate and full I/O graph pass locally. |
| Security and lifecycle | Security passed all four jobs. Daemon-edge and Windows-resident workflows passed their declared scopes. | Preserve the distinction between source/lifecycle checks and installed latency or complete process-tree resources. Successful publish-authorization jobs did not build or publish a release. |
| Native wheel | Both Macs failed the ignored-child CPU correctness check; Windows failed installed SLO enforcement during assembly. | The Darwin source now rejects ambiguous general CPU totals and retains memory. Windows retained six unclassified responses across c16/c64, with zero observed raw-bridge None returns; their native cause remains unknown. Fifth Linux native-wheel CI passed all 14 installed smoke gates and its 100,000-request/250,000-receipt soak, with zero errors, 18,484 successful health checks, one stable daemon and 3.4097% sampled RSS growth. Its soak p95 was 551.88 ms under the unchanged 4,500 ms soak ceiling; the separate registered Claude PostToolUse smoke had only two observations and p95 354.188 ms. Neither series qualifies the original installed-priority targets. |
| Indexed qualification | Four immutable wheel builds passed. All four indexed pairs failed; every candidate reached PostToolUse and returned an invalid error object before an accepted receipt, with substantial budget left. Both Mac frozen baselines also timed out in getfqdn. | The observer now recognizes 34 existing public command-control error codes. Unknown values remain redacted. All four ordinary aggregators hit the verified singleton directory-layout defect, now corrected without changing full collection. No completed pair is manufactured. |
| Installed scenarios | Linux, ARM and Windows each passed all 22 Ollama/Builder native cases. Intel completed ten cases before disabled-control readiness took 523.888 ms against the unchanged 400 ms barrier; Builder passed. | Declared scenario receipts do not qualify every platform, matcher family, installed tail or lifecycle. |
| Installed Claude experiment | Nine of 20 jobs passed; 11 measurement jobs failed. All archives/final retention succeeded. Six POSIX failures matched the canonical fixed native_post_tool_unavailable response; all five Windows failures matched discovery unavailable. | These exact source-response commitment matches do not reveal the underlying failing subcheck. Read-only Windows object/security preflight and finite native error vocabulary improve the next observation. Production activation remains off. |
| Nonpriority smoke | Linux pair zero completed both arms with two timed plus two preflight calls each. Windows retained complete workers but failed on missing RAM identity. Both Mac baselines failed DNS; their candidate arms completed. All four aggregates failed. | Windows now reads actual RAM from the already locked psutil dependency. Exact-name downloads preserve the expected smoke directory. The old worker failures and incomplete comparisons remain unchanged. |
| Package | All ten phase/validation/registry workers completed. Five protect pairs completed; 36 candidate and 23 baseline cardinality cells completed, with 13 censored baselines. Two baseline Composer cases failed. | Keep the separate fifth evidence and fourth-cohort release decision. No native package implementation or failed Rust comparison is claimed. |
| Scanner | Four Rust tests and 69 actual bridge/collector tests passed. The first smoke failed before source identity and preflight: zero offered/completed, all 24 planned attempts unoffered. All three evidence uploads succeeded. | The executable reader now accepts legitimate immutable toolchain ownership/linking while retaining content/path identity checks. Finite setup stages, attempt-bound names and strict retention need fresh execution. Full 840-attempt selection remains off. |
| MCP | The component job and every step passed. | Completion only; no fifth numeric recomputation or pooling with the 24ba decision or d0e cohort. |

See the [fifth report](FIFTH_CI_EVIDENCE.md),
[nonpriority artifact/recovery note](nonpriority-smoke-ci-96a697.md),
[scanner failure note](scanner-smoke-ci-96a697.md), and
[Windows discovery diagnostic scope](claude-discovery-diagnostics.md).
All attempted and unoffered work retains its original classification.

The failed indexed candidate cases were Linux omp.PostToolUse.block.1m,
ARM cursor.afterShellExecution.benign.max, Intel pi.PostToolUse.benign.1k and
Windows codex.PostToolUse.benign.1k. Their native elapsed times were 9, 33, 55
and 47 ms with about 2,937–2,985 ms left. None had an accepted receipt. The
old observer's other classification does not identify a specific native cause.
Linux and Windows baseline blocks retained 136 numeric observations across
38 series; Windows separately reported 55 unsupported source-reference denials
and incomplete corpus coverage. Those refusals do not establish content review.

Mac resolver self-tests and supplementary registration succeeded, but no actual
OS reverse query reached the fixture. Exact file removal and observed OS
registration retirement are separate; some immediate cleanup snapshots still
show the registration. Preserve each attempt's facts. Neither configuration
visibility nor successful numeric lookup proves the frozen baseline is repaired.
Do not patch that artifact or enlarge its construction/readiness budget.

The [native command program](../../../contracts/extensions/native-command-program.v1.json)
retains schema `guard.native-command-program.v1` and reference profile
`cpython-3.12-ucd15`, program digest
`4df5208d0dc05ceaadb1de6a6d8f6d3f9e5395dffcf992640fed87b82a0df1c9` and catalog
digest `232ff389ca607b805118a02bd9560e972453f9a406188237037138f4834faf11`.
Its [translation contract](../adr/0013-native-command-extension-program.md) and
[compatibility inventory](../native-command-compatibility-admission.md) distinguish
249 declarative rules from 42 null-matcher identities; owned uncertainty is not
successful empty matching. The fourth and fifth Linux, ARM and Windows scenario receipts
supply actual installed production-route proof for their declared cases. They do
not certify every matcher family, Intel readiness or a measured compatibility
speedup. This is the scope of RSP-120's coverage and diagnostics publication.

## Package completeness and approval provenance

The [format parity correction](package-format-parity-coverage.md) advances current
parsing to complete-v3. A malformed top-level Bundler spec previously left a
partial dependency list marked complete; current parsing discards the views and
requires review. The unsupported Bun binary fallback now avoids a content read
in manifest target discovery as well as direct/transitive completeness paths.
The named source-test matrix closes RSP-059 only. Its original dependency remains unchanged; this does not close native or installed qualification. Actual v2-to-v3 saved-approval identity changes are tested. Supported grammar and
explicit unsupported semantics remain documented; no general Bundler parser or
native format implementation is claimed. Prior paired performance evidence retains baseline complete-v1 and candidate
complete-v2; neither measures or qualifies the current complete-v3 interpretation.

## Working-file integrity and scanner parity

The [scanner read correction](scanner-working-file-contract.md) binds bounded
reads to retained descriptors and checks identity again before detection. Files
that change or fail after admission now produce an incomplete scan and exit 2,
while retaining earlier findings. Normal exclusions and supported links remain.
POSIX traversal retains ancestor descriptors; Windows uses compatible handles
and same-domain metadata comparison. Its documented Windows ancestor limitation
and pending actual platform execution remain explicit. The source has 93 focused
passes and a separate 54-pass detector/bridge run with 16 binary-dependent skips;
the suites overlap. Five new native parity cases are wired into existing CI.
RSP-071 remains OPEN and the fifth smoke still offered zero of 24 planned attempts.

## Measured decisions and their limits

The [package decision](package-native-selection-decision.md) retains optimized
Python and selects **no package Rust implementation or activation for release
3.2**. Five independent alternating pairs of the exact npm protect source route
at D=B=1,000 report median wall **8,785.843 → 327.344 ms** and CPU
**7,739.458 → 319.842 ms**. Median paired reductions are **96.2752% wall and
95.8662% CPU**. Imports, fixture setup, pre-admitted signed bundle and
postvalidation remain outside that interval; serialization and evidence
persistence remain inside. These observations are neither installed CLI tails
nor a Rust comparison. The separate [fifth package cohort](PACKAGE_FIFTH_CI_EVIDENCE.md)
reports wall 11,735.251 → 274.568 ms and CPU 5,930.041 → 245.011 ms,
with median paired reductions of 97.6966% and 95.8707%. Its six profiles assign
41.9683% protect/53.6792% evaluator exclusive calling-thread CPU to Guard Python
and zero calls to Pydantic. All 36 candidate cells completed; 23 baseline cells
completed and 13 were censored. These figures are not pooled with the decision
cohort, and they do not supply a native comparison or complete format parity.

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
context/HMAC, fallback, cache and failure-retention expectations. Its first actual
smoke failed before any of the 24 planned offers; the corrected setup requires
new execution. It does not activate native detection or support a blanket
no-port conclusion.

## Source ready to execute and release exit

The [baseline launcher ranking](installed-launcher-baseline-ranking.md) remains
one descriptive Windows block with 80 actual registered invocations. Ordering
changes by event and load; Claude is not established as uniformly most expensive.
No installed usage weighting, missing-platform ranking or qualified tail follows.
The dormant launcher and its repaired experiment therefore still need an actual
comparable benefit result before activation.

The [nonpriority companion](nonpriority-installed-tails.md) exposes a selected
four-platform smoke for cursor.beforeShellExecution.global: four collection
jobs plus four aggregators, two timed observations per arm after independent
benign/block preflight. Fifth Linux alone passed its pair worker; none of the
aggregators passed. Windows complete worker reports cannot bypass its failed
RAM identity admission, and Mac candidates cannot replace failed baselines.
The full 16-route × four-platform × five-pair plan remains explicit opt-in at
320 jobs. Smoke cannot satisfy the 1,000-observation route minimum.

Both actual Mac correctness checks exposed approximately double accumulation
of ignored-child CPU in the pinned OS counters. The corrected [Darwin reader](darwin-resource-accounting.md)
therefore reports general process-tree CPU unavailable with
darwin_reaped_cpu_ambiguous. Parent/child endpoint snapshots cannot distinguish
historical once-versus-twice accumulation. Memory and private raw diagnostics
remain available; neither dividing all counters by two nor loosening tolerances
is permitted. Bounded known-child witnesses retain the original 2 ms lower/20 ms upper discrepancy bounds
and distinguish the observed accounting behavior; they do not qualify general
tree CPU. RSP-011 remains OPEN.

The integrated [ACK-only posture correction](acknowledged-posture-contract.md)
samples one authenticated request binding for native evaluation, the shared
command-control lease and final Watch delivery. Local Watch becomes effective
only after the correct resident ACK; a pending local update cannot weaken an
enforcing result. Native decisions/receipts and unchanged availability responses
remain separate. The source run passed 24 new and 153 adjacent tests, with one
platform skip. This supports RSP-031's authenticated visibility contract, while
RSP-034's actual mixed-transition and installed qualification remain open.
Historical measurements do not qualify this new behavior.

Run the coherent corrected source and inspect exact admission and failure
observations. Restore required Main CI and the actual quality gate; re-execute
the selected Claude, nonpriority and scanner diagnostics with all evidence
retained. Use actual native error codes or current Windows discovery facts to
choose a production fix only after the failure boundary is known. A passed
known-child Mac witness does not restore missing general CPU. Every original
sampling, timing, resource and semantic requirement remains unchanged.

Final acceptance still requires comparable installed performance, exact signed
and frozen artifacts, live update/rollback, mixed offered-load/mutation/recovery,
durable receipts, complete final-head validation and independent latest-push
approval. Source inventory, the recorded package/archive decisions and this
handoff can close their literal criteria while dependent work stays open or
conditionally deferred. Original dependencies remain intact; RSP-012 and the
latest-head release gates do not close through a status refresh. PR #2970 targets
`release/3.2`; protected merge, canary and release remain incomplete.
