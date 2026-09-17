# Ninth CI evidence

This report binds published source `d33f64d5fb86a3f2baa6848382ce763e2ed9fc59`,
tree `0a40e2ebd6515094b5ce6b92c21a5fde3d056f40`, and tested merge
`009c7253ce2e132bffaea837b23b0a36b9bc16c2`. Independently retrieved GitHub
commit metadata confirms the merge has the same tree and parents release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the published source. Source
and merge are distinct build identities. Frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` remains unchanged where used;
the scanner smoke runs both arms from the same ninth source.

At **2026-09-17 21:49:16 UTC**, all original workflows are terminal:
**36 successful, five failed and one skipped**. The original cohort contains
**42 first-attempt synchronize workflows** created
at 21:17:49 UTC, including a skipped native-client profile workflow whose label
was absent at dispatch. Five later label-triggered workflows at 21:18:33 UTC
are separate: the native-client diagnostic and authorization-only PyPI workflow
succeed, while scanner, Claude and qualification label events skip. These
instances are neither pooled into the original cohort nor counted as additional
ordinary benchmark pairs.

The failed original workflows are Main CI, native-wheel CI, native performance
qualification, the installed Claude experiment and the package component run.

The [manifest](evidence/ci-d33f64d5/manifest.json) retains exact IDs, source
proofs, bounded job/artifact metadata and references to independent component
evidence. The [eighth report](EIGHTH_CI_EVIDENCE.md) remains historical. Later
source or fixture repairs do not replace original failures. Full installed
qualification and release acceptance remain incomplete.

## Main CI, security and ownership

[Main run 35275855362](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855362)
finishes with **104 successful, four failed and six skipped jobs**. Of the
96 pytest shards, 94 pass and two fail. All 96 duration artifacts and all 96
coverage artifacts are retained, including failed shards. The API lists
**194 unexpired artifacts**: those 192 plus the dashboard bundle and shard
plan. Artifact API identities are not independent artifact-byte verification.

The four failed jobs preserve distinct evidence:

| Job | Observed failure |
| --- | --- |
| Windows compatibility, 105386195146 | The ordinary packaged daemon bootstrap test passes its initial start/status/stop sequence and second bootstrap schema, then observes `retry_status.running == false`. The status fields needed to identify a narrower cause were not retained. The earlier selections pass 246 tests with five skips and two Codex process-tree tests with 14 deselections. |
| Pytest shard 35, 105386575577 | 234 tests pass, one skips and one fails. The partial-connection test observes active count two, then unclassified count one where two was expected. The actual CI interleaving is unobserved. |
| Pytest shard 73, 105386579450 | 236 tests pass and one fails. The archive-footprint test expects 15 named sidecar suffixes but observes 17 after the two identity diagnostic sidecars were added. Its existing raw UTF8 byte/file-bound assertions pass. |
| Aggregate CI, 105388355404 | Its dependency assertion sees `TESTS_RESULT=failure`; quality, test-plan, compatibility and scheduling-sensitive dependencies report success. |

Duration aggregation, `sonar-guard` and Sonar itself skip. **There is no ninth
Sonar analysis or new quality-gate conclusion.** Earlier analysis/gate outcomes
remain in their own cohorts; no custom Sonar query or disposition was performed.

The connection fixture is corrected separately in `def62b8ee2`: it observes
the third original `process_request` call returning before checking the original
two counters and oldest-client closure. The absolute 0.2-second deadline and
capacity two remain unchanged; the focused test passes. Source ordering proves
that eviction may remove a pending entry before releasing capacity, but does
not establish that this was the captured CI interleaving. The archive assertion
is corrected separately in `dacd247972`, retaining the file cap while accounting
for 17 suffixes and 53 fixed pair files; its owner's 20-test check passes.
Neither correction is a passing ninth rerun.

[Security run 35275855423](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855423)
passes Semgrep, Trivy, workflow policy and Gitleaks. Decision-critical I/O
`35275855459` and Rust authority ownership `35275855229` pass. Windows resident
`35275855257` passes both jobs; daemon edge `35275855231` passes five jobs and
skips one. These source/workflow outcomes do not complete installed latency
qualification.

## Scanner smoke and dormant source pilot

[Scanner smoke 35275855201](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855201)
passes all three jobs. Its actual-binary checks pass four Rust and 192 selected
Python tests. The single independent `working_provider_large` run completes
**24 of 24 observations**, with no failures or unoffered work. Twelve native
observations each report four native files and zero fallbacks. Within this shard,
all complete-result commitments and stdout commitments agree; preflight and
source/interpreter identity checks pass.

Both public ZIPs are independently downloaded, bounded and verified against API
sizes and SHA-256: public artifact `10520013619` is 2,791 bytes and aggregate
`10520716834` is 753 bytes. The encrypted artifact `10520343299` is metadata-only.
The producer receipt reports 113 files and 10,851,501 encrypted bytes; no
ciphertext download, authentication or recovery is claimed. The one-run smoke
does not meet the independent-run minimum, reports no qualified benefit, and
is not pooled with the eighth source's full 840-observation experiment.

[Dormant pilot 35275855055](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855055)
passes all four platform jobs. Each passes the bound fixture check, 32 Python
tests and 17 Rust tests. Explicit feature-off/on source smoke reports match
capability and command presence, with registration unchanged and installed
qualification false. These checks do not establish ordinary installed launcher
activation.

## Installed Claude experiment

[Installed Claude 35275855558](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855558)
finishes with **15 successful POSIX jobs and five failed Windows jobs**. Planned
work conserves as **1,760 = 1,320 offered/completed + 440 unoffered**. Each
successful job completes 88 attempts, including 80 timed observations, giving
1,200 completed timed observations across the 15 POSIX jobs. Each Windows job
fails a direct-child ACL preservation assertion before experiment offers;
107 selected tests pass and six skip. This is separate from Main's failed
ordinary bootstrap retry.

All 20 retention steps pass. The 15 POSIX producer receipts each report six
encrypted files; Windows emits five explicit `no_observations` receipts with
zero files. These are decoded-log/producer claims, not independently verified
ZIP or recovered ciphertext contents. All qualification and production-selection
flags remain false. Linux PreToolUse native p95 remains above 50 ms in all
five runs (51.255–51.535 ms); four of its five PostToolUse native p95 values are
at most 50 ms (range 41.457–51.529 ms). Those small experimental results do not
establish the complete release latency contract.

## Component and installed evidence

The [package/MCP checkpoint](PACKAGE_NINTH_CI_EVIDENCE.md) preserves phase
success, 36/24/12 candidate/baseline-complete/baseline-censored cardinality
observations, and 20/18/2 candidate/baseline-complete/baseline-failed formats.
All ten protect observations from five independent pairs complete. The median
paired reductions are 96.9181551258% wall and 95.8590879179% process CPU, separate
from arm medians and earlier cohorts. The parser remains candidate `complete-v3`
versus frozen `complete-v1`; no optimized-Python-versus-Rust selection follows.

MCP completes 30 workers and 10,080 outcomes with no failures. Its 80 warm
resource windows complete with 142–340 samples and no missing warm samples.
The ten separate lifecycle rows remain incomplete, retaining 17 missing samples
and 38 descriptor denials. Package producer receipts total 331 encrypted files;
MCP reports 182. Four public ZIPs are independently verified; ciphertext
recovery and complete lifecycle accounting are not claimed.

The [native-wheel checkpoint](NATIVE_WHEEL_NINTH_CI_EVIDENCE.md) retains three
successful platforms and one failed platform. Linux, ARM and Windows pass all
14 emitted adapter smoke gates. Intel fails only recovery latency: p95
1,152.981 ms exceeds the unchanged 1,000 ms smoke gate, based on two observations.
The other 13 Intel gates pass. These smoke gates do not replace ordinary-priority
release targets or sample minima.

Linux and Windows each complete 21 accepted and processed default-auto receipts,
with zero drops and pending receipts, while each retains a separate writer
failure counter of two. The passing conservation predicate does not establish zero historical
writer failures or explain the eighth cohort's mismatch. This normalized daemon
corpus is distinct from 21 installed launcher registrations and from Main's
failed packaged bootstrap retry.

Linux completes **100,000 logical calls and 100,000 responses**, with no reported
errors; all **19,126 health checks** succeed. It retains one stable daemon PID,
71 peak threads and 203 peak file descriptors. RSS grows from 614,260,736 to
810,242,048 bytes, **31.9052%**, within the original 50% long-soak limit. Soak p95
is 617.21 ms and maximum 1,698.46 ms under its 4,500 ms bound. The actual lifecycle
list contains `start_requested` and `ready` only; no stopped marker is claimed.
Its 250,000 verified receipt rows were preseeded, and each logical call permits
up to three transport attempts. These counters do not prove 100,000 exact wire
attempts, individual native verdicts or newly emitted hook receipts. The finite
reports are reconstructed from complete GitHub logs; wheel/artifact hashes are
metadata, with no binary or artifact ZIP download claimed.

The [qualification checkpoint](QUALIFICATION_NINTH_CI_EVIDENCE.md) retains
**27 jobs: 15 successful, ten failed and two skipped**. All four immutable-wheel
builds pass. Six indexed arms complete, retaining **816 numeric observations**
across 38 series per arm, **2,316 normalized cases** and **372 registered
priority-launcher validations**. Both frozen Mac baselines fail in original
daemon construction before offers. Linux and Windows ordinary aggregates have
available one-pair smoke comparisons; both Mac comparisons remain incomplete.
Sampling and full qualification remain false. The frozen Windows baseline's
55 unsupported-source denial cases are explicit denials, not successful content
reviews or parity-equivalent candidate work.

Completed indexed blocks retain **failed side scopes**. All four candidates fail
the Codex browser-continuation witness, malformed priority-input route witness
and broader registered-surface corpus. The raw UTF8 diagnostic also interrupts
during registration; that failure is distinct from its intentional always-false
full-qualification flag. Mixed-load acceptance remains false on every candidate.
Indexed c64 closed-loop waves account for all responses but include 6/4/16/28
overloads on Linux/ARM/Intel/Windows respectively. Separate offered-rate waves
each attempt 1,280 offers: generator drops are 1,106/900/1,095/1,072, with
0/208/46/9 failures among admitted work. Accounting conservation does not turn
those failures or drops into successful native evaluation or a passed load gate.

The separate nonpriority tails complete six arms: **12 of 16 planned timed
observations**, plus **12 separate preflight invocations**. Authenticated Mac
diagnostics establish that both frozen baselines stop in `socket.getfqdn`
during daemon construction, before case or numeric offers; the other four timed
observations are unoffered. Linux and Windows smoke comparisons succeed, while
Mac comparisons fail. None reaches the tail sampling requirement.

The identity side scenario completes **18 hooks in six arms**, including all
four candidate platforms. Each arm measures a prepared-resident first hook
and two warm hooks. Linux candidate reuses registered live-child proof; Mac and
Windows deliberately retain complete executable validation. Capability-cache
hits do not eliminate that preceding hash. No unprepared cold resident or
launcher startup identity work is measured, and no cold-hook closure follows.

All four Builder scenarios pass. Linux and ARM complete all 22 native settings
lifecycle cases each. Windows completes two cases before enable readiness fails;
Intel completes twelve before update readiness fails under the unchanged 400 ms
barrier. The sampled stacks do not identify the cause of those readiness
failures. The eighth source's complete four-platform lifecycle exercise remains
historical evidence, not qualification of this later source.

Qualification custody is recorded separately from the workflow census: 20
bounded ZIPs are verified. Four indexed archives and the two Mac tail archives
are authenticated and recovered; the two successful Linux/Windows tail
ciphertexts remain undecrypted. Numeric journal/aggregate equivalence and
receipt-context checks are retained at their declared scope.

## Supplemental diagnostic and release boundary

[Native-client profile `35275926017`](native-client-profile-ninth-ci.md)
belongs to the later label event, whereas
original profile `35275855739` skips. All four supplemental platform jobs pass:
160 offers complete with zero failures. Each target reports one helper,
42 frames, 40 matched hook requests and 40 hook socket opens. Its owner verifies
eight ZIPs and authenticates four archive recoveries. Each target's source
checks pass 77 Python and five Rust tests. This instrumentation is
separate from normal release builds and installed headline timing. Client
response-read time includes queueing, resident evaluation and transport; the
same-request isolated resident evaluation span remains absent.

Publish-named success does not establish a release. Original PyPI
`35275855216` executes authorization and Build + Verify; all 14 downstream jobs
skip. Supplemental PyPI `35275926002` executes authorization only, with all
15 downstream jobs skipped. Both Desktop feeds validate and skip publication.

This evidence changes no original task definition, dependency, gate, production
default or release authorization. Successful source tests, diagnostic requests
and small smoke comparisons retain their literal scope; failed, skipped,
partial, censored and unoffered work remain explicit.
