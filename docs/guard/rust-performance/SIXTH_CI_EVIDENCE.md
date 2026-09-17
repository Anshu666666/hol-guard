# Sixth CI evidence

This report records published source `9d3907a2e6ed1ec201281901cb878836a7dad32d`,
tree `833ea191211db2a0613db8520d072f5edf485380`, and PR merge
`64164db9cd11e3d05182a99dba100daa6011c83d`. The merge has the same tree and
parents `4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the published source.
Candidate and merge build identities remain distinct. Frozen baseline
`2e672d2d950c6ec471005ddba46e49bba16dc23b` remains unchanged.

At **2026-09-17 18:33:51 UTC**, the exact source query returns **41 first-attempt
workflow instances, all terminal: 35 successful and six failed**. Job-level skips
remain separate from workflow conclusions. Later source repairs do not inherit
these outcomes. Full installed qualification, production native selection and
release acceptance remain incomplete.

The [public manifest](evidence/ci-9d3907/manifest.json) retains exact source,
workflow, job and artifact commitments. The [fifth report](FIFTH_CI_EVIDENCE.md)
and earlier cohorts remain unchanged; their measurements do not qualify these
new bytes.

## Observed workflow scopes

| Scope | Run | Observed result and limit |
| --- | --- | --- |
| Main CI | 35257232478 | 110 successful, three skipped and one failed job; all 96 pytest shards and duration aggregation pass; Sonar quality gate fails. |
| Security Gates | 35257232866 | All four declared security jobs pass. |
| Decision-critical I/O ownership | 35257232607 | Success on this source. |
| Rust authority ownership | 35257233055 | Success on this source. |
| Native wheel | 35257232892 | Failure; Linux c64, Intel source-review availability and Windows test setup failures are retained below. |
| Installed Claude experiment | 35257232562 | 13 successful and seven failed jobs; all 20 jobs pass final retention. |
| Offline scanner experiment | 35257232537 | Failure after actual native correctness tests; zero measurement offers. |
| Package Python component | 35257232889 | Phase job passes; format and cardinality jobs retain frozen-baseline failures/censoring. |
| MCP Python component | 35257232655 | Its one declared component job passes; no new installed or native-selection claim is made here. |
| Native performance qualification | 35257233257 | 11 successful, 14 failed and two skipped jobs; all four indexed pairs fail. |
| Windows resident | 35257232991 | Both declared jobs pass; no broader performance qualification inferred. |
| Daemon edge | 35257232789 | Five declared jobs pass and the optional soak is skipped. |

Successful publish-named workflows did **not** publish a release. The PyPI
workflow did execute Build + Verify and upload distributions, hashes, SBOM and
the installed-canary subject. Native-wheel assembly, canary, reservation,
publication, GitHub-release and container jobs were skipped. Both Desktop-feed
workflows passed validation and skipped their actual publishing jobs. Thus the
PyPI result is not described as authorization-only.

## Main CI and ownership

Main CI has 114 terminal jobs: 110 successful, three skipped and one failed.
All 96 pytest shards passed and uploaded 96 coverage plus 96 duration artifacts;
195 artifacts were retained overall. Duration aggregation job `105326242055`
and the aggregate CI job `105326242161` passed. The sole failed job was Sonar
`105326284610`: analysis completed at 18:22:11 UTC, then its quality gate failed.
Fresh numeric Sonar conditions are not established by the retained summary;
earlier cohort ratings or coverage percentages must not be reused here.

All four Security Gates jobs passed. Decision-critical I/O ownership job
`105323756422` and Rust authority ownership job `105323758251` also passed on
this source. Those source gates do not qualify installed performance.

## Native wheel and scanner correctness

Linux job `105323757981` passed 13 of 14 installed-smoke gates and failed
`concurrency_64_bounded`. Its c64 wave returned 64 responses with zero transport
errors: 32 native-resident, 15 native-fail-safe, 17 explicit-overload responses,
and zero unclassified responses. The separate engine-bypassed counter was two;
it is not an additional response category. The raw bridge observer counted 15
original None returns. The separate c16 wave recorded all 16 native. The later
Linux installed-soak step was skipped, so this cohort supplies no new 100,000-request
soak result.

The public serializer replaced each nested None-record field with
`truncated`. This affected both printed output and the uploaded JSON; no
underlying None cause can be recovered from those records. Later source
`e6746e5ff3d66364b934d61a30b8c245691791d5` moves only the existing closed
projection to a shallower report field, preserving global privacy depth, all
redaction rules, counters, failed gates and standalone report schemas. It passes
64 focused tests and independent source review. It does not retroactively repair
sixth evidence or identify a production cause.

Linux artifact `10512767325` has producer-reported upload ZIP size 8,432,812
bytes and SHA-256
`e17d1c2566654b16cc3299381851eeecd1a297e342105345e0eec0279b6d8735`.
Those facts came from the GitHub upload log; the ZIP was not independently
downloaded. The finite report was parsed from the complete GitHub job log.

Intel job `105323757874` passed its prebuild tests, then retained a Cline
250-KiB source-review failure with typed
`native_command_control_mutation_in_progress`: one call, zero accepted
receipts, 71 ms elapsed and 2,976 ms remaining. This is not deadline exhaustion.
Its upload-log artifact is `10513028032`, 8,192,807 bytes, SHA-256
`bba5f2cec7fa0d6a284cee3128e25c7b94f32f4af1885463c393d649ff082250`;
it was not independently downloaded.

The working-file reader/route checks passed all 42 new source cases on Linux
and both Macs. Linux's complete prebuild selection passed 63 tests. Each Mac
selection passed 112 and skipped one Linux-only resource test. Windows passed
16 new cases and skipped 25 POSIX-only cases; one oversized pytest-generated
node ID failed during setup and teardown, producing two error reports. The
complete Windows selection was 46 passed, 25 skipped, two errors. No reader
assertion failed in that result, but the interrupted case is not counted as
passed. Later fixture-only correction `4f23a8d053e2960c82c3fe0665ea1cbc2f0ccd37`
uses bounded explicit IDs and passed 42 local tests plus independent review.
It is not an actual Windows rerun.

Actual Darwin witnesses distinguish known-child evidence from general tree
accounting. ARM nested expected/raw CPU was 162,641,000/162,643,166.6667 ns;
ignored-child was 59,664,000/119,452,416.6667 ns. Intel nested was
308,537,000/308,538,949 ns; ignored-child was 336,336,000/673,058,608 ns.
The known-child classifications are waited-once and twice respectively.
General Darwin tree CPU remains unavailable; no resource-window completeness
or zero-CPU claim follows.

## Scanner experiment and retention

Run `35257232537` has plan job `105323757083` successful, collector
`105323827159` failed and aggregate `105324160462` failed. It executed four
Rust tests and **95 Python tests with zero skips**, including the five newly
added actual-native parity cases. These are correctness results, not 95
independent native-parity scenarios.

The collector retained `python_executable_identity_failed`, null fixture and
source identity, and failed preflight. All **24 planned attempts remain
unoffered**: zero offered and zero completed. The precise failing executable
identity subcheck remains unknown. Source correctness does not create a passing
experiment or a native-selection decision.

Public, encrypted and aggregate uploads completed. The producer sealed two
private files into 3,743 encrypted bytes. The scanner owner independently
downloaded and verified all three ZIPs:

| Artifact | ZIP bytes | ZIP SHA-256 |
| --- | ---: | --- |
| 10513677373 public | 1,503 | 9a0af4d34529e6f42b8b4305f48eaf3484ba5e0acc871e59cb60f23e5fd65804 |
| 10513642348 encrypted | 3,894 | eb62d59efcd3911bc5d02b1d054b191e977faa482f64b3c1dc316cb2d532ebf1 |
| 10512882146 aggregate | 570 | 6d347829b185da449a25236a526e58ab7978393a6637ac60d827507ba4829fc5 |

No ciphertext was decrypted. Download/hash verification is distinct from
authenticated plaintext recovery.

## Installed Claude experiment

The 20 jobs include 13 successful and seven failed jobs: Linux 5/5, Intel 5/5,
ARM 3/5 and Windows 0/5. Attempt conservation is 1,760 planned = 1,219 attempted
+ 541 unoffered, with 1,212 completed and seven failed attempts. The 13 complete
jobs supply 1,040 completed timed observations; failed-job partial timings stay
separate and are not replaced by completed-job counts.

ARM run 3 failed optimized-Python PostToolUse sample 2; ARM run 4 failed native
PostToolUse sample 9. Both retain the canonical availability response hash;
underlying causes remain unknown. All five Windows jobs failed native PreToolUse
benign preflight sample -1. Their totals are 440 planned, eight attempted, three
completed, five failed and 432 unoffered, with zero timed observations. Delivered
exit 0 and the fixed 254-byte response shape are availability outcomes, not native
allow proof.

The Windows read-only preflight witness reports `security_rejected` for the
current key and state files while its six other stages pass. This does not prove
which object or substage rejected the original native request. All five Windows
retention gates passed and fixtures were restored. All 20 experiment jobs passed
their encryption, public upload, encrypted upload and final-retention steps.
The Windows public aggregates and
receipts were independently downloaded and hash-verified; encrypted payloads
were not downloaded. POSIX results were parsed from complete job logs, with
upload identities read from those logs rather than independently downloaded
ZIPs. No new native activation or all-platform qualification is established.

## Indexed qualification and scenarios

The qualification workflow has 27 terminal jobs: 11 successful, 14 failed and
two skipped. All four immutable-wheel builds pass. Every indexed pair and its
ordinary aggregate fails. ARM and Windows candidate scenarios pass; Linux and
Intel scenarios fail. The narrower causes of those two scenario failures have
not been independently established in this report. Artifact transitions and the second nonpriority group
are skipped. Successful individual arms do not establish a complete comparison.

ARM candidate and Linux baseline public completion manifests each commit 136
numeric observations across 38 series. The ARM candidate also completes 386
daemon and 62 registered semantic cases; its frozen baseline fails daemon
construction in reverse DNS. The ARM numeric commitment and matching report
hash are verified through the public manifest and archive receipt. Its 26-file
archive was authenticated and recovered. The recovered final numeric file was
independently rehashed: 4,013 bytes, 38 series and 136 observations, SHA-256
`4c16471cdd0660e172f7683d07c516f65d1434dc549fb5d9c2cbd5566c20850c`,
matching the public commitment. The separate append-only journal has a different
hash and is not substituted for that final numeric file.

Linux candidate likewise completes 386 daemon and 62 registered cases. Its
concurrency-16 Codex PostToolUse batch 36 retains 16 latency values and a
`validated` terminal record, which follows successful route validation. The
subsequent failure occurs at `native_slo_batch.validate_batch_routes:32` inside
`measure_load_profiles`; the exact concurrency, offered wave and route-counter
deltas are absent. Authenticated private recovery establishes these distinct
boundaries. The later failure does not invalidate that completed batch, and the
completed batch does not turn the failed arm into a complete comparison.

Both Windows arms fail: the baseline at unavailable.small with
`native_request_unavailable` and unresolved setup cause, and the candidate
during daemon construction in the outbox transaction/store-bootstrap path,
before its corpus. Both Intel arms also fail; the candidate's Cline block at
16 KiB returns `native_command_control_mutation_in_progress`, with 46 ms elapsed
and 2,939 ms remaining. That typed error proves a native shared-lock acquisition
failure, not which process or thread held the lease. A separately demonstrated
ordinary refresh that held an unnecessary exclusive lease is later source work,
not retrospective proof of the CI lock holder.

All four indexed ZIPs were independently downloaded and SHA-256 verified.
Producer archive receipts retain 26 ARM, 24 Linux, six Windows and eight Intel
files, including pair-manifest and numeric commitments. Linux and ARM
authenticated recovery was performed. Producer numeric-verification flags
are distinguished from independent plaintext rehashing. The manifest
preserves the exact artifact and encrypted-archive identities.

## Nonpriority installed smoke

Linux worker `105327060656` and aggregate `105328367757` passed. Windows worker
`105327061199` and aggregate `105328367922` also passed. Each complete pair has
two timed observations and two semantic-preflight calls per arm, zero errors,
native-resident route proof, stdout/exit checks and four validated cases per arm.
The aggregates retain `pair_comparison_complete`, but sampling, tail-sampling,
ordinary-c1 and overall qualification flags remain false. A two-sample smoke is
not full qualification or a qualified latency comparison.

ARM worker `105327061153`/aggregate `105328367837` and Intel worker
`105327061814`/aggregate `105328367805` failed with `pair_collection_incomplete`.
Each retained a failed baseline and a completed candidate with two timed plus
two preflight calls and zero candidate errors. Across the four platforms, six
completed arms supply 12 accepted timed observations out of 16 planned. The four
planned Mac-baseline observations were unattempted: authenticated recovery
verifies that both frozen baselines stopped at
`qualification_fixture.daemon_fixture_deadline_at_construct_daemon`, inside
`socket.getfqdn` called by `HTTPServer.server_bind`, before collect, semantic
preflight or numeric offers. Neither baseline created a numeric journal.

All eight worker and aggregate artifact ZIP hashes were independently checked, and
all four encrypted payload and manifest hashes matched their receipts. The
retained archives are complete and their numeric commitments verified. This
establishes the corrected singleton artifact layout on both passing and failed
pair reports; it does not make incomplete comparisons pass. Public Mac resolver
facts show registration, passing self-test, zero observed actual traffic and
reverse-query timeouts. Authenticated recovery establishes the construction
boundary above, without a new resolver-repair claim.

## Package cohort

The [package evidence note](PACKAGE_SIXTH_CI_EVIDENCE.md) retains the complete
source and format limits. The candidate uses `complete-v3`; the frozen baseline
uses `complete-v1`. All three package jobs passed their 132 selected source
correctness tests; these overlapping selections are not additive.
Phase job `105323757499` passed. Format job `105323757176` retained two
frozen-baseline Composer package-count failures: 20 candidate cells completed,
18 baseline cells completed and two failed. Cardinality job `105323757509`
retained 12 baseline attempts censored at the unchanged 15-second whole-worker
limit: 72 offers, 36 candidate completions and 24 baseline completions.

All ten phase workers completed: two validation, six profiles and two registry
workers. Each reports one parse, one index and one evidence batch. Registry
workers each made 100 admitted GETs. Instrumented Guard-Python origin medians
were 42.3513% for protect and 54.2777% for the evaluator; Pydantic was zero.
Zero in-route crypto belongs to the explicitly preverified fixture.

Five protect pairs completed. Separate sixth-cohort baseline/candidate medians
were 8,765.804810/320.749072 ms wall and 7,750.150/312.036 ms CPU. Median paired
reductions were 96.3404978500% wall and 95.9716882649% CPU. These diagnostic
figures are not pooled with the fourth decision cohort or earlier measurements;
all qualification flags remain false. Complete-v3 correctness changes retain
their own source identity.

Public ZIPs were independently downloaded and hash-verified by the package
owner:

| Artifact | ZIP bytes | ZIP SHA-256 |
| --- | ---: | --- |
| 10513567494 format | 4,919 | e0613abab97300b80b5ebc08a67c76fdf79269a0a69ee297b48c29d125a5d753 |
| 10512522630 phase | 7,464 | 70ddb05c7c09190ea7aa66b7a2f89b3cb88dfd66c1d5934022a89ccbfb55fead |
| 10512678191 diagnostic | 11,730 | 32ff4b3ef0eeeb8c05b737428ed673fba53dcc65e9b8f4c5c500a68efa668e5d |

Nine producer encryption groups contain 331 files: 103 format, 34 phase and
194 diagnostic. Staging reports no missing files. No ciphertext recovery was
performed; successful producer retention is not independently recovered content.

## Scope and limits

The terminal census, individual job conclusions and retained commitments cover
this exact source. Unresolved narrow failure causes remain unresolved: no later
source repair is treated as an installed rerun, and no successful producer
upload is described as recovered plaintext without authenticated recovery.
All six failed workflows, skipped work and unoffered observations remain in
the manifest. This checkpoint establishes no new production native activation,
full installed qualification, human approval, completed merge or release.
