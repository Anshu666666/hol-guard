# Tenth installed qualification evidence

This records attempt 1 of [Native performance qualification run 35283194680](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194680), with published source `095074cda6a751ffaf12b070ecc46a3091f12471`, source tree `04d79da9c1cf212cce263c202bfdd5b4350007e3`, and actual PR merge `9e85de6f42910785e7ba4b53198ddcc05672607c` with the same tree. The frozen baseline remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`. The [companion manifest](evidence/qualification-095074cd/manifest.json) retains exact job, artifact, build/runtime, workload, numeric, failure, and authentication commitments. Earlier attempts, including the [ninth record](QUALIFICATION_NINTH_CI_EVIDENCE.md), remain separate.

The workflow finished **12 successful, 13 failed, and 2 skipped jobs out of 27**. All four immutable wheel builds passed. Only Linux completed both indexed arms and its aggregate. The run is **smoke**, one index-zero baseline/candidate pair per platform; all full qualification and minimum-sampling flags remain false. A successful collection or available comparison does not certify the performance or side-scenario gates.

## Indexed collection and retained failure boundaries

| Platform | Pair job | Baseline | Candidate | Aggregate job/result |
| --- | ---: | --- | --- | --- |
| Linux x86_64 | 105411622991 | Completed, 136 numeric values | Completed, 136 numeric values | 105415371553 / success |
| macOS ARM | 105411622938 | Construction failed; zero numeric offers | Completed, 136 numeric values | 105415371533 / failure |
| macOS Intel | 105411622916 | Construction failed; zero numeric offers | Completed, 136 numeric values | 105415371572 / failure |
| Windows x86_64 | 105411623015 | Completed, 136 numeric values | Failed after 66 observed values, 50 validated | 105415371573 / failure |

Eight arm processes were offered. Five completed and three failed. The five final numeric aggregates contain **680 values** with exact authenticated aggregate/journal equality. The Windows candidate retains **66 additional partial values**, kept outside completed aggregates: 50 validated earlier values and 16 returned but unvalidated concurrent registered-launcher latencies. Both Mac baseline journals contain zero numeric offers. None of these counts pools the identity, phase, load, mixed, tail, or earlier-run diagnostics into headline series.

Each of the six arms that reached the initial corpora completed 386 normalized cases and validated 62 registered cases: **2,316 normalized completions and 372 registered validations**. These are semantic-corpus observations, not 2,688 headline latency samples. The Windows frozen baseline separately validates 55 declared platform denials. Its source-reference content review and identity-verification scopes remain unsupported, those refusal timings are ineligible, and no denial is treated as successful content review.

The exact original public Mac failures identify `qualification_fixture.daemon_fixture_deadline_at_construct_daemon` and retain `socket.getfqdn` → `HTTPServer.server_bind` in the constructor stack. Their outer worker `timed_out` and `containment_failed` fields are false; the inner construction deadline remains a failure. The independently attempted candidates complete. This is evidence about these baseline constructions, not proof of an OS resolver cause or a repaired baseline.

The Windows candidate failure is `native_slo_batch.validate_batch_routes:32`, whose exact tenth-source branch rejects a mismatch between native route counts and delivered decisions. Its numeric journal locates the interruption at the first `INSTALLED_LAUNCHER.c16.claude-code.PreToolUse` wave. All 16 returned latencies were retained before that validation failed. There is no retained per-result route/error journal for this wave, so the exact counter mismatch or underlying native/transport cause is unknown. Neither a timeout nor an executable startup failure is inferred. The original public outer timeout and containment flags are false. Later load, recovery and attribution scenarios were not reached on that arm.

The Linux pair producer retains `comparison_available=false`; the separate Linux aggregator makes the completed paired comparison available. These are different stages. Sampling, scope, performance, and program qualification remain false. The other three aggregate reports retain incomplete collection rather than producing partial comparisons.

## RSP-025: actual fresh-process preparation and hook identity work

The new [cold lifecycle observer](cold-hook-identity-observation.md) ran on five reached arms: Linux baseline and candidate, both Mac candidates, and Windows baseline. Each records **three planned, offered, started, and validated requests**, with zero not-started, unknown-start, or unoffered requests in that reached scenario. Every child exits zero; ready, observer completeness and drainage are true; startup, returned and cleanup failures are absent. The separate existing prepared-resident scenario also validates three requests on each of these five arms: **15 cold-lifecycle diagnostic hooks and 15 separate prepared-resident diagnostic hooks**.

Each identity request is the ordinary 1,024-byte benign Claude `PostToolUse` request through daemon HTTP. This is not registered-launcher startup timing or evidence for every event/payload route.

Both Mac baseline blocks and the Windows candidate block stop before either identity scenario. They have no identity measurements, not zero-cost identity work. In particular, **the candidate Windows cold/prepared scope is not measured in this attempt**.

The child journal begins after interpreter imports and private journal admission, before observer installation. Its lifecycle interval includes observer installation, ordinary construction, preparation, scheduling and the first handler through return. The ordinary constructor may prepare the resident before that first hook. No cache/proof is cleared, no constructor is bypassed, and this does not measure a cold executable/OS file cache or interpreter-import identity work. Instrumentation and private journal overhead occur inside the original deadlines. The lifecycle interval is not exclusive identity cost and must not be added to overlapping parent startup time.

Each of the three hooks has exactly one status call within its handler bounds. The authenticated detailed child records and independently recomputed totals show no unfinished, nested, unassigned, phase-crossing, ambiguous-cache, unknown-identity or mismatched-identity call. Preparation calls below are all publication-owned; the main preparation owner has zero observed status calls. Values are individual diagnostics, not percentiles or tail qualification.

| Platform/arm | Preparation status calls | Preparation hashed bytes | Preparation status wall ms | Hook status wall ms: first / warm / warm | Hook hashed bytes: first / warm / warm | Lifecycle through first handler return ms |
| --- | ---: | ---: | ---: | --- | --- | ---: |
| Linux x86_64 baseline | 2 | 12,610,304 | 26.796797 | 7.321557/7.472951/7.382330 | 6,305,152/6,305,152/6,305,152 | 3741.536929 |
| Linux x86_64 candidate | 5 | 48,967,040 | 62.342462 | 2.985445/3.443312/2.877502 | 0/0/0 | 4319.170340 |
| macOS ARM candidate | 3 | 32,318,304 | 156.458376 | 9.857417/8.300250/8.903958 | 10,772,768/10,772,768/10,772,768 | 4627.327500 |
| macOS Intel candidate | 3 | 33,832,044 | 130.911039 | 31.777448/31.224161/30.922247 | 11,277,348/11,277,348/11,277,348 | 7364.761085 |
| Windows x86_64 baseline | 2 | 10,878,976 | 64.154300 | 13.782600/12.950700/11.176900 | 5,439,488/5,439,488/5,439,488 | 8911.591700 |

The Linux candidate's five preparation status calls include four full validations and one live-proof reuse; those validations hash 48,967,040 bytes in total. Its three hooks each reuse a verified live proof and hash zero executable bytes, while independently hitting the capability cache. Zero hashed bytes here is a recorded count supported by successful live-proof hits, not a missing measurement. The Linux baseline and Mac/Windows observed arms still perform full hook validation. Darwin does not support that Linux live-attestation reuse at this source; a capability-cache hit does not avoid full binary hashing. The frozen baseline has no corresponding live-proof API, so absent API support is not an eligible proof miss.

Windows baseline additionally records **two publication-owned calls during cleanup**, distinct from its two preparation calls. Each cleanup call hashes 5,439,488 bytes. Owner totals include those cleanup calls; the preparation table deliberately groups by phase as well as owner and excludes them. All original per-call wall/CPU, status, full-hash bytes, capability hit/miss/process counts and live-proof observations are retained in the authenticated projection. Hook-handler and actual HTTP/request-call intervals are also retained separately.

This supplies the previously missing lifecycle-boundary observations on the reached arms and preserves the distinct prepared/warm diagnostic. It does not finish the candidate's four-platform RSP-025 measurement scope: Windows candidate is censored by the earlier concurrent route failure. It also does not imply performance benefit, an eligible Darwin/Windows attestation cache, or any global qualification closure. Task status changes are outside this evidence record.

## Load, resource and additional scopes

The closed-loop c64 and offered-rate c64 records conserve completed, failed, overloaded and generator-dropped work separately. All c64 tail/load qualification flags below remain false.

| Platform/arm | Closed completed/offered | Closed errors | Closed overloads | Closed native evaluated allows | Offered-rate completed/failed/admitted | Generator drops of 1,280 offers | Offered-rate overloads | Offered-rate native evaluated allows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux x86_64 baseline | 64/64 | 0 | 27 | 37 | 225/0/225 | 1055 | 85 | 140 |
| Linux x86_64 candidate | 64/64 | 0 | 7 | 57 | 177/0/177 | 1103 | 2 | 175 |
| macOS ARM candidate | 64/64 | 0 | 4 | 60 | 163/223/386 | 894 | 27 | 136 |
| macOS Intel candidate | 64/64 | 0 | 9 | 55 | 136/161/297 | 983 | 50 | 86 |
| Windows x86_64 baseline | 50/64 | 14 | 13 | 37 | 147/342/489 | 791 | 105 | 42 |

At offered rate, `completed + failed = admitted` and `admitted + generator_dropped = 1,280` in every listed c64 report. Overload counts are a subset of completed responses, not extra completions. A recorded timeout count of zero does not erase other failed work. The Windows candidate has no completed load-profile report; its earlier c16 failure is separate.

Both Mac candidate general process-tree CPU metrics remain **null/unavailable**, with false reaped-descendant completeness and explicit Darwin ambiguity/inventory/permission missingness. They are not zero CPU. Linux observed-tree CPU and Windows fixture-job CPU retain their distinct collectors and coverage semantics. Windows baseline steady and capacity resource sample gates pass with 39 and 112 samples respectively, while its load and mixed gates fail. Linux candidate has 10 steady and 55 capacity samples, with the capacity unavailable-sample count preserved and resource gate false. These do not establish all-platform full-tree resource qualification or the global mixed-workload requirement.

All five completed arms retain failed mixed, priority-approval, priority-input, raw-UTF8 and registered-surface scopes. Candidate approval records stop at `qualification_Codex_browser_continuation_unproven`; baseline approval retains its original resolution failure. Input scopes retain `priority_launcher_input_route_mismatch`. The raw-UTF8 interruption maps to the exact source's registration-override check at line 100; its deliberately diagnostic/unqualified design is separate from that real interrupted attempt. Candidate registered-surface failure maps to its per-case native-route mismatch assertion at line 273; no hypothetical root cause replaces it. Exact failures and all mixed actions/checks are retained in the manifest.

Python phase observations validate eight attempts on each reached candidate (Linux and both Macs). Baseline phase scopes retain cleanup-not-acknowledged failures. The full phase group reports recovered from authenticated journals supplement the depth-truncated public aggregates. Missing phases remain unobserved, not zero; these reports do not by themselves prove complete config-alias instrumentation or replace the separate native-client/evaluator profiler.

## Settings/Builder scenarios

| Platform | Job | Native completed cases | Native result | Builder | Overall |
| --- | ---: | ---: | --- | --- | --- |
| Linux x86_64 | 105411623049 | 22 | Pass | Pass | Pass |
| macOS ARM | 105411622952 | 22 | Pass | Pass | Pass |
| macOS Intel | 105411622939 | 2 | Enable-stage readiness failure | Pass | Fail |
| Windows x86_64 | 105411622998 | 22 | Pass | Pass | Pass |

All reports preserve exact candidate build identity. Intel retains `installed_ollama_native_readiness_failed`, expected revision 1 and 400.736 ms elapsed against the unchanged 400 ms deadline, with no returned snapshot and no timely ACK. The later diagnostic sample sees revision 1/generation 2 cached but still unacknowledged. Its sampled stack is in catalog-manifest/store authority reading; that does not prove contention, a database bug, or the cause of the deadline miss. Two completed cases remain completed; the remaining corpus is not reported as executed. The three successful targets and all four Builder subchecks do not override the Intel failure or alter the independently recorded earlier all-platform settings result.

## Supplemental nonpriority route smoke

The companion remains the fixed Cursor `beforeShellExecution` global route at two timed observations per arm, with benign/block semantic preflight separate. Eight tail jobs finish **2 success / 6 failure**. Eight arm processes were offered; five complete and three fail. **10 of 16 planned timed observations complete, with 10 separate validated preflight invocations**. Six timed hooks were not journaled as offered in the three failed arms. This is 20 completed registered invocations, not 20 timed samples.

| Platform | Pair job | Baseline timed | Candidate timed | Aggregate comparison |
| --- | ---: | --- | --- | --- |
| Linux x86_64 | 105411623205 | 2 | 2 | Available; all qualification flags false |
| macOS ARM | 105411623184 | Unoffered after constructor failure | 2 | Unavailable |
| macOS Intel | 105411623195 | Unoffered after constructor failure | 2 | Unavailable |
| Windows x86_64 | 105411623277 | 2 | Unoffered after original failure | Unavailable |

Both Mac baseline private archives independently retain `construct_daemon`/`getfqdn` startup failure before any case or numeric journal. The Windows candidate private failure originates at `safe_output_windows._raise_windows_error:196`, carrying raw Win32 code **32**, which means **ERROR_SHARING_VIOLATION**. The exact source passes `GetLastError()` into `OSError`, so Python labels this instance `BrokenPipeError` through its errno mapping; Windows' broken-pipe status is 109. The failure therefore does not prove a pipe disconnect. The precise failed caller, operation and conflicting handle remain unknown. The [Windows system error definitions](https://learn.microsoft.com/en-us/windows/win32/debug/system-error-codes--0-499-) support the code-domain distinction. Original public `worker_failed`, outer timeout false and containment false are preserved. No sharing/locking fix is inferred or applied by this report.

Neither two observations nor the fixed smoke selection meet the original 1,000 nonpriority or 10,000 priority minima, five independent pairs, full route/workload coverage or ordinary tail gates. The full 320-job companion and artifact-transition scenario were not offered.

## Custody, verification and limits

The manifest commits **20 API-hash-verified ZIPs, 9,587,454 bytes and 81 extracted members**: 12 indexed/settings/aggregate ZIPs (9,515,525 bytes, 44 members) plus eight tail ZIPs (71,929 bytes, 37 members). Each downloaded ZIP and extracted member was rehashed against its retained commitment.

All four indexed ciphertexts were authenticated with the authorized recovery key, exact run/attempt/source/manifest context and encrypted inventory, covering **142 private members**. Every completed indexed numeric aggregate matches its committed bytes and exact incremental journal sequence; the Windows candidate's partial journal remains separate. Only finite numeric, status, attribution and source-bound failure projections are published; raw request data, private paths, keys and exception text are not included.

All four tail ciphertext hashes were verified. The ARM, Intel and Windows tail archives were narrowly authenticated/recovered, covering **21 private members**; completed numeric values in those archives were compared with their journals. The Linux tail ciphertext was not decrypted, and no authentication/recovery claim is made for it. Its public report and ZIP/member/ciphertext commitments remain verified. The tail summary itself is committed at 77,166 bytes, SHA-256 `dce9539dda659ab0c3fc662d7dcf046ae0275bdb4f8ae19cbc2523fcbb5c79f5`.

An independent local reviewer rehashed the four indexed ZIPs, extracted members and ciphertexts and checked receipt/context, public/private projected equality, per-hook containment, per-phase owner accounting and exact source bindings for the cold evidence. That reviewer did not duplicate decryption; authenticated archive opening is the collecting owner's claim. No local performance workload, remeasurement, source mutation, threshold change, baseline patch or remote rerun produced this record.
