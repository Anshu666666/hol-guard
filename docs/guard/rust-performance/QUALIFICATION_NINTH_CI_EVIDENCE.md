# Ninth installed qualification evidence

This note records the original attempt of [Native performance qualification 35275855862](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855862) for source `d33f64d5fb86a3f2baa6848382ce763e2ed9fc59`, tree `0a40e2ebd6515094b5ce6b92c21a5fde3d056f40`. The pull-request merge `009c7253ce2e132bffaea837b23b0a36b9bc16c2` has that same tree. The installed baseline remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`. This is the single-pair **smoke** plan: it does not meet the five-run sample minima or qualify a performance, platform, release, or whole-program gate.

The [machine-readable manifest](evidence/qualification-d33f64d5/manifest.json) retains job identities, artifact API commitments, verified ZIP/member hashes, authenticated indexed archive projections, the separately reviewed tail custody record, installed runtime/package/wheel identities, failures, and exact missingness. Neither earlier successful runs nor unrelated scanner/profile experiments replace an observation in this attempt. Task statuses, baseline bytes and deadlines are unchanged.

Custody covers 12 indexed/scenario/aggregate ZIPs (10,064,944 bytes; 44 members), plus the eight tail ZIPs described below: 20 outer ZIPs and 10,141,328 bytes in total. All four indexed ciphertexts were authenticated in memory against their exact receipt contexts; all 146 member commitments are retained, public/private pair manifests agree, and all six completed numeric files match their committed hashes, sizes, series counts and exact journal values. The identity journals match the public observer reports and retain separately projected HTTP spans. Raw private payloads and recovery keys are not published. Tail authentication is narrower, as stated below.

## Indexed collection and missingness

The workflow is terminal: **27 jobs = 15 success, 10 failure and 2 skipped**. The four immutable builds passed. Linux and Windows indexed pair and ordinary aggregate jobs pass smoke collection; both Mac pairs and aggregates fail because their baseline arm is incomplete. The two skipped jobs are the unselected artifact-transition and second tail-group jobs. Each pair offers baseline then candidate on its own runner; a contained baseline failure does not erase its independently attempted candidate.

| Platform | Pair job | Baseline | Candidate | Completed headline numeric values |
|---|---:|---|---|---:|
| Linux x64 | 105387928206 | Completed | Completed | 272 |
| macOS ARM64 | 105387928225 | Constructor deadline at `socket.getfqdn` | Completed | 136 |
| macOS Intel | 105387928220 | Constructor deadline at `socket.getfqdn` | Completed | 136 |
| Windows x64 | 105387928407 | Completed | Completed | 272 |

Each completed block has 136 values in 38 series. The six completed blocks above retain **816 values, 2,316 completed normalized daemon cases and 372 separately validated registered priority-launcher invocations**. No interrupted arm retains a partial numeric value in this attempt. These are accounting totals across distinct series and arms, not a pooled latency distribution. Both Mac baseline numeric journals have zero offered and observed values; their new identity scenario was never reached. Zero offered observations do not mean zero latency or zero CPU. Their bounded failure stacks identify `HTTPServer.server_bind` through `socket.getfqdn` within `construct_daemon`. The frozen baseline remains unmodified; candidate numeric binding and runner conditioning do not convert the failed baseline into a comparable success.

The ordinary aggregate jobs are Linux 105393932484, Windows 105393932487, ARM 105393932490 and Intel 105393932542. Linux/Windows retain `comparison_available=true`; Mac aggregates retain `pair_collection_incomplete`. All four sampling and qualification flags remain false. Windows baseline source-reference support is absent: 55 declared normalized denial cases pass their fail-closed contract, while full-content review and identity verification remain missing. Candidate Windows full source review is separately supported. The comparison explicitly excludes incomparable source-reference semantics and timing; baseline refusal is never counted as content review.

Completed collection does not mean all side scopes passed. Each of the six completed blocks retains its own side-scenario results. All four candidates fail the Codex browser-continuation witness, malformed priority-input route witness, raw-UTF8 registration diagnostic and broader registered-surface corpus. The UTF8 source diagnostic is intentionally never a full transport qualification; its registration interruption is an additional observed failure. The candidate mixed scenarios also remain false: Linux retains 600 delivered binding matches but fails evidence-drop/resource coverage checks; ARM retains 599 matches and fails control, complete-binding, receipt/drop/resource checks; Intel retains 599 matches and fails completion/control/drop/latency/resource checks. Windows also fails completion, offered-work retention, control, complete binding, receipt/drop, latency, resource and RSS checks. None is promoted by block completion.

All four candidate c64 closed-loop batches complete 64 offers with zero recorded errors, but overload responses remain explicit: Linux 6, ARM 4, Intel 16 and Windows 28. Thus their native evaluated-allow counts are 58, 60, 48 and 36 respectively, not 64. The c64 offered-rate batches retain 1,280 attempted offers each: Linux admits/completes 174 and drops 1,106 at the generator; ARM admits 380, completes 172, fails 208 and drops 900; Intel admits 185, completes 139, fails 46 and drops 1,095. Completed overload responses are 4, 40 and 56 respectively. Windows admits 208, completes 199, fails 9 and drops 1,072; its 145 overload responses and 54 native evaluations are distinct from 74 delivered allows. These failures and drops remain failures; `accounted=true` means conservation, not a passed load contract. Warm/cold/recovery/run sampling minima stay false. The Windows aggregate records its steady-state-resource sample gate true, while its mixed-resource check and overall sampling/qualification gates remain false; this is not an all-platform resource pass. Mac resource CPU is unavailable (`darwin_reaped_cpu_ambiguous` and other observed collection failures), never an inferred zero; successful memory observations do not establish complete process-tree CPU.

## Actual evaluated-hook identity observations

The new RSP-025 side scenario creates a separate normal daemon fixture, finishes ordinary resident preparation, confirms there were no earlier hook routes in that fixture, then observes exactly three actual 1,024-byte Claude PostToolUse HTTP requests. Row zero is `first_hook_prepared_resident`; rows one and two are `warm_hook`. It does not clear caches, retire proofs, restart the resident, or contribute samples to a headline or launcher series.

All six reached identity scenarios pass their exact three-offer checks: planned/offered/validated/request-started are three, unoffered/not-started/unknown are zero, and the observer is complete and drained with no unexpected hook. Every row has one status lookup, one capability call, a capability-cache hit, no capability subprocess, no ambiguity and a returned hook. The authenticated case journals also preserve actual HTTP/request-call spans separately from handler/status spans.

| Arm | Executable SHA-256 bytes on each hook | Validation calls per hook | Retained live-proof hits/calls | Status wall milliseconds, first/warm/warm | Handler milliseconds, first/warm/warm |
|---|---:|---:|---|---|---|
| Linux baseline | 6,305,152 | 1 | Unobservable in frozen source | 8.530 / 8.203 / 7.363 | 54.217 / 29.161 / 25.714 |
| Linux candidate | 0 | 0 | 1/1 on each hook | 3.956 / 2.849 / 2.768 | 53.526 / 16.130 / 20.641 |
| ARM candidate | 10,774,224 | 1 | 0/1 on each hook | 8.823 / 16.474 / 12.280 | 76.116 / 76.805 / 69.376 |
| Intel candidate | 11,277,348 | 1 | 0/1 on each hook | 51.701 / 32.790 / 36.859 | 166.045 / 82.773 / 79.055 |
| Windows baseline | 5,439,488 | 1 | Unobservable in frozen source | 11.164 / 10.116 / 9.269 | 115.820 / 372.371 / 152.017 |
| Windows candidate | 11,323,392 | 1 | 0/1 on each hook | 16.105 / 16.225 / 18.003 | 150.437 / 121.512 / 59.331 |

These few values describe these requests; they are not percentiles, a speedup acceptance test, or independent cold starts. Exact integer nanoseconds, calling-thread CPU, bytes and counts are retained in the manifest. Baseline proof observability is false; the absence of its optional function is not recorded as a proved cache miss.

The platform difference has an explicit source explanation. At this exact source, `native_runtime_identity.py::live_native_identity` returns no proof on non-Linux platforms, and native-process attestation is likewise unsupported there. `native_runtime.py` then performs full executable validation. The observer's `live_proof_observable` field means that the function exists, not that the platform supports it. Thus the Mac and Windows misses are platform exclusions, not evidence of a stale eligible proof. Capability caching is separate and occurs after obtaining the executable identity; its hit cannot establish that executable hashing was avoided. The Linux hits establish successful retained proof for those particular requests, without identifying a specific filesystem or process-start marker in this report.

RSP-025's immutable acceptance asks for status lookups, executable bytes hashed and latency for **warm and cold hooks**, distinguishing capability and digest-cache behavior. This report supplies actual prepared-first/warm observations on the reached arms. It does not measure constructor/preparation hashing, an unprepared cold hook, a cold executable/capability/OS cache, fresh launcher startup or complete process-tree identity CPU. Every report retains `cold_resident_measured=false`, `headline_timing_eligible=false` and `cache_state_modified=false`. There are 18 validated side-scenario requests across six reached arms. The two failed Mac baseline blocks never offer their possible three requests each; these six are unreached, not observed zero-cost hooks. A separately identified cold-hook profile remains necessary; neither the prepared first hook nor another test count can substitute for it.

## Explicit nonpriority route smoke

The fixed Cursor `beforeShellExecution` global-registration workload retains two semantic preflight invocations and two timed invocations per completed arm. Linux and Windows pair and aggregate jobs pass collection; both Mac pair and aggregate jobs fail because their frozen baselines do not construct. Both Mac candidates complete.

| Platform | Pair job | Aggregate job | Completed timed / planned | Collection result |
|---|---:|---:|---:|---|
| Linux | 105387928520 | 105388890457 | 4 / 4 | Passed |
| Windows | 105387928493 | 105388890502 | 4 / 4 | Passed |
| ARM | 105387928518 | 105388890387 | 2 / 4 | Failed baseline; candidate completed |
| Intel | 105387928480 | 105388890448 | 2 / 4 | Failed baseline; candidate completed |

Six completed arms retain **12 timed observations plus 12 separate preflight invocations**. Authenticated recovery of only the two Mac tail archives proves that the four remaining timed offers were never reached, rather than partially timed or zero-valued. The public `worker_failed` outcome is preserved; the recovered `construct_daemon`/`getfqdn` cause is recorded separately. Linux/Windows aggregate `comparison_available=true` is a smoke comparison, while every tail-sampling, ordinary-performance and full-qualification flag remains false. The minimum remains 1,000 observations per nonpriority route/arm over five independent pairs; priority minima remain 10,000.

Tail custody includes eight verified outer ZIP API hashes, 38 members, 76,384 ZIP bytes and four verified ciphertext commitments. Only the two Mac tail ciphertexts were authenticated and recovered for this audit (16 private members); Linux/Windows ciphertexts remain unrecovered. The exact candidate raw values match their journals in those two recovered archives. The finite tail projection is independently source-bound and its hash is included in the manifest.

## Installed command settings scenarios

Linux job 105387928167 and ARM job 105387928170 pass all 22 native Ollama settings cases plus the Builder check. All four Builder subchecks pass. Windows job 105387928305 and Intel job 105387928287 fail the original bounded native-readiness requirement; their top-level outcomes remain false.

Windows completes two initial native cases, then the enabled revision-one preparation returns no snapshot after 422.0 ms. Its cached publisher remains on revision zero/generation one without an ACK. The sampled background stack includes the Windows SID API-binding path during committed-authority reading. Intel completes 12 native cases through enable, approved retry and disable, then the updated revision-three preparation returns no snapshot after 433.007 ms; its cached state remains revision two/generation three without an ACK. Its sampled stack includes policy-integrity database connection work. These samples locate work underway; neither proves that a particular call consumed the interval or caused the miss. No cache optimization, retry, readiness increase or authority change follows from this evidence.

Both failures preserve the original 400 ms readiness gate, completed-case progress and exact runtime/wheel/package identities. The earlier eighth all-platform 22-case success remains historical evidence and is not rewritten. Settings-control update/rollback is not a package downgrade, release-signing, interactive enrollment, or native v3/v4 approval-consume claim. All ninth timing, cold identity and remaining installed acceptance limits stay explicit.
