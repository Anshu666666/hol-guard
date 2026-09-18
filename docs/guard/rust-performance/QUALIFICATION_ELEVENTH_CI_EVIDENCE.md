# Eleventh installed qualification evidence

This records attempt 1 of [Native performance qualification run 35287995187](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995187), published source `23bef02c5edd2fb24dbfec768a9dbd5e80c2b31d`, tree `e3fa69336ff37d8e91add1ecd0a5a89b5cca35d9`, and actual PR merge `fb6112dd964df5b88e90e43e04229a4d6914f7e6` with the same tree. The source cutoff before publication was `224cca37a57ea4e068c0c586d2354c15abd887f0`, tree `7c4322a4c243c900bedf1365aa2194d888023f7b`. The frozen baseline remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`. Exact jobs, artifacts, source/runtime identities, failures and authenticated projections are retained in the [companion manifest](evidence/qualification-23bef02c/manifest.json). The [tenth record](QUALIFICATION_TENTH_CI_EVIDENCE.md) remains unchanged.

The workflow finished **14 successful, 11 failed and 2 skipped jobs out of 27**. All four immutable wheel builds passed. Only Linux completed both indexed arms and its aggregate. This is **smoke**, one index-zero baseline/candidate pair per platform. All full qualification and minimum-sampling flags remain false. Successful diagnostic collection does not override failed semantic, load, resource or side-scenario gates.

The three attribution scopes now execute before the contract corpora and headline measurements, as documented in [Attribution before corpus](attribution-before-corpus.md). The original offer counts, isolated fixture construction, filenames and deadlines are unchanged. This changes workload ordering and earlier cache warming; it is a new source cohort and is not pooled with older performance observations. Later failures still fail the block. The early order makes attribution available independently of those later failures; it does not establish their cause or repair them.

## Indexed collection and original failure boundaries

| Platform | Pair job | Baseline | Candidate | Aggregate job/result |
| --- | ---: | --- | --- | --- |
| Linux x86_64 | 105425729797 | Completed, 136 numeric values | Completed, 136 numeric values | 105427890637 / success |
| macOS ARM | 105425729877 | Construction failed; zero numeric offers | Completed, 136 numeric values | 105427890643 / failure |
| macOS Intel | 105425729857 | Construction failed; zero numeric offers | Later fixture startup failed; zero numeric offers | 105427890638 / failure |
| Windows x86_64 | 105425729875 | Registered-corpus setup failure; zero numeric offers | Normalized-corpus request failure; zero numeric offers | 105427890686 / failure |

Eight arm processes were offered: **three completed and five failed**. Completed final numeric aggregates retain **408 values**, with exact committed-byte and incremental-journal equality. All five failed arms retain zero numeric offers and zero observed numeric values; that says nothing about the cost of earlier constructor, attribution or corpus work.

The normalized corpora retain **1,598 completed cases**: 386 on each Linux arm, the ARM candidate and Windows baseline; 26 on the Intel candidate; and 28 on the Windows candidate. The registered corpora retain **228 validated cases**: 62 on each Linux arm and the ARM candidate, plus 42 on the Windows baseline. These are semantic-corpus counts, not headline timing samples. The Windows baseline's explicit unsupported source-reference denial scope remains non-comparable content review; this attempt does not turn refusals into reviewed content.

Both Mac baseline original block failures retain the construction deadline and `socket.getfqdn` → `HTTPServer.server_bind` stack. Earlier attribution attempts on those arms also retain their own failures and partial cold preparation. Their outer worker timeout/containment flags are false; the inner constructor deadlines still fail. No OS resolver root cause or baseline repair is inferred.

The Intel candidate completes all early attribution and 26 normalized cases, then a later fixture fails at the original startup deadline. Its sampled stack is in `hook_process_runner.wait_for_capacity` through service startup. That locates a waiting boundary; it does not prove worker leakage, contention, a specific capacity owner or a new ordering defect.

The Windows baseline completes 386 normalized cases, then offers 43 registered cases and validates 42. It fails `codex.PreToolUse.unavailable.small` at `native_slo_workloads.validate_setup:847`, with `native_request_unavailable` unproven. The Windows candidate offers 29 normalized cases and completes 28. Its failed case is `claude-code/PreToolUse/review/small`, stage `delivery`, HTTP status not returned and route unknown. The public `RuntimeError` at `native_slo_session._request:238` is the original wrapper around an `OSError` or `ValueError` from the authenticated Claude request. The retained envelope does not identify the wrapped cause, so neither a timeout nor a pipe/ACL/native-evaluator cause is asserted.

The Linux pair producer's `comparison_available=false` is distinct from the Linux aggregate's available comparison. Other aggregates retain incomplete-pair failures. Even the Linux comparison is smoke and does not pass the full sampling or program gates.

## RSP-025: preparation, first hook and warm identity observations

All four candidate platforms now complete the separately identified fresh-process lifecycle and prepared-resident scenarios. Linux and Windows baselines also complete both: **six successful arms, 18 cold-lifecycle diagnostic hooks and 18 separate prepared-resident hooks**. Each successful scenario records three planned, offered, started and validated requests, zero unknown/not-started/unoffered requests, and complete/drained observers. Every successful cold child exits zero with no startup, returned or cleanup failure. The same ordinary 1,024-byte benign Claude `PostToolUse` HTTP request supplies each observation; these are not registered-launcher startup or all-route measurements.

Both frozen Mac baselines attempt preparation but offer no identity hook. Each retains three planned-but-unoffered cold hooks and zero started/validated hooks, an incomplete observer, and the original constructor failure. Their partial child journals retain real preparation work: ARM two publication status calls hashing 10,095,264 bytes in 63.282292 ms; Intel two preparation calls hashing 10,825,832 bytes in 119.459154 ms. Intel additionally records a separate cleanup call hashing 5,412,916 bytes in 27.967078 ms. No lifecycle-through-first-return value exists on either arm. The zero offered-hook counts do not mean zero preparation cost.

The [cold observer boundary](cold-hook-identity-observation.md) begins after interpreter imports and private journal admission, before observer installation. It includes installation, ordinary construction/preparation, scheduling and the first handler through return. The ordinary constructor may prepare the resident before that first hook. No cache or live proof is cleared, no constructor is bypassed, and neither cold OS/executable cache nor import-time identity work is claimed. Observer/journal overhead remains inside the original budgets. This inclusive lifecycle interval is not exclusive identity time and must not be added to overlapping startup intervals.

For all six successful arms, each hook contains exactly one observed status call. Detailed records preserve calling-thread CPU, inclusive status wall time, full executable bytes hashed, capability hit/miss/subprocess counts, live-proof calls/hits, handler intervals and actual HTTP/request-call intervals. There are no unfinished, nested, unassigned, crossing, ambiguous-cache or mismatched-identity calls in these complete observations. Preparation in the table is grouped by phase as well as owner; cleanup is separate.

| Platform/arm | Preparation status calls | Preparation hashed bytes | Preparation status wall ms | Hook status wall ms: first / warm / warm | Hook hashed bytes: first / warm / warm | Lifecycle through first handler return ms |
| --- | ---: | ---: | ---: | --- | --- | ---: |
| Linux x86_64 baseline | 2 | 12,610,304 | 24.525536 | 7.569525 / 7.730288 / 7.508785 | 6305152 / 6305152 / 6305152 | 3128.811306 |
| Linux x86_64 candidate | 5 | 48,967,040 | 50.126951 | 2.959279 / 2.007715 / 1.850349 | 0 / 0 / 0 | 3317.011655 |
| macOS ARM candidate | 3 | 32,318,304 | 44.628499 | 10.333167 / 7.566542 / 8.466250 | 10772768 / 10772768 / 10772768 | 4430.462417 |
| macOS Intel candidate | 3 | 33,832,044 | 250.751551 | 57.083775 / 67.750817 / 57.376455 | 11277348 / 11277348 / 11277348 | 15565.447678 |
| Windows x86_64 baseline | 2 | 10,878,976 | 43.437200 | 9.182300 / 8.972000 / 8.952300 | 5439488 / 5439488 / 5439488 | 5136.960000 |
| Windows x86_64 candidate | 3 | 33,987,072 | 84.005600 | 16.555200 / 15.674800 / 16.383200 | 11329024 / 11329024 / 11329024 | 6484.421100 |

Linux candidate preparation has five status calls, four full validations and one live-proof reuse. Its three hook calls each reuse a verified live proof, hash zero executable bytes and independently hit the capability cache. Those zeros are observed counts supported by successful proof hits. Two additional Linux candidate publication calls occur during cleanup; they are retained outside the preparation table. Other observed candidate platforms fully hash the executable on every hook despite capability-cache hits. Live-proof eligibility remains Linux-only at this source; absent/noneligible proof support is not an eligible cache miss. The frozen baseline lacks the corresponding live-proof API.

These actual candidate observations provide the requested status-call, full-hash-byte and warm/lifecycle latency evidence across four platforms at the stated request scope. They do not establish a benefit threshold, a cold resident at the first handler, whole-tree CPU, platform cache equivalence or full qualification. Task-status adjudication is separate from this evidence record.

## RSP-008: explicit config bindings and phase boundaries

All four candidate phase scenarios validate eight instrumented hooks each: **32 candidate hooks** across small and maximum-supported-inline allow/block cases. Authenticated phase journals retain full aggregates that were depth-truncated in public block reports. The config observer now checks the module binding plus the imported bindings in hook worker, daemon server and native review continuation.

An independent source/data review confirms eight finished candidate phase groups and **32 complete binding windows**: four bindings per group, with foreground context observed. All report zero config calls in those windows, explicitly distinguished from unsupported, uninstalled, in-flight or discarded observation. Hashing, JSON, admission, queue, submission and response aggregates remain numeric. Nested binding entries are not additive lookups. This observes those declared bindings during the selected foreground route; it is not universal proof that every possible configuration path is cost-free.

Native connection and resident-edge evaluator spans are separate, already authenticated observations from the dedicated native profile. Those diagnostic spans are not pooled into Python phase timing or this run's headline distributions. The [Python phase contract](python-phase-attribution.md) retains instrumentation scope and missingness. Literal measurement coverage and full performance acceptance are separate decisions.

Linux and Windows baseline phase summaries fail with cleanup-not-acknowledged; Mac baseline phase construction fails. The former exception is raised only after the fixture invokes its containment helper and confirms the direct child has exited, closes streams/readers and closes any Windows job. It is not evidence that no termination was attempted. The helper's successful kill-group/job call and direct-child poll do not independently measure descendant-zero or system-wide resource quiescence. No claim of zero residual-resource overlap or causation of later failures is made, and the failed phase gate stays false.

## Load, resources and remaining side scopes

All retained c64 tail/load gates below fail. Overloads are subsets of completed responses. Offered-rate `completed + failed = admitted` and `admitted + generator_dropped = 1,280` remain exact; failed and generator-dropped work does not disappear.

| Platform/arm | Closed completed/offered | Closed errors | Closed overloads | Closed native evaluated allows | Offered-rate completed/failed/admitted | Generator drops | Offered-rate overloads | Offered-rate native evaluated allows |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux x86_64 baseline | 64/64 | 0 | 27 | 37 | 337/3/340 | 940 | 202 | 135 |
| Linux x86_64 candidate | 64/64 | 0 | 21 | 43 | 243/4/247 | 1033 | 63 | 180 |
| macOS ARM candidate | 64/64 | 0 | 0 | 64 | 131/284/415 | 865 | 8 | 123 |

Linux baseline/candidate steady-state resources have 19/13 samples, below the original 30-sample minimum. Their capacity windows contain 48/58 samples but preserve three/one unavailable samples and false resource gates. ARM candidate steady/capacity windows have 10/28 samples, general tree CPU is null, and reaped-descendant completeness is false with Darwin ambiguity/inventory/permission missingness. Null CPU is not zero. Intel and Windows have no final resource report because their later block failures precede that collection. No all-platform resource or saturation qualification follows.

All three completed arms retain failed mixed, priority-approval, priority-input, raw-UTF8 and registered-surface scopes. Candidate approvals retain `qualification_Codex_browser_continuation_unproven`; baseline approval retains its resolution failure. Input scopes retain the route mismatch. The raw-UTF8 failure maps to the actual registration-override check at line 100, separate from that diagnostic's intentionally unqualified design. Candidate registered-surface failure maps to its per-case route witness; baseline Copilot retains the unexpected `continue` projection. Exact failures and partial counts are in the manifest; none is rewritten into an expected success.

## Settings/Builder and nonpriority route smoke

| Platform | Settings job | Native completed cases | Native | Builder | Overall |
| --- | ---: | ---: | --- | --- | --- |
| Linux x86_64 | 105425729769 | 22 | Pass | Pass | Pass |
| macOS ARM | 105425729828 | 22 | Pass | Pass | Pass |
| macOS Intel | 105425729774 | 22 | Pass | Pass | Pass |
| Windows x86_64 | 105425729846 | 12 | Updated-stage readiness failure | Pass | Fail |

The Windows updated attempt returns no snapshot after **406 ms** against the unchanged 400 ms deadline, requesting revision 3 while the bounded before/after samples retain revision 2, generation 3 and unacknowledged state. Its 12 completed cases remain completed. Sampled publisher state/stack does not establish the reason for lateness. The other three native successes and four Builder successes do not override this attempt's failure or erase earlier settings evidence.

The companion remains fixed Cursor `beforeShellExecution`, global registration, small c1, with two timed observations per arm and benign/block preflight separate. Its eight jobs finish **4 success / 4 failure**. Eight arm processes were offered; six complete and two Mac baselines fail. **12 of 16 planned timed observations complete, with 12 separate validated preflight invocations**, for 24 completed registered invocations. Four Mac-baseline timed hooks were never offered, as their authenticated inventories contain no case/numeric journals after constructor failure.

| Platform | Tail pair job | Baseline timed | Candidate timed | Aggregate comparison |
| --- | ---: | --- | --- | --- |
| Linux x86_64 | 105425730039 | 2 | 2 | Available; all qualification flags false |
| macOS ARM | 105425729964 | Unoffered after constructor failure | 2 | Unavailable |
| macOS Intel | 105425730031 | Unoffered after constructor failure | 2 | Unavailable |
| Windows x86_64 | 105425730018 | 2 | 2 | Available; all qualification flags false |

Both Mac baseline recoveries retain the exact `construct_daemon`/`getfqdn` failure before offers. Windows succeeds in this attempt; that does not explain the different previous failure or prove a remedy. No eleventh sharing-violation or pipe-failure claim is made for this tail. Smoke does not meet the 1,000 nonpriority or 10,000 priority minima, five independent pairs, full route coverage or ordinary tail gates. Neither the full 320-job companion nor artifact transitions was offered.

## Custody and review limits

The manifest commits **24 API-hash-verified ZIPs, 6,950,754 bytes and 86 members**: 16 own ZIPs (four small build-provenance, four indexed pairs, four settings and four aggregates), plus eight tail ZIPs. All downloaded ZIPs and extracted members were independently rehashed against retained API/producer commitments. The four build metadata files separately bind native runtime/source identities without downloading wheel bundles for this audit.

All four indexed ciphertexts were authenticated with the authorized recovery key, exact source/run/attempt/manifest context and encrypted inventory, covering **127 private members**. Complete numeric files match their exact committed bytes and journal sequences. Early identity/phase evidence is retained even when no final block report exists. On those failed arms, binding claims name the authenticated parent/child records, public pair manifest and separate build provenance; an absent public block report is not claimed to exist.

All four tail ciphertext producer hashes were verified. Only the two failed Mac archives were authenticated/recovered, covering **16 private members**; their completed candidate numeric values match journals and sealed commitments. Linux/Windows tail ciphertexts were not decrypted. The tail summary commitment is 78,271 bytes, SHA-256 `3363149855a4fb00f94e256b1554aafe4313347d050c663ee75c1a0aa49d29c5`.

Public evidence contains finite numeric, status, source-bound failure and aggregate observations, not raw private request data, paths, keys or exception text. Independent reviewers check source, retained commitments and projected accounting without claiming duplicate archive authentication. No local performance workload, remeasurement, baseline patch, threshold change or remote retry produced this record. The separate Claude/native-client/scanner workflows and all prior cohorts remain separate evidence.
