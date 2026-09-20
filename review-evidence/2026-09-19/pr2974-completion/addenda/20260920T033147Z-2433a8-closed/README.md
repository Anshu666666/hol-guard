# PR2974 closed 2433a8 cohort and continuation

This is the closed hosted cohort for product `2433a8ce570f34f5ad3dbf23f3d7367267aad461`, not the current PR head. The PR advanced concurrently to `79c555fc2ac19b55f7cf585ab96480392c30a694` (tree `1bd2af0961603b185119969fe5dfbe24a25528d3`, parent 2433a8). That 70-file update is retained and under separate source/CI review. No 2433a8 pass is automatically transferred to it. The original eight-file follow-up remains unpublished, with its own complete validation and a clean content merge onto the new head. Later source and results require a new additive record.

Observed cutoff: 2026-09-20 03:31:47 UTC.

Read [PRD-checkpoint.md](PRD-checkpoint.md), [TODO-current.md](TODO-current.md) and [TAKEAWAY.md](TAKEAWAY.md). The full original 144 task objects and 119 evidence catalog objects remain unchanged and are verified in [preservation.json](preservation.json). No task status is promoted.

The 2433a8 normal cohort is terminal: **188 checks, 164 successful, 19 skipped, 5 failed**. All 96 main pytest shards passed. Failures are Intel capacity, the Sonar job and external Sonar gate, Greptile at 4/5, and Kilo's output-limit failure. Sonar identified five worker-thread assertion findings; the prepared test correction preserves their main-thread propagation. There are 55 review threads: 54 resolved and one current corpus-scope thread awaiting publication. Formal reviews contain no independent approval.

| Original 2433a8 run scope | Terminal result and its limit |
| --- | --- |
| Normal Linux | 100,000 requests/responses, 250,000 receipts, zero request errors, 21,084 health checks with zero failures, one stable resident; reported RSS growth 2.7105%. Stress p95 544.63 ms is below its separate 4,500 ms ceiling and does not meet the original installed-launcher target by substitution. |
| Normal Windows | Ten real storage controls, all five normal resident tests, and installed default-auto 21/21 decisions plus 21 committed receipts pass. No historical journal-permission cause is inferred. |
| Normal Mac ARM | All 21 resident controls and original normal smoke pass; default-auto has 21 decisions and 21 committed receipts. This is still smoke. |
| Normal Mac Intel | All 21 resident controls and default-auto pass; capacity 16 has 13 resident routes and three native_fail_safe routes; all 16 delivered responses allowed. The later isolated diagnostic attributes the reproduced failures to the flush timeout setter. |
| Isolated Linux paired | Both arms and a comparison complete, but full qualification is false. Actual installed warm/c16 latency gates fail in addition to intentional smoke sample minima. Cline/nonobject daemon-only route attribution, mixed contention and approval supplemental gates remain failed. |
| Isolated Windows paired | No completed comparison: original-baseline setup fails; candidate Cursor afterShellExecution block 256 KiB returns native_request_invalid_json. Ollama later misses 400 ms at 406 ms; original-baseline rollback is unaccepted. |
| Isolated Mac paired | Both baseline arms fail DNS construction. ARM candidate fails batch-route validation; Intel candidate fails priority policy semantics. No completed comparison or accepted original-baseline rollback. These are distinct from normal Intel capacity. |
| Isolated Linux observer | All 13 persistence checks pass, with 600 completed/bound hooks and 605 committed receipts. Mixed resource coverage fails on four unavailable polls and one descriptor denial despite 262 valid samples. Workspace has six passing and nine failing cells. Phase export has explicit loss and no guaranteed complete final tail. |

The source security scan covered 1,341 commits and found no leaks. All three CodeQL language analyses passed; that does not establish zero historical alerts. Full signing, frozen-package qualification, canary proof, fresh requested review score and genuine independent last-push CODEOWNER approval remain open.

The publication manifest binds every added file. Binary archives and executables remain represented by verified artifact IDs, byte counts and hashes; their omission from this text packet does not change the original artifact evidence. This record does not claim implementation completion, qualification, approval, merge, activation or release.
