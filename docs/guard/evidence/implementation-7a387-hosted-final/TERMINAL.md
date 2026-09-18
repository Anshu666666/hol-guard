# PR 2954 terminal hosted evidence for 7a387

PR [2954](https://github.com/hashgraph-online/hol-guard/pull/2954) remains draft and unmerged at `7a387128e2cf2ec79b890dfebe2697e8a49eb45d`, against `release/3.2` at `4b89e0d2d496a85f04922b2e019a4aea15326bb9`. All workflows for this head have finished. The implementation is **not qualified for activation or release**. This read-only collection was completed on 2026-09-18; it preserves the terminal outcomes of the 2026-09-17 runs without reruns, cancellations, changed thresholds, or changed baseline artifacts.

The native wheel jobs built GitHub's test merge `95ba3911b8b68227510c034306554c8fb7f8a66d`. Its parents are the exact base and head above, and its tree is identical to the head tree, `1ccec336c8a3aff22a4500b8f8350ae8fee3a345`. Paired qualification separately built candidate `7a387` and frozen baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b`; all four platform build metadata records confirm these identities. The baseline remains unchanged.

## Terminal inventory

| Collection | Verified count | Outcome |
| --- | ---: | --- |
| Workflows for the exact head | 37 | 33 success, 4 failure; all terminal |
| Check runs, explicit `filter=all` | 206 across 3 pages | 171 success, 23 skipped, 12 failure; all terminal |
| Check runs, default `filter=latest` | 203 across 3 pages | 168 success, 23 skipped, 12 failure |
| Main CI jobs | 114 across 2 pages | 106 success, 6 skipped, 2 failure |
| Main CI artifact inventory | 194 across 2 pages | Complete metadata inventory; coverage archives were not all downloaded |
| Paired qualification jobs | 4 | 4 failure |
| Native wheel jobs | 4 | Linux failure; Windows and both macOS jobs success |
| Desktop contract jobs | 1 | Success |
| Normal CodeQL Actions jobs | 4 | Success; separate security check still fails |
| Immutable snapshot diagnostic jobs | 6 | 2 success, 4 failure; no clearance inferred from successful jobs |
| PR review submissions | 9 | All COMMENTED; no APPROVED submission |

The three additional entries under `filter=all` are earlier successful Gitar check runs with IDs `105387617729`, `105389506008`, and `105392209865`. They are not three additional independent approvals. Both API views are retained, so earlier snapshots with different live counts are not overwritten or treated as contradictory terminal results.

## Main CI, Desktop, and security

[Main CI run 35276260830](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260830) passed its quality, scheduling-sensitive, and Python compatibility jobs. Shard 20, job `105387963658`, failed `test_missing_command_can_only_be_blocked_through_real_resolution[codex]` at line 61 of `tests/test_native_slo_launcher_empty_approval.py`: the original assertion expected `result["state"] == "resolved"`, but observed `"failed"`. The shard retained **218 passed, 8 skipped, 1 failed in 45.87 seconds**. The assertion did not expose the controller's underlying failure details; this receipt does not establish a timeout, race, or persistence failure as its cause. Aggregate job `105389544025` failed because the tests dependency failed. Sonar and Sonar Guard were skipped, so this head has no fresh passing Sonar result.

[Desktop contract run 35276260739](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260739), job `105387531257`, passed. Its exact decoded log is retained.

[Normal CodeQL Actions run 35276260698](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260698) completed successfully, while security check `105387753376` still reports **11 new high severity alerts** and concludes failure. The original check output is retained. No alert dismissal or annotations-endpoint retry was attempted. [Snapshot diagnostic run 35276260889](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260889) has four failed jobs and two nominally successful jobs; its job results do not clear the normal security check. Source materialization and SARIF validity require the separate diagnostic audit.

There is no fresh Greptile 5/5 evidence in the captured PR reviews, comments, or checks. The Sonar bot comment last updated at 15:28:48Z on September 17 is historical and reports a failed gate; it cannot substitute for the skipped Sonar jobs at this head. The PR remains draft, and no approved review submission is present.

## Paired installed qualification

[Run 35276260804](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260804) finished with failures on all four hosts. All four original qualification ZIP archives were downloaded, verified against the GitHub API SHA-256 and byte size, and every JSON member was retained without newline or encoding changes.

| Platform / job | Baseline block | Candidate block | Terminal time, UTC |
| --- | --- | --- | --- |
| Linux / `105387531453` | Failed `codex.PostToolUse.benign.1m`, `reviewed_output_sha256` mismatch | Failed `omp.PostToolUse.block.max`, route mismatch | 2026-09-17 21:29:51 |
| macOS Intel / `105387531536` | Fixture construction deadline; stack in `socket.getfqdn` via `HTTPServer.server_bind` | Failed `codex.PostToolUse.benign.1k`, route mismatch | 2026-09-17 21:37:25 |
| macOS ARM / `105387531735` | Fixture construction deadline; same `getfqdn` stack | Failed `kimi.PostToolUse.benign.1k`, route mismatch | 2026-09-17 21:28:30 |
| Windows / `105387531744` | One completed block, with incomplete qualification and adverse scenario results | Failed `codex.PostToolUse.benign.1k`, route mismatch | 2026-09-17 21:43:59 |

Every candidate failure retained a 73-byte native error object without a valid edge receipt, despite `native_ready` status and an acknowledged publisher. The complete error digest is `7a692e19a92387993c84e2e640f8952bd51ef7e992631a891afb2a0f1050d84a`, which matches SHA-256 of the public enum `native_command_control_mutation_in_progress`. This identifies the reported error enum; it does not identify a lock holder or prove the historical scheduling sequence. Caller deadlines were not exhausted. Windows, for example, retained 2,890 milliseconds after a 47-millisecond call. All four pairs report `comparison_available=false` and `qualification_complete=false`.

The Windows baseline completed block contains 386 validated daemon corpus cases and 62 registered-launcher cases within its implemented platform scope. It explicitly reports `qualification_complete=false`, unsupported source-reference full-content review and identity verification, and failed mixed-contention and posture-transition scenarios. Completing that block does not establish a passing baseline qualification or any baseline/candidate comparison.

The installed offline secrets scanner now passes **all 28 cases on all four platforms**, including Windows. Every scanner report has `run_complete=true`; this closes the previous Windows fixture-name execution gap only for this scanner receipt. It does not change the paired, native review, or performance qualification result.

| Platform | Installed Ollama result | Retained readiness evidence |
| --- | --- | --- |
| Linux | Failure in `disabled`, after 10 cases / 3 phases | Revision 2; 0.031 ms; 400 ms budget not exhausted; publisher error unclassified |
| macOS Intel | Failure in `updated`, after 12 cases / 4 phases | Revision 3; 508.137 ms exceeds unchanged 400 ms budget; no publisher error reported |
| macOS ARM | Passed its installed Ollama report | Narrow feature result only |
| Windows | Failure in `enabled`, after 2 cases / 1 phase | Revision 1; 0 ms; 400 ms budget not exhausted; publisher error unclassified |

All four artifact-transition suites fail. The original baseline rollback rejects the candidate policy snapshot with `native_policy_snapshot_unknown_field`; native startup is not ready. The retirement verification then returns exit code 2 with 33 stderr bytes, SHA-256 `6dc34d5cdd1cb07a44699a7f9a4c43b15b7239016a864fc7c40524bc18e9d9fb`, and `verified=false`. Its earlier `already-stopped` diagnostic leaves authentication, acknowledgement, generation, locks, and serving shutdown as unknown. The hash-only receipt does not prove which cleanup condition failed. No verified expected-negative credit or candidate restoration follows. Each suite retains 3 of 7 required positive checks and 0 of 1 required expected-negative checks. Compatible stopped-artifact rollback passes its three phases independently; its success does not qualify the original baseline rollback or the full transition suite.

The Linux Claude launcher pilot retains three completed 30/30 cells, then fails the first native PostToolUse cell after 23 attempts and 22 completions. It completed **0 of 5 planned blocks**, excludes the incomplete cell from comparison, and reports `qualification_complete=false` and `activation_qualified=false`. Its native error digest matches the same public mutation-in-progress enum. No paired performance benefit is established.

## Native wheel receipts

[Native wheel run 35276260779](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260779) has a Linux failure and three successful platform jobs. All four wheel archive API digests and sizes were verified. The installed runtime identity SHA-256 and size on each platform were then matched independently to the actual embedded runtime bytes in the downloaded wheel. These builds use test merge `95ba391`, whose tree matches `7a387` exactly.

All four default-auto reports record 21 resident decisions from 21 normalized ingress cases, zero fail-safe decisions, zero one-shot decisions, and zero Python semantic decisions. Windows additionally records **3 receipt persistence failures**, despite all 21 receipts eventually processed and zero dropped or pending receipts. Therefore its default-auto result must not be described as zero persistence errors.

Linux and both macOS hosts each completed four real Pi output cases through the installed native daemon, including empty output, with four resident routes. Each also retained six rejecting negative cases and one observe-mode preservation case. These are the actual installed Pi receipts at this source tree.

Linux's SLO smoke failed the unchanged capacity route-conservation check at concurrency 64. It delivered 64 responses: 34 allowed and 30 explicit overloads, with zero transport errors. Counters attribute 22 responses to resident decisions and 12 to fail-safe decisions; native overloads remained zero. The diagnostic retains 8 detailed records out of 12 missing native outcomes and sets `native_details_truncated=true`. All 8 retained records match the 73-byte mutation-in-progress error described above; the other 4 records and the lock holder are not identified. Linux did not proceed to its soak after this failure.

Both macOS SLO reports say `passed=true`, `evidence_class=smoke`, and **`qualification_complete=false`**. Their 64-request batches have zero fail-safe responses: Intel records 32 resident responses and 32 explicit overloads; ARM records 38 resident responses and 26 explicit overloads. These smoke reports use their declared installed-adapter smoke thresholds and are not the original PRD's full performance qualification. Windows has its default-auto, identity, and independent Win32 lock interoperability receipts; this native wheel job contains no installed SLO report.

## Integrity and publication scope

`manifest.json` records every retained file's size and SHA-256; compressed records also include the original decoded byte size and SHA-256. Original UTF-8 BOMs, CRLF sequences, and JSON whitespace are preserved. Gzip uses a fixed timestamp, and decompression was checked against the original bytes. The source URL for each GitHub API response, decoded job log, and artifact JSON member is recorded. The complete API page inventories and distinct IDs were checked before counts were derived.

Only authenticated GitHub metadata, decoded job logs, and artifact JSON reports are published here. No private fixture journal, password, or signed download URL was copied. Content inspection found no signed-query URL, GitHub/cloud token shape, or private-key block in the retained text; this is a content inspection, not a replacement for the repository's pinned Gitleaks scan. Large wheel ZIPs remain available in the collected local artifacts and the original GitHub run, with API digests, sizes, and all member hashes retained in this manifest. No production changes, issue creation, review messages, alert mutations, reruns, or cancellations were made by this collector.
