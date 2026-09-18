# Foundation a001: terminal hosted evidence

All 25 workflows for PR #2951 head `a001b2691f481b7b5a66dd14d68e48d61c44cb78` are complete and successful. The complete check inventory remains 160 successes, 19 skips, and three failures across 182 distinct check IDs. Workflow success does not resolve the separate CodeQL security and review gates.

The collection ran from `2026-09-18T08:36:05Z` to `2026-09-18T08:46:42.010934+00:00`. API pages use `per_page=100`; exact totals and unique IDs were checked across both check pages and both CI job pages. Raw API response strings and decoded job logs are retained with lossless gzip and both compressed and decoded SHA-256 values. Previously published cdd and 26cd interim evidence is unchanged.

| Population | Terminal result |
| --- | --- |
| All workflows | 25 successful |
| All checks, including original attempts | 160 success, 19 skipped, 3 failure |
| [Main CI](https://github.com/hashgraph-online/hol-guard/actions/runs/35275504115) | 114 distinct jobs: 111 success, 3 skipped |
| [Native wheel CI](https://github.com/hashgraph-online/hol-guard/actions/runs/35275503985) | Linux, Windows, Intel macOS, and ARM macOS successful |
| Desktop contract CI | Successful |
| Sonar | Quality gate passed: 0 new issues, 0 security hotspots, 81.4% new-code coverage |

## Exact installed identity and scope

All four downloaded ZIPs match GitHub's artifact digests. Every embedded runtime binary matches its wheel manifest's size and SHA-256. Each manifest identifies test-merge build `4631c7098bd229cc164d2408a32191331492adcc`. Its tree is exactly `24e28be411272ad055f47012603d35e0394de67b`, equal to the published a001 tree; its parents are release base `4b89e0d2d496a85f04922b2e019a4aea15326bb9` and a001. These receipts therefore identify the actual tested source. ZIPs remain available through the artifact links in the manifest; verified JSON members and embedded runtime manifests are retained here without duplicate wheel binaries.

Each host records 21/21 native-resident default-auto decisions and zero fail-safe decisions. Linux and both Macs additionally pass the real generated Pi extension's four output-preserving native routes, six rejecting malformed-result cases, and one preserving observe-mode case. Windows has no Pi, installed-SLO, or soak report in this artifact. The old artifact-evidence field `windows_waiver: validated by the platform matrix` is not accepted as proof; the separate Windows job and its actual default-auto receipt provide the stated Windows evidence.

## Linux soak and older foundation contract

Linux job `105385354510` completed naturally at `2026-09-17T21:51:59Z`. Its enforced soak step ran from `21:17:12Z` to `21:51:54Z` (34 minutes 42 seconds). The final report records 100,000 requests and responses, 250,000 receipts, 24,198 health checks, zero request errors, zero health failures, and zero transient health failures. One daemon remained stable. The p95 was 617.98 ms, maximum 850.31 ms, RSS growth 0.085565, maximum 64 threads, and maximum 192 file descriptors. Both `passed` and `soak_passed` are true.

The installed SLO results retain the older foundation smoke contract: installed p95 and 16-way p99 ceilings are 1,000 ms, and the 64-way wave has no latency ceiling. The Linux 64-way report includes 30 fail-safe and 32 overload outcomes; ARM reports 29 fail-safe and 29 overload; Intel reports 32 and 32. These two counters are retained as reported and are not summed into an invented disjoint partition. Intel 64-way p99 is 1,596.86 ms. The reports pass their older contract, but they do not establish the implementation's strict capacity accounting, zero-error performance gates, required populations, or full release qualification. No acceptance threshold changed.

## Security and independent review remain open

The external CodeQL check `105385218227` fails with eight new high-severity alerts and eight annotations, although the CodeQL Actions workflow succeeded. Kilo check `105385045811` fails because its model output limit was reached. No alert was dismissed, no query suppression was added, and no review was submitted in this collection.

Original Gitleaks job `105385031447` failed before scanning: installation of pinned 8.24.2 encountered `sum.golang.org` HTTP/2 `INTERNAL_ERROR` while verifying two module checksum tiles. Its original log SHA-256 is `8d6417fca31a4b59e2a1479031760d54bd9a5b6689011a65582d35594af96996`. The previously authorized single retry, job `105386994289`, succeeded with pinned 8.24.2 over `4b89e0d2d496a85f04922b2e019a4aea15326bb9..a001b2691f481b7b5a66dd14d68e48d61c44cb78`, scanning 1,254 commits with no leaks. Its log SHA-256 is `bbf917035196670ca031e26e843d3496b9adac5ed043d84eb35ae05444c0038f`. The three other attempt-2 job records have identical start/end times, runner IDs, and steps to their original executions; they are carried-forward records, not three further reruns. All eight job records are retained. No further rerun occurred.

PR #2951 remains open, non-draft, unmerged, and `mergeable_state=blocked`, with existing squash auto-merge enabled. All 54 review submissions are retained: 52 COMMENTED and two DISMISSED, with no active approval. The 43 returned review threads include nine unresolved. The existing review request is for `deep-purple-boots`. The Greptile 5/5 comment and dismissed auto-approval explicitly refer to historical `e449594e86c717e66e14598a4130475de79c536f`; neither approves a001.

Active ruleset 14511015 requires strict `quality`, one approving CODEOWNER review, approval independent of the last push, dismissal of stale reviews, and resolved review threads. CODEOWNERS is `* @kantorcodes @deep-purple-boots`; the ruleset has no bypass actors and reports that the current user can never bypass. These gates remain unsatisfied. This terminal evidence does not complete the Rust migration backlog or authorize activation.

The prepublication evidence-label review renamed one derived review field to `mapped_commit_sha`; all nine values remain the same verified public Git commit. The original derived file, original manifest and failed scan are preserved losslessly in [the normalization receipt](../prepublication-evidence-labels-6c5/README.md). Raw GitHub review responses and all hosted outcomes remain unchanged.
