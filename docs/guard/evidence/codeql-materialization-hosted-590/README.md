# Fresh materialized snapshot diagnostic at PR head 590ce013

Run [35330471687](https://github.com/hashgraph-online/hol-guard/actions/runs/35330471687),
attempt 1, completed successfully on 2026-09-18. All six new artifact ZIPs match
their GitHub API byte counts and SHA-256 digests and pass ZIP CRC checks. All
six SARIF files are complete, parseable outputs with successful execution,
collector-matching result counts, no external result-file references, and no
warning/error notifications.

This is a fresh execution of the two unchanged immutable cdd/d8 profiles.
It repeats **25 raw findings for cdd and 29 for d8**. It does not analyze the
current PR runtime, map these results to GitHub alert IDs, dismiss any alert,
or complete the migration/security qualification gates.

## Exact run, workflow context, and analyzed source

The run belongs to PR 2954 and uses event `pull_request`. GitHub's run/head
metadata identifies `590ce01334a7724f3f1349b2ab252110a5a268f5` on
`codex/release-3.2-rust-performance`. All six diagnostic manifests separately
record the workflow event's `GITHUB_SHA` as
`6981551052e75dfee9f372513177caed76df53a8`.
The retained Git-commit API response verifies that this synthetic merge has
parents `4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the exact `590ce013` head.

Each job's full log proves two actual checkouts: first the explicit PR head
`590ce013`, from which the collector and workflow definition are staged outside
the analysis root, then the immutable profile commit below. The event merge SHA,
definition checkout, and analyzed source are distinct recorded identities.

| Profile | Analyzed commit | Exact tree | Tracked files present |
| --- | --- | --- | ---: |
| Foundation cdd | `cdd14176ef0e0a258d4655c64210524d7047a257` | `efb4e859e19b5456f2bdfbac17b2de784adf36a7` | 3,902 |
| Prepared implementation d8 | `d8bde000de992009be3b2ed009347d2b3707ef0d` | `1967a2127a325ae340d313bf73e80c60abb4d1f6` | 4,793 |

Every manifest verifies the pinned commit/tree, clean tracked source, full
materialization, inactive sparse checkout, zero skip-worktree entries, zero
assume-unchanged entries, and zero missing tracked files. The working directory
and source root are the repository workspace, with staged collector and results
outside it. Each actual CodeQL database-init command in the full job log uses
`--source-root=/home/runner/work/hol-guard/hol-guard`.

The collector's original `extractor_invocation_log_verified: false` field is
preserved unchanged. This separate review verifies the database-init source-root
command directly from each retained full log; it does not rewrite that collector
field or invent a separate extractor invocation receipt.

The staged collector SHA-256 is
`eb1e69744e4679425f8658d2b2e7872fc8b9f463efb93e76111d04d89d7ad6f4`.
The staged workflow SHA-256 is
`6fb4ae07779a7c3f64864d9214797c4cbe27e5ae9354673de2f588628e43cf51`.
Both match the exact `590ce013` Git blobs and the previous completed diagnostic.

## Six fresh artifacts and actual analysis coverage

| Profile | Language | Job ID | Artifact ID | ZIP bytes | Successfully extracted files | Raw findings |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| cdd | Actions | 105553413428 | 10540429008 | 106,441 | 62 | 2 |
| cdd | JavaScript/TypeScript | 105553413533 | 10541017510 | 171,464 | 657 | 0 |
| cdd | Python | 105553413560 | 10541092642 | 192,396 | 2,605 | 23 |
| d8 | Actions | 105553413724 | 10540882700 | 116,668 | 64 | 2 |
| d8 | JavaScript/TypeScript | 105553413638 | 10540638652 | 182,297 | 681 | 0 |
| d8 | Python | 105553413680 | 10540663745 | 211,615 | 2,876 | 27 |

The actual CLI version/build in all six logs is **CodeQL 2.27.0 /
`b47b3e59262c95aff4eeb84ac72d09e25a9c37e9`**. Actual query-pack paths identify
Actions **0.6.35**, JavaScript **2.4.5**, and Python **1.8.10**. The pinned action
is `8aad20d150bbac5944a9f9d289da16a4b0d87c1e`.

The query selection remains `bundle_default_queries`. The unchanged diagnostic
ignore list contains only `src/codex_plugin_scanner/guard/stable_digest.py`;
findings involving that file remain in the raw SARIF. No result filtering or
new suppression is applied. Diff filtering is false, security-result upload is
`never`, and database upload is false.

Both JavaScript zero counts come from successful analysis with the stated
extraction counts and complete fresh SARIF; they are not missing-source outputs.
Python extraction includes production `src/` paths. The profiles analyze
Actions, JavaScript/TypeScript, and Python; the materialized Rust files do not
constitute a Rust analysis result.

## Exact comparison and reuse of the prior source review

The comparison baseline is completed run
[35326220494](https://github.com/hashgraph-online/hol-guard/actions/runs/35326220494),
attempt 1 at diagnostic head `54c0ce882f83edb341e148d5eae2817bdf0c6451`.
Its original evidence manifest SHA-256 is
`2592f645c9a3c952b7da20c46fd5ae97a42c7898c3871ffd6ac5a3fe5e505fa1`.
Every prior manifest record was rehashed, including decoded gzip bytes, before
using that review.

All **54 complete raw SARIF result objects** are equal between the two runs as
multisets, including every rule reference, location, complete flow, message,
fingerprint, suppression field, and property. No result field was removed or
normalized for this comparison. Cdd Python's result ordering differs;
`result-comparison.json.gz` maps every new result index to its exact prior index
and records a canonical SHA-256 of the complete result object. The other five
pairs retain the same result order.

The complete SARIF tool/rule definitions are equal. Extraction-notice and artifact
array ordering differs in all six pairs. Each notice's local index was first
verified against its complete artifact location, including URI and URI base;
each artifact's self-index was verified against its actual array position. Only
those verified local index numbers were then omitted for comparing these
extraction/metadata entries. All remaining fields and multisets match. This
normalization applies only to artifact/extraction metadata, not to findings.

The first two assembly attempts made stricter assumptions about those local
indices and failed. Their exact scripts and failure receipts are retained.
Their partial outputs were not accepted as completed evidence. The final
comparison resolves and verifies the references rather than dropping a source
path or changing a finding.

All **84 retained source blobs** used by the prior review were compared again
with `git show` at their exact immutable profile commits, byte for byte; their
sizes and SHA-256 hashes match. The source trees, materialization proofs,
query configuration, tool definitions, and complete results are unchanged.
`source-review-reuse.json.gz` therefore binds each new result to the existing
source assessment. It does not claim a new independent review or new runtime
experiment. The original review, full finding/source summaries, and exact source
blobs are retained here without rewriting their conclusions.

There are no added or removed raw findings relative to that completed diagnostic.
Existing source distinctions—including metadata/content hashing, guarded config
reads, synthetic fixtures, workflow-event reachability, and the retained legacy
password-hash compatibility path—remain the prior review's conclusions. The
legacy compatibility behavior is not newly removed or migrated by this run.
These raw counts still do not equal the historical GitHub new-alert counts of
8/11, and no alert-ID overlap or disposition is inferred.

## Retained records and limits

`hosted-summary.json` records per-job source, CLI, pack, source-root command,
artifact/SARIF digest, extraction count, and result count. `raw/` contains each
fresh ZIP, six complete job logs, terminal run/jobs/artifacts, the run inventory
page, and the workflow-event merge record. The original collector JSON and full
SARIF members are losslessly retained in `members/`. Existing collector fields
are preserved, including fields that do not claim verification.

`inspection.json.gz`, `result-comparison.json.gz`, and
`source-review-reuse.json.gz` provide the complete fresh result structure and
review mapping. `prior-review/` binds the earlier assessments to their verified
manifest; `source-blobs.json` identifies all exact source bytes. Reproduction
scripts and the unsuccessful comparison attempts are retained. `manifest.json`
hashes every file and the decoded bytes of every gzip archive.

No workflow dispatch, rerun, cancellation, alert mutation, query change, or
threshold change was performed during this collection. The six successful
snapshot jobs do not clear the current-runtime CodeQL workflow, the complete
PR CI cohort, an SLO gate, or an open migration requirement.
