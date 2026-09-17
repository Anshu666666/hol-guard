# Historical RSP acceptance and dependency audit

This records the earlier isolated audit and proposed changes. Its corrections are integrated. Current source/status/GitHub observations are in [EXECUTION.md](EXECUTION.md) and [EXECUTION_LEDGER.md](EXECUTION_LEDGER.md). RSP-141 is now DONE after reconciliation; current counts are64 DONE/40 OPEN/40 BLOCKED. The dated evidence below remains historical.

All 144 original tasks were reviewed against root integration `fe7460946a2b41ab26bb8d46c9ce4958e6200a2c` on 2026-09-17. This proposal changes only the machine ledger and this audit report in an isolated documentation branch. Root owns the final `EXECUTION.md`, `EXECUTION_LEDGER.md`, `CURRENT_CONTRACT.md`, `TAKEAWAY.md`, artifact publication and status integration.

Proposed counts: **63 DONE, 41 OPEN, 40 BLOCKED, 0 DEFERRED**. These counts describe individual task acceptance; they are not a release-completion percentage. Installed qualification, unsupported Windows source review, independent review, package/program rollback and release remain incomplete.

## Requirements preserved

Every original `id`, `number`, `title`, `acceptance` and dependency-ID array is unchanged from the root ledger. All 144 titles, acceptance strings and dependency-ID arrays were also compared to the original TODO. The PRD and TODO files are unmodified.

The previous JSON dropped one non-ID dependency: RSP-134 originally says **“RSP-133; all selected implementation tasks.”** The proposal preserves the existing ID array and adds the exact `original_dependencies` from the TODO to every task. This restores the omitted all-selected requirement without changing the dependency graph or inventing new requirements.

Canonical preserved-requirement SHA-256:

`b5ae2b58a58192d5629f331522e696af9e3e064eaab44f90919d1eab798cdbe3`

The machine ledger records the encoding and original PRD/TODO file hashes. It reports zero dangling dependency IDs and zero cycles.

## Proposed status changes

| Task | Before → proposed | Acceptance basis |
| --- | --- | --- |
| RSP-032 | DONE → OPEN | Reopen: the code removes acknowledged-observe rereads only. Complete ordinary enforcing/missing-binding posture transfer remains RSP-031 OPEN; do not count partial removal as that broader acceptance. |
| RSP-037 | OPEN → DONE | Complete component profiling: 47 small/exact-6-MiB codec/allocation records, 30 samples each, cover the specifically requested timeout, protocol, shutdown and edge-copy phases. Installed attribution remains separate. |
| RSP-052 | OPEN → DONE | Complete supported Python single parsing: immutable text projections now cover Yarn, pnpm and Bundler in addition to JSON/JSONC/TOML. Reported 296 existing plus 64 projection tests preserve limits and completeness. |
| RSP-066 | BLOCKED → OPEN | Active work replaces a blocked-only label: an actual native-span/full-CLI comparison is underway. No final port decision, installed activation, Unicode or large-input pass is claimed. |
| RSP-070 | OPEN → DONE | The separate actual isolated-worker profile and hostile/binding witnesses are complete. Two of 510 timed outcomes fail their exact-result gate and remain recorded; the worker is retained and no native rollout is qualified. |
| RSP-100 | DONE → OPEN | Reopen: actual ordinary requests still derive categories for both approval identity and fresh policy. Request-local summary reuse and faster literal scans do not establish the original once-per-unchanged-input acceptance. |
| RSP-119 | OPEN → DONE | Complete component catalog benchmark: 638 combinations, 7/48/86 extensions, valid control/candidate bounds, cold/warm separation and explicit false-review counts. Installed lifecycle and an end-to-end speedup remain unqualified. |
| RSP-141 | DONE → OPEN | CURRENT_CONTRACT is updated; reopen the remaining stale EXECUTION/TAKEAWAY/ledger handoff pending root reconciliation with the selected source and artifacts. |

## Decisions that remain open

The integrated 53514c73b Watch correction also keeps the intrinsic native edge denial/reason distinct from Python Watch allow/warn delivery; the edge does not add direct-hook observe prefixes.

The original PRD §6 permits retaining a measured current implementation when targets and predicted benefit do not justify a large migration. The proposal removes the later rule that an optional native pilot must always be built before a measured deferral. It does not grant a deferral from an unmeasured workload or a small-input result.

- Package RSP-050/054 remains open while the 36-cell dependency/bundle comparison completes. Large cases retain material parsing/index cost. All-format Python correctness does not implement or activate RSP-055–060.
- Scanner RSP-062/066/072 remains open while rich, cold-cache and actual full-CLI native comparisons finish. The first small staged case regressed; large rich workloads still require measurement. The experimental span contract leaves Python responsible for rich findings/HMAC/completeness.
- MCP RSP-098/103 and conditional native rows remain open or blocked. The completed source stdio traces record 3,370 attempts with zero unexpected outcomes, but final optimized residual route profiling is active. The deliberate 5 ms barrier, child/network/human waits and fresh policy checks remain.
- Archive RSP-070 is a completed scoped investigation. Its evidence is not a successful p95 gate, a native-worker comparison, or a blanket proof that replacing interpreter startup cannot help. A future complete native worker would need its own unchanged containment/result and full-operation benefit qualification.
- RSP-080 installed expiry, restart, stricter-policy and ambiguous-response continuation scenarios are still active. The integrated source repair uses ordinary local Allow once semantics, distinct from the native v3/v4 API.

## Suspicious existing DONE classifications

RSP-032, RSP-100 and RSP-141 are proposed for reopening above. Other DONE rows require these limits to remain visible:

| Task(s) | Audit conclusion |
| --- | --- |
| RSP-009/010 | Matrix and statistical runner implementation can be complete while RSP-007/008/136/137 observations remain missing. Windows refusal coverage is explicitly not full-source coverage. |
| RSP-027/042/114/123 | Tested source implementation/specification does not satisfy outstanding technical review RSP-024 or authorize final release. |
| RSP-028 | Replacement-defense source tests and older installed status/child probes do not close signing/frozen/update transitions. |
| RSP-092 | Pool measurements are real but used observation-only Pi and retained cold failures. Recheck the changed dispatch: native Codex now bypasses the legacy pool; compatibility and legacy Codex callers remain. No startup removal is qualified. |
| RSP-106 | Retain DONE only for current Python protocol tests. Its still-blocked RSP-105 predecessor means it cannot supply selected-native-kernel correctness or RSP-107 qualification. |
| RSP-126 | Existing tests do include corrupt SQLite and read-only checkpoint recovery; the earlier short ledger description omitted those cases. No downgrade is warranted on that basis. |
| RSP-133 | Workflow-selection audit is distinct from passing every exact-head workflow. The latest verified remote candidate had four failed workflows. |

## Outstanding dependencies on DONE rows

Task status records its own evidence. The following declared predecessors are not DONE; they remain obligations and are not silently waived. This is why DONE counts cannot be read as a closed critical path.

| DONE task | Unresolved declared predecessors |
| --- | --- |
| RSP-002 | RSP-001 OPEN |
| RSP-003 | RSP-001 OPEN |
| RSP-009 | RSP-007 OPEN, RSP-008 OPEN |
| RSP-013 | RSP-001 OPEN |
| RSP-016 | RSP-015 OPEN |
| RSP-017 | RSP-012 BLOCKED |
| RSP-022 | RSP-015 OPEN |
| RSP-023 | RSP-015 OPEN |
| RSP-026 | RSP-025 OPEN |
| RSP-027 | RSP-024 BLOCKED |
| RSP-030 | RSP-008 OPEN, RSP-015 OPEN |
| RSP-037 | RSP-008 OPEN |
| RSP-042 | RSP-024 BLOCKED |
| RSP-045 | RSP-012 BLOCKED |
| RSP-049 | RSP-001 OPEN, RSP-008 OPEN |
| RSP-051 | RSP-050 OPEN |
| RSP-061 | RSP-001 OPEN |
| RSP-063 | RSP-062 OPEN |
| RSP-065 | RSP-062 OPEN |
| RSP-070 | RSP-066 OPEN, RSP-024 BLOCKED |
| RSP-092 | RSP-011 OPEN |
| RSP-099 | RSP-098 OPEN |
| RSP-101 | RSP-024 BLOCKED, RSP-098 OPEN |
| RSP-106 | RSP-105 BLOCKED |
| RSP-109 | RSP-001 OPEN |
| RSP-114 | RSP-024 BLOCKED |
| RSP-119 | RSP-118 BLOCKED |
| RSP-122 | RSP-121 OPEN |
| RSP-123 | RSP-024 BLOCKED, RSP-121 OPEN |

RSP-024, RSP-029 and RSP-118 have no unresolved direct ID predecessor but remain blocked by external review, final signing/update artifacts, or installed lifecycle/rollback evidence. RSP-107 has a DONE immediate test predecessor but still lacks its transitive selected native implementation (RSP-105). The machine ledger keeps these external/transitive blockers explicit.

## Evidence freshness and validation

Last GitHub state supplied by the audit owner: remote `42579f046ac262ff93c0c020547bc3873d308652`, 32 of 36 workflows successful. Paired run `35210168801` was smoke and failed all targets before complete sampling. Root committed per-target artifact JSON and hashes in the takeover evidence; final publishing and fresh exact-head review remain root-owned.

Windows immutable baseline/candidate source opens deliberately return `PathChanged` and therefore `no_output_to_review`; changing a fixture suffix cannot repair that platform limitation. Linux fault-injection interception and macOS reverse-DNS startup each have separate repairs. Linux/macOS arm64 native Ollama subprocesses recorded 22 lifecycle cases, but outer identity verification failed; Windows/macOS x64 failed readiness. These partial observations do not close RSP-118/135–139.

Validation performed for this proposal: parsed all 144 original TODO records; compared all original fields and full dependency text; verified contiguous unique IDs, unchanged PRD/TODO files, graph validity, exact status counts and every local evidence-catalog path; checked JSON and whitespace. Historical source/CI test results are attributed to their own reports, not rerun or transferred to this documentation commit.

The MCP owner also requested a separate bounded read-only review of pure-facts prefilters at `d811b08f0`. No semantic regression was found: literal alternatives generate their own necessary-condition filters, valid IP shapes cannot be rejected by the shape check, and the lowercase shortcut preserves the exact ASCII camel regex. Its 15 focused tests passed in 8.98 seconds. This is correctness review only; it does not establish the pending route benefit or native-port decision.
