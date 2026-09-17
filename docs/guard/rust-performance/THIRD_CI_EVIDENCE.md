# Third finalization CI checkpoint

This report records published candidate `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`
(tree `21429c003dcffc9fac7f90c618bee6d16c10dab0`) on
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970), targeting
`release/3.2` at `4b89e0d2d496a85f04922b2e019a4aea15326bb9`.
The API snapshot on 2026-09-17 retains **43 workflow instances: 36 successful,
five failed, two skipped, none active**. Label events explain the additional
instances; this is not a count of unique workflow definitions. The exact
[manifest](evidence/third-ci-d0e/manifest.json) retains each run and attempt.

**Installed qualification and release remain incomplete.** Later source repairs
are identified below without changing these outcomes. The [first](FIRST_CI_EVIDENCE.md)
and [second](SECOND_CI_EVIDENCE.md) checkpoints are separate artifact and hardware
cohorts. Their samples are not pooled with this report.

## Source, platform and security checks

| Scope | Actual result and limit |
| --- | --- |
| [Main CI](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473529) | 114 jobs: 109 success, three skipped, two failures. All 96 pytest shards passed. Duration-manifest assembly found 95 files because an in-process launcher test cleared the output environment variable before shard 91 wrote its report. Sonar analysis completed but the quality gate failed. |
| [Security Gates](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473774) | All four jobs passed. The Go-built Gitleaks binary identified itself as pinned v8.24.2; all 15 controller checks passed and the isolated release-base-to-candidate range contained no reported leak. |
| [Windows resident](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473530/job/105243304915) | 13 FFI tests, 45 Job CPU tests, 22 related resource/fixture tests with two skips, locked Rust checks and four authenticated resident tests passed. Both actual immediate-exit direct/nested CPU witnesses ran. |
| [Daemon edge hardening](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473122) | Contract, low-descriptor, Linux, macOS and Windows jobs passed; the optional soak job was skipped. |
| [MCP component](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473439) | The strict finalizer and both public/encrypted uploads passed. Thirty workers and all 10,080 calls completed without call failures. This is a Linux source-stdio component, not installed or cross-platform qualification. |

The Windows resident and native-wheel jobs used PR merge
`c855bae3e83579587d229c83b597dc1cbc1d4bb6`, combining this candidate and the
release base. Their artifacts must not be relabeled as a raw candidate checkout.
The resident Windows interpreter was CPython 3.12.10.

Sonar's remaining 42 findings are the individually reviewed S5332 (28), S2245
(10) and S2583 (four) cases in the [source-bound review](../security/sonar-release-32-review.md).
The earlier S5863 self-comparison no longer appears. Coverage is 82.4%, new-code
duplication 0%, maintainability A and hotspot review 100%; reliability/security
ratings C fail the gate. Proposed individual dispositions are still unapplied.
A passing analysis is not a passing quality gate or independent approval.

## Installed native-wheel results

[Run 35233473553](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473553)
failed overall: Linux passed, while Windows and both macOS targets failed.

- Linux passed the installed adapter SLO step and the separate enforced soak.
  The [retained finite projection](linux-d0e-installed-smoke.md) binds both
  original artifact identities and preserves their smoke/qualification limits.
  The latter retained 100,000 responses for 100,000 requests, 250,000 receipts,
  zero request errors, 20,128 health checks with zero failures and one stable
  daemon. Its p95 was 495.90 ms and maximum 583.38 ms against that workload's
  unchanged 4,500 ms ceiling; sampled RSS grew 5.5121%. These are legacy soak
  observations, not the PRD ordinary installed p95/p99 or mixed-mutation gates.
- Windows passed all 30 RSS tests, installed identity/control checks and the
  21-decision no-override native-resident corpus. The later registered Claude
  PostToolUse preflight failed its native-authority route check. No final SLO
  aggregate was written. The [bounded diagnostic](windows-installed-launcher-diagnosis.md)
  preserves the next original failure without changing the gate.
- macOS ARM failed the OMP 5 MiB source witness; Intel failed Kimi 250 KiB.
  Each original native edge call returned no edge while retaining almost three
  seconds of caller budget. The request-local client failure context was
  `not_recorded` before and after. This does not establish a native cause.
  [Exact finite evidence and the stage observer](macos-source-bridge-diagnostics.md)
  preserve source, runtime, stopped-daemon proof and the new observer's limits.

## Qualification retry and installed launcher experiment

[Qualification run 35233473603](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473603)
attempt 1 was cancelled during build by an unrelated Claude experiment label
event. That skipped event shared its cancellation group. The
[run-and-attempt isolation correction](qualification-run-survival.md) prevents
that interference without weakening the qualification plan.

Attempt 2 ran 18 jobs: six passed, 11 failed and one was skipped. Linux and both
macOS targets built and retained both immutable wheels. Windows built the
wheels but failed admitting one for bundle export with `archive_source_changed`.
The three POSIX pair jobs proceeded and retained failed arms; Windows lacked its
bundle. Linux and macOS ARM installed Ollama/Builder scenarios passed. Intel's
Builder checks passed, but an enabled-control Ollama policy was not ready within
the original 400 ms limit. Windows scenarios could not start. All four pair
aggregators failed, and the opt-in stopped-artifact transition job was skipped.

The failed POSIX pairs supply no completed timing comparison. Linux baseline
completed 386 daemon cases and 26 registered cases before its next registered
case failed a reviewed-output digest check. Both macOS baselines stopped during
daemon construction in `socket.getfqdn`. Candidate arms reached real daemon
cases before receiving `native_post_tool_unavailable` without a native result.
Those availability responses must never be counted as native-evaluated allows.
The preserved failures do not establish an underlying runtime defect's cause.

Later source inspection identified the Linux baseline registered Codex fixture's
missing host `cwd`. The [correction](registered-host-workspace-fixture.md) supplies
that context identically to both arms without changing frozen registration,
source-digest validation or deadlines. Its source-path explanation is consistent
with the retained failure; the original capture did not expose decoded digest
fields, and a corrected installed pass remains unobserved. The other candidate,
Windows and macOS failures remain separate.

The labeled [Claude experiment](https://github.com/hashgraph-online/hol-guard/actions/runs/35233552830)
ran all 20 platform/run jobs, but each failed before measurement. Fifteen POSIX
jobs rejected the `uv`-selected `python3` alias at private-interpreter admission.
Five Windows jobs failed journal/archive identity checks in contract validation.
No native launcher speedup, sample plan completion or production activation
follows. The [canonical interpreter correction](claude-pilot-interpreter-admission.md)
and [Windows metadata correction](private-qualification-evidence.md) preserve
the original admission requirements and need execution on the next source.

## Measured component evidence and next decisions

[Package evidence](PACKAGE_PHASE_CI_EVIDENCE.md) retains all ten completed phase
workers and five plain protect pairs. Median paired reductions were 96.2766%
wall and 95.7711% CPU versus the frozen Python baseline. All 36 candidate
cardinality and 20 format cells completed; 12 baseline cardinality attempts
remained censored and two baseline Composer cells failed. These are not
successful baseline comparisons. The selected phase names leave 82–86% of
exclusive calling-thread CPU unattributed; the [bounded collector extension](package-phase-attribution.md)
adds disjoint origin categories to the same existing diagnostic attempts.
RSP-054's native package decision remains open until the residual evidence can
support it. The profiling interval is not an uninstrumented latency series.

The exact successful MCP public artifact is retained as
[mcp-component.json](evidence/third-ci-d0e/mcp-component.json), SHA-256
`0d628f7a3035267aa25920cf64dce74e0397d57e237cf74083846240b23d4451`,
988,622 bytes. GitHub artifact 10503001658 is 93,291 bytes, SHA-256
`dcda5bde3e03ab556ea70ec52ca42bfd91e46a46754ab3a5082890549f3c9af8`.
The [archive receipt](evidence/third-ci-d0e/mcp-archive-receipt.json) binds 182
encrypted files; this checkpoint does not claim a new decryption test. The
[measured MCP deferral](mcp-native-selection-decision.md) remains its separately
reviewed 24ba decision, with explicit reopening conditions and no invented
native benchmark. No source-component report qualifies installed tails.

Independent recomputation verified every paired comparison and recorded harness
hash. For this d0e cohort, the large-catalog candidate/baseline median ratio is
0.533961 for warm wall p50 (95% interval 0.508358–0.555922) and 0.444666 for mean
parent-process CPU (0.419106–0.468266). The 16 KiB trace ratios are 0.689268
(0.658196–0.710949) and 0.627089 (0.586583–0.651522), respectively. All 80 warm
resource windows are complete, with 129–326 samples and zero missing snapshots.
All ten lifecycle windows remain incomplete: 18 missing snapshots and nine
descriptor-error rows are preserved. These finite component observations do
not remove the separate lifecycle, installed-tail or platform requirements.

Later reviewed changes also bind pytest duration output at session start and
add an explicitly opt-in [nonpriority tail collection](nonpriority-installed-tails.md).
They require new execution. Full priority/nonpriority tails, final artifact
signing and lifecycle, unresolved native choices, required CI, independent
latest-push review and concrete canary/rollback evidence remain release gates.
