# Current acceptance and retained installed failures

PR [2974](https://github.com/hashgraph-online/hol-guard/pull/2974) is at `e44008445630aad28ccc291ec234f55a14892e6d`, tree `addf0c1daf8ceb6313d6805ee4d05e216d6fdac8`. Source pinning (RSP-001) and request-local risk reuse (RSP-100) are accepted for the exact scopes below; RSP-099 has current functional revalidation. The complete six-file artifact rehearsal also passed. Installed correctness, full performance, signing and live lifecycle qualification remain unfinished.

| Result | Evidence and practical limit |
| --- | --- |
| Source and artifact pinning accepted | Complete baseline/current tree and 1,531-path delta, current refs, original platform/toolchain/package/runtime/rule identities; [assessment](individual-acceptance-and-source-roster/ASSESSMENT.json) |
| Request-local risk reuse accepted | Eight actual interpreter/platform lanes, all 13 mandatory positive cases and 49 approval cases per lane; direct RSP-099 dependency has ten current functional cases; [assessment](current-risk-functional-acceptance/ASSESSMENT.json) |
| Six-file rehearsal passed | Two byte-identical clean source distributions, exact offline pure-wheel rebuild, strict full-set/four-native validators and Twine; [result](release-rehearsal-success/RESULT-SUMMARY.json). Unsigned rehearsal, not a canonical release |
| Current normal CI is terminal | 175 success, 19 skipped, two failed; four native platforms and aggregate pass. Real macOS recovery failure and external Kilo output-limit failure remain; [census](e440-terminal-ci-and-review/SUMMARY.json) |
| Current Linux ordinary soak passed | 100,000 requests, 250,000 receipts, zero reported errors or health failures, RSS increase 3.5126%; [original source-bound evidence](e440-posix-normal-artifacts/SUMMARY.json). Original mixed-load and performance requirements remain |
| Current installed approval is incomplete | Claude ask/resolution/retry passes on three platforms; Codex remains pending after durable allow; [actual result](current-approval-three-platform-result/ANALYSIS.json) |
| Cline alias attribution is incomplete | 25 alias cases pass before the first Cline failure on each platform. The witness observes the fixture worker, but Cline runs a separate CLI worker; its child route is unknown. No Rust bypass conclusion follows |
| Windows lock hypothesis was not reproduced | All five real Windows overlap cells pass, within 26 controls. Original held truncate succeeds; [result](windows-lock-overlap-actual/verified-result.json). Historic journal failure cause stays unknown |

The [PRD status](PRD-STATUS.md), [TODO](TODO.md), [Takeaway/resume prompt](TAKEAWAY.md) and [latest work in progress](WORK-IN-PROGRESS.md) carry the current decisions and next actions. The [144-task overlay](task-status-overlay.json) preserves every original task's acceptance, dependencies, hash and archived status. Only the explicit [current acceptance decisions](current-acceptance-decisions.json) establish new current scope; the 74 historical DONE labels are not 74 newly revalidated tasks.

This adds evidence to predecessor `c35d9056a14c7380b572cfee7d0262bd041bc5b4`; all its 10,068 leaves and earlier failed or stopped results remain unchanged. The original 119-entry catalog and task hashes remain preserved. New diagnostics retain their own source, artifact and observation limits and cannot retroactively change an earlier failure.
