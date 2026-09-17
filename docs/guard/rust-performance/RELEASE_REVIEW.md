# Release/3.2 Rust performance review

Reviewed 2026-09-17. **The next source checkpoint is implemented and reviewable;
installed qualification and the release are still incomplete.** This review
covers source `c964a61a3a4c19d721358e69c400d6059dfd1156`, tree `96143b80f7f1b41e7ceff1a98a7ad9ee81fbd6f1`, before these documentation edits.
The measured GitHub checkpoint is the earlier PR #2970 head
`107606388ad55f924a4e2924b4ff84e5fa08e6ff`. Later source corrections do not inherit
its measurements. Inspect the live pull request for subsequent publication.

The original [PRD](PRD.md) and all 144 [TODO](TODO.md) titles, acceptance conditions
and dependencies remain unchanged. The [release addendum](RELEASE_3_2_PRD.md)
connects those requirements to the current implementation and conversion
priorities. The [ledger](EXECUTION_LEDGER.md) contains **67 DONE, 36 OPEN and
41 BLOCKED, with zero DEFERRED**. This checkpoint changes evidence, not task
status. Source completion cannot close an installed, native-comparison, signing,
rollout or approval gate.

## What is ready for the next run

| Change | Implemented behavior and remaining limit |
| --- | --- |
| Indexed installed qualification | Build immutable wheels and locked dependency bundles once per platform; run five independently indexed, alternating same-runner pairs. Each pair retains the original sample plan and two 60-minute worker bounds. A 125-minute collection step plus separate archive/upload time fits a 200-minute job. Exact raw numerical bytes are bound to sealed archive receipts and checked during cohort aggregation. Actual completion and performance remain unproved. |
| Benchmark authority and failure retention | Common workload identity is separate from each arm's supported semantics. Expiry renewal preserves acknowledged command extensions and exact authenticated publication. Incremental private journals retain observations before failure. Recovery errors retain bounded phase, route, reason and elapsed observations inside the standard failure envelope. No product deadline or baseline semantic behavior changed. |
| Linux installed interpreter | POSIX benchmark environments copy the same interpreter bytes into an owned private executable before installation. This satisfies the unchanged frozen validator on runners whose tool cache is world-writable. Source and copy identity are verified. Windows behavior is separate; this is a fixture repair, not a production validator exception. |
| Windows resources and authority setup | Dedicated fixture Job CPU avoids charging the generator to the daemon. Retained process identity and ancestry bind current working-set/private-commit observations; missing final values fail completeness. Production Windows DLL wrappers, structures and function signatures are reused, while owner, ACL, file and authority reads remain fresh. Actual Windows reruns must validate both changes. |
| Mac resolver diagnosis | The next diagnostic distinguishes call entry, reverse lookup, numeric lookup, direct libSystem lookup and OS resolver registration. It retains bounded private captures after the paired command finishes. Earlier numeric lookup succeeded while reverse lookup stalled; the frozen baseline stall is unresolved. No baseline patch or extended startup deadline is introduced. |
| MCP component evidence | The v2 collector adds five paired run-level confidence intervals, separately attributed loopback transport/service work and 80 complete warm resource windows before teardown. It retains all offers and failures. Production classification prefilters are integrated. The first v1 measurements predate these changes; a native kernel decision remains open. |
| CI fixture and secret-scan corrections | Launcher test doubles accept current runtime arguments; parser invalidation uses a genuinely future version; Mac source fixtures canonicalize the OS temporary root. Storage/header fixtures preserve startup and ownership boundaries. The exact public-digest exception restores the pinned Gitleaks global defaults. None of these edits changes production thresholds. |

Independent review found the fixed full indexed plan fits the existing private
archive caps: at most 32 files per pair and a conservative total below 124 MiB,
against limits of 256 files, 32 MiB per file and 128 MiB total. This is a source
and synthetic-serialization capacity check, not a runtime or compression result.
Generic custom plans outside the shipped workflow are not covered by that bound.

## Verification and the remaining local failure

The combined 36-module integration batch produced **575 passes, seven skips and
seven failures**. Six failures came from the test fixture's literal PID 10
colliding with the actual test driver's PID inside this environment. The fixture
now uses a distinct synthetic PID; the focused resource/identity/journal rerun
passed **61 tests with two platform skips**. The guard that refuses load-generator
CPU remains unchanged and its negative test remains.

The seventh failure remains open:
`test_locked_storage_hook_burst_fails_safe_without_stranding_daemon` timed out
reading an HTTP response at its original 1.75-second limit. The 24-request burst,
1.6-second latency assertion and original deadlines are unchanged. Cleanup now
retires the fixture, but that does not make the burst pass. Boundary diagnosis
continues; no full combined-suite pass is claimed.

The authority gate passed for 131 changed files; the I/O ownership gate passed
with 437 reachable functions and 3,861 inventory entries. Scoped source suites
and independent reviews cover the pair pipeline, MCP v2, resolver, interpreter,
recovery envelope and Windows contracts. Their counts overlap and are not summed.
The prospective GitHub publication ancestry also passed Gitleaks with zero
findings across 1,257 commits, using the intended published parent. These checks
precede this documentation commit and do not replace CI of the published tree.

## First finalization CI: 33 successes and six failures

All 39 workflows at `107606388...` are terminal. The retained
[first-CI report](FIRST_CI_EVIDENCE.md) and its 19 exact public reports provide
artifact identities, numerical evidence and failure boundaries.

| Workflow | Observed result at the measured checkpoint |
| --- | --- |
| [Security](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287255) | Public digest matched a secret detector. The narrow source-fixture exception and default-policy repair need new-head CI. |
| [Main CI](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287428) | Three shards failed on launcher, storage/header and parser-version fixtures. Quality, compatibility and scheduling-sensitive jobs passed. The integrated fixes do not rewrite the failed run. |
| [Daemon edge](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287297) | Mac fixture rejected the OS temporary-root alias as a symlink. Actual ancestor/leaf symlink refusals remain tested after the fixture correction. |
| [Package component](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287514) | All 20 candidate format cells and 36 candidate cardinality cells completed. Two baseline Composer coverage failures and 12 censored baseline cardinality workers prevent complete comparability. |
| [Native performance](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287310) | All four smoke jobs failed. Every candidate stopped at expiry-publication authentication. Baselines separately retained Linux interpreter, Mac reverse-lookup and Windows side-scenario failures. |
| [Native wheel](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287375) | Linux and Mac ARM passed. Mac Intel failed recovery sample 1; Windows lacked RSS evidence. Native-wheel artifacts identify merge source `a806a38...`, separate from the paired source above. |

The Linux wheel run completed 100,000 requests, 250,000 receipts and 17,888 health
checks with zero request/health errors, stable PID and 3.9683% sampled RSS growth.
Its 528.06 ms response p95 passed the legacy soak's own allowance; it does not
meet or replace the PRD's 50 ms installed-priority target. Registered Python
launcher smoke measured 344.126 ms on Linux and 282.838 ms on Mac ARM, with only
two observations each. Both retain `qualification_complete=false`.

The dormant Claude source-feature workflow passed all four targets. Both Macs
also passed 22 installed native Ollama cases and Builder checks. Windows passed
ten Ollama cases before a 406 ms disabled-phase readiness miss against the
unchanged 400 ms limit. No installed native Claude activation, changed-package
rollback or release approval follows from those narrower successes.

## Conversion decisions still to earn

The strongest measured package result is already from Python optimization:
five actual local protect pairs at 1,000 dependencies and bundle entries reduce
median CPU from 5,923.255 to 242.241 ms. Attribute the optimized residual before
selecting a Rust package port. Censored 15-second whole-worker cells are not
15-second evaluator lower bounds. The unversioned bundle kernel and real
registry-resolved protect route remain distinct workloads.

MCP v1 reduced the 1,000-tool catalog's mean parent CPU from 51.886 to 24.455 ms
per call, but lacked paired intervals and complete resource evidence. Run v2
before selecting a native kernel. The new opt-in installed Claude experiment,
optimized package phase attribution and stopped-artifact transition probes are
separate pending tranches; they are not included in this source cutoff.

Complete repaired four-platform smoke, actual component measurements and full
indexed qualification. Preserve all failing cells and unsupported scopes, then
make measured go/no-go decisions for package, scanner, MCP, inventory/spool and
optional ingress work. Complete final artifact/signing/frozen, update/rollback,
mixed-load and canary evidence before closing the corresponding ledger tasks.

[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970) targets
`release/3.2` on the isolated branch `codex/release-3.2-rust-finalization`.
PR #2954 has another writer; do not overwrite or merge its whole tree without
review. Foundation PR #2951's 25 successful workflows and 33 resolved threads
are historical observations at `e449594...`; refresh before integration.
Independent latest-push code-owner approval remains a protected-branch gate.
No protected merge, canary or release is complete.
