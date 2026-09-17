# Release/3.2 Rust performance review

Reviewed 2026-09-17. **Implementation has advanced; the release is not qualified.**
This checkpoint describes local source
`ce8fce7f504bd67c213d67a60fbca34da724d25e`, tree
`f1b272cbe8ba4762083ef05ddd5d22ece9d95f82`, including the corrected dormant
Claude pilot and package/pilot workflows, and the latest inspected completed CI
snapshot on remote
`5ee52a03e62b9e4940063b348185bedaddf0cb53`. These are different source revisions.
Later work must record its own exact source and artifact identities.

The [PRD](PRD.md) and all 144 [TODO](TODO.md) acceptance conditions and dependencies
are unchanged. The coordinator's ledger reconciliation closes the source criteria
RSP-062 and RSP-128, yielding **67 DONE, 36 OPEN and 41 BLOCKED**, with no DEFERRED
ports. RSP-070 stays OPEN. Component completion does not close dependent installed,
approval, signing, rollout or performance gates. Use the
[machine ledger](execution-ledger.json) for per-task evidence and
[TAKEAWAY](TAKEAWAY.md) for the actionable continuation.

## Current source corrections

| Area | Integrated correction and its boundary |
| --- | --- |
| Runtime/header admission | Bounded request-permit handoff retains the original deadline. InitialHeaderReader transfers complete-header ownership before parser consumption; exact socket/deadline rechecks protect expiry and overload eviction. `f5cff2cf8` includes initially partial headers. Focused socket/handler tests are source evidence, not an installed load pass. |
| Scheduler | `186aed0cf` stops unchanged queued waiters from repeatedly waking one another. Dispatch progress still notifies; permit release explicitly wakes byte reservations even with no queued reviews. No deadline, capacity or service-estimate threshold changed. The failed CI workload needs rerunning. |
| Windows source access | `2ece1f953` binds reads to retained file handles; `842df0990` exposes the retained parent for permission verification. Capability correction `53b8ee8f8` is integrated with 79 focused tests. The frozen baseline's refusal remains its contract; actual candidate Windows content/identity qualification remains separate. |
| Watch and package identity | Watch correction `d4f05aec2` has 70 current-renderer and 28 frozen-renderer test witnesses. Composer correction `81c8e86d1` preserves ASCII vendor-qualified identities and namespace-bound emergency denies; its 176-test combined batch and final 30-case focused batch pass. These overlapping counts are not a unique total or installed qualification. |
| Numeric daemon bind | The completed source audit confirms existing `9cca767fe` already uses numeric TCPServer binding, preserving normal socket binding without reverse DNS. Three bind tests and six paired-driver tests pass, with independent source review. Frozen baseline DNS behavior is unchanged; actual macOS efficacy remains unqualified. Candidate continuation after contained baseline failure is already implemented in `6515e525e`. |
| Native authority and approvals | The compiled command program, live control fence, protected recovery floor and complete receipt binding remain integrated. Native Codex browser completion performs fresh native evaluation and exact signed consume/replay checks. Ordinary local approval behavior is separate from exported native v3/v4 APIs. |
| MCP and evidence | `6190a5869` reconstructs public evidence recursively from bounded typed fields, conserves attempt/phase counts, retains failed reports and excludes arbitrary private text. Production framing/terminal cleanup and the 5 ms freshness barrier remain. Component rebaseline and installed transport qualification are distinct. |
| Scanner and package baselines | `5e23434c0` bounds scanner diagnostic/cache state and states the limits of source identity. `83d2d7e10` adds an independent finite package matrix with real evaluator/protect routes, strict coverage and failure retention. It is a Python baseline harness, not a native package performance result. |
| Dormant launcher and workflows | Corrected Claude pilot `1026d43b0` plus `9454cb959` is integrated with all four peer findings closed. Package workflow `770e2b721` and four-platform pilot correctness workflow `ce8fce7f5` are integrated and reviewed. The launcher feature remains off; no default registration, installed activation or measured native benefit is claimed. |

The coordinator reports a final combined local batch of **135 passing tests**.
Additional scoped checks passed: 21 pilot Python tests, 15 package CI tests,
the 179-changed-file ownership gate, native approval contract and workflow policy.
The pilot owner also reported 12 Rust and 14 Python tests plus default/pilot
executable capability smoke passes; the package owner reported 75 combined and
15 final source checks. These batches overlap and are not added together.
The preceding qualification gate/public/workflow batch passed 86 tests in
392 seconds. Production Ruff checked 1,251 files and BasedPyright reported zero
errors, warnings and notes before scheduler integration.
These are scoped local checks, not final combined-head CI or installed evidence.
Their counts are not added to overlapping workstream suites.

Actual final-head CI/installed qualification remains pending. Regenerated
decision-diff evidence changes only the source hashes for
`lockfile_parse_result`, `supply_chain_package_eval` and `text_lockfile_parse`;
all nonbinding report fields are identical. Five local report tests pass,
including exact reproducibility and source binding. One fresh-process metrics
test failed at its unchanged 60-second deadline, and the isolated rerun failed
at the same limit. No cause is established and no full-suite pass is claimed.
The frozen baseline and all readiness/deadline limits remain unchanged.
Check current ownership and HEAD before editing; do not publish the shared PR
branch over another writer.

## Latest completed GitHub result: 32 success, 4 failure

The coordinator's GitHub API refresh during this review found **36 terminal
workflows: 32 successful and four failed**, all at remote `5ee52a03e`. The failing
workflows are below. Their failures remain failures after local corrections.

| Workflow | Exact observed failure |
| --- | --- |
| [Desktop contract CI 35213401527](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401527) | Job `105176074010`: stale source-bound decision-diff report. Local regeneration updates only three source hashes and exact reproduction passes; the separate fresh-process metrics timeout and final CI remain unresolved. |
| [CI 35213401782](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401782) | Job `105176074932`: 48-review scheduler deadline failure. Shard 24, job `105176401956`: the same stale source-bound report. A passing isolated retry is not a green original batch. |
| [Native wheel CI 35213401455](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401455) | Linux job `105176073353`: installed launcher did not use resident authority. macOS Intel job `105176072970`: source full-review witness. These require exact installed route/artifact diagnosis and reruns. |
| [Native performance qualification 35213401779](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401779) | All four baseline arms failed: Linux `105176074335` and Windows `105176074627` on `watch.1k` oracle mismatch; macOS ARM `105176074613` and Intel `105176074664` in baseline `getfqdn` construction. No complete paired qualification follows. |

Foundation [PR #2951](https://github.com/hashgraph-online/hol-guard/pull/2951) last
recorded 25 successful workflows and 33 resolved threads at
`e449594e86c717e66e14598a4130475de79c536f`, with independent last-push approval
still required. That is a separate historical checkpoint; refresh before merge.
Implementation [PR #2954](https://github.com/hashgraph-online/hol-guard/pull/2954)
has concurrent writing activity and is now reported at prefix `ae339`. Its newer
head does not inherit the inspected `5ee52a03e` results. The coordinator's isolated
publication is still pending. This review makes no new remote change or merge claim.

## Verified macOS DNS experiment outcome

Both latest job logs show the PTR wrapper surrounding the entire paired command.
The downloaded artifacts have these exact identities:

| Target | Artifact | ZIP SHA-256 |
| --- | --- | --- |
| macOS ARM | `10494172464` | `75589f593c3b28b345220ae95b4b26a9641ddb25bd1af8c9cf6aefb0ca80985b` |
| macOS Intel | `10493874671` | `c03f43d06e166f183e5b9e1179509cf9f8ea3ac1224f0acb90c490ee679b2261` |

Their `aggregate/runner-resolver.json` files independently report configuration
installation and cleanup completed, experiment attempted, command exit 1, and
**received/answered/rejected/error counters all zero**. Before, after and
after-cleanup legacy resolver probes all exceeded five seconds, with elapsed
observations of approximately 5,003–5,012 ms. Baseline startup stacks reached
`socket.getfqdn → HTTPServer.server_bind`.

Thus the experiment ran but did not resolve the failure. No packet reached the
responder; the strict question parser was not the observed failing boundary.
File installation does not establish resolver registration or selection. The
artifacts cannot distinguish an OS resolver/service stall from alternate routing
or ignored configuration. The configuration's domain/port syntax is documented
in [Apple's resolver manual source](https://github.com/apple-oss-distributions/libresolv/blob/main/resolver.5);
this does not prove efficacy on these runners.

The reports retain `runtime_patched=false`, `baseline_artifact_modified=false`,
`fixture_deadline_changed=false` and `qualification_pass=false`. The local
[composed diagnostics](macos-loopback-resolver.md) add fixed call-start,
reverse-name and numeric controls within the same five-second phase budget;
these new diagnostics have not supplied CI results yet. No system DNS changes
or timing experiments were run locally for this review. Preserve a contained
baseline failure and attempt the candidate independently without passing the pair.

## Remaining evidence and release decisions

- Run exact repaired installed artifacts on all four targets, retaining actual
  registered launcher, Watch/availability, approval, receipt, source identity,
  recovery and mixed-load outcomes. Keep source refusal and native enforcement
  separate. The frozen sample counts, zero-error c16 requirement, product
  latency targets and resource safeguards remain in the PRD.
- Finish the [isolated MCP rebaseline](mcp-proxy-rebaseline.md) and
  [independent package matrix](../rsp-package-matrix-v2.md) with retained failed
  cells and exact source/environment identities. Neither selects a Rust port
  before a comparable optimized-Python/native result exists.
- Complete assigned benchmark fixes separating common workload identity from
  arm-specific Windows coverage, preserving each observation in the private
  journal before worker timeout, and measuring Windows CPU through explicit job
  accounting. These gaps remain open at this source cutoff; missing platform
  CPU or timeout observations cannot become zero-cost or complete evidence.
- Use the [rich scanner report](../rsp-scanner-qualification.md) only at its
  recorded Linux source/CLI boundary. It includes unstable timing and incomplete
  cache scopes; no installed or native cutover follows. The
  [archive report](archive-worker-qualification.md) retains two unexpected
  timeouts among 510 inspections; RSP-070 is open. Its separate test-history
  section records a 146-pass/one deadline-assertion failure batch and an earlier
  141-pass/one unexpected-result batch. Targeted or later passing witnesses do
  not retroactively make those original batches green.
- Preserve encrypted raw observations, bounded public aggregates and every
  offered/terminal attempt. Missing data, killed workers and unsupported metrics
  must remain incomplete. Qualify actual Windows publication/ACL behavior and
  authorized archive recovery, then signing, frozen sidecars, artifact update/
  rollback, canary and rollback execution.

Earlier rounds and narrow successes remain in [EXECUTION](EXECUTION.md) and the
[historical takeover manifest](evidence/takeover-42579/manifest.json). They must
not be attributed to a later source tree or promoted into a passing release.
