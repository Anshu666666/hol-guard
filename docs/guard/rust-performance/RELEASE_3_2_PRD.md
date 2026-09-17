# Release/3.2 implementation addendum

This addendum applies the original [Rust Performance PRD](PRD.md) to
[PR #2970](https://github.com/hashgraph-online/hol-guard/pull/2970), targeting
`release/3.2`. The original requirements, all 144 [task IDs](TODO.md), acceptance
conditions, dependencies and numerical thresholds remain unchanged. The user
has authorized implementation; the initial proposal's read-only scope does not
limit that work.

**Product outcome:** reduce the time and CPU HOL Guard adds to real developer
tool calls while preserving decisions, delivered responses, approval authority
and artifact trust. Rust conversion must earn its place through a comparable
real-route result. This work does not prove optimal performance or complete
release acceptance.

Implementation source cutoff: `d06d8093bb1744ff22fcaf65fcfd1e908c989c2d`, tree
`9b2caee188ace6c0bc97379e08708f7f4019d4e0`. The [ledger](execution-ledger.json) records the evidence
for each original criterion.

84 DONE / 23 OPEN / 29 BLOCKED / 8 DEFERRED

## Users, scope and observable behavior

Developers should receive the same enforcing decision, Watch response or
availability continuation through their installed harness, with lower ordinary
latency. Approval must still resolve only the original live request under
current policy. Maintainers must be able to identify, update and roll back the
installed artifact without stale authorization. Operators need bounded queues,
resource use and recovery, private evidence, and truthful health under load.

Keep four timing boundaries explicit: named Rust **KERNEL**, **NATIVE_CLIENT**,
authenticated **DAEMON_INGRESS**, and actual registered **INSTALLED_LAUNCHER**.
The last includes process startup, stdin, stdout and exit validation. Cold
launcher, cold resident, daemon readiness and recovery remain separate series.
The [current contract](CURRENT_CONTRACT.md) defines the boundaries. A source
component or kernel result cannot qualify an installed route.

## Current evidence and conversion decisions

The [fifth CI checkpoint](FIFTH_CI_EVIDENCE.md) records measured PR head
`96a69725eab018674174dabc6f205a4087d6ff4b`, tree `7da3dcf25df5dc75b61f773c40a3a4dd96bbf2fa`.
Its merge `c9a4b508ec5e9f5e6526990f9a3fad8c8b97646d` has the same tree and distinct build identity.
All 41 workflow instances are terminal: **33 successful and eight failed**.
Successful authorization-only publish workflows did not publish a release.
Later source corrections require new CI; earlier
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md),
[third](THIRD_CI_EVIDENCE.md) and [fourth](FOURTH_CI_EVIDENCE.md)
cohorts retain their original identities and failed observations.

| Area | Implemented behavior or actual evidence | Release decision and remaining acceptance |
| --- | --- | --- |
| Existing native decision core | Typed results, canonical identity reuse, immutable compiled policy/command state and bounded output work are integrated. | Preserve semantic/adversarial parity and prove installed CPU and latency benefit. |
| Native command extensions | The v1 program translates reviewed declarative families and publishes compatibility ownership. Fifth Linux, ARM and Windows Ollama/Builder scenarios each passed all 22 native cases; Intel failed disabled-control readiness at 523.888 ms against 400 ms. | Keep the 42 null-matcher identities explicit. Declared-case receipts do not qualify every matcher, platform or full extension lifecycle. |
| Runtime identity and posture | Verified live-process reuse and one resident-ACKed request posture eliminate demonstrated duplicate work within their supported scopes. | Preserve current process/image, authority, generation and command-control fencing. Installed mixed transitions, replacement and recovery remain required. |
| Native launcher | Dormant four-target source exists. Fifth target admission reached real requests: nine of 20 experiment jobs passed and 11 failed; all final archives were retained. | Production activation remains off. POSIX failures matched the fixed native PostToolUse-unavailable response; Windows failures matched discovery-unavailable. Underlying causes and qualified benefit are unproved. The next source adds fixed error-code and read-only Windows discovery observations. |
| Package parsing/evaluation | Immutable indexes, one parse and evidence batching are integrated. Five fifth-cohort protect pairs report median wall 11,735.251 → 274.568 ms and CPU 5,930.041 → 245.011 ms. All ten phase/validation/registry workers completed. | The release-scoped no-Rust-selection decision remains bound to its fourth cohort. Fifth results are separate: 36 candidate/23 baseline cardinality completions, 13 censored baselines and two baseline Composer failures. Guard Python origin shares are 41.9683% protect/53.6792% evaluator, with zero Pydantic calls; these are not native benefit estimates. |
| Offline scanner and archive | Archive profiling is complete, with two fail-closed timeouts among 510 measured inspections. The first scanner smoke built the Rust binary and passed four Rust plus 69 bridge/collector tests, then failed before source identity or preflight. | Retain the isolated Python archive worker. Scanner selection remains open: all 24 planned smoke attempts were unoffered. Corrected executable admission, finite setup stages and attempt-bound retention need the same bounded smoke before the 840-attempt full experiment. |
| MCP proxy | Its measured decision uses the corrected 24ba cohort: five independent pairs, 10,080 calls and 80 complete warm resource windows. Fifth component CI completed successfully. | Retain optimized Python and conditional native-kernel/full-proxy deferrals. Fifth completion does not replace the decision cohort, establish installed benefit or repair incomplete lifecycle resources. |
| Installed delivery and transport | Four immutable qualification wheels built. All four indexed candidate arms then failed PostToolUse response validation; both Mac frozen baselines also stopped in reverse DNS. Linux alone passed its nonpriority smoke pair job. | Exact artifact-directory admission is corrected for singleton smoke downloads. Windows source now collects actual RAM, whose absence caused its smoke identity rejection. New error witnesses retain original rejection; there is no completed indexed comparison or activation proof. |
| Evidence and resources | Private journals, encrypted recovery, bounded public projection and artifact commitments preserve successes and failures. Actual Mac tests exposed approximately double ignored-child CPU accumulation. | The corrected Darwin reader reports general tree CPU unavailable with darwin_reaped_cpu_ambiguous, retaining memory and private diagnostics. Missing or ambiguous CPU cannot qualify a resource window. Full mixed-load, mutation, recovery and receipt durability remain required. |

The [package decision](package-native-selection-decision.md),
[MCP decision](mcp-native-selection-decision.md), and
[scanner/archive decision](scanner-current-decision.md) state their evidence and
reopening gates. A measured release deferral is distinct from an unbuilt
implementation. Conditional native schemas, implementations and activation are
not marked DONE merely because Python is retained. Package format parity and
installed acceptance remain separate, and original dependencies stay intact.

The later [package parity correction](package-format-parity-coverage.md) advances
the parser identity to complete-v3. Malformed top-level Bundler specs now return
incomplete output, and manifest dependency discovery recognizes unsupported
bun.lockb without opening it as text. The named source-test matrix closes RSP-059 only; its original dependencies and installed/native qualification remain separate. Saved approvals bind the parser identity,
so the prior v2 interpretation cannot authorize v3 results. Earlier paired evidence retains baseline complete-v1 and candidate complete-v2;
neither measures current complete-v3. This correctness change has no inherited
timing or native-selection result.

The [working-file correction](scanner-working-file-contract.md) uses bounded
retained descriptors and final identity checks. A file admitted for scanning
that changes, grows or fails during reading now makes coverage incomplete and
returns exit 2, preserving earlier findings. Initial exclusions, hardlinks,
contained links, invalid UTF-8 omission and HMAC behavior retain their declared
contracts. RSP-071 stays OPEN for five actual-native parity cases and relevant
platform execution; source tests are not those results.

The integrated [acknowledged posture contract](acknowledged-posture-contract.md)
makes local Watch effective only after the correct resident ACK. Ordinary native
requests sample one authenticated binding for evaluation, command-control lease
and final delivery; local configuration cannot weaken an enforcing result while
an update awaits ACK. Native receipts retain the intrinsic decision. Missing or
expired authority follows the unchanged availability path, not inferred Watch
authority. Source transition tests passed; RSP-034's actual mixed-transition and
installed qualification remain open.

## Requirements for every selected change

1. Preserve authority from admission through finalization: authenticated peer,
   current process/image, exact source content, policy/program/catalog identity,
   generation, expiry, mutation fencing and receipt/replay binding. Cached API
   definitions and metadata hints never replace those checks.
2. Preserve native verdict, posture transformation, availability outcome and
   delivered harness response separately. An availability continuation is not
   a native-evaluated allow. Do not replace ordinary unavailability with blanket
   denial or a Python semantic fallback.
3. Preserve the original waiter, request identity and deadline through approval.
   Revalidate native Codex completion under current authority. Unsigned terminal
   state and ambiguously delivered MCP writes cannot authorize replay.
4. Compare identical intended work and retain semantic differences explicitly.
   Unsupported reads, omitted dependencies and incomplete scans cannot count as
   successful performance observations.
5. Bind evidence to source, artifact, rule/runtime/program, platform,
   interpreter, dependency and workload identities. Install measured wheels
   outside source checkouts and keep the controller environment separate.
6. Retain every offer, outcome and failed observation. Reconstruct bounded
   public fields and authenticate encrypted private evidence. Missing CPU,
   memory, numeric or archive evidence stays missing.
7. Validate update and rollback as artifact transitions. Stopped replacement or
   settings rollback cannot substitute for live replacement, signed/frozen
   packaging or changed-program rollback.

## Performance acceptance and execution

The original PRD is normative where this table abbreviates a requirement.

| Gate | Required evidence |
| --- | --- |
| Priority warm, concurrency 1 | Installed p95 ≤50 ms and p99 ≤100 ms |
| Priority warm, concurrency 16 | Installed p99 ≤200 ms, zero errors |
| Native client / cold native launcher | p95 ≤20 ms / p95 ≤150 ms |
| Readiness | Existing 400 ms barrier; no retry extending the original budget |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU benefit; at most 5% regression in the other primary metric |
| Optional ingress | At least 25% private-memory or 30% concurrency-16 p99 benefit |
| Package/offline native kernel | At least 30% benefit against optimized Python at the real route, including serialization/startup amortization and original parity safeguards |
| Resources | At least 30 valid samples; unchanged 12% short-run and 50% long-soak RSS growth gates |
| Statistical coverage | At least five independent alternating pairs, required confidence intervals, 10,000 warm priority/1,000 other samples and 100 cold/recovery observations per required scope |

The [indexed qualification](indexed-pair-qualification.md) uses five same-runner
pairs on Linux x64, macOS Intel, macOS ARM and Windows x64. Each block receives
2,000 priority, 200 other and 20 cold/recovery observations; scopes and routes
retain their own denominators. Two 60-minute workers fit a 125-minute collection
step, with separate encryption/upload budgets inside the 200-minute pair job.
These containment budgets do not change a product deadline or sample minimum.

The [nonpriority companion](nonpriority-installed-tails.md) now has an explicit
four-platform, single-route smoke selection: four collection jobs plus four
aggregators, two observations per arm after semantic preflight. Fifth Linux
completed both arms; Windows retained complete worker reports but failed RAM
identity admission, and both Mac baselines failed DNS construction. All four
aggregators failed. These observations remain smoke only. Its full 16-route × four-platform × five-pair plan is
320 collection jobs and remains deliberate opt-in. Smoke cannot satisfy the
1,000-observation minimum or qualify host activation, other loads or resources.

## Delivery order and release exit

Execute the coherent corrected source before extending a migration. Fifth Main
failed test inventory and protected collection before any of its 96 test shards
ran. A module-global test import path shadowed the repository's ci namespace;
the correction restores that path after the helper import. Full local collection
and all 24 protected invariants subsequently passed. Two ownership workflows
also failed because the benchmark-only Rust crate lacked its precise manifest
owner; that owner and regression checks are now present. Fresh required CI,
duration aggregation and an actual Sonar quality gate remain necessary. The
42 individually reviewed Sonar dispositions remain unapplied.

Fifth Linux native-wheel CI passed all 14 installed smoke gates and its 100,000-request/250,000-receipt soak, with zero errors, 18,484 successful health checks, one stable daemon and 3.4097% sampled RSS growth. Its soak p95 was 551.88 ms under the unchanged 4,500 ms soak ceiling; the separate registered Claude PostToolUse smoke had only two observations and p95 354.188 ms. Neither series qualifies the original installed-priority targets.

Re-run the selected scanner and nonpriority smoke scopes with corrected identity
and retention. Use fixed native error observations to diagnose the four indexed
candidate failures and Windows discovery without changing acceptance. Read
the preserved Mac resolver evidence before an environment-only remedy: visible
configuration and a passing UDP self-test did not establish OS query delivery.
The frozen baseline, readiness and response deadlines remain unchanged.

Only comparable admitted arms justify full sample collection. Complete installed
posture and approval coverage, signed/frozen artifact identity, live update and
rollback, mixed offered load/mutation/recovery and durable receipts. Prepare the
actual qualified candidate, canary cohort, stop conditions and tested rollback
before final external approval. Source repairs and two-sample smoke cannot
substitute for those requirements.

Source inventory, boundary documentation and this handoff can close their own
literal criteria. They do not close RSP-012, final-head validation (RSP-134),
independent latest-push approval (RSP-142), or dependent installed benefit.
The [release review](RELEASE_REVIEW.md) and [ledger](EXECUTION_LEDGER.md) distinguish
those states. Protected merge, canary and release remain incomplete.
