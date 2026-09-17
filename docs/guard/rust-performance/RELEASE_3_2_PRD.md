# Release/3.2 implementation addendum

The original [PRD](PRD.md) and all [144 TODO criteria](TODO.md) remain normative.
Their IDs, titles, acceptance conditions and dependencies are unchanged. This
addendum records implementation, measured decisions and the remaining release work.

**Product outcome:** reduce the latency and CPU HOL Guard adds to real developer
tool calls while preserving decisions, delivered responses, approval authority,
artifact trust and evidence. A Rust conversion must earn its place through a
comparable real-route result. Optimal performance has not been established.

Implementation checkpoint: `ab06f959bf58fae9006137a4aa21398110dc2409`, tree `34f22d781012a71723b5d377f6817ba86b5bf1f1`.
The [ledger](execution-ledger.json) records **84 DONE / 23 OPEN / 29 BLOCKED / 8 DEFERRED**.
No status changes are made in this refresh. Release qualification remains incomplete.

## Users and observable behavior

Developers receive the same enforcing decision, Watch response or availability
continuation through the installed harness with lower ordinary overhead.
Approvals resolve only the original live request under current authority.
Maintainers can identify, update and roll back the actual installed artifact.
Operators receive bounded queues, resource use and recovery with private evidence
and truthful health under load.

Keep KERNEL, NATIVE_CLIENT, DAEMON_INGRESS and INSTALLED_LAUNCHER measurements
separate. Installed measurement starts the actual registered executable/argv and
validates stdin, stdout and exit, including process startup. Cold launcher, cold
resident, daemon readiness and recovery remain separate series. The
[current contract](CURRENT_CONTRACT.md) defines the exact boundaries.

## Evidence and conversion priorities

The [sixth CI checkpoint](SIXTH_CI_EVIDENCE.md) binds measured PR head
`9d3907a2e6ed1ec201281901cb878836a7dad32d`, tree `833ea191211db2a0613db8520d072f5edf485380`. Its tested merge
`64164db9cd11e3d05182a99dba100daa6011c83d` has the same tree and a distinct build identity.
All 41 first-attempt workflow instances are terminal: **35 successful and six failed**.
Main passed all 96 pytest shards; its remaining failure is the Sonar quality gate.
Publish to PyPI built and verified distributions and retained hashes/SBOMs, but
publication, release and container jobs skipped. No release was published.
The later implementation checkpoint below requires its own CI. Preserve the
[first](FIRST_CI_EVIDENCE.md), [second](SECOND_CI_EVIDENCE.md),
[third](THIRD_CI_EVIDENCE.md), [fourth](FOURTH_CI_EVIDENCE.md) and
[fifth](FIFTH_CI_EVIDENCE.md) cohorts as separate historical evidence.

| Priority and component | Decision for release 3.2 | Evidence and completion requirement |
| --- | --- | --- |
| P0: existing native decision, authority and transport path | Complete and qualify the integrated Rust path. Remove demonstrated duplicate work while preserving authority. | Sixth Intel exposes `native_command_control_mutation_in_progress`. The shared-refresh correction is source-tested; installed validation remains required. Linux c64 and later indexed load-route failures remain distinct unresolved observations. |
| P0: dormant native launcher | Complete the four-target experiment before production selection. | Sixth has 13 passing and seven failing jobs. All five Linux pairs complete, but complete native p95 series remain above 50 ms. Windows offers no timed measurements and rejects key/state ACLs in independent preflight. New producer behavior requires actual Windows proof. |
| P1: offline finding-heavy scanner | Complete the bounded optimized-Python/native experiment; selection remains open. | Four Rust and 95 Python checks pass. Setup fails at Python executable identity before all 24 offers. New finite diagnostics must identify the boundary before the full 840-attempt experiment. |
| P1: package path | Retain optimized Python under the recorded fourth-cohort decision. Reopen only a coarse model/identity/result operation that passes the original comparison gate. | Separate sixth complete-v3 pairs show wall median 8,765.805 → 320.749 ms and CPU 7,750.150 → 312.036 ms. This is Python optimization evidence; no Rust candidate was measured. Two frozen Composer failures and twelve censored baseline cells remain. |
| P1: installed tails, posture and lifecycle | Finish artifact, mixed-transition and load qualification on comparable cohorts. | All four wheels build. Linux/Windows nonpriority smoke compares both arms; two Mac baselines fail construction. Indexed ARM completes a numeric arm but has additional semantic/resource failures; no indexed pair qualifies. |
| Conditional: MCP and archive | Keep the measured Python boundaries and explicit native deferrals. | MCP retains its corrected 24ba decision and incomplete lifecycle resources. Archive retains the isolated worker, integrity reads, expansion bounds and two fail-closed timeouts among 510 measured inspections. Neither has a measured native comparison. |

The [package](package-native-selection-decision.md),
[MCP](mcp-native-selection-decision.md) and [scanner/archive](scanner-current-decision.md)
decisions retain their original evidence and reopening gates. A measured deferral
does not implement a port or close its conditional parity and installation criteria.

## Correctness requirements

1. Preserve authenticated peer and live process/image identity, exact content,
   policy/program/catalog binding, generation, expiry, mutation fences and replay
   protection from admission through finalization. Metadata hints never confer authority.
2. Keep native verdict, acknowledged posture, availability outcome and delivered
   harness response separate. Preserve ordinary availability semantics; do not
   introduce a Python semantic fallback or blanket denial.
3. Keep approval bound to the original waiter, request and deadline. Native Codex
   completion re-evaluates current authority; unsigned state cannot authorize reuse.
   An ambiguously delivered MCP write is never replayed.
4. Compare identical intended work. Incomplete scans, omitted dependencies and
   unsupported reads cannot become successful performance observations.
5. Bind source, exact artifact/runtime/program, workload, platform, interpreter,
   dependencies and host cohort. Measured wheels run outside source checkouts.
6. Retain offers, failures, late outcomes and bounded private evidence. Missing
   CPU, memory, numeric data or archives remain missing.
7. Prove live update and rollback on the tested artifacts. Stopped replacement,
   settings rollback and source tests cannot substitute for signed/frozen or live proof.

The [package parity matrix](package-format-parity-coverage.md) closes RSP-059's
literal source criterion with 265 focused tests, including 49 new cases.
Complete-v3 invalidates saved v2 approvals and rejects partial malformed Bundler
views. Earlier v1/v2 timings remain historical; the separate sixth cohort measures
v3. Original dependencies and native/installed acceptance remain unchanged.

The [bounded working-file reader](scanner-working-file-contract.md) preserves
finding/HMAC semantics and reports incomplete coverage with exit 2 for admitted
changes or read failures. Sixth CI executes all five new actual-native cases;
all 42 reader/route cases pass on Linux and both Macs. Windows has 16 passes,
25 explicit POSIX skips and one fixture setup/teardown error, now corrected in
source. RSP-071 remains OPEN until the relevant Windows rerun. Its documented
ancestor limitation remains explicit.

| Correction after sixth CI | Resulting behavior | Evidence still required |
| --- | --- | --- |
| Periodic command-control refresh | An unchanged authenticated read retains a shared lease. Only the existing mutation-required sentinel triggers a fresh exclusive read after releasing the shared lease. | Re-execute the installed Intel failures; their exact historical lock holder was not observed. Real mutation remains exclusive. |
| Windows discovery producers | Newly created key/state files use a private DACL and retained ancestor handles; fresh setup creates missing directories privately. Existing keys are not repaired, rotated or newly attested. | Actual Windows producer and dormant-launcher execution; legacy files may remain unsupported by the pilot. |
| Windows reader-test identifiers | Finite pytest IDs preserve the complete 65,543-byte fixture without overflowing Windows environment-variable limits. | Actual Windows rerun of the reader and route cases. |
| Capacity evidence export | The final report retains bounded closed-form None witnesses instead of losing them to nested privacy truncation. | A fresh failing or passing observation; the old 15 reasons cannot be recovered. |
| Scanner executable admission evidence | The original failing read retains one of 17 public reason codes and bounded private numeric metadata. | Fresh smoke to identify the cause; admission rules, reads, retries and deadlines are unchanged. |

## Performance acceptance

The original PRD is normative where this table abbreviates a requirement.

| Required scope | Unchanged acceptance |
| --- | --- |
| Ordinary 1–16 KiB priority installed hooks, warm c1 | p95 ≤50 ms and p99 ≤100 ms |
| Ordinary 1–16 KiB priority installed hooks, c16 | p99 ≤200 ms, zero errors and correct decisions |
| Native client / cold native / readiness | p95 ≤20 ms / p95 ≤150 ms / 400 ms barrier |
| Independent sampling | At least five alternating independent pairs with required confidence intervals; 10,000 warm priority, 1,000 other, 100 cold/recovery observations and at least 30 valid resource samples per required scope |
| Selected hot tranche | At least 30% p95 or complete process-tree CPU reduction; at most 5% regression in the other primary metric |
| Optional ingress | At least 25% private-memory or 30% c16 p99 reduction, preserving containment and decisions |
| Native package/offline work | At least 30% benefit against the optimized Python real route, including boundary/startup costs and original parity safeguards |
| Resource growth | Existing 12% short-load and 50% long-soak RSS limits at their actual sampling scopes |

Run Linux x64, macOS Intel, macOS ARM and Windows x64. Exercise 1 KiB, 16 KiB,
256 KiB, 1 MiB and maximum payloads at c1/c4/c16/c64 and offered-rate load.
Count queue and generator delay in offered-to-terminal latency. Keep errors,
timeouts, overload, late work and native receipt coverage in their denominators.
c64 may reject bounded overload; it may not hide failures, leak or mix replies.
Darwin general process-tree CPU remains unavailable after the actual once/twice
reaping witnesses; it cannot qualify a resource window.

The [indexed plan](indexed-pair-qualification.md) and
[nonpriority plan](nonpriority-installed-tails.md) preserve their budgets and
original minima. Sixth nonpriority smoke accepts 12 of 16 planned timed observations;
four Mac baseline observations are unattempted. Its two-sample arms cannot meet
the 1,000-sample minimum. Full tails require deliberate 320-job selection.
The scanner plan remains 24 smoke or 840 full attempts across 35 jobs, with
120-second CLI and 30-second native limits. Admit comparable smoke before full collection.

## Delivery order and release exit

First execute the reviewed corrections, inspect exact-source Main/security/
ownership checks, and identify remaining scanner and capacity failure boundaries.
Then complete the installed launcher and comparable baseline setup, semantic
parity, mixed posture/approval, resource and full sampling requirements.
Preserve the frozen 3.0.1 baseline; Mac DNS failure cannot be repaired by changing
its bytes or extending a product deadline. Frozen Composer rejects valid
slash-qualified transitives; changing fixtures to direct or npm-shaped names
would change the work and is not a comparable correction.

The 42 [individually reviewed Sonar findings](../security/sonar-release-32-review.md)
remain unapplied. The sixth Sonar analysis succeeded, but the actual quality
gate failed; fresh numeric conditions and exact remote issue identities have
not been retrieved. Do not reuse historical gate values as current. Automatic
approval review rejected the project-specific Sonar lookup because it would
send private project, PR and issue identifiers to an external service without
explicit authorization. The specific user permission request for fresh checks
and verified individual false-positive dispositions remains pending at this
checkpoint. Do not retry that action through CI or another route without that
approval. No exclusions, quality thresholds, severity changes or comments are
part of the proposed disposition.

Finish signed/frozen artifact identity, live update/rollback, offered-load
mutation/recovery and durable receipts. Require final-head CI and independent
latest-push human/code-owner approval. Prepare the qualified canary cohort,
stop conditions and tested rollback before final external approval.
PR #2970 targets `release/3.2`; protected merge, canary and release remain incomplete.
The [review](RELEASE_REVIEW.md), [ledger](EXECUTION_LEDGER.md) and
[takeaway](TAKEAWAY.md) distinguish completed source work from those gates.
