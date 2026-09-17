# Release/3.2 Rust performance review

Implementation checkpoint `ab06f959bf58fae9006137a4aa21398110dc2409`, tree `34f22d781012a71723b5d377f6817ba86b5bf1f1`.
The original [PRD](PRD.md), [TODO](TODO.md) and historical reports remain unchanged.
The [current ledger](EXECUTION_LEDGER.md) is **84 DONE / 23 OPEN / 29 BLOCKED / 8 DEFERRED**; no status is promoted
by this refresh. The release remains unqualified.

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

## What sixth CI establishes

| Scope | Exact observation | Meaning and remaining work |
| --- | --- | --- |
| Main, run 35257232478 | 114 jobs: 110 pass, three skip, one fails. All 96 pytest shards, quality, aggregate CI and duration-manifest steps pass. Sonar analysis succeeds; its quality gate fails. | Collection is repaired. There are 96 coverage and 96 duration artifacts. Current numeric gate conditions are unverified; later source needs its own CI. |
| Security and ownership | All four security jobs pass, as do I/O and Rust-authority workflows. | The precise benchmark-crate ownership correction works in CI. These checks do not establish installed performance. |
| Native-wheel, run 35257232892 | ARM passes. Linux fails c64; Intel later fails Cline Post source review with `native_command_control_mutation_in_progress`; Windows stops before build on an overlong pytest environment value. | Linux c64 retains 64 responses: 32 native, 15 fail-safe and 17 overload, with 15 raw None returns. Their reason records were truncated. New export and test-ID fixes need execution. |
| Indexed qualification, run 35257233257 | 27 jobs: 11 pass, 14 fail, two skip. All four immutable builds pass; all four indexed pairs and all four ordinary aggregators fail. | Linux and ARM candidates validate 386 daemon plus 62 priority preflight cases. ARM completes 38 series/136 numeric observations but additional semantic/resource gates fail. No pair qualifies. |
| Installed scenarios | ARM and Windows complete their declared scenarios. Linux and Intel fail readiness checks against 400 ms. | Narrower phases and causes remain unverified; earlier successful platform cohorts do not qualify these failures. |
| Claude, run 35257232562 | 20 jobs: 13 pass, seven fail. All five Linux jobs pass; two ARM measurements and all five Windows jobs fail. All 20 public/encrypted/final-retention paths pass. | Windows has eight offered preflights, three complete and five fail, with 432 of 440 planned preflight/timed attempts unoffered. No Windows timed result exists. Native p95 remains above the 50 ms target in every complete series. |
| Nonpriority tails | Linux and Windows workers and aggregates pass. Both Mac candidates complete; their baselines time out constructing HTTPServer through `socket.getfqdn`. | 12/16 timed observations accepted, four unattempted. Windows RAM is 17,174,360,064 bytes in both arms. Singleton extraction and RAM corrections work; smoke remains unqualified. |
| Scanner, run 35257232537 | Four Rust and 95 Python tests pass, including five new actual-native cases. Setup fails at `python_executable_identity_failed`. | 24 planned, zero offered/completed, 24 unoffered. Evidence retention succeeds. New reason projection is diagnostic only; native selection remains open. |
| Package, run 35257232889 | Phase job passes; format and diagnostic jobs fail. Five protect pairs and all ten phase workers complete. | 36 candidate/24 baseline cardinality completions, twelve censored baseline workers; 20 candidate/18 baseline format completions and two frozen Composer failures. Retain the fourth decision and separate v3 cohort. |
| MCP and lifecycle | MCP, daemon-edge and Windows-resident workflows pass their declared scopes. | Completion is not new numeric analysis or a substitute for incomplete installed/lifecycle resources. |
| Distribution workflows | PyPI workflow builds/verifies distributions and retains hashes/SBOMs. Actual publication, release/container and desktop-feed publication skip. | Built distributions are recorded; no published release or canary is inferred. |

The [sixth report](SIXTH_CI_EVIDENCE.md) and its
[manifest](evidence/ci-9d3907/manifest.json) retain run/job/artifact identities,
failed denominators and the distinction between public observations and authorized
private recovery. Source and merge commits have equal trees but distinct identities.

Linux's terminal c16 Codex Post batch 36 validates all 16 observations. Its later
`native_slo_batch.validate_batch_routes:32` failure occurs in load-profile
measurement; the exact wave, concurrency and counter deltas were not retained.
It must not be attributed to the completed batch or Intel's lock error.
Intel's indexed Cline Post block at 16 KiB returns the explicit mutation error
after 46 ms with 2,939 ms remaining and no receipt. Its native-wheel source case
returns the same code after 71 ms with 2,976 ms remaining. These are not deadline
exhaustion. The shared-refresh source defect is established independently; the
historical holder was not captured.

ARM's completed numeric arm is not successful qualification: baseline construction
fails in DNS, general CPU is unavailable, and Codex continuation, input, registered
surface and mixed resource/receipt checks fail. Windows candidate construction
times out in authority bootstrap before corpus execution. Exact failure stages
and retained details appear in the [indexed follow-up](sixth-indexed-followup.md).

## Corrections ready for their own execution

| Correction after sixth CI | Resulting behavior | Evidence still required |
| --- | --- | --- |
| Periodic command-control refresh | An unchanged authenticated read retains a shared lease. Only the existing mutation-required sentinel triggers a fresh exclusive read after releasing the shared lease. | Re-execute the installed Intel failures; their exact historical lock holder was not observed. Real mutation remains exclusive. |
| Windows discovery producers | Newly created key/state files use a private DACL and retained ancestor handles; fresh setup creates missing directories privately. Existing keys are not repaired, rotated or newly attested. | Actual Windows producer and dormant-launcher execution; legacy files may remain unsupported by the pilot. |
| Windows reader-test identifiers | Finite pytest IDs preserve the complete 65,543-byte fixture without overflowing Windows environment-variable limits. | Actual Windows rerun of the reader and route cases. |
| Capacity evidence export | The final report retains bounded closed-form None witnesses instead of losing them to nested privacy truncation. | A fresh failing or passing observation; the old 15 reasons cannot be recovered. |
| Scanner executable admission evidence | The original failing read retains one of 17 public reason codes and bounded private numeric metadata. | Fresh smoke to identify the cause; admission rules, reads, retries and deadlines are unchanged. |

See [control refresh](command-control-refresh-contention.md),
[Windows producers](windows-discovery-producer.md),
[capacity witnesses](native-capacity-none-witness.md) and
[scanner diagnostics](scanner-executable-identity-diagnostic.md).
The Windows preflight passes directory, bounded reads, authentication and peer
identity but rejects key/state security admission. This is an independent
current-object observation, not an atomic trace of the actual Rust request.
Producer source separately used POSIX modes without a Windows private DACL.
New files now establish privacy at creation; existing keys retain their original
read behavior and may remain unsupported by the dormant pilot.

The integrated 19-module correctness suite passed 617 tests with seven explicit Windows-only skips. The final exception-import follow-up passed 63 tests with four Windows-only skips, and the complete I/O ownership module passed all 30 tests, including current-source graph validation and a content-read rejection regression. These suites overlap and are not added together. Final full collection finds 22,518 cases and all 24 protected invariants. All 24 changed Python files pass Ruff check/format; all 15 changed source/protocol modules have zero type errors at the CI error level. Same-release-base authority, full I/O ownership and privacy gates pass. The exact immutable-source-range Gitleaks scan passes with zero findings. All 394 frozen evaluator source commitments remain unchanged, so the earlier 51,000-case differential evidence needs no regeneration. Independent source and evidence reviews cleared the changes. No local performance workload was run; actual Windows execution, later published-source CI, installed qualification and human approval remain separate.

Owner and independent source reviews are bounded engineering checks. They do not
supply actual Windows execution, installed measurements or latest-push human approval.

## Package, scanner and MCP decisions

The [sixth package note](PACKAGE_SIXTH_CI_EVIDENCE.md) and its
[16-file manifest](evidence/package-ci-9d3907/manifest.json) bind current complete-v3
and frozen complete-v1. Five D=B=1,000 protect pairs have wall medians
8,765.804810 → 320.749072 ms and CPU medians 7,750.150 → 312.036 ms;
median paired reductions are 96.3404978500% and 95.9716882649%.
These are separate Python-route observations. The fourth complete-v2 decision
to retain Python is not replaced or pooled with them.

All ten phase workers complete. Guard Python exclusive function-origin CPU
medians are 42.3513% protect and 54.2777% evaluator; Pydantic records zero calls.
Each route has one parse, one batch and one index. Signed admission precedes the
route interval; zero in-route verification does not erase admission cost.
Each synthetic-transport registry arm issues 100 admitted GETs. The three public
ZIPs and 16 files are verified; producers report 331 encrypted files. No sixth
package decryption or private recovery is claimed.

The frozen Composer parser reads valid vendor/package records, then its generic
transitive identity helper rejects slash-qualified names. Bare names invalidate
Composer inputs; making all dependencies direct changes the workload. There is
no honest same-work fixture correction. Keep these two cells noncomparable and
twelve cardinality workers censored under the unchanged 15-second whole-worker
limit. Source parity RSP-059 is complete at its literal supported/unsupported
test boundary, with original dependencies preserved; no native implementation,
exhaustive grammar or installed qualification is inferred.

The [scanner decision](scanner-current-decision.md) retains seven earlier clean
timed states that failed benefit gates and no completed finding-heavy timing.
Sixth binary correctness is useful but its zero offered smoke cannot decide
conversion. The 17-code observation preserves admission and private data boundaries.
The [working-file contract](scanner-working-file-contract.md) has actual Linux and
both Mac 42-case passes; the finite Windows test ID still needs an actual rerun.
RSP-071 remains OPEN. Keep the documented Windows ancestor limitation and archive
coverage separate.

The [MCP decision](mcp-native-selection-decision.md) remains bound to corrected
24ba evidence: five pairs, 10,080 calls and 80 complete warm resource windows.
Its ten lifecycle windows remain incomplete. Later component success does not
supply a Rust comparison or repair that resource evidence. Archive profiling
retains 508 expected outcomes and two fail-closed timeouts among 510 calls; all
330 hostile/bounded-failure calls remain non-clean. Keep its isolated Python worker.

## Release exit

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

Keep native verdict, resident-ACKed posture, availability and final response
separate. The [ACK contract](acknowledged-posture-contract.md) has source tests;
RSP-034 still needs installed mixed transitions, invalidation, expiry and races.
Both Macs' known-child tests now pass their explicit once/twice accounting
witnesses. General Darwin CPU remains unavailable, with no divisor or widened
tolerance establishing completeness; RSP-011 stays OPEN.

All eight tail ZIPs and encrypted bindings were verified. Private Mac recovery
locates both frozen baseline failures before registration, preflight and numeric
offering. Resolver registration and UDP self-test pass, but actual OS probes
send no query and time out. Exact file cleanup and immediate OS registration
retirement remain different facts. No evidenced environment-only repair has been
selected. Keep the frozen artifact and existing deadlines.

Complete comparable full sampling, selected artifact parity, signed/frozen
identity, live update/rollback, mixed offered-load/mutation/recovery and durable
receipts. The stopped transition probe skipped in this cohort. Require final-head
CI and independent human/code-owner approval of the latest push, then the concrete
canary and tested rollback. PR #2970 remains draft against `release/3.2`;
protected merge, canary and release are incomplete.
