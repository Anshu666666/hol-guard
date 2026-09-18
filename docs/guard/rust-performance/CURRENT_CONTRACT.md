# Current decision and performance contract

This contract describes the implementation identified in [EXECUTION.md](EXECUTION.md),
including the 2026-09-17 takeover corrections to Codex continuation, package
parsing, bounded source experiments and MCP notification delivery. It includes
native command execution, control authority and live-process attestation. Source support
is distinct from installed activation and release qualification; exact evidence
and remaining acceptance are in the [execution ledger](EXECUTION_LEDGER.md).

## Current checkpoint — 2026-09-18

The integrated local source/evidence cutoff is `623a6e058b2c4b650021e3c359d8e58b1be6ea05`. Actual published implementation [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954) remains `7a387128e2cf2ec79b890dfebe2697e8a49eb45d` (draft, unmerged); foundation [#2951](https://github.com/hashgraph-online/hol-guard/pull/2951) remains `a001b2691f481b7b5a66dd14d68e48d61c44cb78` (unmerged, protected review blocked). The later integrated repairs have not been qualified by the earlier published artifacts. All **144 original tasks** remain **74 DONE, 31 OPEN, 29 BLOCKED, 10 DEFERRED**; implementation, qualification, activation and release are distinct.

| Exact source and population | Retained result |
| --- | --- |
| [Implementation 7a terminal cohort](../evidence/implementation-7a387-hosted-final/TERMINAL.md) | 37 workflows: 33 success/four failure. All-attempt checks: 206, with 171 success/23 skipped/12 failure; latest view: 203, with 168/23/12. CI: 114 jobs, 106 success/six skipped/two failure. Desktop passes; Sonar/Sonar Guard skip; external CodeQL reports 11 new highs despite successful Actions analysis. |
| 7a installed execution | All four paired targets fail; no comparison qualifies. Windows completes one adverse, unqualified baseline block. All four retained-Python scanner probes pass 28 cases each. Both Mac SLO reports pass smoke with qualification false; Linux fails strict capacity before soak. |
| [Foundation a001 terminal cohort](../evidence/foundation-a001-hosted-final/README.md) | All 25 workflows succeed; 182 checks retain 160 success/19 skips/three failures. CI 111 success/three skips; Desktop and Sonar pass (zero new issues/hotspots, 81.4% new-code coverage). External CodeQL still reports eight highs; Kilo output-limit and original Gitleaks installer failures remain in the all-attempt population. No active independent approval. |
| a001 Linux soak | Completes naturally: 100,000 requests/responses, 250,000 receipts, 24,198 health checks, zero request/health failures. Step 34m42s; p95 617.98 ms, maximum 850.31 ms, RSS growth 0.085565, maximum 64 threads/192 file descriptors. Its older foundation contract does not qualify the implementation's stricter capacity or full PRD gates. |
| [26cd terminal addendum](../evidence/foundation-26cd-hosted-terminal/README.md) | 25 workflows: 23 success/one failure/one cancelled; 178 checks: 149 success/22 skipped/five failure/two cancelled. Linux soak cancelled after 23m09s; no final soak report. The original 21:09:39Z interim and every earlier failure remain unchanged. |

Actual implementation wheels use test merge `95ba3911b8b68227510c034306554c8fb7f8a66d`, with the exact 7a tree `1ccec336c8a3aff22a4500b8f8350ae8fee3a345`. Foundation wheels use `4631c7098bd229cc164d2408a32191331492adcc`, with a001 tree `24e28be411272ad055f47012603d35e0394de67b`. All embedded runtime identities were verified against downloaded wheel bytes. Frozen paired baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b` remains unchanged. These are artifact proofs for their named sources, not the later local repairs.

The actual [7a publication and full-range secrets scan](../security/gitleaks-implementation-7a387/README.md) are retained from the separate evidence branch: zero findings with pinned Gitleaks 8.24.2, unchanged ignore input and 1,262 commits scanned. The original pre-publication receipt and subsequent branch readback remain distinct. A new published implementation commit needs its own full-range scan.

### Three integrated corrections and their limits

The [daemon refresh repair](../evidence/daemon-refresh-reader-lease/README.md) begins unchanged-authority refresh under the existing shared lease. Only `NativeCommandControlMutationRequiredError`, after SH unwinds, permits a fresh exclusive read. A real POSIX held-reader conflict fails before the fix; five new cases pass in 1.20 seconds and 56 existing cases pass in 10.05 seconds. Server-only types have zero errors/319 warnings; Ruff/format pass. The five-second interval, markers, floors, mutation rules and startup remain unchanged. All 395 actual Desktop source bindings are unchanged and `server.py` is not bound, so no report regeneration ran. The original mistaken regeneration claim and its correction remain in the receipt. This source proof does not identify historical lock holders or qualify installed capacity or Windows behavior.

The [workspace/admission correction](../evidence/installed-workspace-admission/README.md) marks the shared priority fixture's owned workspace explicit. Actual unchanged baseline 2e and candidate 7a adapter/receiver methods admit no workspace before and the owned workspace after, for both events; 1,264 baseline source/support files match original Git blobs. All 386 corpus cases, the 1 MiB expected digest and deliberately empty inputs are preserved. Four pre-fix regressions fail; 42 focused tests pass in 3.55 seconds, fixture types have zero errors/28 warnings and Ruff/format pass. The witness stops at receiver policy admission and does not execute authenticated HTTP or native performance qualification. The accompanying empty-approval assertion adds only the existing bounded result to future failures, preserving the two-/three-second budgets and predicates; its historical cause remains unknown.

The [CodeQL materialization repair](../evidence/codeql-source-materialization/README.md) fully materializes the immutable source and rejects sparse checkout, hidden index flags, missing tracked paths and empty inventories. All 65 diagnostic tests and collector types (zero errors/warnings) pass. Actual cdd/d8 replay restores all 3,902/4,793 tracked paths. Original run 35276260889 remains invalid as complete production analysis: four no-source failures and two zero-result SARIF files containing only diagnostic helper/workflow. All raw artifacts and original erroneous completeness flags are preserved. Separate published diagnostic `54c0ce882f83edb341e148d5eae2817bdf0c6451` has a zero-finding full-range scan and one [dispatch of run 35326220494](https://github.com/hashgraph-online/hol-guard/actions/runs/35326220494). The [initial queued readback](../security/gitleaks-diagnostic-54c0/README.md) remains unchanged.

The [repaired hosted diagnostic](../evidence/codeql-materialization-hosted-54c0/README.md) completed all six jobs at 08:59:28 UTC with full cdd/d8 source present, clean pinned trees and zero sparse/index/missing entries. cdd has Actions 2, JavaScript 0 and Python 23 raw findings; d8 has 2, 0 and 27. All six ZIP/SARIF identities and successful invocations are verified, with no warning/error notifications or external result files. All 54 supplied findings were reviewed against their source/sink witnesses and 84 exact immutable source blobs. The source assessments retain constrained config captures and the infeasible modeled dispatch/generic-config-reader branches; their scope is the provided paths, and no alert disposition or security-gate clearance follows. These 25/29 raw findings are distinct from the PR checks' eight/11 new-alert counts. CodeQL 2.27.0, Actions 0.6.35/JavaScript 2.4.5/Python 1.8.10 query packs, original cdd/d8 profiles, selection/exclusion and disabled security/database uploads remain unchanged. Rust source is materialized but is not analyzed by this three-language matrix.

The component test populations overlap earlier work. Separate [integration checks on exact combined source 623a6e](../evidence/resume-623a-integration-validation/README.md) pass native authority (0.779 seconds), Python semantic boundary (0.197 seconds), I/O ownership (32.980 seconds), and all 82 workflow-permission tests (0.39 seconds pytest time; 4.279 seconds including lock/startup). All 3,291 tracked source/Rust/script/test/workflow files remain identical before and after. These fresh integration gates do not establish a new full-production type run or complete installed qualification.

### Remaining acceptance

The 7a candidate failures retain 73-byte native error objects matching the complete digest of `native_command_control_mutation_in_progress`; they do not prove the historical holder or scheduling sequence. Linux capacity retains 22 resident, 12 fail-safe and 30 overload responses, zero transport errors and only eight of 12 detailed failures. Windows default-auto also retains three receipt persistence failures before all 21 receipts are processed. Linux/both Macs pass four actual Pi output cases plus six rejecting and one observe-preserving cases; Windows full secure source review remains unsupported.

Only ARM passes the 7a Ollama report. Linux/Windows readiness failures occur without exhausting 400 ms; Intel updated readiness takes 508.137 ms. Mac baseline construction remains blocked in `getfqdn`. Every original-baseline rollback still fails verified native retirement (exit 2, 33 stderr bytes), with three of seven positives, zero accepted negatives and no candidate restoration. Compatible stopped rollback passes only its independent scope. Claude retains three complete 30/30 cells then 23 native PostToolUse attempts/22 completions, with zero full blocks. No repair above retroactively replaces these failures.

Complete fresh integrated source/artifact checks and installed smoke, then the original full per-route/platform sampling and targets, mixed receipt/control/resource/recovery soak and selected signing/version/live rollback. Keep RSP-050's literal unversioned full-route gap and residual transport/persistence selection work explicit. Current Python MCP B requires its own immutable tool-call frame/final-authority boundary correction before RSP-100 risk-analysis reuse or benefit selection; inactive F's mutation guard does not establish B behavior. That separate correction is outside this source cutoff. Preserve the ten measured deferrals and stopped inactive F experiment. Obtain fresh external security/Sonar gates, Greptile 5/5 and genuine independent last-push CODEOWNER approval through the required process. Prepare tested final canary/rollback evidence before authorized activation. The [ledger](EXECUTION_LEDGER.md) retains all unresolved dependencies; none is waived by a smoke pass or completed investigation.

The dated records below preserve earlier evidence and instructions at their stated source scopes. The current pointers and remaining acceptance above supersede earlier descriptions of the then-current head or pending run; raw observations and original acceptance requirements remain unchanged.

## Ownership and timing boundaries

Ordinary local HTTP hooks enter `guard/daemon/server.py`, dispatch directly into
`HookWorker.review_http_payload`, then `_review_native_edge` in
`daemon/hook_worker_native.py`. `native_hook_edge.review_raw_hook_native` calls
the persistent native client helper through `native_resident_client.py` and
`native_resident_stream.py`; the Rust resident owns the semantic decision. A
Python guardian/evaluator pool remains relevant to verified compatibility and
Codex approval revalidation paths. Ordinary hooks must not be described as
traversing that pool merely because it exists in the daemon process tree.

| Boundary | Start and completion | Exclusions that must be stated |
| --- | --- | --- |
| KERNEL | A named Rust parse/admission/evaluate/receipt operation | Interpreter, launcher, daemon ingress and transport unless explicitly included |
| NATIVE_CLIENT | Real client request entry through validated native response | Outer registered launcher and daemon ingress |
| DAEMON_INGRESS | Actual authenticated hook HTTP request through delivered response | Registered command startup; normalized HTTP is not installed launcher execution |
| INSTALLED_LAUNCHER | Spawn the executable/argv read from real installed registration; complete stdin/stdout/exit validation | Resident/bootstrap/OS-cache cold unless separately measured |

Cold executable startup, daemon readiness, resident recovery and full process-tree
resources are independent series. A warm helper is not a cold resident; a new
launcher process with a warm daemon is not a full cold boot. The qualification
driver reports independent daemon, helper/resident descendants and measurement
driver costs so load generation does not masquerade as daemon CPU/memory.

## Decision and delivered response

The native verdict and receipt are authority evidence. Posture transformation
and availability handling are separate stages. Ordinary native evaluation and
Python delivery use the same authenticated acknowledged snapshot. Its observe
mode establishes Watch recording behavior without re-reading configuration; a
local Watch edit cannot weaken an enforcing snapshot before its replacement is
accepted. Missing acknowledged authority follows the existing posture-independent
unavailable response. Off, shadow and administrative configuration paths retain
their separate behavior. A metadata-only or unacknowledged mode cache cannot
authorize a stale observation posture after an enforcing update. The
[acknowledged-posture contract](acknowledged-posture-contract.md) records update,
workspace, expiry and validation boundaries.

Ordinary PreToolUse native unavailability currently returns a harness continuation
with warning semantics, including for commands whose unavailable payload might
be high impact. The unavailable branch deliberately does not run another Python
semantic classifier. Designated integrity failure reasons deny; permission
requests have their own response behavior; lifecycle events are observation
events. These outcomes must be checked against actual harness JSON and exit
contracts. The performance work preserves this matrix; changing availability
policy requires a separate product/security decision.

Every benchmark observation distinguishes at least native route/verdict/reason,
acknowledged posture, availability reason and final harness result. A returned
`allow` does not establish that the native evaluator ran. The isolated benchmark
oracle must evaluate both benign and malicious fixtures and cannot enter a
production fallback path. The frozen workload corpus contains independent
expectations, rather than only asserting equivalence with Python.

Full source-reference review has a platform boundary. The audited baseline and
current candidate both deliberately reject non-Unix secure file opening until
an equivalent handle-bound path walk exists. On Windows, a source-ref-only
request therefore returns `no_output_to_review`; Watch may transform its delivered
response but does not create a native content review. Qualification records this
as unsupported full-source coverage and excludes it from successful content-review
timings. Passing Windows inline hooks or package identity checks does not close
that gap. Direct pathname opening is not an acceptable performance workaround.

## Guard TOML capture and publication readiness

Ordinary loading and native publication now share the same
[config-source reader](../security/config-source-confinement.md). It accepts only
`config.toml`, `.ai-plugin-scanner-guard.toml` and `.hol-guard.toml`, resolves an
intentional directory alias at the scope boundary, then retains directory and
regular-file identity while reading. POSIX uses descriptor-relative no-follow
opens; Windows uses the existing no-reparse directory handles and locked file
descriptor. Unsupported secure access has no pathname fallback.

Missing files or workspace directories still add no override. Unsafe or
inaccessible existing sources raise `GuardConfigSourceError`; they cannot silently
become default policy. Linked, non-regular, changed or incompletely read sources
are rejected. Malformed TOML and invalid UTF-8 still raise. Logical path spelling,
config precedence, blocked workspace keys and managed-policy application remain
unchanged; no new owner/permission/ACL condition is added to ordinary config files.
The general reader does not authenticate a workspace. The daemon adds an
explicit `HookConfigReadScope`: it pins a trusted configured home alias to the
canonical home chosen at construction, retains an already-admitted canonical
workspace path, and rejects a changed resolved parent before opening the leaf.
Authorization examines the held parent and its metadata under the existing hook
root policy and owned-temporary exception. This is a pathname/held-capture
boundary, not an inode identity preserved across process launches. A genuinely
missing parent still supplies empty input; it is not authorization of an absent
path. Standalone readers without the injected scope retain ordinary CLI semantics.

The same scoped capture/reader now reaches the publisher and worker, hook-process
CLI, package reloads, persisted approvals and remote approval/resume readers.
Publisher reuse requires the identical capture object, and an uncacheable policy
reload still uses that capture. Rejection withdraws ACK before an older snapshot
can be retained. Source `591d5c81e6bb341c6c3271332f3a6615a01bc748` has the
bounded combined checks recorded below; new hosted analysis and actual Windows
execution remain pending.

The later source `73e83ddfac66ef1e04771a2aa51e96cdb1fbee77` passes that existing reader
through `guard.packageShims.audit` into its home configuration load. A rejected capture
takes the existing failure path before the audit callback. This three-line transport
change has its own [18-case and one-file type
receipt](../evidence/remote-audit-config-validation/manifest.json), separate from the
591 validation populations.

The inclusive **1,048,576-byte (1 MiB)** ceiling is a new input acceptance bound
for ordinary Guard TOML, which previously had no byte limit. It matches the
existing safe-file and publisher capture ceilings. Oversize or growing sources
are rejected without parsing a truncated prefix or using an unbounded fallback.
This security bound does not revise any frozen performance threshold.

The [publisher](../security/config-source-publisher-confinement.md) hashes and
parses those same captured bytes. A home or either workspace config rejection
clears `_acked` under its condition lock and notifies waiters before re-raising,
even when no ordinary observer ran and the previous acknowledgement has not
expired. A generic transient publication failure still has its separate existing
handling. No weaker default or new client push is generated. Nine publisher-path
regressions exercise readiness withdrawal after linked, oversized or unreadable
sources; actual Windows and installed qualification remain unproved.

## Limits and authority

| Existing boundary | Limit or rule |
| --- | --- |
| Native resident client/stream | 6 MiB request, 2 MiB response |
| Native decision receipt | 16 KiB receipt; bounded 512-byte string fields |
| Policy snapshot | 256 KiB, 4 KiB bounded fields, depth 32, 4,096 collection items; internal JSON string admission remains separately bounded |
| Approval protocol | 6 MiB request, 2 MiB response, 64 KiB approval |
| Legacy command/PreTool API | 64 KiB request; do not conflate with larger raw hook envelope |
| Source package input | 8 MiB retained per input, 128 MiB retained per evaluation; alias bytes counted once |
| Lockfile structure | 100,000 entries, 250,000 nodes, depth 128; incomplete output never presented as complete |
| Foreground evidence queue | 2,000 queued records and 16 MiB retained facts, plus one bounded in-flight batch |
| Evidence batch | At most 50 records per pass, existing nominal 25 ms batch wait and 50 ms SQLite timeout |
| Workspace policy registration | 1,024 workspaces plus home; capacity exhaustion closes the publication barrier rather than evicting a stricter active overlay |
| Native command program | 4 MiB, 1,024 rules, 16,384 graph nodes, depth 32; typed configs and complete digest validation |
| Command authority marker | 4 KiB, authenticated canonical record and retained SH/EX lock |
| Managed source context | At most 512 configured targets, 256 characters per target and 512 KiB authenticated context record |
| Live attestation registry | 256 reusable proofs/full-validation blockers; saturation disables reuse for the Python process lifetime |
| MCP UTF-8 line | 4 MiB including newline; incomplete frame bounded to 30 seconds from first bytes |
| MCP child output queue | 64 frames and 16 MiB encoded bytes; nonblocking admission and terminal overflow |
| MCP unmatched replies | 64 responses and 8 MiB encoded bytes per direction |
| MCP nested operation | 4,096 frames and depth 16 under the original deadline; ordinary writes bounded by configured timeout capped at 30 seconds |

These are distinct limits, not a single process RSS cap. Decoded objects and
catalogs have additional memory cost. A performance
optimization must not weaken duplicate-key rejection, strict UTF-8, unknown-field
policy, byte versus character distinctions, collection/depth bounds, canonical
field ordering or digest domains. Exact-byte identities retain CRLF and Unicode
semantics. Every native API change requires negotiated capability and strict
result validation; legacy optional-field absence must retain legacy encoding.

Executable status binds package version, manifest/runtime digest, target and
ownership/permissions. Capability caching alone does not eliminate executable
hashing. Implemented attestation reuse refers to an already verified Linux live process,
with stable start identity, exact image, verified package and current manifest.
Stat metadata can invalidate a cache but cannot prove content integrity. A new
spawn requires fresh full validation; death between lookup and dispatch must not
let a cached digest authorize its replacement. Unsupported platform/filesystem
proof retains full validation.

## Native program and control authority

The reviewed trusted compiler produces executable typed configurations; a matcher
name and digest alone are not a program. The Rust interpreter admits one immutable
program, verifies all graph digests, shares compiled state and evaluates one
canonical command with candidate indexing and memoization. Complete rule,
permission, variant and owned-uncertainty observations feed the existing core
floors. Unsupported/context-heavy cases cannot silently become no-match or allow.
The semantic profile is pinned to CPython 3.12/UCD15; opaque operand handling does
not imply arbitrary non-ASCII configuration support.

Production command publication requires both `native-command-program-v1` and
`native-command-control-fence-v1`, exact program/catalog/trust identity and verified
local/managed control authority. Missing capability or proof closes readiness;
there is no unbound legacy command fallback. Legacy APIs where the optional
command extension field is absent preserve their previous canonical encoding.

Control mutation holds a retained exclusive lock and durably writes an
authenticated closed marker **before** credential/SQLite semantic effects. A
committed marker identifies the verified result. Native publication/admission,
evaluation and final approval authority use the overlapping shared lock. Stable
Python reconciliation also uses shared access; a semantic-write sentinel releases
it and re-verifies under a new exclusive lease before effects. There is no
in-place shared-to-exclusive upgrade. Compilation is outside the critical lease. The 2026-09-18 daemon refresh correction now uses this stable shared-read path for its periodic registry refresh as well. It catches only the explicit mutation-required sentinel after SH is released, then reads authority again under EX. A tampered or degraded result never selects that retry; the five-second interval and mutation/floor rules remain unchanged.

Local and managed floors remain independent and monotonic. Explicit recovery
chooses the new key/epoch before effects and links the exact prior authenticated
native floor. Historical recovery cannot permit a later key change in the same
epoch. Failed mutations/crashes leave authority closed until verified recovery.
A signed activation source manifest pins managed enabled-control meaning across
catalog replacement/deletion; legacy missing-source records conservatively clamp
enables. Mutable current manifests cannot retroactively establish old authority.
The cloud acknowledgement is not rewritten.

Native receipts preserve the complete optional command binding in SQLite
migration 28. `GuardStore.get_native_decision_receipt()` reconstructs and validates
the full durable receipt; a row count alone is not evidence that the current
program/control binding survived ingestion.

## Deadlines, commit points and replay

Rust setup, bounded parse, admission, queueing, transport and evaluation consume
the caller's remaining deadline; an internal retry cannot reset that budget.
Expired/canceled work cannot publish a late success. OS reads and filesystem
flushes are cooperative boundaries: elapsed checks before/after a read cannot
preempt a kernel operation already blocked. The Python edge's normal capture
budget and caller admission bound must not be advertised as hard OS-I/O preemption.

Ordinary local approval retry uses **resolved-row reuse**. The queued action
contains a validated `guard.native-review-policy-binding.v1` derived from the
native result, binding policy/rule/runtime and compact command observations.
Request metadata cannot manufacture it. A resolved allow is eligible only for the
same binding, harness, tool, launch and workspace. Legacy absence matches only
legacy absence; policy renewal alone may retain the same effective binding.
A native block cannot be replaced by a saved allow.

The Python worker holds the shared authority fence through native evaluation,
queue/reuse and final rendering, after posture/ACK preparation. Mutation takes the
exclusive fence and therefore cannot cross that protected decision. The lock
consumes the caller's deadline. Timeout, failed authority or late allow follows
the existing availability contract; a completed native block remains a block.
The installed controlled-approval helper uses the existing local resolution API
with policy persistence disabled. That path does not call the exported native
v3/v4 one-time challenge/claim/consume APIs and must not be described as doing so.

Codex browser-wait continuation has a distinct production path. The queue attaches
one live waiting operation to the original bridge process, home, workspace,
request digest and deadline. A local Allow once resolution authorizes only that
operation. Completion requires a fresh real native evaluation and verified
receipt under the shared control lease before atomically consuming the signed
local authority. A current native block or uncertainty remains restrictive.
The original process and deadline are checked again after durable finalization;
a late allow is refused while the consumed record remains available for exact
retry reconciliation. A mutable terminal approval row alone cannot authorize
replay. The qualifier independently checks the canonical redacted command and
workspace projection against the exact private approval row; it cannot create
missing authority by copying metadata into the row.

This corrects the earlier `exact_approval_authority_missing` continuation defect.
Source and real-store tests cover the handoff, stale/mutated bindings, expiry,
process replacement and late durable outcomes. Actual installed platform coverage
is reported separately. Claude resolve-and-retry and Codex live continuation must
not be treated as interchangeable test witnesses.

Native v3/v4 approval APIs have separate authority-bound challenge, claim and
transactional consume tests. Their final consume holds the shared fence. Actual
ordinary-launcher exercise of those APIs is not established. An ambiguous consume
or tool write must not be transparently retried, regardless of which approval
route eventually uses it. [The authority protocol](../rust-native-command-control-binding.md)
records the exact request, binding, floor and recovery contracts.

MCP forwarding commits at the actual child stdin write. Full-catalog generation,
authority, input and entrypoint freshness are revalidated at the final boundary,
including the existing 5 ms quiet drain. `tools/list_changed` notifications during
approval invalidate saved catalog authority. Out-of-order responses retain their
JSON-RPC IDs. Ambiguous writes are terminal; they are not transparently replayed.
Bounded framing keeps notification processing live while approvals are pending
and while the client is idle. The idle reader drains the existing bounded child
multiplexer before its next client poll; a server catalog invalidation no longer
waits for another client request. The existing operation limits and final 5 ms
prewrite barrier remain in force.
The runtime retains the optimized Python category path after the request-facts
candidates regress supported workloads. The explicit immutable facts API remains
an inactive experiment: consumers own and match exact inputs, including scalar
types, container shape, dictionary order and signed zero. No facts value is
retained across approval/catalog/claim boundaries, and no performance selection
is inferred from semantic parity tests.

The completed private native text experiment evaluates four category groups
through 13 fixed predicates. Its whole UTF-8 packet is bounded to 16 MiB including
the 16-byte envelope, with one admitted request and an exact 13-byte sequence-bound
response. External MCP framing stays at 4 MiB. Python keeps normalization, current
policy, catalog and approval authority, credentials and exact forwarding. The
full source-proxy comparison includes IPC and helper CPU and fails the original
selection gate; the helper is inactive. RSP-100 remains open because production B
still derives categories for approval identity and fresh policy separately. The completed
[owned-preparation E experiment](../rust-performance-mcp-owned-preparation.md)
records one category tuple per selected immutable lifetime and test coverage for
current policy/browser/store/claim composition and public callback/fallback
behavior. Within those tested cases it validates and writes the same encoded
bytes after the final quiet barrier.
Its historical 64 measured cells and 32 public pairs pass their selected
correctness scope; they do not establish general pre-forwarding mutation safety.
Later independent review found E selects its final protected writer from mutable
method text. The initial F fork retained that selector: actual child-pipe tests
showed a changed plain method reaching the child and a hostile method invoking
its callback. Frozen E source, tests and campaign bytes remain unchanged; the
previous broad claim that every pre-forwarding change fails closed is withdrawn.
Unsupported, package and busy paths still use B. General E activation was also
rejected on measured benefit/regression and memory evidence. Positive narrow
observations remain historical; B stays default and RSP-100 remains OPEN.

The separate [F source experiment](../mcp-streaming-preparation-pilot-boundary.md)
selects the admitted frame by object identity and then retains complete binding
and actual-wire equality checks. Its corrected 44-test gate and finite source
review cover the two selector regressions, real nested normal/error restoration
and unrelated replies; the 96 authority comparisons are included in that count.
The earlier failures are retained. F's first [fixed route attempt](../rust-performance-mcp-streaming-preparation.md)
now retains 19 completed cells, one failed B cell and 44 never attempted. Its
400 verified completed-cell forwards include 202 F derivations/bound writes;
401 calls were attempted. Nine complete pairs independently match, while the
collector produced zero comparisons and no profiles. The unpaired F cell is
retained. Failed-cell forwarding and the EOF cause remain unresolved because
the retained zero count lacks a ledger-availability witness and stderr/worker
detail are missing. No five-block gate, retry, pooled E result, installed/platform
qualification or activation follows. Both remain inactive; no private prepared
lifetime is saved as authority across later preparations.

Overflow, malformed frames and timed-out/ambiguous writes retire the captured
stream generation and quarantine the child. No subsequent normal result or
forward is permitted. Quiet drains cannot reset the deadline or discard catalog
invalidation. [The framing contract](../../mcp-framing-bounds.md) distinguishes
real POSIX tests from simulated Windows worker coverage.

Evidence acceptance is distinct from durability: memory accepted can be lost
before journaling; journal-durable records replay; database-committed records may
replay after a pre-checkpoint crash but deduplicate by stable identity. Journal
mutation uses the existing cross-process lock, not an invented lifetime-exclusive
daemon lease. Checkpoint retry does not invoke the decision engine. Legacy records
without a stable occurrence timestamp retain their documented best-effort behavior.

## Private Claude launcher boundary

The experimental Linux Claude Pre/Post command is implemented in the existing
runtime distribution and selected only by private qualification registration.
Package and registration authentication has its own purpose and is independent
of daemon discovery. The pilot preserves the original challenge/POST exchange
on one loopback connection and contains completion under the original absolute
deadline. Existing daemon/resident policy and approval authority remain unchanged.
The anonymous sealed input handoff does not put the request in a persistent file
or argv. Detailed HTTP
framing and timeout conformance limits are recorded in the [pilot report](claude-native-launcher-pilot.md).
Component and later focused integration checks pass in their recorded scopes.
The actual [9db Linux installed receipt](evidence/takeover-9db62e/perf-linux-installed-claude-launcher-pilot.json)
binds its wheel/runtime and completes 30 Python plus 30 native PreToolUse launches
with exact contracts and native-resident routes. The next Python PostToolUse cell
attempts 11 and completes ten before an unexpected delivered reason. Zero full
blocks complete; all scope/qualification/activation flags remain false. This is
partial installed evidence, with complete post/fault/benefit gates still missing.
No default launcher or signed Desktop registration selects the pilot.

## Source ownership and retained historical proof

`scripts/ci/rust_pretool_no_python_gate.py` and `rust_io_ownership_gate.py` protect
the authority/I/O boundary. The latter follows recording-mode callers and labels
decision-time config access `synchronous_posture_config`; it does not relabel it
as background work. Background captured-byte policy compilation and foreground
native receipt validation retain their distinct ownership.

Current test suites cover native contracts, malformed/source mutation, separate
native approval APIs and ordinary local review reuse, Watch/availability,
policy publication and scanner parity. Those tests
are necessary but do not establish installed performance or final code-owner
approval. The [combined d4e13547f validation](evidence/hosted-integration-d4e13547f.json)
passes 317 tests, 26-file lint/format and all 1,253 production type files with
zero errors and 20,232 nonfatal warnings, plus workflow-policy and the three
ownership gates. It precedes the separate CodeQL extractor and config-source
corrections; tests overlap previous component counts and establish no hosted
qualification.
The [config/publisher validation](../security/config-source-publisher-validation.json)
passes 88 tests with one actual-Windows-only skip, five-file Ruff/format and
three production type files with zero errors/80 nonfatal warnings. That combined
count includes the shared-reader 67-test suite; the separate foundation 67-test
application is another overlapping source scope. Original assertion and disk-full
attempts remain retained. These are source tests, not fresh hosted or CodeQL passes.
The subsequent 5da39f986 production type gate passes 1,254 files with zero errors
and 20,236 warnings; authority/semantic checks pass. Its I/O ownership gate
initially reports 15 unclassified filesystem sites in the new reader. The
[correction receipt](evidence/config-integrated-5da39f986.json) retains that failure
and adds six exact function/primitive classifications plus exact helper-path
protection. I/O remains visible as synchronous posture/config work. The existing
I/O/architecture suite passes 46 tests/99.32 seconds, including actual inventory
validation and negative cases; static checks and one contract type file pass
with zero errors/warnings, with finite independent review clear. Product source
is unchanged from 5da. These separate source gates are not an aggregate test
count, installed qualification or a clean external security gate.
Later source `591d5c81e6bb341c6c3271332f3a6615a01bc748` adds scoped capture and
propagation; it is not covered by that earlier inventory-only statement. Its
[retained validation](../evidence/daemon-scoped-config-validation/manifest.json)
records the following exact, overlapping populations.

The retained 591d5c81 source validation records boundary/remote 137 passed and one
skipped; server scope 12 passed, one skipped and 102 deselected; an initial ownership
result of 46 passed/one failed on exported tomllib-helper classification, followed by
one passing actual-inventory correction and 98 passed/one skipped across
parser/config/source/reconciliation after extraction. Native authority and Python
semantic gates pass; 82 workflow-permission tests pass. Full production typing before
the two-file parser extraction covers 1,255 files with zero errors/20,241 warnings.
Final two production plus two gate files have zero errors/68 warnings; inverse
reconstruction proves the other 1,253 production files unchanged from the full run.
These populations overlap and are not summed. Initial failures, a 180-second lock
timeout with no tests executed, a wrong pytest path with no tests executed, and the
first verifier lint failure remain retained. Hosted and installed qualification are not
established.

Foundation a7's retained hosted analysis still has eight new high-severity
Python path findings and two inherited Actions findings; old 343/344 are fixed
on that foundation. These local source checks do not change alert disposition
or establish a fresh CodeQL/Sonar pass. The remote-audit delta separately passes
18 public remote/update cases in 5.23 seconds and one-file typing with zero errors/
five warnings in 1.506 analyzer seconds. Its preceding 180.259-second lock timeout
executed no analyzer. AST transport equivalence and all 1,255 before/after source
digests are retained; no full-production type rerun is claimed.

Actual [prepared checkpoint
`d8bde000`](https://github.com/hashgraph-online/hol-guard/commit/d8bde000de992009be3b2ed009347d2b3707ef0d)
has the same tree as source 73. Its [full-range Gitleaks
scan](../security/gitleaks-prepared-d8bde000de99/receipt.json) has zero findings with
the unchanged reviewed ignore input; a later documentation/evidence child requires a
separate scan. This does not assert current branch publication or fresh hosted success.
Read [PR #2954](https://github.com/hashgraph-online/hol-guard/pull/2954) and [PR
#2951](https://github.com/hashgraph-online/hol-guard/pull/2951) for actual heads and
checks. Historical 9db was the retained installed-test checkpoint for that earlier receipt.

The later foundation cdd observation and its fixture/probe corrections retain their
own source and evidence pins below. The earlier prepared d8 tree and its scan do not
include those later changes or establish a passing final integrated head.

The later foundation checkpoint `cdd14176ef0e0a258d4655c64210524d7047a257` was published
on 2026-09-17. Its actual hosted checkout/build uses test merge
`c92e557349cabd633db408912c644471c002ee4d`, with the same tree
`efb4e859e19b5456f2bdfbac17b2de784adf36a7` and release-base/cdd parents. The [external
CodeQL check](https://github.com/hashgraph-online/hol-guard/runs/105364546143) still
fails with eight high-severity findings; the [CodeQL Actions
workflow](https://github.com/hashgraph-online/hol-guard/actions/runs/35269310464)
succeeds. Workflow success does not clear the external gate, and no new alert dismissal
is recorded. Read the actual PR heads and checks for later state.

The [frozen cdd hosted receipt](../evidence/foundation-cdd-ci-attempt/manifest.json),
observed through 2026-09-17 20:35 UTC, is explicitly interim: 25 workflows comprise 22
successes, two failures and one running; 178 check attempts comprise 144 successes, 22
skips, 11 failures and one running. These are separate inventories. Kilo fails because
its model output limit was reached and reports zero annotations; this is not an inferred
code finding. Linux passed default-auto assemble/install and installed SLO steps, but
its later 100,000-request/250,000-receipt soak is still pending at that cutoff. Its
running log was unavailable, so internal progress is unknown. The original 45-minute
limit covers the entire job; no attempt was cancelled or rerun. A later foundation push
would cancel a still-running job under the unchanged concurrency rule, so read its
actual status before advancing that branch. No complete cohort or hosted correction
qualification is claimed.

The stale Desktop report is corrected by independent full 51,000-case regeneration in
[foundation](../evidence/desktop-source-refresh-20260917/foundation-cdd/manifest.json)
and
[implementation](../evidence/desktop-source-refresh-20260917/implementation-prepublication/manifest.json).
Both generator checks pass. Exactly five expected source bindings change; every other
decoded report, decision, oracle and corpus field is identical, with unchanged-content
SHA-256 `ebfd48ed52410b62aa1d5c1c8105da84cc5605e2ccb5f6311a743bea3fc28cd6`. The 392
foundation and 395 implementation bound source hashes are verified. Foundation
regressions retain 15 passes and one failure against the unchanged 45-second budget in
132.03 seconds; the truncated original assertion does not reveal the exact second
elapsed value. Implementation regressions pass all 16 cases in 117.42 seconds. Its
broader source snapshot observes a concurrent edit to the separate maintenance test
fixture, outside the bound inventory and selected regression modules; those bound
sources were verified again. No product, oracle, deadline or threshold changes, repeated
generation, or fresh hosted pass are claimed.

The test-only [worker fixture
correction](../evidence/daemon-worker-fixture-keywords/manifest.json) makes the two
existing startup/refresh doubles accept the explicit `config_reader` keyword. The
separate [maintenance fixture
correction](../evidence/daemon-maintenance-fixture-reader/manifest.json) gives its
construction-bypassing fake server the reader field and adapts its load double. Main
commit `703d33e37c8b471deee725d596217b7722ac116e` retains two focused passes in 15.11
seconds and the separate maintenance pass in 0.98 seconds, each failed node run once
under the shared lock, plus Ruff and format checks. Return values, recording,
assertions, global-home/no-workspace semantics, retention, production behavior and
deadlines remain unchanged. Original hosted failures are from foundation cdd/c92; the
original fixture bytes were identical in main, but no hosted main failure is claimed.
The receipts pin the owned test files, not every concurrently edited checkout file;
these local checks do not replace a complete hosted shard.

The [default-auto probe
correction](../evidence/native-default-auto-scope-admission/manifest.json), main commit
`e14d9b82403aefba0b164ac8156e2dcc5ce9e72d`, admits the newly created workspace
canonically once before direct-worker registration and keeps that value through the
route corpus. It adds a fixed-code, privacy-filtered readiness-error diagnostic. The
real scoped-capture/publisher witness rejects a lexical alias, accepts canonical
admission with the same capture object, then rejects a retarget and withdraws ACK.
Deadlines, held-parent authorization, capture identity and ACK rules are unchanged; no
production module changes. Main final focused validation has 39 passes, separate from
repeated earlier runs, two-file Ruff/format and one-file types with zero errors/42
warnings. Initial lint failure and all original outcomes remain retained. Synthetic
native status/binding in this source witness does not qualify native IPC or installed
resident ACK. Historical foundation cdd Linux passes default-auto assembly; macOS
Intel/ARM and Windows fail policy readiness. Their original logs lack the publisher
error code, so the demonstrated alias mechanism does not prove every hosted cause;
Windows remains unexplained. No new hosted platform pass or threshold change is claimed.

The [fresh diagnostic
preparation](../evidence/codeql-current-snapshot-diagnostic/manifest.json) fixes six
jobs to cdd/d8 crossed with Actions, JavaScript/TypeScript and Python. Historical
e449/abf profiles remain unchanged and do not rerun. d8 has no observed original
security-analysis run: original merge, run, job, check, count, CLI-build, query-pack and
path-ignore observations remain null. The cdd external check has eight high findings,
but their individual identities and overlap with earlier findings are not established
here. Final source validation has 138 tests in 2.77 seconds, collector-only typing with
zero errors/warnings, and Ruff/format passes; the earlier 135-test result remains
separate. Exact source/tree/layout and workflow/collector checks remain enforced.
Security-result upload stays never, database upload stays false, and only raw SARIF plus
diagnostic metadata are retained. No new hosted diagnostic SARIF or passing security
gate exists in this preparation receipt. Retrieve and verify the six actual run
artifacts after completion before interpreting their findings.

Actual prepared foundation correction `3d11976aaf0e0beb91ebaab30d13666b90465909` has
parent cdd and tree `72749b8a0a3ae04c8d1a86832c7c1cf0270b987a`, equal to local
`0984ddd35c91fa5710d66a8dea204661726c5305`. Its [full release-base
scan](../security/gitleaks-prepared-3d11976aaf0e/receipt.json) reports zero findings
with pinned Gitleaks 8.24.2 in 9.634 seconds including lock acquisition, with unchanged
ignore input and no new suppression or alert disposition. The receipt records no
branch-ref movement; read the actual foundation PR head for later publication. This scan
does not clear cdd's external CodeQL failure or qualify the corrections on hosted
platforms.

The [earlier source validation](evidence/pilots-checkpoint/source-validation.json)
keeps its 147-test integration set, 42-file lint/format and 1,253-file type result
with 20,229 nonfatal warnings at that exact source. Later experiments and fixes
retain their own gates; they are not a combined full-suite pass. Latest
[9db hosted evidence](evidence/takeover-9db62e/manifest.json) records 107 passing
scanner rows, one failed row and four unreached cases, plus four successful
compatible stopped rollback sequences. Every original-baseline strict quiescence
sequence still fails. Linux interpreter provisioning now passes its real installed
same-byte/runtime/validator proof; paired route failures remain separate. These
partial functional results and the historical narrower Linux soak do not complete
installed qualification, live rollback or canary acceptance. The
[execution ledger](EXECUTION_LEDGER.md) records the remaining gates.

The final publication package includes artifact-only correction
`27a102aac076ca68fcb1fac0323c3089a96daa1f`. It preserves the original probe
manifest and exact archived patch bytes using lossless gzip after the whole-net
whitespace check identified the patch's context-only blank lines. The failed
preflight is retained; the corrected full-range diff passes. The current probe
manifest covers 30 artifacts. Probe and test source hashes are unchanged, so the
39-case and focused type results remain their original observations; no test or
type run was repeated for this packaging change.

The [completed cdd hosted attempt](../evidence/foundation-cdd-ci-attempt/FINAL.md)
retains all 25 terminal workflows (22 successful, three failed) and 178 check
attempts (145 successful, 22 skipped, 11 failed). Linux completed its original
100,000-request and 250,000-receipt soak naturally; its older foundation contract
does not establish strict implementation capacity conservation. The other three
platform failures remain recorded, and the artifact's hardcoded Windows waiver
is not accepted as proof. The earlier interim receipt remains unchanged.

Foundation [26cd4dff3f138990a8e9f6a729a970c1dbd90fa4](https://github.com/hashgraph-online/hol-guard/pull/2951)
is now published after that soak completed. Its [exact full-range secrets scan
and readback](../security/gitleaks-foundation-26cd4/README.md) verify zero findings
with the unchanged ignore input and the tested local tree. Fresh hosted checks,
Greptile 5/5 and genuine independent last-push CODEOWNER approval remain required.
The cdd security failure and dismissed historical approvals remain separate.

The [later 26cd hosted checkpoint](../evidence/foundation-26cd-ci-attempt/README.md)
proves 21/21 native-resident default-auto decisions on Windows and both Macs.
Windows native-wheel, Desktop and the four previously failing CI shards pass.
Both Macs then fail the separate Pi probe. Its [once-only root admission
correction](../evidence/installed-pi-scope-admission/README.md) has 32 focused
passes per branch and retains the five-second deadline. Its focused type gate
still has three pre-existing errors and 158 warnings; every diagnostic matches
the archived original after accounting for filename and two inserted lines.

The same hosted fairness case accounts for 238 of 240 requests, with two Claude
RemoteDisconnected exceptions and no established cause. The [bounded client
phase diagnostic](../evidence/daemon-acceptance-failure-stages/README.md) has
14 focused main passes and eight foundation passes while preserving retries,
deadlines and accounting. Its counters describe caught client exceptions and
do not prove server execution. This is diagnostic evidence, not a transport fix.
Sonar was skipped after the test failure, and external CodeQL still reports
eight high findings. Linux soak and Kilo remain incomplete at the frozen
21:09:39 UTC checkpoint; subsequent outcomes require separate evidence.

Foundation [a001b2691f481b7b5a66dd14d68e48d61c44cb78](https://github.com/hashgraph-online/hol-guard/pull/2951)
is published with [exact full-range secrets-scan and readback
evidence](../security/gitleaks-foundation-a001b/README.md): zero findings,
unchanged ignore input and the validated local tree. The earlier implementation
source/evidence cutoff is `e7b8110732b15e8a215358c0ca237d9fd21231f8`. Its production Python/Rust trees equal
prepared d8; later probe/test/docs changes have separate receipts. All 144
original tasks, full dependency prose, thresholds and status counts remain
unchanged. Fresh installed qualification, security gates and independent
last-push review remain incomplete.
