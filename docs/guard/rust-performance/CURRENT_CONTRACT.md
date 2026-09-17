# Current decision and performance contract

This contract describes the implementation identified in [EXECUTION.md](EXECUTION.md),
including the 2026-09-17 takeover corrections to Codex continuation, package
parsing and MCP notification delivery. It includes native command execution,
control authority and live-process attestation. Source support
is distinct from installed activation and release qualification; exact evidence
and remaining acceptance are in the [execution ledger](EXECUTION_LEDGER.md).

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
in-place shared-to-exclusive upgrade. Compilation is outside the critical lease.

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

## Source ownership and proof

`scripts/ci/rust_pretool_no_python_gate.py` and `rust_io_ownership_gate.py` protect
the authority/I/O boundary. The latter follows recording-mode callers and labels
decision-time config access `synchronous_posture_config`; it does not relabel it
as background work. Background captured-byte policy compilation and foreground
native receipt validation retain their distinct ownership.

Current test suites cover native contracts, malformed/source mutation, separate
native approval APIs and ordinary local review reuse, Watch/availability,
policy publication and scanner parity. Those tests
are necessary but do not establish installed performance or final code-owner
approval. The [execution ledger](EXECUTION_LEDGER.md) records those remaining gates.
