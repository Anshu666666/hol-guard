# Current decision and performance contract

This contract describes local source `c964a61a3a4c19d721358e69c400d6059dfd1156`.
It incorporates published PR #2970 head `107606388` and the subsequent reviewed
measurement, Windows authority and fixture corrections. The last observed CI
belongs to `107606388`, not this later source. Source support is distinct from
installed activation and release qualification. [RELEASE_REVIEW.md](RELEASE_REVIEW.md)
records exact current evidence; [EXECUTION.md](EXECUTION.md) retains older rounds.
All original requirements remain in the [PRD](PRD.md) and [TODO](TODO.md).

## Ownership and timing boundaries

Ordinary local HTTP hooks enter `guard/daemon/server.py`, dispatch directly into
`HookWorker.review_http_payload`, then `_review_native_edge` in
`daemon/hook_worker_native.py`. `native_hook_edge.review_raw_hook_native` calls
the persistent native client helper through `native_resident_client.py` and
`native_resident_stream.py`; the Rust resident owns the semantic decision. A
Python guardian/evaluator pool remains relevant to verified compatibility and legacy Codex
revalidation paths. The integrated native Codex browser completion uses fresh native-worker
evaluation instead of that pool. Ordinary hooks must not be described as
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
and availability handling are separate stages. An authenticated acknowledged
observe snapshot can establish Watch recording behavior without re-reading
configuration. When that proof is absent, the current config and availability
logic remain necessary. A metadata-only or unacknowledged mode cache cannot
authorize a stale observation posture after an enforcing update.

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
semantics. Borrowed canonical serialization feeds the request hash directly,
while a bounded counting writer enforces envelope size without a temporary
serialized buffer. Object keys remain sorted and only the original root
transport fields are omitted; the digest version and domain are unchanged. Every native API change
requires negotiated capability and strict
result validation; legacy optional-field absence must retain legacy encoding.

Executable status binds package version, manifest/runtime digest, target and
ownership/permissions. Capability caching alone does not eliminate executable
hashing. Implemented attestation reuse refers to an already verified Linux live process,
with stable start identity, exact image, verified package and current manifest.
Stat metadata can invalidate a cache but cannot prove content integrity. A new
spawn requires fresh full validation; death between lookup and dispatch must not
let a cached digest authorize its replacement. Unsupported platform/filesystem
proof retains full validation.

## Package parsing and completeness

RSP-052 is DONE at its original source/component acceptance boundary. Integrated 17c531a10 completes
single-traversal Yarn/pnpm/Gemfile manifest and direct-selector views alongside the existing shared
JSON/JSONC/TOML decode. Immutable complete-v2 results preserve exact bytes, supported
duplicate/alias behavior and typed completeness; a failed parse is reused only within one evaluation
and a new evaluation parses again. Numeric 8 MiB/100,000-entry/250,000-node/depth-128/deadline
limits remain unchanged, with explicit text-node/depth/projection accounting. Owner batches passed
49 new and 142 existing tests; a broader 275-case run had 274 passes and one old retry expectation,
then the corrected context-reuse regression passed in the final 50-case and single-case runs. All
392 frozen-base direct-selector comparisons agreed. No timing, native package or installed
qualification is claimed.

See the [text lockfile contract](../rsp-text-lockfile-contract.md). JSONC/UTF-8 and
duplicate semantics stay with the existing supported parsers. Text admission now
explicitly counts grammar nodes, indentation/bracket depth and selector projections;
newly over-budget text becomes typed incomplete. The contract does not claim full
YAML/Bundler/Yarn validation. RSP-050/054/059 and installed/native comparisons remain separate.

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
evaluation and final approval authority use shared leases on the same retained
lock; an exclusive mutation lease excludes those operations and vice versa. Stable
Python reconciliation also uses shared access; a semantic-write sentinel releases
it and re-verifies under a new exclusive lease before effects. There is no
in-place shared-to-exclusive upgrade. Compilation is outside the critical lease. Windows uses actual `LockFileEx`
shared/exclusive byte-zero locking on the admitted private handle. The CRT
`msvcrt` read-lock constant was exclusive and is no longer used as a shared
lease. Cross-process raw whole-file overlap and bundled-Rust verifier probes
are wired; successful installed Windows execution is still a separate proof.

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

Ordinary local approval continuation is **resolved-row reuse**. The queued action
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

Claude ask → local resolve → retry and native Codex browser-wait completion
have distinct authority. At this source cutoff, eligible registered native Codex
reviews preserve the original independently live process, validated home context
and bounded wait deadline. Their local-once grant is narrowly created for that
verified waiting operation even when general policy persistence is disabled.

The queued native receipt's full-input `request_digest` becomes the MAC-bound
`artifact_hash`. Completion re-evaluates the exact raw hook with the original
source context and acknowledged policy, then validates the native receipt's
policy generation/digest, runtime identity, program and command observations.
Fresh request digest must equal both the stored receipt commitment and signed
artifact identity. The six fixed fields—request ID, harness, artifact ID, artifact
hash, workspace and publisher—are compared at final rereads. Mutable display
metadata cannot select another signed grant or skip the final native check.
Generation renewal conservatively requires new approval for this route; ordinary
resolved-row reuse keeps its separately documented effective-binding behavior.

The shared control lease spans fresh native evaluation, final checks and atomic
one-time consumption. Only strict native allow or review outcomes are eligible;
independent blocks and uncertainty retain their floors. Terminal replay requires
an exact, unexpired, MAC-verified consumed grant, with claimed time no later than
now. Unsigned resume status cannot supply authority, and a newly terminal row
cannot bypass consumption. The original bridge must remain live and within its
original wait deadline; final elapsed checks include database finalization and
lease retirement. A late consumed result is not delivered as timely allow.

Integrated source `ae0725300` and getter `f5e96de0f` have 72 final focused passes.
The broader 117-test run had 115 passes and two failures: the two-second
app-server adapter timeout reproduced on unchanged source, and the waiting case
passed alone. No limits were raised and no socket-environment excuse is used.
Actual installed Codex browser continuation is still pending; source tests and
qualification assertions are not an installed success.

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
Bounded framing keeps notification processing live while approvals are pending.
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
as background work. The narrow Python shared lease is classified as synchronous authority fencing,
not asynchronous publication. Background captured-byte policy compilation and
foreground native receipt validation retain their distinct ownership.

Current test suites cover native contracts, malformed/source mutation, separate
native approval APIs and ordinary local review reuse, Watch/availability,
policy publication and scanner parity. Those tests
are necessary but do not establish installed performance or final code-owner
approval. The [execution ledger](EXECUTION_LEDGER.md) records those remaining gates.

## Qualification fixture scope

Fresh command qualification sessions use a real generated authority key,
encrypted storage, durable empty state and independent protected-health readback
before daemon construction. The publisher must establish an actual native ACK
within the unchanged 400 ms deadline. Interactive enrollment is unexercised.
Large eligible output requires the native reviewed-content digest. Source/kernel,
HTTP delivery, actual registered-launcher and instrumented phase evidence remain
separate. A failed or missing observation cannot become a successful sample.

Both installed environments are outside source checkouts. Runtime, wheel,
manifest and canonical build SHA remain bound to the tested artifact; Ollama
identity uses `build_sha` through both privacy projections. One readiness attempt
retains phase, prior completed cases, elapsed/returned state and nonblocking
cached publisher diagnostics. Observations cannot retry, publish, renew state or
authorize readiness. Approval-queue injection matches the real positional
`persist(request, now)` signature in frozen and candidate code.

A contained baseline failure is retained before an independent candidate attempt.
The pair stays incomplete and has no valid comparison. Lost containment stops
further work. Exact case journals record offered and terminal outcomes before
assertions; unknown normalized adapter HTTP status is explicitly unobserved.
Declared oversize transport uses the frozen `request_body_too_large` refusal.
The separate malformed, approval, nonpriority and mixed scenarios retain their
own outcomes; instrumented phase work does not enter headline latency.

### Watch and native boundaries

The authenticated raw native edge preserves intrinsic secret deny/block and its
unprefixed reason. The daemon separately renders Watch delivery as warn/allow,
with the original output digest where the harness exposes it. That operation
does not invent `observe_mode` or `observed_policy_action` fields. The direct
`guard-hook-core` observe API has a different response contract. Regression
vectors pass through the real frozen and candidate Python worker/renderer paths;
they do not claim an installed Rust run. Unavailable Watch remains separate from
completed native evaluation. Production policy was not changed to fit the corpus.

### Bounded HTTP and concurrent evidence

Initially partial headers are observed through `InitialHeaderReader`; framing
ownership changes under the classification lock before the parser can hide the
terminator. Waiting occurs outside the lock against the original absolute
400 ms deadline. CPython retains syntax, line and header-count validation.
Body and subsequent-request bytes are preserved. Watchdog and overload eviction
recheck the exact socket/deadline under the same lock before closure; request
capacity is released once outside that lock.

The scheduler notifies queued waiters only when dispatch changes work state.
Permit release explicitly wakes byte reservations. Deadlines, fairness,
predictive admission and capacity are unchanged. The confirmed unchanged-state
notification cycle is fixed; the separate historical CI deadline failure still
requires an installed/batch rerun.

Concurrent response routes remain `pending_batch_validation` because shared
counter deltas cannot identify a single overlapping request. An isolated wave
must conserve exact attempts, completions, errors, resident decisions, native
fail-safe decisions and explicit engine-bypass overloads. c16 requires exactly
16 completed requests with no overload; c64 requires exactly 64 accounted
outcomes. Generic denials cannot be inferred as overload from health counters.
HTTP503 requires the exact production capacity body or a known typed capacity
reason; unknown, unauthenticated, malformed and oversized responses fail.
No unsupported individual route attribution or retry changes a zero-error gate.

### Windows source-read support

The frozen baseline rejects non-Unix secure opens and reports
`no_output_to_review`; that failure remains visible. The candidate Windows reader
walks relative to retained directory handles, rejects ambiguous names/reparse
points, preserves ancestry, denies write/delete sharing and verifies full
128-bit file identity, volume, metadata and security descriptor around a bounded
read. The source layer retains the one-link rule, digest and byte/deadline limits.
The common read facade allows separately controlled package-file policies.

`native-source-handle-read-v1` is advertised on implemented Unix/Windows targets.
The qualification selector verifies the actual bundled runtime and exact path
before consulting that capability. An old Windows artifact gets only its known
refusal oracle, excluded from successful source-review timing. A capable Windows
candidate gets the original full-content, malicious-content and digest oracles;
a candidate refusal cannot select the old baseline exemption. The Windows wheel
workflow now invokes installed SLO checks and retains failed reports. Cross-target
compilation is not Windows execution, and neither proves an installed latency SLO.

Numeric daemon binding already delegates to `TCPServer.server_bind` and records
its actual numeric host/port without reverse DNS (`9cca767fe`). Existing IPv4/IPv6
metadata and real IPv4 binding tests pass. The frozen macOS baseline still hangs
in `getfqdn`; its PTR fixture received zero queries. Candidate startup and OS
resolver behavior require separate observed CI evidence.

## Private qualification evidence

[The encrypted archive contract](private-qualification-evidence.md) accepts only
explicit bounded flat JSON/JSONL files. Filenames, hashes and context remain
inside authenticated AES-256-GCM ciphertext; fresh keys are wrapped to the
committed RSA-3072 public recipient using OAEP/SHA-256. A public receipt exposes
only bounded status and ciphertext metadata. Empty/missing input records no
observations. Every tag, manifest hash, name and bound is verified before recovery.
Windows publication retains its handle; Unix uses the documented OS-user
filesystem boundary. Raw observations and the private recovery key stay out of Git.

Local archive/recovery tests include exact interrupted JSONL and private Unix
modes. Actual CI retention, download, recovery and Windows ACL behavior remain
required. Public MCP evidence is reconstructed recursively from finite typed
fields and exact attempt/phase conservation. Scanner cache errors expose fixed
categories instead of OS messages. Historical scanner digests cover the specified
12 scanner/security files, not the full CLI/harness/dependency environment.

## Source baselines and conditional ports

Immutable `complete-v2` package results reuse one bounded parse per evaluation,
including text formats and both direct/manifest projections. Composer transitive
identity now preserves canonical ASCII `vendor/package` names; invalid paths and
non-ASCII normalization tricks remain rejected, npm behavior is unchanged, and
direct dependencies are excluded by their qualified identity. The frozen
Composer omission is a coverage defect and not a comparable performance result.

The independent package matrix and isolated MCP runner retain real routes,
strict semantic coverage, failed attempts and artifact identity. Their source
validation does not select a Rust port. The rich scanner and 1/10/100-workspace
source baselines meet RSP-062 and RSP-128 respectively. Native comparisons,
installed load, full process-tree resources and rollout remain separate tasks.
The archive profile retains failed observations and does not close RSP-070.

The dormant Claude launcher pilot is integrated behind the default-off
`native-claude-launcher-pilot` Cargo feature. Authenticated daemon responses retain
supported denial bytes; unsupported response profiles return an explicit block,
while actual availability failures keep the existing continuation policy.
Authority and package files use retained read-only handles with their separate
verification rules. The four peer findings are corrected. Source tests and
explicit default/pilot executable checks pass on Linux; the four-platform feature
workflow is wired and awaits execution. Registration, supported-domain parity,
installed lifecycle/recovery, stalled-stdio containment and paired performance
benefit remain separate acceptance gates. The [ledger](EXECUTION_LEDGER.md)
retains every conditional go/no-go and installed release requirement.
