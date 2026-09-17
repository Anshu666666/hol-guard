# Current decision and performance contract

This contract describes the implementation identified in [EXECUTION.md](EXECUTION.md),
including the 2026-09-17 takeover corrections to Codex continuation, package
parsing, bounded source experiments and MCP notification delivery. It includes
native command execution, control authority and live-process attestation. Source support
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
CLI, package reloads, persisted approvals and remote command/resume readers.
Publisher reuse requires the identical capture object, and an uncacheable policy
reload still uses that capture. Rejection withdraws ACK before an older snapshot
can be retained. Source `591d5c81e6bb341c6c3271332f3a6615a01bc748` has the
bounded combined checks recorded below; new hosted analysis and actual Windows
execution remain pending.

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
or establish a fresh CodeQL/Sonar pass. Publication/new analysis remain pending.

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
