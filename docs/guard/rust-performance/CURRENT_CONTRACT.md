# Current decision and performance contract

Implementation checkpoint `224cca37a57ea4e068c0c586d2354c15abd887f0`, tree `7c4322a4c243c900bedf1365aa2194d888023f7b`.

The [tenth CI evidence](TENTH_CI_EVIDENCE.md) records **42 terminal first-attempt workflows: 37 successful, 5 failed and 0 skipped**
at PR head `095074cda6a751ffaf12b070ecc46a3091f12471`, tree `04d79da9c1cf212cce263c202bfdd5b4350007e3`. The equal-tree PR merge
`9e85de6f42910785e7ba4b53198ddcc05672607c` is a distinct build identity. Each report retains whether its workflow
checked out the PR head or that merge. The later implementation checkpoint
`224cca37a57ea4e068c0c586d2354c15abd887f0`, tree `7c4322a4c243c900bedf1365aa2194d888023f7b`, preserves these measurements as historical evidence;
its changed tests, observers and collector ordering require execution at the new publication. All ten
cohorts and prior supplemental label events remain separate. The native-client
profiler belongs to the original tenth 42; no tenth supplemental event is pooled
into that census. Failed, censored and unoffered work keeps its original denominator.

Original [PRD](PRD.md) and [144 TODO definitions](TODO.md) remain normative.
The [ledger](EXECUTION_LEDGER.md) is **91 DONE / 19 OPEN / 26 BLOCKED / 8 DEFERRED**. RSP-012 closes its literal record/threshold/selection-decision criterion, and RSP-085 closes actual four-target same-request attribution. RSP-011 remains OPEN for complete process-tree resources, RSP-025 remains OPEN for the missing Windows candidate cold and prepared measurements, and RSP-008 remains OPEN for corrected installed config coverage and its other residual phases. All original dependencies are unchanged; these two closures do not promote dependent installed qualification or release criteria.
The established ownership/authority contract below is preserved. Named earlier
cohort observations keep their historical scope; the final section records the
latest measured evidence and later implementation changes.

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

### Compatibility preparation and foreground work

Capacity identity and CLI harness canonicalization use the existing static
contract maps rather than loading every adapter implementation. Accepted aliases,
unknown strings and capacity buckets keep their original semantics. Payload
preparation imports only the selected harness preparer. Foreground load
observations retain bounded queue state and wake the supervisor; process-tree
resource probes and capacity changes execute there with unchanged limits and
pressure policy.

Explicit compatibility processing consumes its existing 1.45-second ordinary
or 2.75-second post-hook cap from connection acceptance, respecting an earlier
caller deadline. Authentication/admission do not create a fresh stage allowance.
The existing outer connection budget also applies to challenge plus hook.

Only an admitted Python-oracle surface prepares compatibility code, rendering
and the immutable built-in manifest before evaluator readiness. Preparation has
no guard-home/request input; store construction, configuration, current verified
authority and approval/evaluation stay on the request path. Failed preparation
cannot announce ready. Normal native operation does not gain a Python classifier
or authority cache. Cold work before readiness must still fit existing startup
budgets. The original storage burst passed unchanged assertions. The older
broader deferred-backfill failure remains recorded in its investigation; all
96 pytest jobs at d0e passed. At the fourth checkpoint, 95 of 96 passed;
one package attribution test rejected a negative profile total. Its correction
uses the real fresh-worker CLI and preserves strict invalid-total rejection.
Fifth Main failed collection before any shard ran because a scanner test left
a scripts path in the global import path, shadowing the root ci namespace.
The scoped import correction subsequently passed sixth Main: all 96 pytest
shards, quality, aggregate CI and complete duration aggregation succeeded.
Sonar analysis succeeded and its quality gate failed. This historical cohort
does not supply green CI or installed qualification for later source.

## Decision and delivered response

The native verdict and receipt remain authority evidence. For ordinary auto/force
hooks, the exact resident-ACKed snapshot selected for the request supplies delivery
posture as well as native policy binding. Local Watch becomes delivery-effective
only after its correct ACK; an in-flight request keeps its sampled binding.
Missing, expired, invalidated or rejected acknowledgement supplies no posture
authority and retains the separate existing availability behavior. External
config changes retain bounded observer/reconciliation visibility, not an
instantaneous guarantee. The [acknowledged posture contract](acknowledged-posture-contract.md)
records both transition directions, strongest workspace composition, receipt
preservation and the unchanged off/shadow test-oracle boundary. An unacknowledged
local setting cannot weaken a bound enforcing result or bypass its command-control
fence. Source tests do not qualify installed mixed-load transitions.

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

The later [format parity correction](package-format-parity-coverage.md) advances
current LOCKFILE_PARSER_VERSION to complete-v3. Invalid top-level Bundler specs
cannot publish partial views as complete; unsupported bun.lockb fallback avoids
content parsing in manifest target discovery. Package approval context includes
the parser version, and a saved v2 allow cannot match the new v3 interpretation.
The preceding source-test observations remain historical; fourth/fifth paired
measurements retain baseline complete-v1 and candidate complete-v2 and do not
measure this later complete-v3 correctness change. The separate sixth package
cohort measures candidate complete-v3 against frozen complete-v1 and preserves
the two frozen Composer failures and twelve censored baseline workers.

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
notification cycle is fixed. Later foreground import/resource-probe and evaluator
preparation corrections have their own source evidence. The d0e pytest matrix
passed, while final installed/fairness qualification and next-head validation
remain distinct from both that success and older backfill observations.

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
workflow invokes installed SLO checks and retains failed reports. At d0e its
30 process-tree memory tests, four independent control-lock checks and
21-decision no-override native corpus passed. The subsequent actual registered
Claude PostToolUse native-route proof failed before a final SLO aggregate was
written. The separate Windows resident workflow passed its exact Job CPU,
related resource/fixture and authenticated-resident checks; those successes do
not qualify the failing launcher. [The diagnostic note](windows-installed-launcher-diagnosis.md)
keeps exact suite scopes and the unproven cause separate. Cross-target
compilation is not Windows execution, and neither alone proves an installed SLO.

Numeric daemon binding delegates to `TCPServer.server_bind` and records its
actual numeric host/port without reverse DNS. Existing IPv4/IPv6 metadata and
real IPv4 binding tests pass. Frozen baseline macOS constructor/reverse-lookup
failures retain their earlier source identity. Bounded resolver registration,
direct-libSystem and separate UDP self-test observations are implemented;
read the actual qualification rerun's reports before selecting a new OS-fixture
correction. An independent candidate scenario or numeric bind does not qualify
frozen baseline readiness. Do not modify baseline source, readiness targets or
budgets to manufacture a comparison.

The d0e Mac wheel source witnesses concern another boundary: OMP/5 MiB on ARM
and Kimi/250 KiB on Intel returned no admitted raw edge despite substantial
remaining caller budget, with client context absent before and after. The
[bridge witness](macos-source-bridge-diagnostics.md) now records actual imported
status, envelope, client, decoder, receipt and failure-recorder calls on that
HTTP handler thread. It copies only fixed labels, booleans and bounded counts.
Projection failures cannot replace the original result or exception. A
nonblocking fixture-only owner excludes concurrent and nested observers without
waiting, serializing requests or interfering with another context's restoration.
No new authority read, client call, decode, retry or deadline is introduced.
The original source-digest/native-result requirement still determines success;
missing stage observations cannot be described as a completed native review.

Qualification attempt 2 retained different pair failures: the Linux baseline
passed 386 daemon and 26 registered cases before reviewed-output digest failure;
both Mac baselines stopped during `socket.getfqdn` construction; candidates
reached actual daemon cases before native unavailability. Independent Linux and
Mac ARM candidate Ollama/Builder scenarios passed. Intel's Builder passed but
enabled-control Ollama readiness failed at the original 400 ms limit. These are
partial workloads, with no completed pair comparison or transition execution.

## Private qualification evidence

[The encrypted archive contract](private-qualification-evidence.md) accepts only
explicit bounded flat JSON/JSONL files. Filenames, hashes and context remain
inside authenticated AES-256-GCM ciphertext; fresh keys are wrapped to the
committed RSA-3072 public recipient using OAEP/SHA-256. A public receipt exposes
only bounded status and ciphertext metadata. Empty/missing input records no
observations. Every tag, manifest hash, name and bound is verified before recovery.
Windows publication retains its handle; Unix uses the documented OS-user
filesystem boundary. The d0e Windows journal/archive tests and bundle export
exposed mixed metadata domains: CPython path stat and descriptor stat do not
give `ctime` the same meaning. The correction uses fresh handle metadata for
path, open descriptor and inventory comparisons. Full identity, mode, size,
write/change times, single-link, owner/DACL and ancestry checks remain; no field
is masked or replaced by cached `DirEntry` metadata. At the fourth checkpoint all five Windows pilot jobs passed their contract
tests and encrypted one failure summary; ordinary Windows qualification bundle
export also passed. The pilot stopped before measurement journals, so this
does not prove their installed retention path. Fifth experiment jobs reached
real measurement preparation/offers, and all 20 final archives were retained.
Three nonpriority fifth archives were independently authenticated and recovered
with 25 private files in total; their original Windows/RAM and Mac baseline
failures remain. This is bounded recovery evidence, not all-platform fault
qualification. Raw observations and the private recovery key stay out of Git.

Local archive/recovery tests include exact interrupted JSONL and private Unix
modes. The second-checkpoint MCP archive was actually authenticated and recovered:
182 files, with the expected 0700 directories/0600 files and unchanged archive
bounds. That Unix component proof does not establish every success/error/fault
artifact's retention, interrupted Windows recovery or installed platform ACL
behavior. The original failed public projection remains byte-for-byte historical. Public MCP evidence is reconstructed recursively from finite typed
fields and exact attempt/phase conservation. Scanner cache errors expose fixed
categories instead of OS messages. Historical scanner digests cover the specified
12 scanner/security files, not the full CLI/harness/dependency environment.

## Source baselines and conditional ports

Current immutable `complete-v3` package results reuse one bounded parse per evaluation,
including text formats and direct/manifest projections. Composer transitive
identity preserves canonical ASCII `vendor/package` names; invalid paths and
non-ASCII normalization tricks are rejected. Direct dependencies are excluded
by their qualified identity. The frozen Composer omission is a coverage defect,
not a comparable performance result.

The [package decision](package-native-selection-decision.md) retains optimized
Python for release 3.2. Five independent fourth-checkpoint protect pairs at
D=B=1,000 have median paired reductions of 96.2752% wall and 95.8662% CPU.
The original ten-worker phase plan completed: two validation workers, six
profiles and two explicit npm `*` resolution workers. Every profiled route
parses once, constructs one index and submits one evidence batch; signed bundle
admission precedes this route interval. Zero in-route signature calls do not
erase admission cost. All six profiles match separate semantic/evidence
commitments and their authenticated private terminal records.

Disjoint function-origin CPU assigns Guard Python median shares of 37.31% in
protect and 51.75% in evaluator. Both Pydantic categories recorded zero calls.
The former unnamed exclusive CPU is now partitioned; inclusive spans still
overlap, and Python-origin entries can own opaque native work. Instrumented
fractions are neither ordinary route CPU nor native speedup bounds. Repeated
normalization, immutable identity and result construction remain material.
No parser-only or single-helper Rust port is selected. A future coarse
model/identity/result operation must first avoid equivalent redundant work in
Python and then pass an actual optimized-Python/native comparison under the
original 30%/5% gate. There is no measured failed native implementation.

Both explicit-`*` resolution arms make 100 admitted GETs through the actual
decoder, semver resolver, evaluator, protect projection and evidence persistence.
They select lower-risk version 2.0.0 over higher-risk 1.0.0, unlike the separate
None-version highest-risk kernel. Only transport bytes are synthetic. Bare
`latest` retains its literal shortcut and is not covered by this witness.
At the fourth decision cohort, RSP-050 retains its kernel/censored-baseline scope: 36 candidate cardinality
cells complete, 24 baseline cells complete and 12 are censored. All 20 candidate
format cells complete; 18 baseline cells complete and two Composer cells fail.
The separate fifth cohort has 36 candidate/23 baseline completions and 13
censored baseline cardinality attempts, with the same two baseline Composer
failures. Its own paired route and phase figures are retained in
[PACKAGE_FIFTH_CI_EVIDENCE](PACKAGE_FIFTH_CI_EVIDENCE.md); no cohort is pooled or
converted into a native benefit result. The separate
[sixth package cohort](PACKAGE_SIXTH_CI_EVIDENCE.md) completes 36 candidate and
24 baseline cardinality cells with twelve censored baselines, 20 candidate and
18 baseline format cells with two frozen Composer failures, and all ten phase
workers. Five protect pairs report wall median 8,765.804810 → 320.749072 ms and
CPU median 7,750.150 → 312.036 ms. Guard Python origin medians are 42.3513% and
54.2777%, with no Pydantic calls. These are independent v3 Python observations,
not native benefit or installed qualification. RSP-059's named source parity
criterion is separately complete; exhaustive grammar and installed tails remain separate.

At that decision checkpoint, the [scanner decision](scanner-current-decision.md)
retained optimized Python while awaiting one fixed finding-heavy comparison
of the existing experimental regex boundary. Seven completed clean states in the earlier source-CLI pilot
showed no qualifying 30%/5% benefit; omitted finding-heavy states prevent a
blanket native no-go. The integrated [opt-in pilot](scanner-regex-pilot-ci.md) plans 24 smoke or
840 full attempts. Its first actual smoke passed binary/bridge correctness
checks, then failed before source identity and preflight; all 24 planned
attempts remain unoffered. Sixth smoke passes four Rust and 95 Python tests,
including all five new actual-native cases, then fails at
python_executable_identity_failed before all 24 offers. A later diagnostic
retains one of 17 fixed public codes from the original read and bounded private
numeric metadata. It adds no extra read, retry, copy or relaxed admission.
That source correction required fresh smoke; the completed eighth full comparison
and subsequent smoke observations are recorded below. Production detection remains Python. Its bounded plan preserves actual fresh Python/Git/Rust startup, serialization,
full findings/HMAC/ordering, complete CPU and exits 0/2/3. Native admission
remains ASCII at most 4 MiB per logical file; other inputs retain declared
Python behavior and cannot count as native coverage.

The [archive profile](archive-worker-qualification.md) satisfies RSP-070's literal
interpreter/member-loop profiling criterion. It retains 510 inspections and
60 separate profiles, with 508/510 expected results and two measured fail-closed
timeouts plus a separate warmup timeout. All 330 hostile/bounded-failure calls
remain non-clean. Retain the separate isolated Python worker; no parser-only
Rust port is selected for this release. A whole-worker native proposal would
need a distinct comparable startup/operation result and containment proof.
Preserve all integrity reads, digest/inode/launch binding, HMAC, expansion
bounds, no-network/read-only isolation, two-second worker deadline and 0.5-second
termination grace. Profiling completion does not imply native qualification or
completion of the original scanner dependencies.

### MCP measurement and retained scope

The [MCP selection decision](mcp-native-selection-decision.md) uses corrected
second-checkpoint v2 evidence: 30 workers, 240 sessions, 10,080 calls and five
independent pairs across eight traces. Eight plain comparisons use run-level
bootstrap intervals; pooled warm calls are not independent runs. Parent-process
CPU, diagnostic calling-thread phases, child-owned loopback service work,
synthetic approval waits and the existing freshness barrier remain separate.
All 80 warm resource windows are complete; all ten lifecycle windows remain
incomplete. Sampled peak memory is not an exact maximum.

Small pure fingerprint/classification residuals beside store/composition/
persistence work support RSP-104/105/107's measured release deferral and RSP-108's
recorded full-proxy decision. RSP-106 is unchanged. No Rust candidate was measured
and no native benefit gate failed. Reopening selection restores the original
contract, implementation, parity and optimized-Python comparison requirements.

The d0e component is a separate successful cohort: 30 workers, 10,080 calls and
80 warm windows with 129–326 samples and no missing readings. Its ten lifecycle
windows retain 18 missing snapshots and nine descriptor-error rows. The earlier
decision cohort has 16 missing lifecycle snapshots. The fourth, fifth and sixth source-stdio jobs
passed, but this refresh does not pool or reanalyze those later cohorts. Source
inventory now binds both imported platform CPU readers; that does not expand
the MCP public projection beyond its actual Linux CPU scope.

### Installed launcher, target and failure contracts

The dormant Claude launcher remains behind default-off
`native-claude-launcher-pilot`. Supported authenticated denial bytes are retained;
unsupported response profiles block explicitly, and actual availability failures
preserve continuation semantics. Read-only package and authority handles retain
their validation contracts. Earlier source-feature tests are not installation
or production activation.

The fourth experiment's 20 jobs all reached registration preparation, then
failed the same target-domain mismatch before offering measurements. The
[correction](claude-launcher-target-identity-diagnosis.md) binds required
`manifest_target` separately from the runtime's `ARCH-OS` label. Python admits
only four shipping associations; Rust independently checks compiled architecture,
OS and ABI. Full config, manifest, runtime, source, package and rule identities
remain required. No global capability-schema change, target normalization or
environment-derived ABI is introduced. Old configs without the new field fail
closed and require explicit preparation. Fifth admission reached real offers:
nine experiment jobs passed and 11 failed, with final archives retained. The
POSIX fixed unavailable-response and Windows discovery-response matches do not
identify their underlying cause. Sixth has 13 passing and seven failing jobs,
with all 20 final retention paths successful. All five Linux jobs complete;
two ARM measurements and all five Windows jobs fail. Every complete native p95
series remains above 50 ms. Windows independent preflight rejects key/state
security admission while bounded reads, authentication and peer identity pass.
The new [producer](windows-discovery-producer.md) establishes private DACLs on
new files without repairing or rotating existing keys. Tenth staged Windows
witnesses show exact native child descriptors unchanged; only the GetSecurityInfo
projection differs for direct children after parent provisioning. The later
preservation oracle compares all queried native descriptor bytes plus the
original identities and payloads, retaining strict legacy-key rejection and
separate Get diagnostics. Its revised Windows test still needs actual execution.
The tenth original packaged bootstrap passes; no cause is inferred for its
separate ninth failure. Production registration remains off.

The [pair validator](qualification-target-identity.md) uses the same four exact
distribution/platform associations while retaining complete wheel, runtime,
package, build, interpreter and dependency commitments. Both recording and
aggregation use this check, including nonpriority tails. Correcting it does
not rewrite fourth-source failed manifests or fabricate unoffered candidate
measurements. All four fourth-source wheel builds passed; all four pair jobs
and aggregators failed. Linux/ARM/Windows candidate Ollama/Builder scenarios
passed, including 22 Windows native cases; Intel exceeded 400 ms readiness.
Fifth likewise built all four wheels, then all indexed candidates failed
PostToolUse response validation. Its Linux/ARM/Windows scenarios each completed
22 native cases; Intel disabled readiness failed at 523.888 ms against 400 ms.
Both Mac frozen baselines remain blocked in OS reverse lookup.
Sixth builds all four immutable wheels. Its four indexed pairs fail, although
Linux and ARM candidate preflight validates 386 daemon and 62 priority cases,
and ARM completes 38 numeric series with 136 observations. ARM retains further
semantic and resource failures; it is not qualified. Windows candidate authority
bootstrap times out before corpus execution. Intel identifies the existing
native_command_control_mutation_in_progress error. Linux fails a later
load-profile route check after its terminal validated c16 Codex Post batch;
the precise failed wave and deltas were not retained.

[Capacity](native-capacity-none-witness.md) and
[stdout-rejection](fourth-installed-failure-observations.md) witnesses retain
finite failure-only facts without extra native/receipt/status calls, retries,
schema acceptance or deadline changes. Existing thread-local failure codes may
be stale. Delivered response shapes do not establish native authority or prove
an availability cause. Stdout diagnostic hashes identify UTF-8 re-encoding of
decoded output, not original stream bytes. Failed batches and all offered and
unoffered work remain in the original journals/manifests.

### Resource and further qualification boundaries

The [Darwin resource collector](darwin-resource-accounting.md) retains pinned
Apple ABI, native birth/timebase identities and bounded reads. Actual fifth ARM
and Intel ignored-child witnesses exposed approximately double accumulation;
endpoint snapshots cannot disambiguate historical signal/reaping behavior.
The corrected general collector therefore returns CPU unavailable with
darwin_reaped_cpu_ambiguous and keeps CPU/resource completeness false. Memory
and private raw counters remain independent diagnostic facts. Other missing,
denied or identity-changed reads remain sticky. Neither psutil replacement nor
division by two can establish complete CPU. Known-child tests retain their
2 ms lower/20 ms upper discrepancy bounds and classify the observed once/twice behavior without
qualifying a general workload. Sixth actual corrected checks pass on both Macs:
nested waited children accumulate once and ignored children accumulate twice.
This verifies the truthful unavailable result, not a complete general CPU
measurement. RSP-011 remains OPEN.

The [nonpriority companion](nonpriority-installed-tails.md) covers 16 actual
registrations independently from normalized HTTP. Explicit
`rust-nonpriority-tail-smoke` selects one Cursor route, pair index zero on four
platforms: 16 timed and 16 preflight invocations if every arm completes.
It takes precedence over full companion labels while leaving main priority mode
independent. Smoke cannot satisfy five-run or 1,000-observation acceptance.
Without the smoke label, both full companion labels select the 320-job plan.
Every route/platform keeps its original denominator and strict sealed-cohort
aggregation. Fifth Linux completed both two-sample arms; Windows retained
complete workers but failed missing-RAM identity admission, and both Mac
baselines failed DNS while candidate arms completed. All four aggregators
failed. Sixth Linux and Windows complete and aggregate both arms; Windows
records 17,174,360,064 RAM bytes in each. Both Mac candidates complete, but their
frozen baselines time out in getfqdn before registration or offering. All eight
worker/summary ZIPs and encrypted bindings are verified. Twelve of sixteen
planned timed observations are accepted; four baseline observations remain
unattempted. All qualification flags remain false.

The independent stopped-artifact transition probe uses exact indexed wheels,
a third environment, candidate-locked dependencies, five stopped phases and ten
registered cases. It was skipped at the fourth, fifth and sixth checkpoints. Stopped replacement
does not qualify in-flight generations, signing/frozen changes, live program
updates or rollback. Full priority/nonpriority samples, mixed offered load,
resource minima, actual signed artifacts and tested rollout remain mandatory.

The [bounded installed ranking](installed-launcher-baseline-ranking.md) keeps
one Windows block's actual 80 Claude/Codex invocations. Ordering varies by event
and load, so Claude is not uniformly the slowest route and missing surfaces
have no invented zero cost. RSP-073's ranking, RSP-024's technical review and
RSP-074's launcher design retain their original scope. An accurate RSP-144
handoff and RSP-120 coverage publication do not supply RSP-118 platform success,
RSP-137 performance qualification, RSP-142 independent latest-push approval or
RSP-143 canary/rollback execution. The [ledger](EXECUTION_LEDGER.md) remains the
complete record of the unchanged 144 acceptance and dependency fields.

## Current qualification observations and resource limits

| Workstream | Tenth observation and practical limit |
| --- | --- |
| Main CI and security | Main has 114 terminal jobs: 110 successful, one failed and three skipped. All 96 pytest shards, the CI aggregate and duration aggregate pass. The Windows packaged bootstrap passes its original regression in 53.60 seconds; the earlier ninth failure remains historical, without a new cause. Ordinary Sonar analysis succeeds and the unchanged quality gate fails; no numeric gate condition is inferred. Security passes all four jobs, and both authority and I/O ownership workflows pass. All 195 unexpired Main artifacts are verified by paginated metadata, including 96 coverage and 96 duration artifacts; this does not claim artifact-byte recovery. |
| Installed native launcher | Fifteen POSIX jobs complete 1,320 of 1,760 total planned attempts, including 1,200 timed observations; the five Windows jobs leave 440 unoffered. Linux native PreToolUse p95 ranges 41.048–51.696 ms with one of five at or below 50 ms; PostToolUse ranges 41.475–53.556 ms with two of five at or below 50 ms. ARM Pre/Post ranges are 119.325–188.568/136.322–179.435 ms; Intel ranges are 202.568–420.056/208.314–439.638 ms. All 15 POSIX runs restore registration and retain production activation and qualification as false. Fifteen encrypted six-file producer receipts are retained; no ciphertext recovery or new native selection is inferred. |
| Windows preservation witness | Five Windows launcher jobs each retain 107 passing tests, six skips and one failed original child-preservation assertion, before any of their 440 planned requests. Their complete identical staged witnesses show every 148-byte native descriptor unchanged across all four stages and around every GetSecurityInfo read. Only the Get projection of the two direct children changes after manager provisioning; owner/group, file identity and payload remain unchanged. This does not establish a stored descriptor mutation or undocumented Windows internals. Five zero-file no_observations receipts remain separate from completed POSIX work. The later test correction compares complete native owner/group/DACL bytes plus original identity and payload, retains strict legacy-key rejection and separate Get diagnostics, and still requires actual Windows execution. Production setters and deadlines are unchanged. |
| Existing native-client transport | All four installed diagnostic targets pass 125 Python and nine runtime profile tests each, with two additional Windows companion pipe/handle tests. Each completes 40 of 40 hooks with zero failures or unoffered cases, one helper, 42 client frames, 43 resident frames and 40 successful matched socket opens. Eight ZIPs match GitHub hashes/sizes and four five-file archives authenticate and recover. Independent review rehashes all 20 private files and recomputes all 160 unique request/client/resident joins, final helper and relay EOF/count coverage, and every client/evaluator/dispatch aggregate. RSP-085 is DONE at its literal attribution criterion. Benign authentication/evaluator p95 milliseconds are Linux 4.672/0.829, ARM 38.214/0.461, Intel 33.951/1.044 and Windows 2.556/2.068. The evaluator elapsed span includes validation, snapshot, fence and receipt encoding; authentication includes waiting. Inclusive spans are not added/subtracted, and this is neither pure CPU nor a measured connection-reuse benefit. Normal-release, process-tree resource and full qualification flags remain false. |
| Cold and warm executable identity | Five reached arms retain fifteen validated cold-lifecycle hooks and fifteen separate prepared-resident hooks: Linux baseline/candidate, both Mac candidates and Windows baseline. Every reached scenario has three planned/offered/started/validated hooks and no unknown or unoffered work. Fresh-child cold scenarios have complete/drained observers and verified child exit status 0. The cold interval starts after imports/private-journal admission, before observer installation and the real daemon constructor; normal preparation can ready the resident before the first hook. It is not OS-cache or import cold time. Each 1 KiB benign Claude PostToolUse hook has one status lookup and capability hit. Linux candidate reuses verified live proof and hashes zero executable bytes per hook; its preparation still performs four full validations plus one reuse. Linux baseline hashes 6,305,152 bytes per hook, ARM candidate 10,772,768, Intel candidate 11,277,348 and Windows baseline 5,439,488. Capability reuse is distinct from digest reuse. Windows baseline preparation and cleanup each have two publication calls hashing 10,878,976 bytes, separately timed at 64.1543 and 24.3286 ms. Their distinct phases are not combined. Both Mac baselines fail construction and Windows candidate stops at an earlier c16 route assertion, before either identity scenario. RSP-025 remains OPEN specifically for that missing candidate coverage; the later ordering change requires its own execution. Only Linux has a completed paired comparison. |
| Indexed qualification and settings | The 27-job qualification workflow finishes with twelve successes, thirteen failures and two skips. Four immutable wheels build. Five complete indexed arms retain 680 numeric values; Windows candidate separately retains 66 partial values, fifty validated and sixteen returned but unvalidated. Its first registered Claude PreToolUse c16 wave fails route-count validation; the exact mismatch and cause are unobserved, with no inferred timeout. Six reached corpora complete 2,316 normalized cases and 372 registered validations; 55 Windows baseline source-reference denials remain unsupported review, not content parity. Both frozen Mac baselines fail getfqdn. Only Linux completes a paired aggregate. Every completed arm fails mixed, approval, input, raw-UTF8 and registered-surface side scopes. UTF8 registration interruption is additional to its deliberately unqualified design. Windows baseline retains 39 valid steady and 112 capacity samples; Linux candidate has ten and 55 with unavailable counters. Darwin process-tree CPU remains unavailable where ambiguous. Settings/Builder retain 22 native cases on Linux, ARM and Windows; Intel stops after two at 400.736 ms against the unchanged 400 ms enable deadline, and all four Builder subchecks pass. No sampled stack identifies the cause. Full Python phase groups are authenticated and retained despite public depth truncation; absent config observations are not zero and motivate the later binding-coverage correction. Twenty ZIPs (9,587,454 bytes, 81 members), four authenticated indexed archives (142 files), and three authenticated tail archives (21 files) retain their individual custody levels. Complete sampling, resources and qualification remain false. |
| Nonpriority tails | Eight tail jobs finish with two successes and six failures. Five of eight arms complete; ten of sixteen planned timed values and ten separate preflights are retained, with six timed values unoffered. Only Linux has a complete paired comparison. Both frozen Mac baselines fail constructor getfqdn before offers. Windows candidate fails before any case or numeric journal, while its baseline completes two timed samples. Its finite error origin is safe_output_windows._raise_windows_error: raw GetLastError code 32 means Windows sharing violation, even though the existing OSError wrapper labels it BrokenPipeError. The failed operation, conflicting handle and underlying cause remain unknown. Eight ZIPs (71,929 bytes, 37 members), four ciphertext hashes and three narrowly authenticated recoveries of 21 files are verified; sampling and qualification remain false. |
| Installed native wheel and soak | Native-wheel CI finishes two successful and two failed targets. Linux and Intel pass fourteen smoke gates each. Windows passes thirteen but fails c16 p99 at 1,282.125 ms against its unchanged 1,000 ms smoke bound; sixteen responses return with zero errors. ARM stops before build at the decimal-PID privacy assertion: 111 tests pass, one fails and one skips; its wheel/SLO observations remain unoffered. The three completed targets each retain 146 SLO numeric values, 21 default-auto resident decisions and 21 accepted/processed receipts with no drops or pending. Separate writer-failure counters are Linux zero, Intel zero and Windows three. c64 conserves 64 responses each, with 1/25/22 explicit overloads respectively and zero errors; no c64 latency ceiling is emitted. Linux soak completes 100,000 logical calls/responses with zero final errors and 17,367 successful health checks, stable PID and start_requested/ready/stopped lifecycle. Its p95/max are 503.43/581.21 ms against 4,500 ms; RSS rises 615,759,872 to 638,566,400 bytes (3.7038%), below 50%, with 71 threads and 199 descriptors at peak. Up to three transport tries per logical call and 250,000 preseeded receipt rows do not prove 100,000 new native decisions or durable receipts. Runtime bytes bind equal-tree merge 9e85de6f separately from head 095074cd. Thirteen public JSON records are reconstructed from exact decoded-log spans; artifact metadata does not claim ZIP, wheel or private-ciphertext recovery. These smoke gates do not replace the 50/100/200 ms ordinary priority release gates. |
| Package | All three component jobs pass 132 correctness tests. Formats retain twenty candidate and eighteen baseline completions plus two failed frozen Composer cases. Cardinality retains 36 candidate and 24 baseline completions plus twelve censored baseline workers, under unchanged 15/20/30-second budgets. All ten phase workers complete. Five complete protect pairs retain wall medians 8,760.358205 to 319.871925 ms and CPU medians 7,730.081 to 311.412 ms; median paired reductions are 96.3541685537% and 95.9764129901%, distinct from ratios of medians. Separately instrumented Guard-Python exclusive calling-thread origin shares are 41.6229614% protect and 53.0125243% evaluator, not attainable native savings. The measured change is optimized Python against frozen Python. Composer v1/v3 cardinality mismatch remains noncomparable. Four component public ZIPs including MCP total 116,807 verified bytes; the repository retains twenty public files including derived receipts/metadata, separately from fourteen ZIP members. The 331 package encrypted-file commitments remain producer evidence without recovery. The original package keep-Python decision is unchanged. |
| MCP | MCP passes 126 correctness tests and completes thirty workers with 10,080 outcomes and zero failures, 48 groups, 240 run traces and 364 phase rows across eight five-block comparisons. All eighty warm resource windows have 145–357 samples with no missing readings. Ten lifecycle rows remain incomplete, with fourteen missing samples and 35 descriptor denials across nine rows. The catalog-1000 wall ratio is 0.556841 (95% CI 0.555858–0.563984), CPU 0.463798 (0.459105–0.469547); the 16 KiB payload wall ratio is 0.686183 (0.677683–0.692586), CPU 0.619391 (0.617353–0.625873). These are complete same-route optimized-Python observations at their declared scopes. The verified public ZIP is 92,714 bytes; 181 raw commitments and a 182-file encrypted producer receipt do not establish private recovery. The original native no-selection decision and lifecycle/resource limits remain unchanged. |
| Scanner | The tenth smoke completes 24 of 24 same-source observations, with four Rust and 192 Python tests passing. Twelve native observations each scan four native files with zero fallback; result/stdout commitments match. Two public ZIPs totaling 3,520 bytes and four members are verified. Encrypted evidence remains metadata/producer commitments for 113 files. This one independent run does not replace the historical eighth 840-attempt comparison, whose only passing case/cache cohorts were the large dense provider fixture in both states. Production Secrets CLI remains Python; no universal size cutoff or installed/platform activation is selected. |
| Dormant source pilot | All four source-pilot platform jobs pass 32 Python and 17 Rust tests each, the bound fixture and explicit feature-off/on source smoke. Production registration remains unchanged and installed qualification remains false. |
| Packaging and release | PyPI authorization and Build + Verify pass, while all fourteen downstream release jobs skip. Both Desktop feeds validate and skip publication. No release, canary, signing, live update or rollback is inferred from these workflow names. Latest-push human/code-owner approval remains absent. |

| Later source change | Resulting behavior | Required next evidence |
| --- | --- | --- |
| Darwin privacy assertion | Replace a decimal PID-substring check with exact report keys, finite reason/string fields and numeric scalar shapes. A deterministic duration of 338.413213 exercises the real collision while preserving every CPU-unavailable and incomplete assertion. The production collector is unchanged. | The revised test must pass on the actual ARM wheel job that previously stopped before a build; its missing measurements remain unoffered. |
| Windows preservation oracle | Compare every queried native self-relative descriptor byte, exact object identity and payload. Preserve strict existing-key rejection before/after the same product calls, parent identity, key value and separate GetSecurityInfo diagnostics. Tests reject changes in protection/inheritance bits, access mask, owner/group, reserved/padding bytes, identity, payload and key admission. | Execute the revised assertions on Windows. The prior failure and 440 unoffered requests remain historical; no flag masking, child repair, setter, retry or deadline change is introduced. |
| Config lookup coverage | Observe the four actual foreground module bindings: canonical configuration, HookWorker, daemon server and native continuation. Preserve original results/errors; count each binding entry and time only the outermost nested lookup. Fixed-schema coverage records setup, wrapper changes, restoration and overlapping work. Only complete restored coverage with a completed eligible foreground operation can certify zero calls. | Execute the corrected observer in installed attribution scopes. Missing/unsupported bindings, setup overlap, in-flight teardown, replaced wrappers and unscoped callbacks remain incomplete or excluded; absent counts are never inferred as zero. Existing authenticated full phase groups remain retained. |
| Attribution before qualification gates | Run the existing Python-phase, prepared-identity and cold-identity collectors once immediately after runtime/profile admission, before contract-corpus and headline gates. Reuse and validate those exact reports later. Existing collector bodies, independent fixtures, payloads, file names, deadlines, archive bounds, and original exception/traceback behavior are preserved. | Obtain actual Windows candidate cold/prepared observations and corrected config coverage even when a later unrelated corpus/c16 gate fails. Execution order changes warming conditions, so this is a new source cohort and cannot be pooled with earlier timings. It does not fix the existing route failures or establish an OS-cache-cold measurement. |

Tenth witnesses establish exact native child descriptor preservation at the observed stages; the later oracle correction still needs target execution. Default-off native-client instrumentation measures original inclusive elapsed boundaries, never exclusive CPU or predicted benefit. Capability reuse, live executable proof and full hashing remain distinct. Native verdict, acknowledged posture, availability and delivered response remain separate. No production Rust activation or release qualification is inferred from diagnostic completion. The config observer must prove complete four-binding foreground coverage before claiming zero lookup work; setup/teardown overlap and changed or missing bindings remain explicit. Early attribution collection preserves independent fixtures and original exceptions but changes execution order; the new cohort cannot be combined with prior timings.

See [RELEASE_REVIEW](RELEASE_REVIEW.md), [TENTH_CI_EVIDENCE](TENTH_CI_EVIDENCE.md)
and [TAKEAWAY](TAKEAWAY.md) for exact evidence and remaining acceptance.
