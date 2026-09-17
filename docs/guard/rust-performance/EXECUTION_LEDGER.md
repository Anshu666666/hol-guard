# RSP execution ledger

Execution status for the original 144 tasks. This is an active implementation record, not a release acceptance certificate. The original [TODO](TODO.md) and [PRD](PRD.md) retain the complete proposal and source links. The [machine-readable ledger](execution-ledger.json) retains every original acceptance condition and dependency.

Snapshot: 43 BLOCKED, 37 DONE, 64 OPEN. Installed performance qualification is not complete.

| Task | Status | Acceptance evidence or remaining work |
| --- | --- | --- |
| RSP-001 — Pin the implementation source and artifact | OPEN | Baseline source, locked toolchain and Linux native wheel are pinned in EXECUTION.md. Final candidate and four-platform artifact identities await qualification. |
| RSP-002 — Recheck active migration overlaps | DONE | Seven overlapping PRs rechecked through GitHub on 2026-09-17; reuse/conflict decisions and exact heads are recorded in EXECUTION.md. |
| RSP-003 — Trace and name the four timing boundaries | DONE | Current call graph and four timing boundaries documented in CURRENT_CONTRACT.md; benchmark output keeps installed launchers separate from normalized HTTP and kernel probes. |
| RSP-004 — Repair the Python semantic reference | DONE | Isolated scripts/native_benchmark_oracle.py exercises the Python semantic reference; off-mode availability cannot pass the benign/malicious oracle checks. |
| RSP-005 — Assert semantic work on both benchmark arms | DONE | Reference and candidate benchmark fixtures assert route, verdict and reason class; synthetic secrets cannot pass as availability continuations. Oracle remains scripts-only. |
| RSP-006 — Correct existing SLO descriptions | DONE | Existing gate labels retain warm OR and cold AND semantics; 1,000 ms adapter budget and diagnostic versus qualification limits are documented. |
| RSP-007 — Add actual installed launcher measurements | OPEN | Registered Claude PostToolUse launcher pilot implemented. Four priority installed pre/post argv routes and full platform measurements are being integrated. |
| RSP-008 — Add attributable phase measurements | OPEN | Bounded phase profiler and resource reporting implemented; complete hashing/config/JSON/admission/queue/native/evidence/response attribution remains required. |
| RSP-009 — Create the workload and platform matrix | OPEN | 377 independent semantic/delivery cases and size/concurrency matrix frozen; complete installed platform execution is pending. |
| RSP-010 — Add statistically meaningful qualification mode | OPEN | Alternating paired driver, sample minima and confidence intervals implemented; final executable corpus/recovery runner integration is pending. |
| RSP-011 — Measure the full process tree and saturation | OPEN | Closed-loop plus offered-rate accounting implemented; independent daemon process-tree resource collection is being integrated. Unsupported CPU/private metrics stay unavailable. |
| RSP-012 — Freeze baseline and choose measured tranches | BLOCKED | Requires complete frozen installed baseline. Algorithm prerequisites are selected; optional Rust migrations remain behind the original benefit gates. |
| RSP-013 — Capture the real ordinary native call graph | DONE | CURRENT_CONTRACT.md traces direct daemon HookWorker dispatch and persistent helper reuse; it identifies approval/compatibility pool callers separately. |
| RSP-014 — Inventory every installed harness surface | OPEN | Existing generated adapter contracts plus qualification corpus inventory aliases and observation surfaces. Complete installed registration matrix is pending. |
| RSP-015 — Freeze Watch and availability response fixtures | OPEN | Frozen corpus separates native decision and harness delivery for Watch, unavailable, integrity, size, permission and lifecycle cases; installed execution is pending. |
| RSP-016 — Separate native verdict from delivered response | DONE | Qualification corpus and CURRENT_CONTRACT.md distinguish native decision, posture transformation, availability and final response. Availability allow is not native-evaluated allow. |
| RSP-017 — Specify coarse request/result contracts | OPEN | Existing versioned coarse contracts and limits documented; optional native extension program/control binding is under implementation. |
| RSP-018 — Define byte, Unicode and canonicalization behavior | OPEN | Existing strict JSON/UTF-8/digest contracts retained by core tests. Native extension IR adds a separately pinned Python/Unicode semantic profile. |
| RSP-019 — Define deadline ownership | DONE | Rust client/runtime setup, admission and evaluation share one remaining deadline; output and cooperative OS-I/O limitations documented. Core deadline tests pass. |
| RSP-020 — Define generation-bound identity rules | OPEN | Generation/package/peer/expiry rules documented; live-process attestation proof and extension control generation binding are under implementation. |
| RSP-021 — Define non-replayable request behavior | DONE | CURRENT_CONTRACT.md records approval consumption, durable policy publication, MCP prewrite and evidence replay commit points; ambiguous tool writes are not replayed. |
| RSP-022 — Expand source ownership gates | DONE | I/O ownership walker follows recording-posture config reads and labels synchronous_posture_config. Seven gate tests plus 50 posture/availability tests passed. |
| RSP-023 — Build independent correctness vectors | OPEN | 377 independent expectations plus package/scanner fault tests added; full installed/native extension vector execution remains pending. |
| RSP-024 — Approve the technical contract through review | BLOCKED | Final technical review and independent code-owner approval are outstanding; current availability behavior is preserved and stale ownership prose corrected. |
| RSP-025 — Profile executable validation on the ordinary route | OPEN | Installed baseline status component measured: each warm lookup hashes 6,171,560 bytes despite capability-cache hit. Actual warm hook attribution remains pending. |
| RSP-026 — Choose a verified runtime-lifetime design | OPEN | Narrow Linux live-child executable proof under implementation; unsupported filesystem/platform cases retain full validation. |
| RSP-027 — Implement generation-bound attestation reuse | OPEN | Generation-bound live-process attestation is under implementation; every new spawn must fully validate before receiving request bytes. |
| RSP-028 — Test executable replacement defenses | OPEN | Replacement, permission, manifest, process death and race regressions are under implementation with attestation. |
| RSP-029 — Test signing and update transitions | BLOCKED | Requires final attestation implementation and installed signed/frozen artifacts on all selected targets. |
| RSP-030 — Measure request-time configuration loading | OPEN | Acknowledged Watch mode avoids one redundant config read and is tested. Full route count/phase measurement remains pending. |
| RSP-031 — Extend acknowledged posture binding if needed | OPEN | Existing authenticated observe binding is reused; complete posture state transfer requires measurement and authority review before any schema expansion. |
| RSP-032 — Remove redundant ordinary configuration rereads | OPEN | Redundant read removed only when the acknowledged native snapshot already proves observe mode. Enforce/unavailable paths retain current config authority. |
| RSP-033 — Move the small transformation layer only if selected | BLOCKED | Native transformation layer is conditional on measured selection; current Python delivery contract remains authoritative. |
| RSP-034 — Exercise policy and posture transitions under load | OPEN | 50 focused Watch/availability tests passed and background mutation-to-ACK tests exist. Installed mode-toggle/load/restart qualification is pending. |
| RSP-035 — Qualify identity and posture improvements | BLOCKED | Requires final identity/posture candidate and paired installed qualification. |
| RSP-036 — Retire redundant work and document proof | BLOCKED | Retirement proof depends on attestation and installed results. No platform loses validation on the strength of a metadata-only cache. |
| RSP-037 — Measure parsing, serialization and allocation counts | OPEN | Rust parse/copy diagnostic timings recorded; complete allocation and installed phase attribution remains pending. |
| RSP-038 — Return typed lifecycle disposition | DONE | Typed lifecycle disposition removes shutdown reparse; failed or unauthorized shutdown cannot stop the resident. Rust lifecycle tests passed. |
| RSP-039 — Reuse validated timeout metadata | DONE | Strict discard JSON parsing retains framing, duplicate-key, depth and UTF-8 validation while avoiding a temporary full tree; core adversarial tests passed. |
| RSP-040 — Compute canonical request identity once | DONE | Validated canonical request identity is computed once and reused for evaluation/receipt creation; digest and approval contract tests passed. |
| RSP-041 — Keep PreTool results typed through receipt creation | DONE | PreTool result remains typed through receipt creation with result-matrix validation; runtime and edge tests passed. |
| RSP-042 — Compile policy maps at snapshot admission | DONE | Policy maps compile at immutable snapshot admission with key/action and canonical harness conflict validation; freshness/scope checks remain per request. |
| RSP-043 — Share immutable compiled policy state | DONE | Compiled policy state shares immutable ownership across requests; generation swaps and approval consume synchronization remain fenced. |
| RSP-044 — Reduce post-tool output copying | DONE | Output traversal/concatenation avoids repeated character-count copies; ordering/newline/limits and source-equivalence tests passed. |
| RSP-045 — Benchmark scanner prefilter alternatives | DONE | RegexSet/prefilter comparison performed. Sample-heavy prototype regressed about 13%, so production retains the existing OnceLock scanner. |
| RSP-046 — Preserve scanner chunk and deadline semantics | DONE | Core scanner chunk, multibyte, source isolation and original-deadline tests passed; no cross-document overlap reuse introduced. |
| RSP-047 — Run core parity and adversarial suites | OPEN | 196 command crate tests, 137 runtime tests, 12 edge tests and clippy passed on the core tranche. Combined final-head differential/adversarial CI is pending. |
| RSP-048 — Qualify end-to-end benefit of core changes | BLOCKED | Kernel improvements are diagnostic only until installed/native-client comparisons qualify on final artifacts. |
| RSP-049 — Inventory package-core production consumers | DONE | Production package consumers and local versus launch/network/approval boundaries inventoried in ../rsp-package-performance.md. |
| RSP-050 — Benchmark dependency and bundle cardinality independently | OPEN | 36 independent cardinality/mode cells and five alternating 1,000-by-1,000 exact pairs recorded; 13 baseline process timeouts remain censored. Full qualification pending. |
| RSP-051 — Build verified immutable bundle indexes in Python | DONE | Verified immutable bundle indexes preserve duplicates, namespaces, versionless risk/ties, emergency denies and freshness. Focused plus independent parity tests passed. |
| RSP-052 — Parse each lockfile input once in Python | OPEN | Structured JSON/JSONC/TOML decode is shared with extraction; existing Yarn/pnpm text projections retained. Full format-wide installed parity remains open. |
| RSP-053 — Share one immutable input snapshot per evaluation | DONE | One exact-byte lazy snapshot per evaluation binds parser/context/evidence, with 8 MiB input and 128 MiB aggregate retention bounds and explicit incomplete outcomes. |
| RSP-054 — Rebaseline and decide whether Rust is justified | OPEN | Current versus optimized full local evaluator compared with matching output hashes; 98.22% median CPU reduction observed in five pairs. No native candidate qualified. |
| RSP-055 — Define native package batch schemas | BLOCKED | Conditional native package contract awaits a measured go decision against optimized Python; proposed schema is not shipped as a supported API. |
| RSP-056 — Implement one native parser format end to end | BLOCKED | No native package parser selected; requires RSP-054 benefit decision and RSP-055 contract. |
| RSP-057 — Implement native indexed bundle evaluation | BLOCKED | No native bundle evaluator selected; immutable Python indexes are implemented. Native authority proof requires the conditional contract. |
| RSP-058 — Integrate the coarse native call into a real surface | BLOCKED | No coarse native package call activated without a qualified real consumer. |
| RSP-059 — Expand format parity and malformed-input tests | OPEN | 151 focused disconnected/loopback tests, 117 isolated parser/store tests and 67 independent checks cover Python parity; native format expansion remains conditional. |
| RSP-060 — Qualify and activate only supported formats | BLOCKED | Native format activation requires an actual native implementation and installed benefit proof over optimized Python. |
| RSP-061 — Map rich secret detector capabilities | DONE | Exact rich offline versus hook scanner capability matrix published in ../rust-performance-scanner-review.md. |
| RSP-062 — Baseline repository, staged and history workflows | OPEN | Seven workloads, five alternating repetitions, full Secrets CLI and separated Git/detector CPU diagnostics recorded. Platform/cold-cache/finding-heavy qualification pending. |
| RSP-063 — Batch Git object reads in Python | DONE | At most two lazy bounded Git object readers verify immutable SHA-1/SHA-256 blobs, deadlines, headers and child cleanup; scanner regressions passed. |
| RSP-064 — Deduplicate blob scanning without losing occurrences | DONE | Per-scan immutable object/detector/path-policy finding cache retains every path/commit occurrence and existing finding/coverage budgets. |
| RSP-065 — Share secure traversal for plugin checks | DONE | Plugin checks share one secure traversal and immutable per-file input while retaining containment/exclusions/incomplete coverage; focused tests passed. |
| RSP-066 — Rebaseline and approve only justified scanner ports | BLOCKED | Optimized Python baseline exists; no equivalent offline native boundary has met the full-command benefit gate. |
| RSP-067 — Specify separate offline detector schemas | BLOCKED | Separate offline native schema remains conditional; hook ScanMatch is explicitly not substituted for rich finding/HMAC/completeness output. |
| RSP-068 — Implement bounded native detector batches | BLOCKED | Rich native detector batch is not selected pending RSP-066 and exact richer contract. |
| RSP-069 — Wire the real secrets CLI and exit behavior | OPEN | Existing real Secrets CLI preserves exits 0/2/3 with optimized Python; native CLI consumer remains conditional. |
| RSP-070 — Qualify hostile archive worker separately | OPEN | Hostile archive isolation and identity/expansion controls retained; dedicated archive cost profiling still required before selecting a port. |
| RSP-071 — Run secret and scanner adversarial parity | OPEN | 178 scanner/transport/shared-input tests pass, including mutation, redaction and incomplete coverage. Native detector/archive differential remains conditional. |
| RSP-072 — Publish scanner go/no-go and coverage evidence | OPEN | Python diagnostic evidence and exact retained scopes published. Installed/native/platform comparison is outstanding, so no native speed claim is made. |
| RSP-073 — Rank launcher cost by actual harness use | BLOCKED | Priority installed launcher matrix is being completed; route ranking must use those actual measurements. |
| RSP-074 — Design a package-bound native launcher command | BLOCKED | Package-bound native launcher is conditional on RSP-073; existing signed/manifest-bound runtime distribution is the proposed reuse point. |
| RSP-075 — Implement one canonical pre/post launcher | BLOCKED | No new canonical native launcher is activated without route-specific installed benefit and delivery parity. |
| RSP-076 — Integrate registration and repair | BLOCKED | New native registration/repair depends on a selected launcher implementation; existing registrations remain under contract tests. |
| RSP-077 — Verify no-environment installed selection | OPEN | Qualification builder installs wheel artifacts with development overrides cleared and reads registered argv. Four-platform execution is pending. |
| RSP-078 — Port and qualify an alias-heavy harness | OPEN | Cursor/Copilot alias and response fixtures are frozen. A new native alias launcher and its installed qualification remain conditional. |
| RSP-079 — Port and qualify Pi/OMP source references | OPEN | Pi/OMP source-reference contract remains covered by existing tests/corpus; a new launcher port is conditional. |
| RSP-080 — Preserve approval continuation across launchers | OPEN | Existing one-time approval/revalidation/consume contracts retained. Final installed launcher restart and ambiguous-completion matrix is pending. |
| RSP-081 — Qualify wheels and frozen sidecars | BLOCKED | Requires selected launcher and final four-platform wheels/frozen sidecars; source tests cannot satisfy this acceptance. |
| RSP-082 — Measure cold/warm launcher improvements | BLOCKED | Requires actual final installed launcher observations and route/platform target comparison. |
| RSP-083 — Expand route by route with declared support | BLOCKED | No additional route activated without parity plus benefit proof; preflight and observation surfaces stay accurately labeled. |
| RSP-084 — Test launcher upgrade and rollback | BLOCKED | Native launcher upgrade/rollback depends on a selected new launcher and installed registration matrix. |
| RSP-085 — Profile discovery/connect/auth versus evaluation | OPEN | Existing persistent Python-to-native helper verified; direct native/client phase and connection accounting are being integrated into qualification. |
| RSP-086 — Choose connection reuse or ingress consolidation | BLOCKED | Connection or ingress consolidation requires full process-tree comparison against the optimized current path. |
| RSP-087 — Specify bounded native session protocol | OPEN | Existing v2 generation-bound native framing and limits documented; any additional connection protocol remains conditional. |
| RSP-088 — Implement generation-bound persistent connections | BLOCKED | Further resident connection reuse requires measured selection and authenticated scope/lifetime proof. |
| RSP-089 — Exercise replacement and recovery races | OPEN | Current generation/expiry/restart/admission tests retained; expanded final installed recovery and replacement matrix pending. |
| RSP-090 — Prototype hook-only native ingress if selected | BLOCKED | Hook-only native ingress not selected; no administrative server rewrite is authorized by a hypothetical hook gain. |
| RSP-091 — Preserve Windows and Unix transport guarantees | OPEN | Foundation Windows resident/native identity CI passed. Final candidate DACL/peer/process/Unix path checks remain required. |
| RSP-092 — Audit the remaining Python process-pool callers | OPEN | Compatibility and Codex approval pool distinction documented; full remaining caller inventory and idle/startup footprint audit pending. |
| RSP-093 — Lazy-start or replace only proven pool consumers | BLOCKED | Pool lazy-start/replacement requires measured remaining consumers and first-approval/revalidation proof. |
| RSP-094 — Stress admission and fault containment | OPEN | c16/c64, offered-rate and explicit failure accounting implemented; final mixed payload/fault containment runs pending. |
| RSP-095 — Qualify the transport benefit | BLOCKED | No new transport benefit is claimed without installed p99/CPU/private-memory qualification. |
| RSP-096 — Roll out or defer native ingress explicitly | BLOCKED | Native ingress remains unselected pending a measured go/no-go decision and tested generation rollback. |
| RSP-097 — Trace actual stdio and remote MCP behavior | DONE | Actual stdio catalog, approval, forwarding and multiplexing route reviewed; remote-http draft #2931 is not treated as shipped current behavior. |
| RSP-098 — Benchmark Guard overhead separate from server wait | OPEN | Actual stdio session benchmark and nested phase profile separate Guard, deliberate drain, child wait and startup. Local timings are noisy diagnostics. |
| RSP-099 — Cache immutable full-catalog fingerprints | DONE | Owned immutable full tool catalog fingerprints cache one canonical digest per validated generation; mutation and pending-approval invalidation tests pass. |
| RSP-100 — Reuse request-local risk analysis | DONE | Risk categories/signals reused only within one exact request; public helpers and changed requests recompute. 342 relevant MCP tests passed. |
| RSP-101 — Bound framing and buffering where required | OPEN | Bounded MCP lines, child queue and unmatched response buffering are under implementation; existing final freshness barrier must be retained. |
| RSP-102 — Preserve the final prewrite freshness barrier | DONE | 5 ms final quiet drain and entrypoint-change quarantine retained; whole-catalog authority is rechecked before forwarding. |
| RSP-103 — Rebaseline optimized Python proxy | OPEN | Actual proxy session profile recorded; controlled installed overhead/memory rebaseline still needed before any Rust choice. |
| RSP-104 — Specify coarse native MCP facts contract if justified | BLOCKED | Native MCP facts contract remains conditional on measured kernel benefit; credentials and remote session orchestration stay outside the kernel. |
| RSP-105 — Implement and integrate selected pure native kernels | BLOCKED | No native MCP kernel is activated before RSP-103/104 selection and full policy/claim parity. |
| RSP-106 — Test protocol and forwarding correctness | OPEN | 342 existing MCP protocol/catalog/approval tests pass; framing/flood/slow-consumer and final integrated tests pending. |
| RSP-107 — Qualify native kernels against optimized proxy | BLOCKED | Requires selected native kernel and real proxy-boundary comparison against optimized Python. |
| RSP-108 — Record full proxy rewrite decision | BLOCKED | Full proxy rewrite has no measured justification. Separate ADR/protocol rollout required if future evidence selects it. |
| RSP-109 — Inventory matcher semantics and current native coverage | OPEN | Foundation inventory is 86 extensions, 291 rules, 304 permissions and 26 matcher families; exact artifact/coverage mapping is being completed. |
| RSP-110 — Freeze extension outcome and control fixtures | OPEN | Control/default/opt-in/uncertainty/hard-floor fixtures and Python oracle vectors are under integration. |
| RSP-111 — Define a bounded versioned matcher IR | OPEN | Bounded executable IR with version, program/catalog/trust digests and explicit CPython 3.12/UCD15 semantics is under implementation. |
| RSP-112 — Build trusted deterministic IR compilation | OPEN | Deterministic reviewed-type compiler translates rules and variants; final generated artifact and unsupported-type rejection tests pending. |
| RSP-113 — Preserve the existing contribution and Builder flow | OPEN | Existing contribution/Builder authoring retained; generated IR is a build artifact. Final normal-contributor build/install proof pending. |
| RSP-114 — Implement native matcher primitives incrementally | OPEN | Core, option/flag, operand/path-set and specialized matcher ports are under integration with independent oracle vectors; no unimplemented family may become allow. |
| RSP-115 — Bind native program to control snapshots | OPEN | Capability-gated optional authenticated snapshot binding and independent durable local/cloud revision floors are under integration; legacy byte identity retained. |
| RSP-116 — Integrate native matching with one canonical command | OPEN | Canonical-command native matching and complete redacted observation/receipt binding are under integration. |
| RSP-117 — Protect core floors and unknown-command behavior | OPEN | Generic independent sensitive-path floor fixed and tested in foundation. Full extension overlap/unknown-command/core-floor matrix pending. |
| RSP-118 — Qualify command.ollama end to end | BLOCKED | command.ollama needs the completed native program, controls, actual installed enable/disable/receipt/update/rollback route. |
| RSP-119 — Benchmark full catalog execution | BLOCKED | Full catalog compile/load/warm/candidate/control benchmark awaits coherent native integration. |
| RSP-120 — Publish native extension coverage and diagnostics | BLOCKED | Publish production native coverage only after final packaged artifact and route proof; compatibility benefit is separate from latency. |
| RSP-121 — Measure foreground evidence submission cost | OPEN | 30 paired synthetic foreground evidence diagnostics cover maximum envelopes and rejection. Real installed mixed-load attribution remains pending. |
| RSP-122 — Use bounded compact evidence before queue admission | DONE | Compact retained facts replace full payload copy before admission; bounded queue rejection is early, correlation and degraded counters retained. |
| RSP-123 — Define persistence milestones and loss window | DONE | Memory accepted, journal durable, DB committed and checkpointed milestones plus cross-process writer lock/loss window documented in ../rust-performance-background.md. |
| RSP-124 — Implement real SQL transaction batching | DONE | Native receipts use bounded 50-record SQL batches with exact uniqueness/rollback; package evidence also uses an atomic evaluation transaction. |
| RSP-125 — Replace per-record whole-journal rewrites | DONE | Per-record journal rewrites replaced with one bounded checkpoint per committed group; retry never reruns the decision or committed batch. |
| RSP-126 — Exercise persistence fault recovery | DONE | Fault tests cover duplicate/replay IDs, SQLite busy, disk full, truncated journal and append/commit/checkpoint process death; 259 background tests plus one skip. |
| RSP-127 — Introduce precise policy invalidation | DONE | WAL-aware precise integrity-domain invalidation skips receipt-driven recompilation; managed/home/workspace reconciliation and key fences retained. |
| RSP-128 — Bound workspace policy tracking | OPEN | Exact captured-byte cache and safe 1,024-workspace admission implemented; 1/10/100 diagnostics recorded. Installed lifecycle/load qualification pending. |
| RSP-129 — Test mutation-to-enforcement freshness | OPEN | Local mutation-to-ACK, lost hint, managed repair and capacity race tests pass; actual installed first decision and platform transition measurements pending. |
| RSP-130 — Profile and optimize incremental inventory | OPEN | Inventory-specific incremental traversal/upsert/cloud attribution remains to be profiled; no Rust inventory speed claim made. |
| RSP-131 — Qualify real receipt ingestion under mixed load | BLOCKED | Actual native receipt ingest under mixed hooks/policy updates and complete process-tree accounting awaits final installed runs. |
| RSP-132 — Decide whether native spool/compiler is still needed | BLOCKED | Native spool/compiler decision depends on optimized Python mixed-load qualification; no exclusive daemon lease or exactly-once legacy guarantee invented. |
| RSP-133 — Audit workflow dependency selection | DONE | 23 validation workflows select release/3.2 and dependent inputs; publication permissions/triggers unchanged. 229 tests and dependency coverage audit passed. |
| RSP-134 — Run scope-appropriate Rust and Python validation | OPEN | Per-tranche meaningful Rust/Python/lint/type tests passed; final combined source and exact-head GitHub checks remain required. |
| RSP-135 — Build and attest all selected release artifacts | OPEN | Four-platform locked native-wheel builder/workflow implemented. Final package/runtime/rule/source identities and frozen/post-sign qualification pending. |
| RSP-136 — Verify installed route and control-mode coverage | OPEN | Independent corpus and registered-launcher helpers implemented/in progress. All selected final installed routes/modes must run on their artifacts. |
| RSP-137 — Run full performance qualification | BLOCKED | Full labeled qualification run requires a frozen final candidate; smoke/diagnostics cannot close this task. |
| RSP-138 — Run mixed offered-load and recovery soak | BLOCKED | Mixed offered-load/recovery/resource soak on final installed artifacts is outstanding. |
| RSP-139 — Verify update, downgrade and rollback behavior | BLOCKED | Final artifact update/downgrade/rollback and mixed-generation installed behavior is outstanding. |
| RSP-140 — Verify evidence privacy and truthful status | OPEN | AIBOM URL credential redaction corrected; benchmark outputs use aggregates/digests and separate availability. Final artifact privacy probes pending. |
| RSP-141 — Reconcile current architecture and old PRDs | OPEN | Original PRD/TODO/TAKEAWAY preserved with current execution contract and provenance; final architecture/native coverage must be reconciled after integration. |
| RSP-142 — Complete independent review of the final head | BLOCKED | Final-head CI and independent code-owner review remain required by the release ruleset; foundation automated findings are being addressed. |
| RSP-143 — Prepare concrete canary and rollback evidence | BLOCKED | Concrete canary/stop/rollback protocol documented in EXECUTION.md; exact selected qualified versions and tested rollback evidence pending. |
| RSP-144 — Publish an accurate implementation handoff | OPEN | This 144-row ledger preserves every acceptance condition and dependency. Final handoff must include exact PR/artifact results and unresolved/deferred scope. |
