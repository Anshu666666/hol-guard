# Rust performance execution for release/3.2

Current implementation and validation are recorded in [RELEASE_REVIEW.md](RELEASE_REVIEW.md), with **67 DONE / 36 OPEN / 41 BLOCKED** in the [execution ledger](EXECUTION_LEDGER.md). The source checkpoint is `c964a61a3a4c19d721358e69c400d6059dfd1156`; the isolated PR #2970 publication exists at `107606388`; subsequent source publication, final installed qualification and release remain incomplete. The original [PRD](PRD.md) and [TODO](TODO.md) are unchanged.

## Historical integration and evidence record

The material below preserves prior source-scoped observations. Historical uses of “current,” source cutoffs and workflow counts describe that recorded round, not the later source checkpoint above. Failures remain failures after subsequent corrections.

This is the implementation record for the original [PRD](PRD.md) and
[144-task TODO](TODO.md). Their requirements are unchanged. The user subsequently
authorized completing the work in `release/3.2`; the old proposal-only wording
does not limit that authorization. [TAKEAWAY.md](TAKEAWAY.md) is now the current
continuation prompt; its original proposal version remains in Git history.
No merge, canary deployment or release completion is recorded here.

The reviewed round-five source cutoff is local integration `923a13634570f7c48021768414ca7a487e72ed83`,
with exact Git tree `8bedacb684c903402f8fb2be96199e93e8198787`, dated 2026-09-17.
It includes native Codex browser continuation, encrypted evidence retention,
single-pass text lockfiles, bounded HTTP header/watchdog corrections and Ollama diagnostics.
**This audited local tree incorporates current remote `42579f046`; publication and
CI of the final reconciled head remain incomplete.** The local
implementation branch is `work/rsp-performance-32`; this documentation worktree
is `rsp-round5-status`, branch `work/rsp-round5-status`.

The historical round-four implementation was `81ef6195c9231bd3fca5efb2aa987edfbd0c5fa6`,
with older tree `3c1d250c23bee22e23e5525880bdd3f65a63a59d`, matching historical
local `b076ea79c`. At the coordinator's 10:27 UTC API refresh, **29 workflows succeeded,
seven failed and none remain active**. These are observations of that published
head, not of the newer source. The documentation author inspected local source
and Git identities; the workflow observations below come from the coordinator.
The full qualification label was absent at that observation, so the round-four performance run was **smoke**.

Current reported PR head 42579f046ac262ff93c0c020547bc3873d308652, tree
096abd5c67d24ab3b324fb911c8bdac5d79090f8, has 36 completed workflows: 32 successful and 4 failed.
Rust authority 35210169031 fails because policy_store_tests.rs has 526 lines against its 500-line
cap; CI 35210168989 fails only Sonar coverage because a synthetic startup filename has no source.
Native wheel 35210168835 fails its Linux c64 bounded gate (job 105165538874): max 615.789 ms, no
latency ceiling, zero errors, 64 fail-safe observations and 32 overloaded observations; the other
three platform jobs pass. Native performance 35210168801 fails all four baseline arms: Linux
review-queue-failed.small reports setup approval_persistence_failed; Windows benign Claude
PostToolUse 1M reports delivered/native no_output_to_review block; both macOS baseline getfqdn
probes still hang. These observed outcomes do not establish underlying causes. Windows
resident/daemon edge and Extension Builder now pass. Results belong to 42579f046, not to the later
audited 923a13634 reconciliation. The older 81ef6195c 29/7 snapshot is historical; neither head is
fully qualified.

On current published 42579f046, all four installed Builder subchecks pass. Linux and macOS ARM also
retain 22 passing native Ollama cases, but their top-level qualification result is false. Source
inspection established that the privacy sanitizer dropped source_sha before an identity comparison
required it. Integrated 923a13634 now uses safe build_sha on both expected and child sides,
preserving exact 40-hex source identity through both sanitizer passes and rejecting missing or
mismatched identity. Three new regressions pass; the preceding 44 diagnostic/probe tests also
passed. This repairs aggregation, not an installed rerun. Windows and macOS Intel retain generic
native_readiness_failed with dropped progress: phase and executed-case count remain unknown. Local
6311a8ade adds bounded phase/publisher diagnostics without changing 400 ms readiness. Changed
program/package update and rollback remain unqualified.

| Failed round-four workflow | Observed failure and integrated or remaining correction |
| --- | --- |
| [Run 35206822200](https://github.com/hashgraph-online/hol-guard/actions/runs/35206822200) | Stale direct-call source check after fenced delegation. Integrated ec56b424d checks fenced delegation and raw-edge invocation with four mutation tests; the published run remains failed. |
| [Run 35206822236](https://github.com/hashgraph-online/hol-guard/actions/runs/35206822236) | Six Rust policy-store fixture rewrites attempted secure CREATE_NEW. Integrated 1bbce6df7 allows explicit existing test-fixture rewrite/truncation while preserving production CREATE_NEW nonmutation; 21 focused tests pass. That historical failure remains; the newer 42579f046 Windows resident/edge runs are reported green, while final reconciled-head validation remains required. |
| [Run 35206822186](https://github.com/hashgraph-online/hol-guard/actions/runs/35206822186) | Same six Rust fixture failures as resident; not twelve independent defects. Same integrated 1bbce6df7 fixture correction; the newer 42579f046 Windows resident/edge runs are reported green, separately from this retained failure. |
| [Run 35206822240](https://github.com/hashgraph-online/hol-guard/actions/runs/35206822240) | Exact-byte LF versus CRLF packaged listing mismatch. Integrated 6971a4331 pins canonical schema line endings without weakening byte comparison; the newer 42579f046 Extension Builder run is reported green; final artifact validation remains required. |
| [Run 35206822316](https://github.com/hashgraph-online/hol-guard/actions/runs/35206822316) | All four targets failed: baseline macOS ARM/Intel DNS diagnostics time out at five seconds with constructor at thirty seconds; baseline Linux exact HTTP reason mismatch; baseline Windows one-million-byte source policy_action mismatch. 6515e525e corrects the verified frozen-baseline HTTP oracle. 41c3b3724 adds three bounded macOS diagnostics (16 tests), and 511d4be0a retains source-witness details (48 tests); neither establishes a DNS or Windows source root cause. Budgets unchanged; no qualifying comparison. |
| [Run 35206822177](https://github.com/hashgraph-online/hol-guard/actions/runs/35206822177) | Shard 18 mixed-fairness request returned 503; shard 55 expected stale ownership inventory 99 rather than observed 96. The integrated native Codex change records the new 104-entry ownership inventory. Bounded permit/header/watchdog repairs 938d59999/27da1a51b are integrated with focused tests; full-workload acceptance and remaining incomplete-header/overload boundaries are unresolved. No deadline was enlarged. |
| [Native wheel 35206822343](https://github.com/hashgraph-online/hol-guard/actions/runs/35206822343) | Windows lock-child and macOS Intel source-witness jobs failed; Linux and macOS ARM jobs passed. Source corrections/diagnostics are integrated, but this published workflow remains failed. |

Native-wheel run 35206822343 is terminal: Linux job 105154527771 succeeded, including the
100,000-request/250,000-receipt soak; macOS ARM job 105154527991 succeeded. Windows job 105154527989
failed the lock-child probe (source correction integrated); macOS Intel job 105154528161 failed the
source witness (cause unproven, diagnostics added). The observed build-source prefix is f7293ab;
retain those exact artifact identities in the machine-readable ledger. Separately, installed Ollama native
22-case scopes passed on Linux/macOS ARM, but Builder isolation rejected all three non-Windows jobs;
integrated 6515e525e moves environments outside source. Windows Ollama retained an unlocalized
readiness assertion after session startup; accumulated progress was dropped, so executed-case count
and phase are unknown. No full lifecycle or final candidate qualification follows.


The retained Linux soak JSON independently records 100,000 requests and responses,
250,000 receipts, zero errors, zero health failures and a stable daemon PID. Its p95
was 590.59 ms, maximum 1,057.92 ms and RSS growth 4.194%, passing that soak's
4,500 ms maximum-hook budget. This is a genuine scoped soak success, not the PRD
installed warm-route latency gate or the later mixed mutation/ingestion workload.
The machine-readable ledger retains these fields and both launcher artifacts' full
runtime/package identities.

There are **65 DONE, 38 OPEN and 41 BLOCKED** acceptance records, with
**0 DEFERRED**. Only RSP-052 changes, from OPEN to DONE at its original component
criterion; the previous counts were 64 DONE / 39 OPEN / 41 BLOCKED. All 144 original
requirements and dependencies remain unchanged. Component passes and successful
local decryption do not close installed qualification.

The current [execution ledger](EXECUTION_LEDGER.md) records acceptance evidence
and missing dependencies for every task. `OPEN` can include tested code whose
broader acceptance still requires installed measurements. `BLOCKED` means a
dependency is unmet. `DEFERRED` is reserved for a measured no-go; an unbuilt
optional Rust component is not automatically a completed investigation.

## Source and reconciliation

| Identity | Value |
| --- | --- |
| Audited/current-main implementation baseline | `2e672d2d950c6ec471005ddba46e49bba16dc23b` |
| Original release/3.2 target | `4b89e0d2d496a85f04922b2e019a4aea15326bb9` |
| Main lineage already carried by release squash | `c996b1d243ddafe8bef04d26ba939615edebb1e7` |
| Local reconciled foundation | `c4bd916fb0d0f375a4e2de0d1e498a0a533f63c8` |
| Published foundation PR | [#2951](https://github.com/hashgraph-online/hol-guard/pull/2951), base `release/3.2` |
| Foundation remote head at reported refresh | `e449594e86c717e66e14598a4130475de79c536f` |
| Implementation PR | [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954), current reported head `42579f046ac262ff93c0c020547bc3873d308652` |
| Current published Git tree | `096abd5c67d24ab3b324fb911c8bdac5d79090f8`; distinct from local audited source |
| Source audited for this ledger | `923a13634570f7c48021768414ca7a487e72ed83`; local reconciled source cutoff |
| Published round-four Git tree | `3c1d250c23bee22e23e5525880bdd3f65a63a59d` |
| Reviewed integrated Git tree | `8bedacb684c903402f8fb2be96199e93e8198787` |
| Local implementation branch | `work/rsp-performance-32` |
| Baseline package version | `3.0.1` |
| Rust toolchain | `1.88.0`, locked workspace dependencies |
| Baseline diagnostic Python | CPython `3.12.14`, locked dependencies |
| Baseline local native target | `x86_64-unknown-linux-gnu` |
| Baseline native runtime bytes | `6,171,560` |
| Baseline runtime SHA-256 | `d3b3613713db36ea5ac836288a33ea03ab1d5e309cb3bba3575c0e315eb0a8b3` |
| Baseline rule digest | `be109c23448f016c3168ac2cf6ff04e75f0857616ffd5ae8a8028f3105c37305` |

The release branch contains a squash of earlier main work. The original and
squashed trees were compared before selecting the already-carried main lineage
as the reconciliation base. A normal merge would have treated already-present
changes as unrelated conflicts. The foundation preserves release-only Everyday
Mode schema/density/stale-write behavior, Fleet, Common CLI and network/sandbox
presentation while incorporating the current main authority implementation.
GitHub commits created from the tested tree can have different author metadata
and SHA from local integration commits; every uploaded tree is checked for exact
Git tree identity before the remote branch is advanced.

Overlaps below retain the GitHub observations recorded on 2026-09-17. They are
a dated reconciliation record; refresh the exact heads before final publication:

| PR and observed head | State | Treatment |
| --- | --- | --- |
| [#2807](https://github.com/hashgraph-online/hol-guard/pull/2807), `91f26d74f3148826b73730722c92e9d6b23794ff` | Open | Preserve Windows handle cleanup and fully populated RSS baseline invariants already present in the audited source; do not replace them with a two-worker baseline. |
| [#2870](https://github.com/hashgraph-online/hol-guard/pull/2870), `c6d71e84b7eae8a79b82d6c46143ef95da169fbd` | Closed, unmerged | Superseded by #2950; do not revive. |
| [#2950](https://github.com/hashgraph-online/hol-guard/pull/2950), `47b4ff21cdb89c70633c57d0a438f5739f316a98` | Merged into main | Current main secret-read and one-time approval behavior is carried by the foundation. |
| [#2931](https://github.com/hashgraph-online/hol-guard/pull/2931), `ac31b5de7a61f87b9dbd89626bbc79fd6008968b` | Open draft | Hosted remote HTTP MCP is not assumed shipped. Preserve future catalog/policy integration seam without importing draft behavior. |
| [#2948](https://github.com/hashgraph-online/hol-guard/pull/2948), `a6d24bdbaaa88e7541399cca013e01866360f427` | Open | Unpublished generic-v2 admission work is separate. Runtime identity caching cannot treat cached publication state as fresh authority. |
| [#2911](https://github.com/hashgraph-online/hol-guard/pull/2911), `ea472d8d67a8539dca7de02096634bb770a36b0f` | Open | CodeSage explicitly describes Python-reference-only coverage. Do not add it to native coverage without importing, compiling and qualifying its contribution. |
| [#2797](https://github.com/hashgraph-online/hol-guard/pull/2797), `4b89e0d2d496a85f04922b2e019a4aea15326bb9` | Open draft | Release-to-main aggregate; this implementation targets its release branch rather than replacing that PR. |

## Implemented work and evidence

Source implementation and installed acceptance are separate. A compiled catalog
and tested native interpreter now exist; neither their presence nor a component
speedup establishes a successful registered hook on every release platform.

| Workstream | Implemented behavior | Evidence and remaining acceptance |
| --- | --- | --- |
| Benchmark integrity | Isolated semantic oracle, frozen expectations, registered launcher execution, paired samples, independent resources and offered-rate accounting | `scripts/qualify_guard_native.py` and `native_slo_*`; source tests pass. Ordinary, mixed, nonpriority, approval, malformed and separate phase runners are integrated through `b076ea79c`; installed execution remains. Baseline side-scenario failures are retained independently and candidate scope is gated. |
| Rust core | Typed lifecycle/results, borrowed canonical request hashing, bounded size counting, strict timeout/discard parsing and immutable compiled policy | [Allocation report](../native-allocation-performance.md): 47 small/maximum phases and paired streaming reduction, with 254 Rust tests and seven ignored diagnostics at the recorded source; final combined-head validation and installed benefit remain. |
| Package evaluation | Verified immutable indexes, one captured-content/parsed input view and atomic evidence batches | [Package report](../rsp-package-performance.md): local 1,000-by-1,000 diagnostic CPU median 6812.312 → 121.574 ms (98.22% reduction). Some cardinality baselines time out; no native package pilot or measured port/no-port decision exists. |
| Offline scans | Bounded Git object streams, immutable blob finding reuse and shared plugin traversal | [Scanner report](../rust-performance-scanner-review.md): source CLI and finding parity, with full installed workflow/platform qualification and any native rich-detector comparison outstanding. |
| MCP | Immutable full-catalog digest, request-local classification, bounded frames/queues/responses and terminal I/O cleanup | [Framing contract](../../mcp-framing-bounds.md): real POSIX pipe and protocol tests; 5 ms final barrier retained. Windows execution and optimized proxy rebaseline remain; no native rewrite benefit claim. |
| Evidence and policy | Compact facts, bounded atomic SQL batches, append/checkpoint replay, stable attempt identity, precise DB/WAL reconciliation and captured workspace content | [Background report](../rust-performance-background.md): fault/mutation tests and diagnostics. Mixed installed resource and durability observations remain. |
| Runtime identity and posture | Reuse of an already verified Linux live image on supported filesystems; full validation elsewhere; acknowledged observe avoids redundant config read | [Identity report](../rsp-runtime-identity-performance.md): 72.28% lower median status-component CPU with the same baseline Rust binary; final hook/signing/platform transitions are separate. |
| Native command extensions | Trusted deterministic compiler, typed bounded Rust interpreter, candidate indexing, complete observations, control fence and durable receipt binding | [Program report](../native-command-program-performance.md), [authority protocol](../rust-native-command-control-binding.md): source differential and crash/recovery evidence; final installed activated coverage remains. |
| Remaining Python pool and inventory | Actual compatibility/Codex callers measured; positive collection discovery coalesced within one call; AIBOM retry ACK preserved | [Pool audit](legacy-pool-and-inventory-audit.md), source `06616ec80`. [Inventory followup](inventory-refresh-audit.md) is integrated: one root discovery per call and one fewer SELECT per upsert, unchanged transactions and mixed timing. Actual first approval, installed scanner/cloud cost and any pool startup change remain unqualified. |
| Mixed workload | Actual daemon hooks, public control updates, matching ACK, first enforcing receipt, real committed receipt identities, inventory and Rust resident recovery | `scripts/native_slo_mixed.py`, integration `a5d2ffeda`, 58 focused tests. Scheduled-offer latency includes queue/scheduler delay. Retained side-scenario invocation is integrated at `b076ea79c`; actual installed execution, daemon-process restart, soak and unavailable persistence metrics remain. |
| Registered surfaces and approval | Actual nonpriority registration readback, exact response checks; ordinary local allow reuse bound to policy/program/observation under SH fence | [Surface report](registered-surfaces-smoke.md), Copilot correction `906d71863`, [approval corpus](../native-priority-approval-corpus.md) and [malformed corpus](registered-input-corpus.md) are integrated. Candidate assertions require actual native/continuation witnesses; native Codex continuation is now integrated; installed host/approval success remains. Local reuse is not exported native v3/v4 consumption. |
| Ollama and Builder | Wheel-only contribution/Builder/control lifecycle probe, full command receipt readback and strict artifact identity | [Installed J118 protocol](../installed-native-ollama-qualification.md), `1b59b2d3b`, `58548bb2e`; 49 focused tests after approval-binding fix. Linux/macOS ARM native 22-case scopes passed; Builder isolation and unlocalized Windows readiness prevent full lifecycle acceptance. Changed program/package update and rollback remain. |

The command program covers 86 extensions, 291 rules, 304 permissions and
2,242 nodes: 29 reviewed matcher types, 26 instantiated families, 249 declarative
and 42 compatibility rule identities, plus four rule-less GitHub permissions.
Its semantic profile is **CPython 3.12 / UCD 15**. Unknown/context-heavy
compatibility has owned uncertainty; unsupported Unicode capability is explicit.
This is not a claim of complete Python equivalence or parity across Python versions.
The program digest is
`4df5208d0dc05ceaadb1de6a6d8f6d3f9e5395dffcf992640fed87b82a0df1c9`;
the catalog digest is
`232ff389ca607b805118a02bd9560e972453f9a406188237037138f4834faf11`.
These source identities must be checked against each final installed artifact.

The source evidence includes 828 complete declarative observation cases,
187 option vectors, 1,571 operand/structured cases, 212 Common CLI cases,
721 remaining-family cases (seven declared Unicode capability errors),
193 compatibility vectors and 123 independently checked GitHub capabilities.
Reserved component admission measurements improved p50/p95 from
144.36/365.63 ms to 43.80/58.83 ms after removing redundant compilation/copies.
This is cold component admission, not daemon readiness or installed hook latency;
the older diagnostic baseline binary hash was not retained. The later [catalog/control
matrix](../native-command-matrix-performance.md) and
[allocation report](../native-allocation-performance.md) retain independent source,
binary, sampling and scope provenance; their newer observations do not erase
this earlier admission result.

A RegexSet prototype regressed the sample-heavy scanner diagnostic and was not
adopted. Native package, rich offline detector, new launcher, additional native
connection/ingress, MCP kernel, inventory, spool and compiler ports remain behind
their respective measured benefit gates. Optimized Python is the comparison
baseline. No optional unbuilt native port is marked DONE or DEFERRED merely
because an algorithm improvement was valuable.

## Integrated followups and current limits

The source cutoff includes all previously listed delivered work. Do not
cherry-pick those earlier workstream hashes again without checking tree identity.
The earlier scenario wiring at `b076ea79c` is retained; the following later changes are integrated
through `27da1a51b`; publication identity and CI are separate.

| Integrated source | Concrete change and evidence boundary |
| --- | --- |
| `9cca767fe`, `3d036af2c`, `84eed35bc`, `980196485` | Numeric local HTTP handling and platform diagnostics; both semantic arms use explicit acknowledged normal policy. Eligible `.rs` source fixtures require exactly one Rust allow and the exact reviewed-content digest. Baseline source remains pinned. |
| `fc72f22ff`, `980196485` | A real generated-key, encrypted, empty protected command authority is provisioned before daemon creation and independently read back. The actual `2e672d2` non-reentrant API was exercised. Interactive enrollment and installed platform success are not implied. |
| `3c9389201`, `3c3f721d8`, `393d219ed` | Windows uses true `LockFileEx` shared/exclusive leases; installed bundled-Rust overlap verification is wired. Bounded native control errors retain their actual code. Successful platform qualification remains outstanding; current Windows persistence failures are recorded above. |
| `5e431b2d5`, `bc0876a6e` | Advancing inventory writes preserve identical rows and first-seen identity while removing one SELECT per upsert. Connection/commit counts are unchanged; broader five-write timings regress. Controlled HTTP waits and missing scanner engines are not real cloud/scanner performance. |
| `91f0a8e57` | 638 valid command/catalog/control rows across 7/48/86 catalogs, cold compile/load versus warm evaluation, candidate/control counts and explicit benign restrictions. All declarative observations match; final-action equivalence is not claimed. |
| `bf2f096a7`, `1aba86a92` | Borrowed canonical hashing and bounded byte counting preserve request identity while reducing maximum pretool identity allocations from 33,563,834 to 273 requested bytes, and bounds/identity from 41,953,658 to 273. These allocator totals are not peak-live memory or installed latency. |
| `13d6aa090`, `fb8d57a8e` | Bounded Python phase attribution and a separate actual 1,024/1,000,000-byte HTTP driver with benign/sensitive semantic, route and byte-count checks. Instrumented diagnostics cannot enter headline samples. |
| `929bf6dbf`, `d7f92c90d`, `d15261b45` | Exact new-row approval resolution, separate Claude/Codex approval scenario, block-only unknown-command helper and 16-case malformed corpus. The latter expects eight native reviews, eight bypasses and zero native allows. |
| `64ae66eac`, `b076ea79c` | Mixed, nonpriority, priority approval and malformed side scenarios are invoked independently. Baseline failures remain failures; candidate scope requires observed success for all four. Headline samples are retained before these scenarios. |
| `ec56b424d`, `6971a4331`, `1bbce6df7` | Fenced-delegation source gate, canonical schema LF pin, and explicit Windows test-fixture rewrite/truncation. Production CREATE_NEW and exact-byte contracts remain intact; 21 focused Rust fixture tests pass. |
| `0012d3c1d`, `511d4be0a`, `41c3b3724` | Raw Windows child shares DELETE consistently with Rust (24 passes, one Windows skip); source-witness diagnostics (48 passes); three bounded macOS resolver probes (16 passes). Diagnostics do not establish the remaining source/DNS failure causes. |
| `6515e525e` | External installed environments, exact frozen-baseline HTTP oracle, pre-assertion daemon journals, candidate continuation after contained failed arms with incomplete comparison still failing, stale artifact rejection and explicit unknown API wire status. 44 focused tests pass, zero source type errors. |
| `f5e96de0f`, `ae0725300` | Exact signed consumed authority and native Codex browser continuation through fixed request identity, fresh native validation and shared-fence finalization. 72 final focused tests pass; installed completion remains unqualified. |
| `4dde4d52a`, `3c28a9a3f` | Encrypted private observations, authenticated bounded manifests, exclusive recovery, separate attempt-specific ciphertext/public receipt uploads and truthful partial-publication status. Local tests and independent production-recipient recovery pass; actual CI retention and Windows execution remain pending. |
| `17c531a10` | Single-traversal Yarn/pnpm/Gemfile validation, manifest and direct views; immutable complete-v2 reuse, explicit existing numeric budgets and complete-or-fail context semantics. RSP-052 component criterion closes; no new performance claim. |
| `938d59999`, `27da1a51b` | Bounded request-permit handoff and synchronized buffered-header/watchdog ownership. Focused regressions pass; the retained 240-request workload still fails and unproven parser/overload boundaries remain. |
| `6311a8ade` | Windows Ollama failure now retains phase, validated prior cases and bounded publisher evidence without changing 400 ms readiness;44 focused tests pass, actual cause pending. |

RSP-037, RSP-052 and RSP-119 are DONE for their exact component acceptance.

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
 Their
original dependencies remain unchanged: installed attribution, Ollama lifecycle,
route activation and release qualification are still open or blocked. The catalog
matrix retains 30 restricted benign rows out of 39 ordinary-control rows per
catalog, all already intrinsic reviews; zero newly restricted intrinsic allows
is narrower than zero false reviews. Its six Docker/Kubernetes review-to-block
compatibility outcomes per catalog remain explicit limitations.

The production Codex correction is now integrated. Native Codex browser continuation is integrated
at ae0725300 with consumed-authority getter f5e96de0f. Fresh native full-input request digest is the
signed artifact hash; request_id, harness, artifact_id, artifact_hash, workspace and publisher
remain fixed across final rereads and atomic consumption. Policy/runtime/program/observation
binding, original live process/home context, strict signed consumed replay, absolute deadlines and
the shared control fence through finalization are retained. 72 final focused tests pass; the broader
117-test run recorded 115 passes and two failures. The two-second app-server adapter timeout also
reproduced on the unchanged checkout; the waiting case passed in isolation. Neither limits nor
expected authority were weakened. Actual installed Codex continuation remains unqualified; exported
native v3/v4 consume is still a separate API.
The fixture observes completion and does not manufacture authority or invoke the
separate exported native v3/v4 approval API.

[Encrypted evidence retention](private-qualification-evidence.md) is now implemented.
Encrypted private-observation retention is integrated at 4dde4d52a/3c28a9a3f: RSA-OAEP-SHA256 wraps
fresh AES-256-GCM keys; bounded authenticated manifests, exclusive recovery and separate
always-upload ciphertext/public receipts preserve flat JSON/JSONL attempts. 56 tests pass with one
actual-Windows ABI skip, plus one receipt-truth regression. Independent recovery with the separately
retained production key verified both exact file hashes, including partial JSONL, and Unix 0700/0600
permissions. Actual CI ciphertext retention/readback and Windows execution remain pending; no
private key, raw observations or private paths are published.

One integrated helper batch reported 38 passing tests and one timeout while the
Claude allow resolver still reported waiting. The same case passed alone in
1.08 seconds at the same source (`review/launcher-approval-timeout-recheck.log`).
The cause remains unknown; neither a source defect nor host scheduling was
established, and no deadline was raised. Resolution deadlines are cooperative
around production SQL/flush work; late durable outcomes remain failed evidence.

The source cutoff includes the mixed-fairness and buffered-header corrections:

Integrated 938d59999 corrects the mixed fixture's eight-per-client admission setting and bounds
request-permit handoff to 50 ms within the original deadline. Its retained 240-request workload
still failed: zero 503 responses, one 408 and p95 1,708.144 ms above the unchanged 1,000 ms
diagnostic target. Integrated 27da1a51b separately transfers already-buffered complete headers under
the classification lock and revalidates the exact expired socket/deadline before watchdog closure.
The watchdog tests pass (24 adversarial/handoff, six header/probe and one blocking-socket refusal);
no passing full-workload rerun exists. Headers completed during parsing and the separate
overload-eviction path remain outside this repair's proof. No deadline or PRD limit changed.

Integrated 6311a8ade preserves the actual failed lifecycle phase, completed validated cases,
one-call readiness elapsed/returned-snapshot state, nonblocking cached publisher state, finite error
codes and up to eight code locations. Forty-four focused tests pass and independent source review
found no blocker. This is diagnostic repair, not a proven Windows readiness cause or a passing rerun; the 400
ms readiness gate and authority/Builder checks are unchanged.

Retained native-wheel artifacts report real registered Claude PostToolUse startup/stdout/exit smoke
with only n=2 per platform: macOS ARM p95/p99 322.268 ms (artifact 10489669145) and Linux 355.223 ms
(artifact 10491149852). Both identify build source f7293abfe50cfb8f6b05e99f3e1b9c0449ada61c and
qualification_complete=false. These values exceed the PRD installed targets numerically and are a
profiling lead, not qualified percentile estimates or a frozen paired comparison. Other registered
routes remain unmeasured by this narrow launcher series.

## Behavior corrections kept separate from optimization

The foundation fixes a generic native request that paired an otherwise benign
command with an independent sensitive file target: the path now retains its
review floor. AIBOM exports redact URL credentials. Copilot uninstall reports
incomplete cleanup when unauthenticated legacy state cannot safely authorize a
configuration rewrite. An AWS credential-read matcher excludes access-key
deletion so the existing provider-specific destructive rule retains ownership.

The scanner reports missing or corrupt historical Git objects as incomplete.
Package input budgets now produce explicit incomplete outcomes; an unavailable
exact content hash blocks rather than presenting a placeholder as valid approval
identity. Package evidence writes become atomic rather than partially committed.
These are intentional correctness changes, with their own regression tests.

Ordinary native unavailability continues to use the current harness-specific
availability policy. A blanket new fail-closed policy is outside this performance
change. The [current contract](CURRENT_CONTRACT.md) records that distinction.

## Qualification and release gate

Qualification must build the baseline and candidate as separate installed native
wheels on Linux x64, macOS x64, macOS arm64 and Windows x64. The workflow pins
source and dependency locks, verifies package/runtime/rule identities and clears
development runtime overrides. Frozen/post-sign distribution evidence is a
separate requirement where that distribution changes.

The same-repository PR label `rust-performance-qualification` selects the full
qualification job; ordinary PR runs are explicitly smoke. Apply the label only
to a stable candidate. Any subsequent code or dependency change requires renewed
qualification on the resulting head. Qualification reports must include every
attempt, failure, timeout, rejection and recovery, and mark unavailable resource
metrics explicitly. A per-route pass cannot stand in for all-platform acceptance.

The historical round-four workflow uploaded public aggregates only.
The newer integrated workflow encrypts the private journals and retains separate
ciphertext/public receipts after timing. Independent local recovery has verified
exact synthetic bytes and permissions, but no successful CI ciphertext upload,
download/recovery or Windows execution is claimed. RSP-140 remains OPEN until
those actual retention and privacy checks pass on the final candidate.

The historical round-three qualification attempt on 2026-09-17,
[run 35201516872](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516872)
at remote head `92cf3c72d80d` selected all four targets but did not qualify them.
Linux and Windows baseline 1 MiB source cases returned an unexpected continuation:
the `.txt` fixture is outside the frozen source classifier, while `.rs` exercises
the intended source scan. macOS ARM logs identify reverse DNS during HTTP server
construction; macOS Intel diagnosis was pending at that observation. These
retained failures are not grounds to patch the pinned baseline, loosen readiness or count missing
data as passing. The integrated corrections above are source-supported repairs;
round-four smoke failed all four targets, with seven failed workflows at that historical head.
Current 42579f046 separately has four failed workflows; no final qualification exists.
Neither local corrections nor partial successes retroactively make the old run pass.

A separate, later-reported installed identity result is evidence-ready for two
platforms. In [native wheel run 35201516674](https://github.com/hashgraph-online/hol-guard/actions/runs/35201516674),
Linux job `105137144858` and Windows job `105137144563` each passed all 17
`probe_installed_runtime_identity.py` cases before subsequent default-auto hook
failures. The probe reports scope `installed_status_and_real_stdio_child`;
cross-release upgrade/rollback and signing are explicitly not exercised. The
observed capability build SHA is
`73f34ba984ff01563257599692cce33098014bdf`, package 3.0.1. Do not equate that
artifact identity with a different source head without tree/artifact verification.

| Observed artifact | Runtime bytes / SHA-256 | Manifest SHA-256 |
| --- | --- | --- |
| Linux x64; uploaded artifact `10488336777` | 12,239,840 / `b68c975462f71339f4342e6dec70cd79c9702bf38777477dcf54e642422c5c55` | `a7ec7e7f69f712a0ac4b2951c76dfdbb1d3f64a540c455a0d0ec0e8e92a312f4` |
| Windows x64 | 11,287,040 / `17ccfc7fa6243d990e31475fbb16d564d0428e85ce059cfae59f8dccb940b7e7` | `ac5209f08b73d97516a4526e3848d216c2d42220f3a2c11b2b764e866b5a9efb` |

These log observations were supplied by the package owner during this audit;
retain/download their job artifacts for the final release evidence. macOS
identity logs had not been reviewed. A different identity job (`105137131940`)
failed pytest plugin import before collection (`No module named tests`), which
is a harness failure, not an observed identity-contract failure. Neither that
failure nor the two passing identity probes determines final hook acceptance.

The foundation PR's reported head
`e449594e86c717e66e14598a4130475de79c536f` had all 25 workflows successful and
33 review threads resolved at the coordinator's fresh reported read. No
independent last-push human approval was present. The performance PR has three
resolved review threads, including the CodeQL finding on a domain-separated
SHA-256 identifier of a randomly generated 32-byte authority key. That value is
not a password verifier. Required final CI and independent approval remain
separate; refresh their exact head before merge.

The frozen targets remain those in the PRD: warm installed c1 p95 <= 50 ms and
p99 <= 100 ms; c16 p99 <= 200 ms without errors; native client p95 <= 20 ms;
cold native p95 <= 150 ms; existing readiness bound 400 ms. A selected hot tranche
needs at least 30% p95 or CPU benefit with no more than 5% regression in the other
primary metric. Optional ingress needs at least 25% private-memory or 30% c16 p99
benefit. Current RSS-growth gates remain intact. Use at least five alternating
independent runs, 10,000 priority warm decisions, 1,000 other-route decisions,
100 priority cold starts, 100 recoveries and 30 resource observations as specified
per scope in the PRD. Do not pool routes to conceal a miss.

This workspace has not established a successful installed daemon/socket matrix.
Source tests, one-shot timings and installed status/stdio component probes retain
their stated boundaries. They do not replace registered launcher, resident
recovery, source-ref, approval, signing or process-tree release evidence.

The mixed runner reports its narrower observed checks separately from full
qualification. It preserves every offered/admitted/completed/failed/rejected
attempt, scheduled-offer-to-terminal latency and real committed receipt IDs.
Candidate receipts require the binding-aware getter; only explicit
`baseline_2e672d2` may validate complete legacy rows with its installed validator.
Journal writes/fsyncs are instrumented; SQLite VFS bytes/fsync are unavailable,
not zero. A 30-second scenario and the inherited 1,000 ms diagnostic adapter
budget do not replace the frozen sample minima, 50/100/200 ms product targets,
longer mixed soak or actual daemon-process restart.

Remaining implementation is concrete: resolve the observed mixed-fairness production races, localize
macOS DNS and Windows source/readiness failures, complete uncovered host and lifecycle/fault
scenarios, and add justified observability for unmet metrics. Native Codex finalization and
encrypted retention are integrated; their actual installed/CI qualification remains required. The
ordinary/approval/malformed/mixed runners, fixture provisioning,
source-shape repairs and Copilot response fix are already integrated. Perform
optimized-baseline/native comparisons for conditional ports; missing
qualification is not the only remaining work.

## Canary, rollback and final handoff

Before activation, record the exact qualified candidate and prior known-good
package/runtime/rule/program digests per platform. Begin with an internal cohort
for each selected harness, then broaden only after installed contract, resource,
policy freshness and approval metrics remain within the frozen gates. Count
evaluated allows, review/block outcomes and availability continuations separately.

Stop on any new semantic mismatch, approval replay, secret-bearing exported
evidence, stale stricter policy, identity failure, unsupported native capability
claim, unbounded queue or violated route/resource target. Retire the affected
generation, restore the prior verified package and registration through the
existing ownership-aware installer, and confirm new requests use the restored
runtime and acknowledged policy. Never downgrade a persistent revision floor or
silently reopen Python semantic fallback to make rollback appear successful.
In-flight requests receive their defined completion/unavailable result; ambiguous
tool execution is not retried. An actual rollback transcript is required before
RSP-139/143 can be closed.

The release ruleset requires a pull request, passing `quality`, resolved threads
and an independent code-owner approval of the last push. Stale approvals are
dismissed; there are no configured bypass actors. Local parallel review and
automated bots do not supply the missing independent approval. Merge status must
be reported separately from implementation and qualification status.

The final handoff must update all 144 records with exact code/test/measurement
references; list selected, measured-deferred and blocked scope; link final PRs
and Actions artifacts; report metric intervals and route/platform misses; and
include the tested canary/rollback versions. The implementation is not complete
while that evidence is missing.

Reconciliation 37198f272 incorporates remote 42579f046 while retaining fixed six-field atomic
request identity and post-transaction original-waiter liveness, both source/startup diagnostic sets,
and independent Windows ABI probes. Retry diagnostics remain observational: hook and challenge
refusals must both be zero, including recovered 503s. Coordinator evidence records 197 passing cases
and one actual-Windows ABI skip in the initial suite; the corrected 29-case batch passes, including
startup coverage XML and refusal-report tests. Source-cap repair 025ddb0b6 splits the private
policy-store fixtures without dropping tests. Final CI of this reconciled source remains required.

Integrated `923a13634` preserves exact source identity through both Ollama privacy passes
with the safe `build_sha` field; positive, missing and mismatched identity regressions pass.
Coordinator reports full production Ruff and formatting clean across 1,254 files;
full BasedPyright was still running at this documentation cutoff. Final-head CI remains required.

## Additional source review before publication

Source checkpoint `6af1f65dd22786cfee415acdcc28ec8f47b26551` (tree
`a019984faf793f9d754b41e2ef3045a9d2e3dea9`) adds the isolated
[MCP component runner](mcp-proxy-rebaseline.md), the corrected approval-persistence
fault fixture, and the [dormant native Claude launcher design](native-claude-launcher-design.md).
No additional task status changes or installed passes are claimed. Full production
Ruff and formatting pass; BasedPyright reports zero errors, warnings and notes.

The approval fault fixture previously accepted only keyword arguments, while both
frozen baseline and current production call persistence with `(request, now)`.
The corrected fixture reaches its injected SQLite failure and records the actual
witness. Thirty-one candidate tests and the same real queue-helper regression
against frozen baseline imports pass; no native socket execution is inferred.

Windows large source references expose a production gap: both frozen baseline and
current `guard-secure-fs` reject every non-Unix secure-open request. The core maps
that read failure to `no_output_to_review`. A safe Windows handle-based reader and
actual installed source tests are required. The green Windows native-wheel job
ran identity, control-lock and default-auto probes; it did not run the installed
source-file SLO suite.

The Linux c64 report also needs correction: overlapping requests infer individual
routes from shared counter differences. Mixed increments become `native_fail_safe`,
so its 64 reported fail-safe rows do not establish 64 actual native failures.
Preserve the failed artifact, replace unsupported attribution with explicit wave
accounting or exact request evidence, and keep all overload/error gates unchanged.
