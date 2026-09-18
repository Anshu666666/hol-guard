# Current decision and performance contract

## Release checkout and immutable evidence archive

The release checkout preserves the user's signed cleanup `c9ed06bbcb7cef2ecbb93955fdad34be71710aa7`: generated evidence dumps, compressed artifacts and scan scratch files remain outside this PR. `.gitignore` and `.gitattributes` remain byte-exact to that cleanup; `.gitleaksignore` separately restores only the 96 exact, individually audited historical fingerprints. The archived integration cutoff is `69a09bc94b22bd5a789f137b9b7ebf3132296f83`. The prepared release source is `4edad2ca1dc075c69cbec7c3b59d1a59fc4d3505` at checkout `5e5f5fe5beaaee38d526f4cd8fc34e99488ea0d9`. Separate local integration for its later MCP and diagnostic changes is retained below; fresh hosted evidence remains required. The archive's source-validation results do not qualify those later changes or establish complete-tree equality.

The [evidence archive](EVIDENCE_ARCHIVE.md) is pinned to separate commit `aeb04b6b06bd15ae2a2ecf00e8671c7501239278`. All 119 catalog objects and all 144 task objects below retain their exact archived values, including the complete RSP-106 record and the original 89 catalog entries. Removed evidence links now open immutable archived paths. Their original relative catalog paths remain provenance and are resolved through [evidence-archive.json](evidence-archive.json); no deleted dump or placeholder directory is recreated.

The last completely retained implementation cohort in the original 119-entry catalog is **590**, followed by the separate **1d846** MCP publication and local **69a09** validation. The release PR subsequently moved to the user's cleanup commit **c9ed**. The additional evidence below retains that exact terminal c9ed cohort separately. Neither earlier cohort grants hosted credit to the later prepared source. The following dated observations retain their exact source scope; they do not qualify the cleaned integrated candidate, establish independent approval, or activate a release.

### Prepared source and remaining execution

The prepared source includes the default MCP callback-authority repair and its independent package handoff correction, the exact ownership declaration, the real Desktop corpus refresh, bounded readiness/surface failure diagnostics, and configured project context forwarding on the daemon fast path. These changes have separate source-bound records below. They preserve the existing authority checks, exact 5 ms MCP fence, baseline source and performance budgets. RSP-100 risk-analysis reuse remains unqualified; the historical E/F campaigns and complete RSP-106 record remain untouched.

Combined validation at `4edad2ca1dc075c69cbec7c3b59d1a59fc4d3505` passes all eight recorded command scopes: native authority, Python semantic reachability, I/O ownership, privacy, full-production Ruff lint and formatting, explicit-interpreter production types, and focused merged tests. Types cover 1,258 production files with **zero errors and 20,272 warnings**. The combined test command passes **231 cases with one expected real-Win32 skip** in 5.62 seconds; earlier overlapping component populations are not added. All 4,354 tracked file hashes remain unchanged after every command. The 395 current Desktop bindings match the separately regenerated fixture; this integration check does not rerun its 51,000-case generation.

### Last terminal hosted cohort — signed cleanup c9ed

The separate c9ed cohort completes all 37 workflows: 34 success and three failure. Its 207 checks across all attempts have 180 successes, 20 skips and seven failures; the 204 latest checks have 177 successes, 20 skips and seven failures. Main CI passes. All four paired jobs fail, and the macOS Intel wheel job fails the unchanged recovery-latency gate with p95/maximum 1,080.857 ms across two smoke observations. Eight native/paired archives and four embedded runtime identities are verified against the exact candidate/test-merge sources. Qualification remains false.

The c9 Sonar comment reports a passed quality gate, zero new/accepted issues or security hotspots, 83.0% new-code coverage and 0.0% duplication. The separate CodeQL check still reports 11 highs. Gitleaks' original 96 findings remain retained with their individually scoped historical-digest audit; the later exact fingerprint restoration does not rewrite that old result or establish a successful scan of the new publication. Fresh default-auto reports show 21 accepted/processed receipts and zero persistence failures on each host, while Linux mixed contention still has receipt failures; earlier Windows three/one-failure observations and their unknown causes remain intact. Neither the bot summary nor these hosted records establish genuine independent approval of the forthcoming head.

The next execution must bind the actual published head, test merge and installed artifacts, retain every natural hosted outcome, and complete the original route/platform, warm/cold attribution, resource, control/posture, mixed receipt and lifecycle qualification. Frozen Mac baseline lookup, original retirement and unobserved global/Windows route scopes remain separate from these local repairs. Full signing/version/live rollback, fresh security/Sonar/Greptile gates, genuine independent last-push approval, and tested canary/activation remain release gates. No task status or acceptance criterion is changed by this source checkpoint or the move to archived evidence.

| Additional source evidence | Exact source and limit |
| --- | --- |
| [Default MCP callback authority repair](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/mcp-authority-callback/README.md) | `7e735d294fe3e9b753b8a07ede30c2e865da9d5e`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/mcp-authority-callback/manifest.json) SHA-256 `ad44567104d9c581c246c365b050144cc3eddbbf823e16d816af0534ea4afd0f`. Finite actual-stdio and source suites preserve original failures, public/private callback order and the exact 5 ms fence. Includes the exact ownership declaration at 6f930c. No RSP-100 benefit, E/F replay, RSP-106 completion or hosted qualification. |
| [Independent local package handoff review](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/mcp-authority-callback-independent-review/README.md) | `7e735d294fe3e9b753b8a07ede30c2e865da9d5e`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/mcp-authority-callback-independent-review/manifest.json) SHA-256 `ead41ae3b3329743cd957876948f9326bb8fa54cfd6e268050ef72c544108cc4`. Both draft mutation cases fail and the identical final three-case witness passes with unchanged forwarding control. Finite source review, not human last-push approval or performance qualification. |
| [Real Desktop corpus regeneration](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/mcp-authority-desktop-refresh/README.md) | `6f930c563e4f4e7d43e3bc74171636bc7cbd9d43`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/mcp-authority-desktop-refresh/manifest.json) SHA-256 `8ad198ded9d6514c6b350cb0fe6bfcec9cc60c1a44eaa80ee5ea198f7d11b7a4`. Actual generator evaluates 51,000 cases with all non-source fields unchanged; all 395 bindings match and 16 contract tests pass. Existing 45-second/512-MiB assertions remain; no installed-route or RSP-100 performance credit. |
| [Bounded policy refusal diagnostics](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/policy-readiness-diagnostics/README.md) | `288409b6b95ced2cc85b804b7a7804e3dfc0b6f2`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/policy-readiness-diagnostics/manifest.json) SHA-256 `3e4c192793fea5e70bb66d3b97e9a52ffdf62ce333b87701c2200b34edb4b355`. 140 finite cases pass; original readiness deadlines, responses and failure fields remain. Direct fixture types retain the same four baseline errors. This preserves future evidence and does not identify or repair either historical Windows cause. |
| [Installed surface failure context](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/registered-surface-failure-context/README.md) | `0372eafd4a95e1f415e4665c1f857773bcb3c332`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/registered-surface-failure-context/package-manifest.json) SHA-256 `af88bab7b75057c0aa619879bfdc91639ed5315b827f5e69cf6d97abdb9e6352`. 70 cases pass with one platform skip. Bounded existing case/route context is retained after the original failure; successful timing and validation remain unchanged. No old route failure is reclassified. |
| [Configured project context forwarding](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/project-hook-context-forwarding/README.md) | `d8a4259a7145a5cecc0524b80ea8cb27e287eb21`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/project-hook-context-forwarding/package-manifest.json) SHA-256 `d811183be04b4703d8c91510cdf8976315d35cc5dcf3074fbabd543631e31fbd`. 198 bounded-CLI tests pass. Actual registration/request/receiver witnesses bind 2e, 590 and repaired source but stop before network and policy preparation. Global workspace absence, original payload and hosted-cause uncertainty remain. |
| [Combined prepared-source integration](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/combined-4edad-integration/README.md) | `4edad2ca1dc075c69cbec7c3b59d1a59fc4d3505`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/combined-4edad-integration/manifest.json) SHA-256 `0079f188528fec0300896e9b3394a409da83d1fbbf60fba5de66a0361c8083ed`. Eight command scopes pass; 1,258 production files have zero errors/20,272 warnings; 231 tests pass with one real-Win32 skip. All 4,354 tracked hashes remain exact. Desktop comparison is inventory-only. No hosted/performance qualification. |
| [Separate source69 archive publication](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/archive69-publication-receipts/README.md) | `aeb04b6b06bd15ae2a2ecf00e8671c7501239278`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/archive69-publication-receipts/manifest.json) SHA-256 `e5fa0e4f7eeafbfe921959a3fbb987e2b36b30031d9e9725089be48a87bb7141`. Exact source69 archive tree, full-range zero-finding scan using its retained historical ignore file, and nonforce branch readback. This is archive publication evidence, not a scan or qualification of the cleaned release source. |
| [Exact historical Gitleaks digest audit](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/c9-gitleaks-digest-audit/README.md) | `c9ed06bbcb7cef2ecbb93955fdad34be71710aa7`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e6d046acf602672e6daccdc8ca648dee92b19e02/docs/guard/evidence/c9-gitleaks-digest-audit/manifest.json) SHA-256 `fa238a6025bd4836c9864465ebca8a611cf4c9a56fe0b555ae195a236dcd0a9d`. All 96 findings match exact fingerprints removed by c9. 82 source values are recomputed; 14 launcher fields have retained probe/report provenance with no fresh historical binary rehash. No wildcard, credential exemption, CodeQL disposition or runtime qualification is justified. |
| [Terminal signed-cleanup hosted cohort](https://github.com/hashgraph-online/hol-guard/blob/e779bc22a97d763b3edf4f6a246b7303e84b658d/docs/guard/evidence/cleanup-c9ed06b-hosted-final/TERMINAL.md) | `c9ed06bbcb7cef2ecbb93955fdad34be71710aa7`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e779bc22a97d763b3edf4f6a246b7303e84b658d/docs/guard/evidence/cleanup-c9ed06b-hosted-final/manifest.json) SHA-256 `6a3e77a063a63efb866690651c040fd5fb02cc667b49945416f5ff61cf2aa9b9`. All 37 workflows terminal: 34 success/three failure; Main CI passes, all four paired jobs fail, Intel wheel recovery fails, and CodeQL retains 11 highs. Eight archives and four embedded runtimes are verified. Original qualification remains false; later fixes receive no hosted credit. |
| [c9 review and exact historical digest restoration](https://github.com/hashgraph-online/hol-guard/blob/e779bc22a97d763b3edf4f6a246b7303e84b658d/docs/guard/evidence/c9-review-and-restoration-receipts/README.md) | `5e5f5fe5beaaee38d526f4cd8fc34e99488ea0d9`; [manifest](https://github.com/hashgraph-online/hol-guard/blob/e779bc22a97d763b3edf4f6a246b7303e84b658d/docs/guard/evidence/c9-review-and-restoration-receipts/manifest.json) SHA-256 `c83c9d156b9fee9eb7381c2b0b8fbb4f500f39eeefea40ab4ba6491bf24f3d97`. Retains the c9 Sonar pass comment, exact 96-fingerprint restoration at 5e5f5f, and preceding e6d publication chronology. The actual lean publication scan was pending at capture. No CodeQL clearance, human approval or later-source qualification follows. |

## Retained validation checkpoint — source 69a09bc9, 2026-09-18

The integrated source before this documentation is `69a09bc94b22bd5a789f137b9b7ebf3132296f83`. Actual implementation [PR #2954](https://github.com/hashgraph-online/hol-guard/pull/2954) remains `590ce01334a7724f3f1349b2ab252110a5a268f5`, draft and unmerged at the last retained readback. Its entire hosted cohort is terminal. The MCP correctness work is separately published at `1d8467bd2c60a05a45199796027b6b328079eb2e` on `codex/rsp100-security-binding-20260918`; it is not the PR's hosted source. Foundation [#2951](https://github.com/hashgraph-online/hol-guard/pull/2951) remains `a001b2691f481b7b5a66dd14d68e48d61c44cb78` with its own retained review/security blockers. Later source fixes and diagnostics require new hosted artifacts.

All **144 original tasks** retain **74 DONE, 31 OPEN, 29 BLOCKED and 10 DEFERRED**. Original PRD/TODO bytes, every acceptance/dependency/status field, complete RSP-106, original 89 catalog entries and all 100 preceding checkpoint entries are preserved. Thirty-three DONE records still have unresolved direct dependencies; RSP-134 includes all selected implementation tasks. No qualification, approval, activation or release is implied by these counts.

| Exact 590 observation | Result and limit |
| --- | --- |
| [Terminal hosted cohort](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/implementation-590ce0-hosted-final/TERMINAL.md) | 37 workflows: 35 success/two failure. All 205 checks: 175 success/23 skipped/seven failure; latest 203: 173/23/seven. Main CI shard 75 has 225 passed/two failed and aggregate fails; Sonar skips. External CodeQL retains 11 highs and no head approval. All six snapshot diagnostic jobs succeed without clearing alerts. |
| Artifact/runtime identities | All four native wheel jobs pass. Their test merge `6981551052e75dfee9f372513177caed76df53a8` has the exact 590 tree `7284a9c2bf2f301d84a500cafd56a6153785f3cf`; each downloaded artifact and embedded executable identity is verified. Paired builder pins direct 590 against unchanged frozen 2e. |
| Capacity and soak | Linux 64 wave conserves 32 resident / 32 overload/zero fail-safe/errors; both Macs also conserve 32/32. Linux soak completes 100,000 responses, 250,000 receipts and 21,012 health checks with zero request/health errors; p95 537.47 ms, maximum 626.7 ms, RSS growth 0.033141. The soak passes its unchanged contract; all SLOs remain smoke and full PRD qualification is incomplete. |
| Paired and installed routes | All four paired jobs fail. Linux completes both smoke arms, each 386 daemon / 62 launcher cases, with only one pair / two ordinary samples and no qualified scope. Linux priority input/nonpriority/posture/mixed/approval faults remain. Both Mac baselines fail in getfqdn and candidates fail interpreter permissions. Windows candidate empty Pi output is native_policy_not_ready; Windows Ollama also fails readiness. Other three Ollama reports and all 112 retained-Python scanner cases pass. |
| Claude and persistence | Linux Claude completes five blocks / 20 cells / 600 attempts for linux_c1_two_events; point-improvement gates pass, uncertainty is unevaluated and eight scopes remain missing. All hosts have 21 default-auto resident decisions; Windows retains one receipt persistence failure despite eventual drain. No link to its separate readiness failure is established. |
| Lifecycle | Every original-baseline transition still has three of seven positives, zero accepted negatives and failed native retirement; no candidate restoration. Compatible stopped rollback passes only its own three phases. No full signing/version/live/in-progress qualification. |

The [590 publication](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-implementation-590ce/README.md) and [separate MCP publication](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-mcp-security-1d846/README.md) each have an exact full-release-range zero-finding scan and branch readback. The [failed unreferenced 6c5 scan](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/prepublication-evidence-labels-6c5/README.md), all old raw observations and source-specific reports remain intact. Neither earlier scan qualifies a later publication. The completed [54c0 full-source diagnostic](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/codeql-materialization-hosted-54c0/README.md) remains 25/29 raw findings across cdd/d8, distinct from the PR 8/11 new alerts and with no alert disposition.

The integrated [MCP binding](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/mcp-tool-call-binding/README.md), [capture](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/mcp-tool-call-binding-capture/README.md), [completed receipt](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/mcp-completed-write-receipt/README.md), [historical adapter test reconciliation](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/mcp-historical-adapter-test-scope/README.md) and [scalar identity](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/mcp-binding-type-identity/README.md) corrections preserve immutable authorized bytes and the exact 5 ms fence. Their finite actual-stdio/source suites retain all earlier failures. Category derivation remains twice. The newly found saved-state callback authority repair is still separate active work; the per-call optimization is inactive, unqualified and untimed. Historical E/F campaigns are not resumed and the complete 106 record is untouched.

The [Mac private interpreter correction](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/macos-interpreter-provisioning/README.md) extends the existing exact-byte/runtime/installed-validator provisioning to both Macs and the third transition venv; 154 local cases pass, but actual Mac loader execution remains unproven. The frozen validator, shared framework permissions, Python bytes/version and original cold-process budgets are preserved. The [CI75 pending-read correction](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/launcher-approval-ci75-590/README.md) has 73 finite passing cases under coverage and retains safe read-only retry before SELECT completion without invoking storage recovery. It proves a separate local SQLite defect, not the cause of the original hosted failures or a full-shard pass.

The [legacy retirement source review](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/legacy-retirement-source-review/README.md) corrects the earlier unreachable-helper claim. Its [observer](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/legacy-retirement-observer/README.md) remains diagnostic-only with proof/coverage/bootstrap false and material retained local overhead. [Mac lookup diagnostics](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/macos-baseline-lookup-diagnostics/README.md) preserve exact DNS response/parser bytes, original deadlines and containment_failed; fixed counters are not atomic partitions. [Receipt diagnostics](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/receipt-failure-diagnostics/README.md) retain fixed failure phase/code labels without changing durability/retry/count semantics. None replaces an old failure or supplies a missing installed proof.

Fresh [combined integration](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/resume-69a09-integration-validation/README.md) initially passes semantic/I/O ownership, production Ruff and 135 observer/interpreter/transition cases (6.67 seconds) at b8f27. Its missing helper ownership declaration and 52 type-check missing-library import errors remain retained failures. Source 69a09 adds only the exact diagnostics helper to the existing persistence/privacy inventories. Native authority and I/O gates then pass, as do 19 ownership tests (5.73 seconds). Full production basedpyright, with the already installed validation interpreter selected explicitly, reports `0 errors, 0 warnings, 0 notes` under `--level error` in 47.849 seconds including lock; this is not a claim about every warning level or a replacement for historical direct-script results. All 31 changed code paths and 395 Desktop source bindings are independently verified; no tracked input changed during either run. The [fresh 590 snapshot diagnostic](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/codeql-materialization-hosted-590/README.md) also retains six successful jobs and 54 complete raw cdd/d8 findings identical to 54c0 as multisets, with exact result mappings and 84 verified source blobs. It explicitly reuses the prior source assessment and does not analyze current PR runtime or clear alerts.

Full original sample minima, final artifact/route/Watch/approval/posture/resource coverage, original-baseline retirement, signing/update/rollback, external CodeQL/Sonar, fresh Greptile 5/5, resolved threads and independent last-push approval remain outstanding. Source correctness, installed qualification, activation and release stay separate. The following earlier narrative is retained historical context; this checkpoint supersedes its old current-head and pending-run labels.

## Retained earlier narrative

This contract describes the implementation identified in [EXECUTION.md](EXECUTION.md),
including the 2026-09-17 takeover corrections to Codex continuation, package
parsing, bounded source experiments and MCP notification delivery. It includes
native command execution, control authority and live-process attestation. Source support
is distinct from installed activation and release qualification; exact evidence
and remaining acceptance are in the [execution ledger](EXECUTION_LEDGER.md).

## Historical checkpoint through 623a — 2026-09-18

The integrated local source/evidence cutoff is `623a6e058b2c4b650021e3c359d8e58b1be6ea05`. Actual published implementation [#2954](https://github.com/hashgraph-online/hol-guard/pull/2954) remains `7a387128e2cf2ec79b890dfebe2697e8a49eb45d` (draft, unmerged); foundation [#2951](https://github.com/hashgraph-online/hol-guard/pull/2951) remains `a001b2691f481b7b5a66dd14d68e48d61c44cb78` (unmerged, protected review blocked). The later integrated repairs have not been qualified by the earlier published artifacts. All **144 original tasks** remain **74 DONE, 31 OPEN, 29 BLOCKED, 10 DEFERRED**; implementation, qualification, activation and release are distinct.

| Exact source and population | Retained result |
| --- | --- |
| [Implementation 7a terminal cohort](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/implementation-7a387-hosted-final/TERMINAL.md) | 37 workflows: 33 success/four failure. All-attempt checks: 206, with 171 success/23 skipped/12 failure; latest view: 203, with 168/23/12. CI: 114 jobs, 106 success/six skipped/two failure. Desktop passes; Sonar/Sonar Guard skip; external CodeQL reports 11 new highs despite successful Actions analysis. |
| 7a installed execution | All four paired targets fail; no comparison qualifies. Windows completes one adverse, unqualified baseline block. All four retained-Python scanner probes pass 28 cases each. Both Mac SLO reports pass smoke with qualification false; Linux fails strict capacity before soak. |
| [Foundation a001 terminal cohort](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/foundation-a001-hosted-final/README.md) | All 25 workflows succeed; 182 checks retain 160 success/19 skips/three failures. CI 111 success/three skips; Desktop and Sonar pass (zero new issues/hotspots, 81.4% new-code coverage). External CodeQL still reports eight highs; Kilo output-limit and original Gitleaks installer failures remain in the all-attempt population. No active independent approval. |
| a001 Linux soak | Completes naturally: 100,000 requests/responses, 250,000 receipts, 24,198 health checks, zero request/health failures. Step 34m42s; p95 617.98 ms, maximum 850.31 ms, RSS growth 0.085565, maximum 64 threads/192 file descriptors. Its older foundation contract does not qualify the implementation's stricter capacity or full PRD gates. |
| [26cd terminal addendum](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/foundation-26cd-hosted-terminal/README.md) | 25 workflows: 23 success/one failure/one cancelled; 178 checks: 149 success/22 skipped/five failure/two cancelled. Linux soak cancelled after 23m09s; no final soak report. The original 21:09:39Z interim and every earlier failure remain unchanged. |

Actual implementation wheels use test merge `95ba3911b8b68227510c034306554c8fb7f8a66d`, with the exact 7a tree `1ccec336c8a3aff22a4500b8f8350ae8fee3a345`. Foundation wheels use `4631c7098bd229cc164d2408a32191331492adcc`, with a001 tree `24e28be411272ad055f47012603d35e0394de67b`. All embedded runtime identities were verified against downloaded wheel bytes. Frozen paired baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b` remains unchanged. These are artifact proofs for their named sources, not the later local repairs.

The actual [7a publication and full-range secrets scan](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-implementation-7a387/README.md) are retained from the separate evidence branch: zero findings with pinned Gitleaks 8.24.2, unchanged ignore input and 1,262 commits scanned. The original pre-publication receipt and subsequent branch readback remain distinct. A new published implementation commit needs its own full-range scan.

### Three integrated corrections and their limits

The [daemon refresh repair](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/daemon-refresh-reader-lease/README.md) begins unchanged-authority refresh under the existing shared lease. Only `NativeCommandControlMutationRequiredError`, after SH unwinds, permits a fresh exclusive read. A real POSIX held-reader conflict fails before the fix; five new cases pass in 1.20 seconds and 56 existing cases pass in 10.05 seconds. Server-only types have zero errors/319 warnings; Ruff/format pass. The five-second interval, markers, floors, mutation rules and startup remain unchanged. All 395 actual Desktop source bindings are unchanged and `server.py` is not bound, so no report regeneration ran. The original mistaken regeneration claim and its correction remain in the receipt. This source proof does not identify historical lock holders or qualify installed capacity or Windows behavior.

The [workspace/admission correction](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/installed-workspace-admission/README.md) marks the shared priority fixture's owned workspace explicit. Actual unchanged baseline 2e and candidate 7a adapter/receiver methods admit no workspace before and the owned workspace after, for both events; 1,264 baseline source/support files match original Git blobs. All 386 corpus cases, the 1 MiB expected digest and deliberately empty inputs are preserved. Four pre-fix regressions fail; 42 focused tests pass in 3.55 seconds, fixture types have zero errors/28 warnings and Ruff/format pass. The witness stops at receiver policy admission and does not execute authenticated HTTP or native performance qualification. The accompanying empty-approval assertion adds only the existing bounded result to future failures, preserving the two-/three-second budgets and predicates; its historical cause remains unknown.

The [CodeQL materialization repair](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/codeql-source-materialization/README.md) fully materializes the immutable source and rejects sparse checkout, hidden index flags, missing tracked paths and empty inventories. All 65 diagnostic tests and collector types (zero errors/warnings) pass. Actual cdd/d8 replay restores all 3,902/4,793 tracked paths. Original run 35276260889 remains invalid as complete production analysis: four no-source failures and two zero-result SARIF files containing only diagnostic helper/workflow. All raw artifacts and original erroneous completeness flags are preserved. Separate published diagnostic `54c0ce882f83edb341e148d5eae2817bdf0c6451` has a zero-finding full-range scan and one [dispatch of run 35326220494](https://github.com/hashgraph-online/hol-guard/actions/runs/35326220494). The [initial queued readback](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-diagnostic-54c0/README.md) remains unchanged.

The [repaired hosted diagnostic](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/codeql-materialization-hosted-54c0/README.md) completed all six jobs at 08:59:28 UTC with full cdd/d8 source present, clean pinned trees and zero sparse/index/missing entries. cdd has Actions 2, JavaScript 0 and Python 23 raw findings; d8 has 2, 0 and 27. All six ZIP/SARIF identities and successful invocations are verified, with no warning/error notifications or external result files. All 54 supplied findings were reviewed against their source/sink witnesses and 84 exact immutable source blobs. The source assessments retain constrained config captures and the infeasible modeled dispatch/generic-config-reader branches; their scope is the provided paths, and no alert disposition or security-gate clearance follows. These 25/29 raw findings are distinct from the PR checks' eight/11 new-alert counts. CodeQL 2.27.0, Actions 0.6.35/JavaScript 2.4.5/Python 1.8.10 query packs, original cdd/d8 profiles, selection/exclusion and disabled security/database uploads remain unchanged. Rust source is materialized but is not analyzed by this three-language matrix.

The component test populations overlap earlier work. Separate [integration checks on exact combined source 623a6e](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/resume-623a-integration-validation/README.md) pass native authority (0.779 seconds), Python semantic boundary (0.197 seconds), I/O ownership (32.980 seconds), and all 82 workflow-permission tests (0.39 seconds pytest time; 4.279 seconds including lock/startup). All 3,291 tracked source/Rust/script/test/workflow files remain identical before and after. These fresh integration gates do not establish a new full-production type run or complete installed qualification.

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
receipt](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/remote-audit-config-validation/manifest.json), separate from the
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
The actual [9db Linux installed receipt](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/rust-performance/evidence/takeover-9db62e/perf-linux-installed-claude-launcher-pilot.json)
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
approval. The [combined d4e13547f validation](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/rust-performance/evidence/hosted-integration-d4e13547f.json)
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
[correction receipt](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/rust-performance/evidence/config-integrated-5da39f986.json) retains that failure
and adds six exact function/primitive classifications plus exact helper-path
protection. I/O remains visible as synchronous posture/config work. The existing
I/O/architecture suite passes 46 tests/99.32 seconds, including actual inventory
validation and negative cases; static checks and one contract type file pass
with zero errors/warnings, with finite independent review clear. Product source
is unchanged from 5da. These separate source gates are not an aggregate test
count, installed qualification or a clean external security gate.
Later source `591d5c81e6bb341c6c3271332f3a6615a01bc748` adds scoped capture and
propagation; it is not covered by that earlier inventory-only statement. Its
[retained validation](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/daemon-scoped-config-validation/manifest.json)
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
scan](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-prepared-d8bde000de99/receipt.json) has zero findings with
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

The [frozen cdd hosted receipt](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/foundation-cdd-ci-attempt/manifest.json),
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
[foundation](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/desktop-source-refresh-20260917/foundation-cdd/manifest.json)
and
[implementation](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/desktop-source-refresh-20260917/implementation-prepublication/manifest.json).
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
correction](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/daemon-worker-fixture-keywords/manifest.json) makes the two
existing startup/refresh doubles accept the explicit `config_reader` keyword. The
separate [maintenance fixture
correction](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/daemon-maintenance-fixture-reader/manifest.json) gives its
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
correction](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/native-default-auto-scope-admission/manifest.json), main commit
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
preparation](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/codeql-current-snapshot-diagnostic/manifest.json) fixes six
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
scan](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-prepared-3d11976aaf0e/receipt.json) reports zero findings
with pinned Gitleaks 8.24.2 in 9.634 seconds including lock acquisition, with unchanged
ignore input and no new suppression or alert disposition. The receipt records no
branch-ref movement; read the actual foundation PR head for later publication. This scan
does not clear cdd's external CodeQL failure or qualify the corrections on hosted
platforms.

The [earlier source validation](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/rust-performance/evidence/pilots-checkpoint/source-validation.json)
keeps its 147-test integration set, 42-file lint/format and 1,253-file type result
with 20,229 nonfatal warnings at that exact source. Later experiments and fixes
retain their own gates; they are not a combined full-suite pass. Latest
[9db hosted evidence](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/rust-performance/evidence/takeover-9db62e/manifest.json) records 107 passing
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

The [completed cdd hosted attempt](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/foundation-cdd-ci-attempt/FINAL.md)
retains all 25 terminal workflows (22 successful, three failed) and 178 check
attempts (145 successful, 22 skipped, 11 failed). Linux completed its original
100,000-request and 250,000-receipt soak naturally; its older foundation contract
does not establish strict implementation capacity conservation. The other three
platform failures remain recorded, and the artifact's hardcoded Windows waiver
is not accepted as proof. The earlier interim receipt remains unchanged.

Foundation [26cd4dff3f138990a8e9f6a729a970c1dbd90fa4](https://github.com/hashgraph-online/hol-guard/pull/2951)
is now published after that soak completed. Its [exact full-range secrets scan
and readback](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-foundation-26cd4/README.md) verify zero findings
with the unchanged ignore input and the tested local tree. Fresh hosted checks,
Greptile 5/5 and genuine independent last-push CODEOWNER approval remain required.
The cdd security failure and dismissed historical approvals remain separate.

The [later 26cd hosted checkpoint](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/foundation-26cd-ci-attempt/README.md)
proves 21/21 native-resident default-auto decisions on Windows and both Macs.
Windows native-wheel, Desktop and the four previously failing CI shards pass.
Both Macs then fail the separate Pi probe. Its [once-only root admission
correction](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/installed-pi-scope-admission/README.md) has 32 focused
passes per branch and retains the five-second deadline. Its focused type gate
still has three pre-existing errors and 158 warnings; every diagnostic matches
the archived original after accounting for filename and two inserted lines.

The same hosted fairness case accounts for 238 of 240 requests, with two Claude
RemoteDisconnected exceptions and no established cause. The [bounded client
phase diagnostic](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/evidence/daemon-acceptance-failure-stages/README.md) has
14 focused main passes and eight foundation passes while preserving retries,
deadlines and accounting. Its counters describe caught client exceptions and
do not prove server execution. This is diagnostic evidence, not a transport fix.
Sonar was skipped after the test failure, and external CodeQL still reports
eight high findings. Linux soak and Kilo remain incomplete at the frozen
21:09:39 UTC checkpoint; subsequent outcomes require separate evidence.

Foundation [a001b2691f481b7b5a66dd14d68e48d61c44cb78](https://github.com/hashgraph-online/hol-guard/pull/2951)
is published with [exact full-range secrets-scan and readback
evidence](https://github.com/hashgraph-online/hol-guard/blob/aeb04b6b06bd15ae2a2ecf00e8671c7501239278/docs/guard/security/gitleaks-foundation-a001b/README.md): zero findings,
unchanged ignore input and the validated local tree. The earlier implementation
source/evidence cutoff is `e7b8110732b15e8a215358c0ca237d9fd21231f8`. Its production Python/Rust trees equal
prepared d8; later probe/test/docs changes have separate receipts. All 144
original tasks, full dependency prose, thresholds and status counts remain
unchanged. Fresh installed qualification, security gates and independent
last-push review remain incomplete.
