# Nonpriority installed-command tail companion

This companion implements the original PRD §5 minimum of **1,000 warm observations for each remaining installed route**. It does not reduce the separate 10,000-observation priority minimum. Source tests establish orchestration and evidence contracts; no installed observation or performance result is claimed by this document.

Each series identifies one actual generated command registration, event alias, registration scope and frozen workload. The published workload also commits its case, size and native result profile. Commands come from the shipped installer followed by exact registration readback. The timer starts immediately before child creation and ends after bounded stdin/stdout/stderr processing and process exit. Registration checks, semantic/native witnesses, durable evidence writes and environment preparation occur outside that timer.

| Registrations | Independent slots | Timed workload |
| --- | ---: | --- |
| Cursor beforeShellExecution | 1 | Small benign shell command |
| Cursor beforeMCPExecution, beforeReadFile, beforeWriteFile | 3 | Small intrinsic review response, kept separate from ordinary allow targets |
| Cursor afterShellExecution, afterMCPExecution | 2 | 1 KiB benign output; delivered hooks are observation-only |
| Copilot preToolUse/postToolUse, global and project | 4 | Small benign pre-tool / 1 KiB benign post-tool; scopes and aliases remain separate |
| Kimi PreToolUse/PostToolUse | 2 | Small benign pre-tool / 1 KiB benign post-tool |
| Grok PreToolUse | 1 | Small benign pre-tool |
| ZCode PreToolUse | 1 | Small benign Bash match; other registered matchers remain unmeasured |
| Cline PreToolUse/PostToolUse | 2 | Small benign pre-tool / 1 KiB benign post-tool; post delivery is observation-only |

The finite `other00`–`other15` numeric keys map to this ordered inventory in `native_slo_surface_tail_contract.py`. They fit the existing public field limit. Keys do not combine routes: the exact registration, case, size and result class remain committed in the per-pair workload. No normalizer-only alias, permission event, preflight surface, Pi/OMP callback, Hermes/OpenCode/OpenClaw host plugin or unavailable post hook is promoted into this command-registration inventory.

Before any timing offer, the worker executes every selected frozen small normal semantic vector for that registration. It then offers exactly 200 observations of its one declared ordinary or intrinsic-review vector. Each observation verifies actual stdout and exit, unchanged registration, exactly one native-resident route increment, effective setup, and the independent native-result oracle. No semantic failures count toward the 200. All offered observations and interrupted batches remain in private journals; missing observations are not replaced by retries. There is no tool execution or invented browser-approval success.

The immutable Windows ZCode registration is presently unsupported because its shell comment is not proven valid for the host command parser. It remains an explicit failed slot; the reader does not strip the marker to invent a working registration. Cline uses the production default `.hol-guard` layout inside the fixture's private home. The frozen production baseline's Copilot delivery-schema failure remains a failure if observed. After a failed arm is contained, its peer is independently attempted; a containment failure prevents unsafe continuation.

## Collection and capacity

Full collection is **16 routes × 4 platforms × 5 pair indices = 320 collection jobs**, plus four platform aggregation jobs. Two fixed matrices contain 160 entries apiece, below GitHub's [256-entry matrix limit](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#jobsjob_idstrategymatrix). Each job owns one route and one index. Global order is baseline/candidate at indices 0, 2 and 4, and candidate/baseline at 1 and 3. Both artifacts run on the same runner within each pair. Exact artifacts, dependency inventory, Python version, CPU model/count, effective CPU count, RAM, OS and runner image must remain consistent across all five pairs; heterogeneous cohorts are rejected rather than pooled.

The companion reuses the main qualification run's immutable wheel and locked-dependency bundle. It does not rebuild wheels or install checkout code in the measured arms. A separate locked controller prepares two external wheel-only environments using the existing verified private-interpreter setup. Bundle hashes and actual worker runtime/package/dependency identities must match. The disposable macOS resolver conditioning wrapper applies equally to both arms and preserves its bounded evidence; no frozen baseline source or artifact is patched.

The original priority pair receives **no extra samples or private files**. Each companion worker keeps its own 60-minute outer containment limit. Two workers fit the 125-minute collection step. The reusable job's explicit step maxima are 5 + 5 + 5 + 5 + 20 + 125 + 15 + 10 = **190 minutes inside a 200-minute job**. Encryption and upload always run, with 25 minutes reserved after collection. The existing per-launch process limit remains 10 seconds. Its arithmetic ceiling for 200 child invocations is 33 minutes 20 seconds per arm, before setup, preflight, witnesses and evidence I/O. Those costs are subject to the unchanged worker limit; completion at worst-case delays is not asserted.

A full plan offers 128,000 timed child invocations, plus at most 1,160 separate semantic preflight invocations. The 320 jobs have a **64,000 runner-minute aggregate job-limit reservation**, not a measured runtime or spend estimate. This is why full collection is explicit opt-in. No latency estimate is inferred from the earlier two-observation diagnostic.

For each arm, the numeric journal has at most 204 records for one 200-value batch; its existing 4 KiB record cap gives less than 836 KiB. The semantic journal has at most 404 records under its existing 1 KiB record cap. Final numeric JSON remains bounded to 64 KiB. A failed worker's bounded stdout is retained only in a private JSON diagnostic; even worst-case JSON escaping of the 256 KiB child-output cap stays below 2 MiB. Two arms, one 64 KiB manifest, and the existing three bounded resolver captures stay below a conservative **10 MiB and 12 private files per companion archive**. The shared 32 MiB per-file, 128 MiB total and 256-file archive limits are unchanged. No records are dropped to satisfy them.

## Evidence and conclusions

Offer records commit the exact context and workload before each arm starts. A successful block must pass a closed public-field schema and exact count/summary checks before any public success file is written. Numeric commitments hash the same bounded byte snapshot that was decoded and validated. Encryption rechecks those exact numeric bytes in the immutable snapshot being sealed. Its authenticated context binds the bundle and the exact companion manifest digest; the manifest commits route, case, size, result profile, sample plan, order, all arm states and raw numeric identities. Substituted routes, changed raw files, failed or unattempted arms, missing indices, missing encryption receipts and unexpected artifact roots prevent a complete comparison.

The estimator remains the shared empirical nearest-rank percentile/bootstrap summary and paired run-level ratio bootstrap. Each route has its own five matched blocks; samples, unlike results and registration scopes are not pooled. Reports separate:

- `collection_complete`: all paired observations and encrypted commitments were retained and validated.
- `tail_sampling_qualified`: five exact pairs provide the original 1,000 observations per arm for the declared route and workload.
- `ordinary_c1_target_applicable` and `ordinary_c1_target_passed`: the existing p95 ≤50 ms and p99 ≤100 ms targets apply to ordinary noninteractive vectors. The three intrinsic-review Cursor vectors do not receive a passing ordinary target by default.
- `ordinary_c1_scope_qualified`: the ordinary target and minimum both pass for this narrow workload. A completed review-response collection may finish as sampling-only evidence.
- `qualification_complete` and `program_qualification_complete`: remain false. This companion does not qualify c16, offered load, other sizes, source references, Watch/faults, approval lifecycle, cold residents, process-tree resources or vendor host activation.

## Deliberate selection

Ordinary PR smoke and scheduled qualification do not run this companion. On a same-repository PR, the explicit `rust-nonpriority-tail-smoke` label selects only `cursor.beforeShellExecution.global`: four platforms, pair index zero, baseline then candidate, and two timed benign observations per arm after separate benign/block semantic preflight. That is four collection jobs plus four aggregators, with 16 timed and 16 preflight registered invocations if every arm completes. No full vendor host activation or performance qualification follows.

The companion's resolved `tails_mode` is independent of the main priority plan. Job names, worker reports, manifests, encrypted context and aggregation retain `smoke`; the full 1,000-observation gate cannot pass. The smoke label takes precedence even if both full labels coexist. Remove the smoke label before selecting full companion collection. Existing priority qualification selection is unchanged: a separately present `rust-performance-qualification` label still controls that main plan. The smoke label alone does not enable it. Fork labels do not authorize companion work, and unrelated labels or scheduled runs do not enable it.

Without the smoke label, both `rust-performance-qualification` and `rust-nonpriority-tails` labels on a same-repository PR select the existing full plan. Manual workflow dispatch remains independent of PR labels and defaults `nonpriority_route` to `none`. Set one exact route ID with `mode=smoke` for a four-platform, two-observation-per-arm diagnostic; smoke rejects `all`. Set `mode=qualification` with one route for its five-pair collection, or `all` for the full 320-job plan. Run targeted route smoke and inspect its independent semantic/delivery/containment result before deliberately selecting the expensive full plan. No worker, process, archive or job limits change for label-selected smoke.
