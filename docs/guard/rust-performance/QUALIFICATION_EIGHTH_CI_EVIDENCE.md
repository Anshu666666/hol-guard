# Eighth qualification run: indexed and nonpriority smoke evidence

[Run 35270080155](https://github.com/hashgraph-online/hol-guard/actions/runs/35270080155), attempt 1, finished with **15 successful, 10 failed and two skipped jobs**. Linux completed one indexed baseline/candidate smoke pair and its aggregate. Both Mac candidate blocks completed independently after their frozen baselines failed construction. Both Windows indexed arms failed, after different amounts of retained work. The separate nonpriority smoke completed Linux and Windows pairs; both Mac candidate arms completed while their baselines failed. **No full sampling or program qualification passed.**

This note freezes source `a933921372ddb3772eff8a9d86771fe15da063b1`, tree `3db430b618fe63cc1b85b8037e5de700cc3378c9`, and equal-tree merge `e54cf7732f61a6a7e609250a4e17344b5e92039d`. Every baseline remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`. This is the original eighth synchronize run with the explicit nonpriority smoke label. It does not pool seventh-run observations, the separate full scanner experiment, or later source fixes. The [manifest](evidence/qualification-a9339213/manifest.json) retains exact jobs, artifact/member commitments, observed identities, partial journals, failure projections and acceptance flags.

## Actual selection and platform mapping

All four immutable wheel builds passed. Four independent candidate settings-lifecycle scenario jobs also passed; these are separate from the side scenarios within each indexed block. The artifact-transition job and second nonpriority group were skipped. Indexed mode and nonpriority mode were both `smoke`: only global pair index 0, in baseline/candidate order, was offered per platform. Full five-pair qualification and the 320-job nonpriority plan were not selected.

| Platform | Indexed pair job | Indexed aggregate job | Outcome |
| --- | ---: | ---: | --- |
| Linux x86-64, `x86_64-unknown-linux-musl` | 105369060360 | 105374122466 | Both arms complete; smoke aggregate succeeds |
| macOS ARM64, `aarch64-apple-darwin` | 105369060326 | 105374122416 | Baseline fails; candidate completes; aggregate fails |
| macOS Intel, `x86_64-apple-darwin` | 105369060447 | 105374122381 | Baseline fails; candidate completes; aggregate fails |
| Windows x64, `x86_64-pc-windows-msvc` | 105369060346 | 105374122363 | Both arms fail; aggregate fails |

| Platform | Nonpriority pair job | Nonpriority aggregate job | Outcome |
| --- | ---: | ---: | --- |
| Linux x86-64 | 105369060749 | 105370343651 | Both arms complete; smoke aggregate succeeds |
| macOS ARM64 | 105369060751 | 105370343682 | Baseline fails; candidate completes; aggregate fails |
| macOS Intel | 105369060710 | 105370343636 | Baseline fails; candidate completes; aggregate fails |
| Windows x64 | 105369060705 | 105370343560 | Both arms complete; smoke aggregate succeeds |

The reusable nonpriority job names do not encode the platform. These mappings were checked against each original job's finalized artifact name and ID, then against the downloaded manifest target and aggregation context. All eight aggregate artifacts retained their reports; the corrected singleton download layout reached the intended evidence. An aggregate failure here is not a missing-directory inference.

## Indexed completion and partial work

| Platform / arm | Normalized preflight completed | Registered preflight validated | Final numeric aggregate | Block disposition |
| --- | ---: | ---: | --- | --- |
| Linux baseline | 386 | 62 | 136 observations / 38 series | Complete |
| Linux candidate | 386 | 62 | 136 observations / 38 series | Complete |
| ARM baseline | 0 | Not reached | Absent; header-only numeric journal | Constructor failure |
| ARM candidate | 386 | 62 | 136 observations / 38 series | Complete |
| Intel baseline | 0 | Not reached | Absent; header-only numeric journal | Constructor failure |
| Intel candidate | 386 | 62 | 136 observations / 38 series | Complete |
| Windows baseline | 386 | 62 | Absent; two validated journal values | Warm-up route failure |
| Windows candidate | 290 | Not reached | Absent; header-only numeric journal | Subsequent fixture readiness failure |

Four of eight indexed blocks produced complete aggregates, totaling 544 observations. The Windows baseline's two separately retained values are daemon startup and policy readiness, not completed headline timing or an additional block. Its normalized journal has 386 offered/completed pairs and its registered journal has 62 offered/validated pairs. The candidate has 290 offered/completed normalized pairs, ending at `copilot/copilotPermissionRequest/unavailable/small`; the next fixture fails before any further case offer. The remaining 96 declared normalized cases are unoffered. A header-only numeric journal means no numeric observations were retained, not zero CPU or zero latency. Preflight and side-scenario counts are never added to headline timing denominators.

The original Windows failures are `qualification_warmup_changed_semantic_route` at `native_slo_qualification_run._run_block:191` for baseline, and `qualification_fixture.native_installed_slo_failed:_native_policy_was_not_ready` at `native_slo_session.start:351` for candidate. Both report outer `timed_out=false` and `containment_failed=false`. The warm-up loop checks allowed delivery and the native route; it did not retain the particular failing warm-up harness/event or its response. Candidate readiness failure does not establish an HTTP timeout, authentication failure, or command-control cause. Earlier successful cases do not authorize either missing conclusion.

The frozen Windows baseline's declared source-reader refusal profile remains separate from content review. Its 386-case preflight completion must not be described as candidate-equivalent source-content semantics. Candidate Windows never produced a complete block or platform comparison in this run.

Linux's pair producer retains `comparison_available=false`; its later successful aggregate computes `comparison_available=true`. Those describe different stages. `sampling_passed`, `qualification_complete`, `program_qualification_complete`, migration benefit and all qualified-scope flags remain false. The other three platform aggregates preserve `pair_collection_incomplete` and no comparison.

## Load, resource and side-scenario failures remain visible

Each completed block includes closed-loop and offered-load diagnostics at concurrency 1, 4, 16 and 64. Completion of a block does not mean those gates passed. At offered-load concurrency 64, the exact retained counts are:

| Completed block | Offered attempts | Admitted | Completed | Failed | Generator dropped | Reported overloads |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Linux baseline | 1,280 | 239 | 239 | 0 | 1,041 | 105 |
| Linux candidate | 1,280 | 173 | 173 | 0 | 1,107 | 0 |
| ARM candidate | 1,280 | 502 | 179 | 323 | 778 | 23 |
| Intel candidate | 1,280 | 159 | 121 | 38 | 1,121 | 47 |

Here completed + failed + generator-dropped equals offered attempts. Overloads are an observed subset, not an extra term. All four concurrency-64 load contracts fail. Linux's concurrency-1 offered-load diagnostics pass, while its 4/16/64 diagnostics fail; both Mac candidates fail all four offered-load contracts. No failure or dropped attempt is silently removed from a tail denominator.

Darwin daemon CPU remains unavailable: both candidate reports retain `cpu_seconds=null`, `cpu_ms_per_attempt=null`, `cpu_includes_reaped_descendants=false` and `short_exited_descendants_cpu_complete=false`, including `darwin_reaped_cpu_ambiguous` and other observed missingness. Available memory measurements remain retained. Linux daemon resource reports contain observed CPU totals, but their 11 baseline and 10 candidate samples do not meet the unchanged 30-sample resource minimum. None of these smoke reports qualifies complete platform resource coverage.

Within all four completed indexed blocks, mixed contention, registered surfaces, approval continuation, malformed input and raw-UTF8 side scenarios remain failed. The candidate approval diagnostic is `qualification_Codex_browser_continuation_unproven`; baseline Linux reports resolution unproven. Input reports `priority_launcher_input_route_mismatch`. Candidate registered-surface failure maps to the exact source assertion `registered_surface_native_route_mismatch`; baseline Linux instead fails the frozen Copilot delivery projection at `unexpected:policy_action`. These are retained observations, not evidence that the new source corrections already fixed them.

Raw-UTF8 failure origin line 100 maps to `registered_utf8_registration_override` in the exact tested source. The two earlier observations remain private evidence; that registration interruption is distinct from the runner's deliberately unqualified raw-UTF8 end state. Candidate Python phase diagnostics each validated eight requests on Linux and both Macs. Their inclusive and missing/truncated phase limits remain intact; baseline Linux's phase attempt fails fixture cleanup. Mixed reports retain failed binding/evidence/receipt/resource checks even where their exception-count map is empty. None is converted to a pass by successful block collection or by the separate installed settings scenarios.

## Nonpriority smoke: one route, twelve of sixteen timed observations

The fixed route is `cursor.beforeShellExecution.global`, case `cursor.beforeShellExecution.benign.small`, concurrency 1. Each successful arm performs separate benign/block semantic preflight and then two timed benign invocations through the actual registered argv. Native `allow`, native policy `allow`, delivered `allow`, stdout and exit 0 are checked separately. Process startup is included; full vendor-host activation and resident cold are not measured.

| Platform / arm | Timed observations | Descriptive median / maximum ms |
| --- | ---: | --- |
| Linux baseline | 2 | 298.021 / 302.940 |
| Linux candidate | 2 | 303.811 / 304.668 |
| Windows baseline | 2 | 375.034 / 381.115 |
| Windows candidate | 2 | 385.720 / 393.061 |
| ARM baseline | 0 offered | Unavailable |
| ARM candidate | 2 | 246.307 / 249.210 |
| Intel baseline | 0 offered | Unavailable |
| Intel candidate | 2 | 1,022.646 / 1,130.761 |

Six completed arms preserve 24 validated invocations: twelve separate preflight invocations and twelve timed observations. The Mac baseline constructor failures occurred before any registered invocation or numeric offer; four of the sixteen planned timed observations remain unoffered. All eight arm offers remain in the pair manifests, and contained baseline failure did not prevent candidate execution. There is no comparison for either failed Mac pair. The Linux and Windows aggregates have collection/comparison evidence, while `tail_sampling_qualified`, `ordinary_c1_scope_qualified` and whole-program qualification remain false. The values above are descriptive n=2 results, not qualified p95/p99 estimates or proof of benefit. The unchanged nonpriority minimum is 1,000 observations across five independent pairs; priority remains 10,000. Neither was approached by this smoke selection.

## Mac construction and resolver experiment

Both indexed baselines and both tail baselines retain the original `construct_daemon` failure stack through `socket.getfqdn` and `HTTPServer.server_bind`. Tail diagnoses were recovered from authenticated worker-stdout files; the public tail wrapper only reported `worker_failed`. Candidate numeric binding bypasses that reverse lookup, but does not repair or modify the frozen baseline artifact.

For all four Mac jobs, temporary resolver configuration installation and file cleanup completed, exact registration was observed after installation, and the separate UDP PTR self-test returned its expected answer. The ordinary resolver probes still exceeded their five-second deadlines; the responder observed zero ordinary traffic. No resolver selection/cache cause is established. The post-cleanup registration was absent in both indexed jobs and in the Intel tail job, but remained present in the ARM tail snapshot. Successful file cleanup does not prove immediate resolver-registration retirement. Original constructor/readiness budgets, artifact bytes and failed outcomes are unchanged; no successful environment repair is claimed.

## Identity and custody

All sixteen downloaded indexed/tail pair and aggregate ZIPs independently match the Actions API SHA-256 and byte count: **8,991,394 ZIP bytes / 78 members**. All eight inner ciphertexts also match their receipts. Recovery authenticates every ciphertext and its 129 private members; the authenticated archive context is independently reconstructed and matched to the receipt. The private pair manifest equals the public one, and every completed raw numeric aggregate's exact bytes, SHA-256, series counts and journal conservation match its public commitment. Partial and failed journals are retained separately. No private command, source body, raw resolver configuration or recovery key is published.

The manifest preserves all ZIP/member hashes, cipher receipts and recovered member commitments. Completed report runtime identities must match the expected arm SHA; package origin is `installed`, native mode `auto`, and package/runtime versions remain the observed `3.0.1`. Candidate wheel and runtime digests match the same-run immutable build identities also observed by the successful candidate settings scenarios. Failed-arm wheel/context commitments are identified as such, not invented successful runtime observations. Common workload and per-arm semantic-scope digests remain distinct. Same-run pairs share their runner; these four platforms, independent tail jobs and prior attempts are not pooled into a synthetic cohort.

This evidence note changes no source behavior, task status, original acceptance, threshold or dependency. Full five-run sampling, unsupported/missing resource scope, failed load and side scenarios, cross-platform comparison and overall release qualification remain separate requirements.
