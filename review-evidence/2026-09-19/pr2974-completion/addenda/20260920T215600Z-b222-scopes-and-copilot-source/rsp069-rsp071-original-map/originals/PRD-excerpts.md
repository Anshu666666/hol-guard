## 5. Benchmark specification

Use four named timing boundaries and record which one every result measures:

1. KERNEL: in-process Rust evaluation, excluding transport.

2. NATIVE_CLIENT: authenticated client request through the resident response.

3. DAEMON_INGRESS: authenticated HTTP hook ingress through the serialized harness response.

4. INSTALLED_LAUNCHER: harness starts its installed hook executable through final stdout, exit status, or documented continuation result.



Measure cold process start, warm steady state, resident recovery, and full daemon startup separately. Human approval wait, remote-service wait, disk read time, and CPU evaluation time require separate attribution. Never subtract them silently from a user-visible result.



Required fixtures cover allowed, blocked, review-required, Watch, unavailable, malformed, expired-policy, integrity-failure, empty-output, output-reference, and oversized inputs. Allowed and blocked corpus decisions must be checked, not merely timed. Capacity results are separate from successful decisions; native-unavailable continuation must not masquerade as an evaluated allow.



Use synthetic source and commands. Keep command text, paths, secrets, raw outputs, tokens, and prompts out of exported artifacts. Aggregate dimensions may include platform, artifact digest, source commit, harness, event, size class, engine route, mode, result class, and bounded reason code.



Test 1 KiB, 16 KiB, 256 KiB, 1 MiB, and maximum supported input sizes. Preserve exact byte versus Unicode-character rules. Test concurrency 1, 4, 16, and 64, with both closed-loop latency and an arrival-rate load test. Report queueing and rejected admission so saturation cannot improve apparent latency by excluding failures.



Performance qualification must use release builds and installed artifacts on declared Linux x64, macOS x64, macOS arm64, and Windows x64 hardware. Record CPU model, core count, RAM, power mode, OS, interpreter/compiler version, build flags, package version, native digest, corpus digest, and background load. Compare baseline and candidate on the same host with alternating order. Keep raw synthetic observations privately available for reproducibility; publish bounded aggregate evidence.



Minimum qualification workload: 10,000 timed warm decisions per priority route and platform across at least five independent runs; 100 cold starts per priority launcher; 100 recoveries; 30 steady-state resource samples. Use at least 1,000 warm samples for remaining installed routes. Report sample counts and confidence intervals with a documented percentile estimator. A route without enough samples is unqualified for a tail claim. Do not pool unlike routes to hide a slow harness.



Use an explicit baseline artifact from current production and an optimized-Python baseline for new Python-to-Rust kernels. The Python semantic oracle is for parity and selected historical comparison, not the sole performance baseline. A 30% improvement means candidate p95 ≤0.70 × baseline p95. A 1.30× throughput increase and a 30% latency reduction are different quantities.



## 6. Proposed acceptance targets

These targets are intentionally distinct from current gates. Baseline work must confirm their applicability to the declared hardware and corpus before implementation is selected; do not quietly loosen a committed threshold to get green CI.



For 1–16 KiB ordinary, noninteractive hooks:

Installed launcher, warm at c1: p95 ≤50 ms and p99 ≤100 ms.

Installed launcher, c16: p99 ≤200 ms, zero request errors, and correct expected decisions.

Native client, warm at c1: p95 ≤20 ms as an absolute target after repairing the benchmark.

Cold native hook process: p95 ≤150 ms. Report full daemon startup and resident readiness separately; retain the current 400 ms readiness ceiling until a stricter target is evidenced. This preserves the adapter-first-request readiness boundary, which starts after snapshot fixture materialization. Measure full policy-ready daemon startup separately.

Selected hot-path tranche: at least 30% lower p95 or 30% lower process-tree CPU per request, with no more than 5% regression in the other primary metric. If the baseline already meets product targets and the predicted benefit is small, defer a large migration.

Optional native ingress tranche: at least 25% lower steady-state process-tree private memory or 30% lower p99 at c16, without weaker fault containment or decision behavior.



For package and offline kernels:

Compare 100, 1,000, and 10,000 dependency fixtures with independently varied advisory-bundle sizes.

Rust must beat optimized Python by at least 30% in end-to-end local evaluation p95 or CPU, including serialization and startup amortization. A fast microbenchmark with slower package-protect execution does not pass.

Preserve bounded memory and exact coverage/completeness status; no dropped dependency or finding can count as a performance improvement.

For repository secrets, qualify small and large file counts, cold and warm filesystem cache, staged-only runs, and many-small-file versus few-large-file workloads. Record both bytes/sec and full CLI wall time.



At c64, bounded overload is acceptable according to the existing admission contract. No hangs, unbounded allocation, deadlocks, leaked children, or cross-request replies are acceptable. Retain the installed short-load observed RSS growth gate of 12% and the separate long-soak growth gate of 50%; report their sampling boundaries. Additionally measure the full daemon/helper/resident process tree independently of the benchmark client. Do not replace process-tree growth with a single-process RSS claim.




## 10. Workstream D: offline secrets and scanner kernels

Existing integration points: guard/secrets/cli.py, secret_repository_scanner.py, secret_staged_scanner.py, secret_detection.py, scanner.py, and existing Rust scanner/secure-filesystem crates.



Proposed component: a dedicated offline-scanner module or crate sharing proven primitives where semantics match.



Requirements:

D1. Produce a detector capability matrix. Include provider rules, entropy, suppression, contextual signals, paths, line/column positions, severity, evidence identity, and redaction/HMAC.

D2. Preserve scan schemas, exit statuses, finding order/deduplication, include/exclude semantics, encoding treatment, ignore rules, and staged-content behavior.

D3. Batch files and amortize native startup. Keep bounded queues and maximum bytes per file/job. Track truncated or skipped coverage explicitly.

D4. Preserve the source identity contract and handle symlinks, changing files, unreadable files, hard links, nonregular files, Unicode names, and platform path semantics.

D5. Use bytes or bounded owned data across the language boundary. Do not cross once per regex or finding.

D6. Before a detector port, batch Git object reads. Current staged/history helpers launch git cat-file size and blob subprocesses per object. Deduplicate scanning of identical objects while preserving each path/commit occurrence and coverage counters. Preserve staged-index bytes when the working tree differs.

D7. Retain current secrets CLI exit behavior: incomplete/error 2, findings with --fail-on-findings 3, and a complete accepted scan 0. Current default scan bounds are 5,000 files, 2 MiB/file, 128 MiB total, 500 findings, and 500 commits. These are defaults, not a license to change explicit user bounds.

D8. For archive/plugin scans, bound entry count, uncompressed bytes, nesting, decode expansion, and time. Never execute or extract untrusted package content just to benchmark it.

D9. Keep hostile archive inspection in its dedicated isolated worker. Preserve no-network/read-only containment, immutable archive digest and file identity, expansion checks, and launch binding. Do not move hostile archive parsing into the resident hook process just to amortize startup.

D10. Third-party scanner output and network intelligence remain distinct evidence. A native lexical scanner cannot silently replace those capabilities.

D11. Accept a Rust implementation only after the richer Python semantics pass parity and the full command beats its optimized baseline.



