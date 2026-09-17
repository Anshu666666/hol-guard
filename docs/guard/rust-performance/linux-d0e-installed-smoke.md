# Linux installed smoke evidence at d0e

[Native-wheel job 105243299147](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473553/job/105243299147)
completed its installed adapter SLO step and enforced soak on 2026-09-17.
The source head was `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`.
Artifact `10503583745` has ZIP SHA-256
`11b1399d4bd15464a522a7aa13eb1d5d570a7085fd2395be309acfc121234374`.
[The finite projection](linux-d0e-installed-smoke.json) retains the original
SLO, soak, installed-identity and artifact-evidence member sizes and hashes,
plus bounded identities and measurements. It contains no fixture paths,
commands, source contents or credentials.

The SLO report is explicitly `smoke`, with `qualification_complete=false`.
All 14 of its declared gates passed. Its installed route corpus witnessed 21
routes across 13 harnesses, all resident. The 42 warm observations had p95
35.372 ms and maximum 44.686 ms. Those observations passed this report's
1,000 ms daemon-adapter ceiling; they do not establish the separate 20 ms
direct-runtime target or the installed-priority tail qualification.

The concurrency records conserve complete waves, without per-request engine
attribution. At concurrency 16, all 16 responses matched 16 resident decisions
with no errors. At concurrency 64, the wave recorded 53 resident decisions and
11 explicit overloads that bypassed the engine, with no errors. The original
`per_request_native_route_proven=false` flag is retained.

The separate legacy soak completed 100,000 requests and 100,000 responses with
250,000 committed fixture receipts, zero errors, and 20,128 health checks with
zero failures. It recorded one stable daemon, p95 495.90 ms and maximum
583.38 ms under its unchanged 4,500 ms maximum-latency ceiling. Sampled RSS
rose 5.5121%; maxima were 71 threads and 202 file descriptors. These are the
legacy soak's workload and gates, not the 50 ms installed-priority target.

The archive proves this run's scoped outcomes. It does not establish why an
earlier installed warmup failed, and it does not replace the separate failed
paired-qualification evidence from run `35233473603`, attempt 2. No production
performance change is inferred from this successful smoke run alone.
