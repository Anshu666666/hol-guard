# Persistent helper to resident diagnostics

This opt-in experiment supplies the missing RSP-085 component attribution. It does not select a persistent-session redesign, close RSP-086/087, qualify a release artifact, or change the frozen benchmark baseline. The workflow uses a separate wheel built with `diagnostic-native-client`; ordinary builds omit its clocks, thread-local state, diagnostic command and capability. No default registration or environment-selected binary is introduced.

## Exact execution boundary

The installed collector clears proof overrides, verifies imports against the installed wheel, requires the bundled runtime and exact build SHA, and commits the wheel, installed package, runtime, rule, dependency lock and collector-helper bytes. The workflow separately binds one of the four shipping distribution triples; the runtime retains its existing architecture/OS capability target. The public identity says `explicit_diagnostic_feature_wheel`, with production selection, normal-release measurement and qualification all false.

A contained isolated Python worker starts the existing `AdapterSession` with the normal synthetic configuration and protected empty local control authority. Its existing policy readiness budget remains 400 ms. It then offers 20 benign and 20 credential-fixture Claude PostToolUse requests through the installed `review_raw_hook_native`, each with the existing five-second request deadline. These are direct installed hook-edge calls: they do not measure launcher startup or daemon HTTP ingress, and do not substitute a Python semantic oracle.

A scripts-only module-local observer changes only the persistent helper command from `resident-client-stream` to `resident-client-stream-profile` and connects its previously discarded stderr to a bounded reader. The executable, state argument, production helper admission, standard input/output framing, environment and lifecycle ownership remain the existing ones. The diagnostic command calls the same Rust client-stream loop. The observer forwards the original request call exactly once, preserving its arguments, result and exception.

The Python request observer hashes the exact encoded bytes passed to that original call. Rust reuses the digest already calculated for the authenticated request frame; it does not add a payload hash. A completed observation requires one matching frame digest, the actual per-request `native_resident` route, the existing validated Rust edge and frozen benign/credential semantic outcome. Background publisher frames are retained separately and cannot supply a match for a different hook request. Neither a fabricated route nor a merely syntactically valid response counts as completion.

## Counters and phase boundaries

All durations are native monotonic elapsed time in nanoseconds. Repeated calls accumulate within one original client-stream request. The spans are inclusive and **must not be added together**.

| Field | Exact measured work | Limit |
| --- | --- | --- |
| `runtime_identity` | Existing `runtime_digest` calls in managed request admission/discovery | Includes the function's existing cache behavior; not isolated hashing |
| `discovery` | Existing `discover_home_states_prefer` call | No separate file-open or file-I/O accounting |
| `peer_validation` | Existing managed-state and connection owner/process checks | Nested inside `connect` for its connection checks |
| `connect` | Existing resident client connection function | Includes nested identity checks and endpoint work |
| `authentication` | Existing nonce and authenticated server-proof exchange | No changed proof, retry or timeout |
| `request_write` | Existing authenticated frame construction and write | Includes the already-required random ID and frame digest |
| `response_read` | Existing committed response read/verification | Includes resident queue/evaluation/transport waiting; evaluation is not isolated |
| `helper_request_nanoseconds` | Existing managed request body inside the client-stream loop | Excludes stream input framing, its initial lease, final stdout frame write and diagnostic stderr serialization |
| `socket_opened` | Successful Unix `socket()` returns or successful TCP connection returns on this path | Known opened count only; any failed `connect` makes socket accounting incomplete |

Missing phases remain null rather than zero durations. Counter/time overflow, absent total span, missing positive connect/authentication/write/read spans, failed mandatory spans, missing/duplicate request correlation, reader failure and unverified cleanup all make collection incomplete. The sampler does not measure kernel socket allocation on failed TCP connects, unrelated HTTP sockets, process-wide syscalls, CPU, RSS or full-hook latency. No failed-connect record claims complete socket accounting.

The instrumented build adds clocks, fixed record serialization, a stderr pipe reader, Python request hashing and durable journals. The report therefore has `headline_timing_eligible=false`; it provides component evidence and no subtraction-based prediction of a production port benefit. It does not measure a cold resident or a normal release artifact as a control.

## Evidence and failure retention

The plan is written before the worker starts. A successful collection contains five private files: `plan.json`, `attempts.jsonl`, `native-profiles.jsonl`, `worker-capture.json`, and `summary.json`. Offered/terminal records retain case, index, result status and exact matching helper/frame/edge digests. Every native frame observed by the script is retained, including background activity and failure records. Public statistics cover only completed validated observations and remain explicitly incomplete if any offer, correlation or cleanup fails.

Each journal is capped at 2,048 records, 4,096 bytes per record and 8 MiB, for at most 16 MiB across both. Each helper emits at most 1,024 native records; the observer admits at most 32 helper spawns and retains at most 1,024 decoded records in memory. The fixed workload has 40 offers; the CLI allows at most 200. These are diagnostic bounds, not changes to production limits.

An invalid native line retains its hash, observed length, an at-most-2,048-byte private prefix and an explicit truncation flag. The outer contained worker has a 180-second limit and a combined 256 KiB standard-stream capture limit. Its private captures explicitly identify UTF-8 decoding and re-encoding, retain bounded prefixes/digests and do not claim the original undecoded bytes. A lost/invalid worker summary leaves `completed=null` and `worker_summary_available=false`; already durable attempts stay available and are not relabeled as zero executed requests. Partial records are retained on failure.

Existing private evidence creation and encryption helpers remain unchanged. The workflow always attempts sealing and both uploads; a green experiment requires collector success, successful encryption, both artifact IDs, and verification of recipient, ciphertext size/hash and the five-file success minimum. Failed partial archives may upload but do not pass that gate. Public files contain only the closed summary and encryption receipt. Raw request data, paths, tokens, arbitrary error text and captures are excluded from the public projection.

## Selection and validation

The separate `Opt-in native client phase diagnostics` workflow runs only by explicit manual dispatch or the same-repository `rust-native-client-profile` pull-request label. It checks out the exact PR head and keeps every run/attempt in a noncancelling concurrency group. It builds and tests the feature on Linux x86_64 musl, macOS Intel, macOS ARM and Windows x86_64 MSVC, then executes the installed collector. The source tests and Rust filtered correctness tests do not substitute for those installed observations.

Local validation for this implementation: 77 focused Python tests pass; six scripts modules type-check with zero errors (241 dynamic/private-API warnings); five exact-module Rust tests pass under Rust 1.88.0 using retained dependencies. The standalone Rust command compiles only `native_client_profile.rs`, not the runtime crate. Rust call preservation and collector/workflow/retention received independent source review. Full feature integration/builds, installed Windows/macOS/Linux behavior, measurement results and any design decision remain pending the explicit CI experiment. No local performance workload was run.
