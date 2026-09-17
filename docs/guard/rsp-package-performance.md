# Package evaluation: algorithm and storage baseline

This work implements the Python prerequisite for RSP-049 through RSP-054 before selecting a Rust package parser. The implementation starts from `2e672d2d950c6ec471005ddba46e49bba16dc23b` and is intended for integration into `release/3.2`. A native package crate is not activated by this change.

## Production consumers and measurement boundary

| Surface | Entry into the shared evaluator | Work outside the measured local route |
| --- | --- | --- |
| `hol-guard protect` and package manager shims | `guard/protect.py` → `local_supply_chain.build_package_protect_payload` → `_build_package_protect_authority` → `evaluate_package_request_artifact` | CLI/interpreter launch, approval, final authority revalidation, package manager execution |
| Workspace audit and package explain | `local_supply_chain.build_workspace_audit_payload` / `build_supply_chain_explain_payload` → `evaluate_package_request_artifact` | Workspace inventory construction, SBOM collection, rendering |
| Daemon package audit | `daemon/server.py::_run_supply_chain_package_action` → `build_workspace_audit_payload` | HTTP ingress, scheduling, response serialization |
| Managed package audit | `runtime/command_executors.py` operation `guard.packageShims.audit` → `build_workspace_audit_payload` | Managed command transport and dispatch |
| Audit CLI | `guard/cli/commands_dispatch_cloud.py` → `build_workspace_audit_payload` | CLI setup and presentation |
| MCP package calls | `guard/proxy/runtime_mcp.py` package evaluation path → `evaluate_package_request_artifact` | Persistent proxy transport, server processing, human approval |

The full local benchmark calls the production `evaluate_package_request_artifact` entrypoint. It includes workspace reads, complete lockfile parsing, signed-bundle cache loading and model construction, local policy/result composition, evaluation cache writes, and SQLite evidence persistence. Signing fixture bundles, initializing the synthetic store, and clearing the evaluation cache occur outside the measured interval. The store is disconnected and contains only generated package names. Its workspace-ID accessor returns the synthetic fixture identity. Unexpected network connections fail the harness.

The unversioned case measures `evaluate_cached_supply_chain_bundle` over a batch of dependency names. It is a separate kernel diagnostic. Production lockfile evaluation resolves exact versions before calling that function, so its timings must not be represented as installed package-protect latency.

## Changes and invariants

**Immutable bundle indexes.** Each parsed `SupplyChainBundle` owns read-only exact identity, versionless name, highest-risk, emergency deny, and signed-order indexes. Ingestion still rejects conflicting canonical duplicates. Indexed lookup retains ecosystem normalization, namespaces, literal version comparison, highest-risk selection for an unversioned lookup, first-in-bundle tie-breaking, and emergency deny precedence. Freshness remains a per-evaluation check, including stale high-confidence and emergency denies. The index is derived data; its existence conveys no signature or trust authority. The signed payload, verification flow, and stored bundle format are unchanged.

The direct target, transitive lockfile, recommended-fix, and version-list helpers share these indexes. An exact lookup with a specified ecosystem does not traverse the bundle. Calls without an ecosystem inspect the distinct ecosystem keys and preserve signed order.

**One structured decode.** JSON, JSONC and TOML validation now hands its parsed document to the production extractor. No second JSON/TOML decode is needed to obtain dependency entries. Immutable direct-version candidates retain Python name normalization and declaration order without retaining a mutable parse tree. The manifest target resolver uses the complete parse result and preserves npm's legacy empty-packages fallback as an explicit projection. Text lockfile selectors retain their existing projection over captured text; this change does not introduce a new YAML or Yarn grammar.

The existing completeness fields, `complete-v1` parser identity, duplicate-key rejection, invalid UTF-8 behavior, 8 MiB/100,000-entry/250,000-node/depth-128 limits, and scaled 0.5 to 1.5 second parser deadline remain. Every emitted dependency view now shares the 100,000-entry limit, including npm's legacy manifest projection and ordered Python version candidates. `bun.lockb` retains its explicit unsupported binary fallback. Failure never publishes partial parsed entries as complete.

**One input snapshot per evaluation.** Path resolution and existence checks capture metadata only. Content is read lazily when a consumer needs it; skipped binary lockfiles are not read merely to establish their existence. Aliases resolving to the same contained path share the same bytes. Parsing, manifest-derived targets, cloud lockfile context and content fingerprints therefore describe identical input. Lockfile hashes use the exact bytes, including CRLF line endings. A nested evaluation gets a new snapshot, and all capture state is discarded at the end of the evaluation. No filename, mtime, size or periodic cache survives into another evaluation. Final launch revalidation continues outside this snapshot and must independently compare current execution authority and content.

RSP-020 did not specify an aggregate content budget. This implementation selects a **new 128 MiB maximum of retained input bytes per evaluation**, with at most 8 MiB retained for one input. These are byte-content admission limits, not a claim that total process RSS is capped at 128 MiB: parsed objects, bundle indexes and result objects also consume memory. An alias does not consume the budget again. Reaching the limit exactly is allowed; the next nonempty input that cannot fit pauses the entire evaluation. A manifest admission failure is handled like a lockfile failure, so no missing targets are silently omitted.

The reader processes 64 KiB chunks and checks a separate 1.5 second elapsed read/hash budget before and after each read. For an oversized input, it discards retained content and streams the remaining bytes solely to establish the exact source identity. This uses the existing HMAC-SHA512 domain key and 64-hex-character truncation; chunking does not change the digest. The deadline is cooperative and cannot interrupt a filesystem read already blocked in the operating system.

| Admission outcome | Evidence contract | Evaluation behavior |
| --- | --- | --- |
| Input exceeds 8 MiB; full source hash completes | `lockfileParseError=byte_limit_exceeded`, exact `lockfileHash`, `inputBytesObserved`, `inputRetainedByteLimit` | Whole evaluation is incomplete; existing security-level handling asks for reapproval or blocks |
| Input cannot fit the remaining aggregate budget; full source hash completes | `lockfileParseError=resource_limit_exceeded`, exact `lockfileHash`, observed bytes and effective remaining input limit | Whole evaluation is incomplete; no targets or evidence are silently truncated |
| Read/hash budget expires before an exact identity is available | `lockfileParseError=deadline_exceeded`, `lockfileHashComplete=false`, `source_hash_unavailable` warning, observed bytes and effective retained limit | Blocks at every security level; the hash placeholder is never valid approval identity |

The incomplete result records the effective per-input retained limit as `min(8 MiB, 128 MiB - already retained bytes)`. The source hash is complete only after end of file is reached. Parser deadlines and parser completeness continue to apply after successful content admission.

**One evidence transaction.** Profiling the indexed implementation exposed a separate cost: `_persist_evidence` called `add_evidence` once per package, opening a SQLite connection and committing every record. Package evidence now goes through `add_evidence_batch` with one connection and transaction. Record fields, filtering, JSON details, evidence IDs and replace-by-ID behavior are preserved. A serialization or database error rolls back the whole batch, including earlier replacements. The caller receives the error; storage failure does not rerun a decision or launch a package manager. This intentionally strengthens the former partial-write behavior into an atomic evaluation batch.

## Reproducing measurements

Use the same checked-in harness with baseline and candidate source trees, the same locked Python environment, and alternating order. Run on an otherwise idle, declared host. In this shared workspace, benchmark owners coordinate using `performance-measurement.lock`; the lock alone does not eliminate unrelated host contention.

```bash
uv sync --frozen --extra dev --python 3.12
.venv/bin/python scripts/bench_guard_package_local.py \
  --source-root /path/to/baseline \
  --dependencies 1000 --bundle-size 1000 --mode exact \
  --samples 5 --output /path/to/baseline.json
.venv/bin/python scripts/bench_guard_package_local.py \
  --source-root /path/to/candidate \
  --dependencies 1000 --bundle-size 1000 --mode exact \
  --samples 5 --output /path/to/candidate.json
```

Vary dependencies and bundle records independently over 100, 1,000 and 10,000. Cover `absent`, `exact`, `deny` and the separately labeled `unversioned` kernel. The harness validates result decisions and cardinality and publishes semantic and corpus hashes alongside wall/CPU observations. Compare both hashes before interpreting a speed difference. It explicitly clears the evaluation cache before every sample: changing `PackageIntent.notes` does **not** change the request identity and is insufficient to prevent a cache hit.

Raw synthetic observations belong with the benchmark artifact. Record source commit, source diff digest, script digest, Python version, CPU/OS, memory, background load and timeout scope. A censored process timeout is not an observed local-route latency. A single sample or five samples cannot support a reliable p95 or p99 claim.

## Observed source-route results

The [bounded aggregate evidence](performance/rsp-package-source-evidence.json) compares audited Python `2e672d2d950c6ec471005ddba46e49bba16dc23b` with corrected source `640b47ae52dea98ad2d4f5dbfc36b86e91800d83`. All final candidate observations ran with that source tree clean. The interpreter was locked CPython 3.12.14 on the same Linux x64 container, exposing nine logical CPUs, an Intel Xeon Platinum 8370C processor and approximately 23.1 GB RAM. Power mode was unavailable. The report includes host load, harness digests, corpus hashes and output hashes.

For the full local exact-match route with 1,000 dependencies and 1,000 bundle records, five independent baseline/candidate process pairs ran in alternating order:

| Observation | Current Python | Optimized Python |
| --- | ---: | ---: |
| Median evaluator process CPU | 6,812.31 ms | 121.57 ms |
| CPU observation range | 6,525.44–11,354.47 ms | 116.68–224.32 ms |
| Median full local wall time | 6,814.46 ms | 121.61 ms |
| Wall observation range | 6,528.28–11,389.11 ms | 116.60–224.38 ms |
| Independent observations | 5 | 5 |

The combined Python changes reduced observed median CPU and wall time by 98.22% in this synthetic comparison. Corpus and semantic output hashes matched. These values describe the uncached local evaluator boundary, not CLI startup, installed shim latency or a Rust improvement. The wide ranges show why these observations do not establish release p95/p99 or a confidence interval.

The dependency/bundle matrix contains all 36 combinations of 100, 1,000 and 10,000 dependencies, independently varied bundle sizes, and four match modes. Every corrected candidate case completed. The earlier baseline matrix completed 23 cases and hit its 20 second whole-process budget in 13 cases; those records remain censored and have no invented evaluator latency. The 23 comparable matrix outputs have matching corpus and semantic hashes. Final candidate matrix observations were rerun after the review fixes, so those matrix comparisons are not adjacent alternating pairs; only the separate five-pair experiment has that property. The artifact identifies the unversioned cases as a separate cached-bundle API diagnostic.

An additional profile of corrected source at 1,000 × 1,000 exact matches records one complete lockfile parse, one bounded source read, and one evidence batch. In that instrumented run, parsing accounts for 5.2% of evaluator cumulative time, bundle evaluation for 24.7%, and evidence persistence for 29.0%. These nested profile fractions include profiler overhead and must not be added as independent components. The earlier indexed-but-unbatched profile showed 1,001 single-record evidence writes consuming approximately 97% of its instrumented evaluator time; this motivated the atomic transaction change. Neither profile is a native performance comparison.

## Validation and conditional Rust decision

Focused tests cover immutable indexes and generation replacement, canonical duplicate rejection, cross-ecosystem order, unversioned highest-risk selection, stale/emergency decisions, one decoder per structured format, malformed and bounded lockfiles, entry bounds for every emitted view, snapshot replacement/deletion/path aliases/containment, skipped binary inputs without content reads, per-input and multi-input admission boundaries, exact-byte hash agreement across the production evaluator and context, chunked digest equivalence, hash-unavailable blocking, identical evidence rows, replay replacement, and rollback on serialization or SQLite failure.

The current execution environment reproduces three existing `test_guard_manifest_install_firewall.py` receipt-storage assertions at the untouched baseline, with the package evaluator replaced by a test stub. These are not evidence of successful installed qualification. The integration owner must resolve or qualify that native receipt environment before claiming package-protect release acceptance.

One broader test command was stopped by automatic approval review when a legacy fixture attempted HTTPS to `hol.org`. That network-enabled batch is not counted as successful verification and was not retried. The safer follow-on uses the opt-in `tests.package_offline` plugin, which permits existing synthetic HTTP fixtures only at the literal loopback addresses `127.0.0.1` and `::1`. It prohibits every other destination through `socket.create_connection`, `socket.connect` and `connect_ex`, and fails teardown even if production code catches an attempted external connection. It supplies no successful HTTP response. This disconnected subset covers lockfile evaluation, bundle matching, snapshots, evidence batching, JS/Python/tier-2 dependency parsing and evidence storage. Python hook/cloud fixtures and HTTP evidence API integration require separate hermetic or installed qualification.

```bash
.venv/bin/python -m pytest -p tests.package_offline -q \
  tests/test_guard_package_input_snapshot.py \
  tests/test_guard_supply_chain_evaluator.py \
  tests/test_guard_supply_chain_bundle.py \
  tests/test_guard_evidence_batch.py \
  tests/test_guard_js_lockfile_resolution_phase11.py \
  tests/test_guard_tier2_supply_chain_phase13.py \
  tests/test_guard_tier2_package_intent_phase13.py \
  tests/test_guard_python_package_intent_phase12.py \
  tests/test_guard_evidence_store.py
```

Validation on corrected source passed 151 focused tests with external networking prohibited and only literal-loopback fixtures allowed, plus 117 parser/storage tests with every socket connection prohibited. Independent review passed 67 focused tests and reproduced both resource-bound fixes. Scoped type checking reported zero errors; Ruff and whitespace checks passed. These are source-level checks and do not replace installed qualification.

RSP-049 consumer inventory and RSP-051/RSP-053 implementation are complete at the source level. RSP-052 removes duplicate structured decoding while retaining text selector projection; a single traversal of every text grammar and format-wide installed parity are not claimed. RSP-050 has an exploratory independent-cardinality matrix with explicit baseline censoring. RSP-054 has a current-versus-optimized local comparison, while installed and statistical qualification remain open.

**Decision: do not activate a native package core in this tranche.** No native candidate has demonstrated the required benefit against this optimized baseline. Native RSP-055 through RSP-060 remain conditional, rather than being marked implemented or universally unnecessary. A bounded native pilot must demonstrate at least a 30% full local p95 or CPU improvement over optimized Python, including serialization and startup amortization, with no more than a 5% regression in the other primary metric, all completeness/authority tests passing, and a real installed consumer. Repeat that comparison with the PRD's sample counts and declared platform artifacts. The current profile helps select a candidate boundary; its small parser share alone is not a final no-port result and does not prove that every package latency target has been met.
