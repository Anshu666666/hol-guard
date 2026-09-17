# Inventory refresh, persistence, and wait attribution

This follow-up extends the [legacy pool and inventory audit](legacy-pool-and-inventory-audit.md) against integration baseline `bdb502bf8cdf66803af0931df223423cc66271e3`. It investigates the remaining RSP-130 components using real local files, actual GuardStore connections and writes, the production optional-scanner process boundary, and the shared HTTP retry client with a controlled transport. It does not establish installed-daemon latency, actual cloud latency, Cisco engine performance, or a Rust migration gate.

## Source ownership and refresh behavior

`guard/daemon/server.py::_refresh_aibom_inventory_loop` owns the periodic inventory job. It resolves the bound workspace and credentials, acquires `GuardStore.hold_cloud_sync_lock`, calls `aibom_commands.sync_aibom_snapshots_if_due`, records the result, and waits for the configured interval or error backoff. `runtime/runner.py` defers routine refresh to that background owner. Foreground cloud commands can force a deep refresh.

The default freshness interval is 900 seconds. The due predicate reads the previous successful sync timestamp; empty inventories retry within 120 seconds. It has no filesystem invalidation generation, file watcher, or unchanged-file cache. A real edit inside the interval does not itself make the inventory due. A subsequent collection rereads directory identities, including supplementary files. Same-size content changes with restored mtime change the verified directory hash. Additions and removals also change the detected inventory. A burst of edits is observed as its current final filesystem state when the next collection runs; this is periodic sampling, not an event-driven coalescer.

This matters for the PRD's incremental-refresh requirement: reducing repeated work inside a collection does not qualify a new filesystem watcher or cross-refresh clean-result reuse. Any later reuse must account for content, directory membership, permissions, symlink state, policy, scanner identity, and omission/error status. A timestamp-only cache would be unsound. Current directory-identity limits and incomplete/non-reusable identities remain authoritative.

## Repeated collection discovery

`guard/inventory_cisco.py::_skill_scan_roots` selects scanner targets from detected artifacts. For non-Hermes skill artifacts, `_nearest_skill_collection_dir` recursively enumerated the same `skills` directory for each artifact before the outer function deduplicated it to one target. The local fixture uses actual `GeminiHarnessAdapter.detect` results, not invented scanner identities.

The bounded optimization shares positive collection-membership proof only during one `_skill_scan_roots` invocation. It never retains negative discoveries, scan results, clean verdicts, content hashes, scanner metadata, or state across refreshes. The final target list and order stay the same, and the scanner still runs against the selected collection. Existing per-target timeouts, shared Cisco budget, `skillsSkipped`, analyzer identities, `client_unverified`, and `guard_cloud` verification requirements remain intact.

The configured Cisco budget is cooperative. Target selection currently precedes the per-target budget decrement, and synchronous filesystem operations cannot be interrupted by that budget. The measured 486-skill baseline consumed more than 30 seconds selecting one root before a scanner could start. This change removes the demonstrated repeated traversal; it does not turn that existing budget into a hard end-to-end deadline.

Three samples per source, measured in separate reserved windows, produced the following component results. The baseline is `bdb502bf8`; the candidate is `cef2edff2`. Every case independently verifies the same single selected collection.

| Detected skills | Median CPU, baseline → candidate | Median wall, baseline → candidate | Recursive walks, baseline → candidate | Matched documents, baseline → candidate |
| --- | ---: | ---: | ---: | ---: |
| 24 | 58.73 → 3.60 ms | 58.73 → 3.79 ms | 24 → 1 | 576 → 24 |
| 128 | 856.30 → 19.77 ms | 857.01 → 19.76 ms | 128 → 1 | 16,384 → 128 |
| 486 | 30,484.76 → 80.05 ms | 35,062.45 → 94.37 ms | 486 → 1 | 236,196 → 486 |

The 486-file CPU reduction is about 99.7% for this component. This is not an end-to-end inventory speedup or a portable release threshold. Host and filesystem variance are visible in the raw samples; the independent count witness establishes the algorithmic work reduction separately. See [baseline roots](evidence/inventory-roots-baseline.json) and [candidate roots](evidence/inventory-roots-candidate.json).

The actual Gemini refresh experiment uses a primary document and supplementary reference in each skill directory. It confirms that no unchanged-file hash reuse exists today:

| Refresh observation | 24 skills: median CPU / verified file hashes | 128 skills: median CPU / verified file hashes | Observed identity change |
| --- | ---: | ---: | --- |
| Initial full discovery | 20.08 ms / 48 | 92.85 ms / 256 | Every skill observed |
| Unchanged filesystem | 19.48 ms / 48 | 106.80 ms / 256 | None; files still reread |
| Same-size primary edit, original mtime restored | 18.83 ms / 48 | 94.54 ms / 256 | Exactly one skill changed |
| New supplementary file | 18.99 ms / 49 | 104.30 ms / 257 | Exactly one skill changed |
| 32 edits before the next observation | 22.10 ms / 49 | 98.18 ms / 257 | Final state of one skill changed |
| Removed primary document | 17.91 ms / 46 | 90.44 ms / 254 | Exactly one skill removed |

For every state, the actual sync-due predicate remained false at 60 seconds and became true at 900 seconds. The [refresh artifact](evidence/inventory-refresh-baseline.json) records these observations at `cef2edff2`, after the collection-selection optimization. It also retains an exploratory SQL workload that replayed identical timestamps; that SQL workload is distinguished from the advancing-timestamp comparison below.

## SQLite and metadata joins

`guard/consumer/service.py` persists an evaluated artifact through inventory, capability, provenance, optional diff, optional snapshot, and receipt operations. MCP tool calls and permission commands also write inventory artifacts. Each public store operation owns its `_connect` context and transaction. `_connect_once` opens SQLite, applies the configured busy timeout and WAL settings, finalizes the review outbox, commits, closes, repairs file permissions, and signals any committed outbox generation. These transaction and recovery responsibilities are separate from traversal and cloud projection.

The inventory upsert had a preliminary `first_seen_at` SELECT. Its `ON CONFLICT` clause already preserves the existing `first_seen_at`, so the SELECT is unnecessary: the INSERT can supply `now` for new rows and let the conflict clause retain the first value. The correction preserves first-seen identity, change timestamps, approval clearing, removed/reappearing artifacts, harness separation, and failed-update rollback. It does not combine authority-affecting writes across artifacts or change durability boundaries.

The reporting join is already linear: `_metadata_lookup_from_snapshots` creates a `(harness, item_id)` dictionary, and `_artifact_rows_from_store` reads inventory once and joins each row against it. Missing stored-only skill files keep their omission/presence behavior; trust metadata and redaction are retained. There is no evidence here for replacing this dictionary join with Rust or adding SQL joins that duplicate metadata already held in memory.

The final SQL pair advances `last_seen_at` on every timed pass and on the separate statement witness, so the inventory writes update actual stored values. The baseline is `16001f0f5`, with the original store implementation; the candidate is `1f6b21e73`. Both retain the same first-seen timestamp and finish with identical normalized inventory-row digests. Raw results are [SQL baseline](evidence/inventory-sql-baseline.json) and [SQL candidate](evidence/inventory-sql-candidate.json).

| Component | Artifacts | Median CPU, baseline → candidate | Median wall, baseline → candidate | Connections / commits per witnessed pass, both sources |
| --- | ---: | ---: | ---: | ---: |
| Inventory upserts | 24 | 86.09 → 65.42 ms | 86.20 → 65.46 ms | 24 / 24 |
| Inventory upserts | 128 | 2,274.98 → 378.64 ms | 2,276.05 → 378.93 ms | 128 / 128 |
| Five related store writes per artifact, excluding receipts | 24 | 378.48 → 455.15 ms | 378.76 → 461.77 ms | 120 / 120 |
| Five related store writes per artifact, excluding receipts | 128 | 2,559.50 → 2,696.05 ms | 2,562.30 → 2,700.02 ms | 640 / 640 |

The exact, reproducible change is one fewer SELECT per inventory upsert: total SELECT statements fall from 96 to 72 at 24 artifacts and from 512 to 384 at 128 artifacts. The five-write sequence removes the same 24 or 128 preliminary queries and keeps every connection/commit boundary. The three remaining SELECTs per inventory write belong to common outbox housekeeping: one query finalizes pending outbox payload hashes; two queries check the wake-state table and read its generation after the committed mutation. Inventory writes retain these existing commit/wake responsibilities. No SQLite busy/locked events were observed in these isolated samples.

Timing is variable: the single-upsert phase improved, while the five-write sequence was slower in both candidate cases. The unusually large single-upsert difference at 128 artifacts must not be generalized into a store speedup. These three-sample results support the exact reduction in database work and preservation of rows; they do not establish broader throughput improvement or a transaction-batching gate. At 128 artifacts, the candidate's five-write profile records median 0.071 ms connection establishment, 2.747 ms transaction scope, and 0.053 ms commit-call time per operation. The transaction scope includes normal connection setup/finalization and housekeeping; it is not pure SQLite execution or fsync time. Receipt construction/persistence, approval composition, cross-process contention, and crash recovery remain outside this component fixture.

The candidate's 128-row read costs 4.10 ms CPU; constructing the metadata index costs 99.83 ms and uses no SQLite connection; combining stored rows with metadata and redaction costs 169.89 ms with one inventory connection per pass. These stages overlap in work and must not be added as independent end-to-end phases. The evidence favors reviewing serialization, metadata projection, and transaction ownership before any native database or walker proposal.

## Scanner process and cloud wait boundaries

`inventory_cisco.run_cisco_inventory_scans` owns target selection and consumes the shared scan budget across MCP targets, skill roots, and detections. It returns explicit missing, unavailable, failed, and timed-out evidence. `integrations/scanner_subprocess.py::run_bounded_scanner_process` owns the isolated process, memory/output bounds, contained cleanup, and deadline. The fixture measures this actual boundary using a clearly labeled Python executable fixture; that result is not a Cisco scan. It separately exercises the actual unavailable-engine paths when optional Cisco distributions are absent. It does not install an engine or manufacture successful scan evidence.

`runtime/runner.py::_urlopen_with_sync_retries` owns timeout, 429, gateway, and DPoP nonce retries. Inventory event requests start with 90-second timeouts and allow one timeout retry at 120 seconds; bounded rate-limit/gateway waits and refreshed request proofs have separate counters. The offline fixture drives the real client with controlled byte streams and errors, records the requested budgets and retry waits, and imposes short known waits instead of contacting a service. CPU time and imposed wait are reported separately. These observations characterize control flow and scheduling, not real network delay or a service SLO.

The actual sync workflow also had an acknowledgment defect: after an initial 401, a successful credential refresh and retry fell through to the original HTTP failure handler. Errors raised by that retry also bypassed the ordinary failure/backoff persistence. The correction places both attempts under the same outer error handling. Exactly one credential refresh is allowed, original event bytes and IDs survive the retry, accepted snapshots reach primary-content upload, and subsequent 401/404/network errors take the established failure/backoff path. Four regression cases reproduce the original defects through the actual shared retry client and a bounded in-process transport.

The [offline wait artifact](evidence/inventory-waits-local.json) records three samples of each case at `cef2edff2`:

| Real bounded process boundary | Median wall | Parent CPU | Reaped child CPU | Outcome |
| --- | ---: | ---: | ---: | --- |
| 1 KiB JSON fixture | 312.74 ms | 6.39 ms | 233.56 ms | Exact expected JSON, exit 0 |
| 256 KiB JSON fixture | 284.74 ms | 5.44 ms | 257.69 ms | Exact expected JSON, exit 0 |
| Fixture with 50 ms child wait | 340.51 ms | 5.12 ms | 259.78 ms | Exact expected JSON, exit 0 |
| 250 ms deadline | 257.60 ms | 4.91 ms | 241.26 ms | Timed out, child reaped, exit -9 |

Startup and containment dominate these small executable fixtures; the three samples do not establish an output-size scaling curve. The actual absent-Cisco wrapper case took median 457.66 ms wall and 8.96 ms parent CPU, with both engines explicitly unavailable. MCP absence was determined inside its existing isolated process; skill absence was determined by its existing parent-side import validation. There is no successful engine scan in these measurements. Moving third-party import/execution into the resident process or treating engine absence as clean would invalidate this evidence and its security boundary.

| Actual shared client with controlled transport | Attempts | Requested timeout budgets | Requested retry waits | Imposed fixture wait | Median CPU / wall |
| --- | ---: | --- | --- | ---: | ---: |
| Accepted response | 1 | 90 s | None | 10 ms | 0.14 / 10.22 ms |
| Timeout then accepted | 2 | 90 s, 120 s | None | 20 ms | 0.31 / 20.48 ms |
| Two 429 responses then accepted | 3 | 90 s each | 2 s, 2 s | 50 ms | 0.70 / 51.83 ms |
| Two 503 responses then accepted | 3 | 90 s each | 2 s, 2 s | 50 ms | 0.88 / 51.32 ms |
| 401 / 404 / malformed JSON | 1 each | 90 s | None | 10 ms each | Explicit HTTP / decode failure |

The retry waits in this table were recorded and replaced by short controlled waits. Neither a 90-second network timeout nor two real two-second backoffs were executed. These are control-flow and wait-attribution observations, not cloud throughput measurements.

## Reproduction and qualification limits

Run the scripts using the frozen Python 3.12 environment under `performance-measurement.lock`. Constructed files, imports, and independent semantic witnesses are outside timed component samples. Traversal/read and SQL statement witnesses are separate from the timings. Reports bind the Git head and relevant source hashes, include all samples, and retain failed availability outcomes. Local paths, credentials, raw content, and SQL text are not persisted in evidence artifacts.

The SQL workload isolates actual store calls from policy evaluation; its five-related-write case intentionally excludes receipt construction and decision authority. Reporting stages reuse the captured detection and snapshot. The filesystem experiment operates inside a warm Python process and does not flush the OS filesystem cache. No sum of stage medians is claimed as end-to-end time.

The first correction passed 111 focused tests covering target discovery, omission/trust metadata, inventory contracts, acknowledgment and content upload, and atomic event batching. After removing the inventory SELECT, 29 store/receipt tests passed (one existing test deselected by repository configuration), including first-seen preservation, approval clearing, removal/reappearance, harness separation, and an actual rejected SQL update that leaves the row unchanged. Scoped BasedPyright for the traversal/retry modules and new tests reported zero errors; existing private/unknown typing warnings remain. Ruff, formatting, and `git diff --check` passed. An independent read-only review found no additional target-selection or retry acknowledgment regression. No new production I/O, background owner, resident worker, or transaction boundary was introduced; the touched production modules remain under 500 lines.

For exact reproduction, use the report's source revision and locked Python environment, then run the applicable command below under the shared measurement lock. The original root baseline predates the script; copy the script from `cef2edff2` into that baseline worktree without changing production modules. Keep each output separate.

```sh
# Roots: bdb502bf8 baseline, cef2edff2 candidate; separate output per arm.
.venv/bin/python scripts/profile_inventory_refresh.py --section roots --samples 3 \
  --label baseline --output inventory-roots-baseline.json

# Filesystem transitions and the exploratory fixed-timestamp SQL case: cef2edff2.
.venv/bin/python scripts/profile_inventory_refresh.py --samples 3 --counts 24 128 \
  --label sql-baseline-current-refresh --output inventory-refresh-baseline.json

# Advancing-timestamp SQL: 16001f0f5 baseline, 1f6b21e73 candidate.
.venv/bin/python scripts/profile_inventory_refresh.py --section sqlite --samples 3 \
  --counts 24 128 --advance-timestamps --label baseline --output inventory-sql-baseline.json

# Actual process boundary / missing engines / controlled transport: cef2edff2.
.venv/bin/python scripts/profile_inventory_waits.py --samples 3 --output inventory-waits-local.json
```

RSP-130 still needs installed filesystem-triggered invalidation and lifecycle qualification across supported harnesses, cross-refresh reuse with verified identities, any broader transaction batching with approval/crash semantics, actual installed Cisco engine accuracy/performance, and real cloud/network observations. This follow-up provides attributed local evidence and bounded Python corrections before any further native migration decision.
