# Experimental package-lock projection boundary

This is a finite RSP-054/Phase 2 selection experiment. The ordinary installed
runtime does not include or invoke the example. No signature, freshness, keyring,
rollback, authority, cache, evidence or policy operation moves out of Python.

The explicit benchmark option `--native-pilot-binary` installs a temporary parser
adapter at `lockfile_evaluation_support.parse_lockfile_text`. Both arms still run
`evaluate_package_request_artifact`, including the captured lockfile read, cached
signed-bundle model load, package matching, policy composition, result construction,
cache work and SQLite evidence persistence. Python remains the default.

## Declared native scope

The example accepts one captured UTF-8 `package-lock.json` with integer
`lockfileVersion: 3`, a `packages` object, and no unsupported legacy dependency
fallback. The benchmark adapter selects Linux inputs from 256 KiB through the
existing 8 MiB product limit. Lower-size controls, other operating systems, custom
parser callbacks, and the nine other supported lockfile formats use the unchanged
Python parser. Native JSON traversal is limited to depth 64; deeper inputs fall
back under the original Python depth limit. This does not lower the product limit.

Python sends one versioned JSON request through standard input:

```json
{
  "schema_version": 1,
  "request_id": "<64-character Python source digest>",
  "source_text": "<whole captured package-lock input>",
  "limits": {
    "max_bytes": 8388608,
    "max_nodes": 250000,
    "max_entries": 100000,
    "max_depth": 64,
    "remaining_ms": 1500
  }
}
```

The actual remaining time is the smaller of 1500 ms and the original absolute
parser budget remaining at request creation. Lower configured byte/node/entry/depth
limits are propagated. Native admission cannot increase any hard bound.

The response contains exactly `schema_version`, `request_id`, `status`, `reason`
and `entries`. A complete entry is an ordered array of dependency path, package
name, raw version string and direct-dependency boolean. `status: "fallback"` must
carry an empty entry array and a bounded reason. Complete responses have a null
reason. Python checks response identity, field types, entry cardinality, unique
dependency paths and direct-dependency consistency before constructing the immutable
`LockfileParseResult`. Its source digest and `complete-v1` parser identity remain
Python-owned.

Rust validates all JSON descendants, including unused arrays and metadata, for
duplicate decoded keys and node/depth limits. It preserves input object order,
explicit-name trimming, alias names, nested dependency paths and raw versions.
Unsupported numeric spellings such as `3.0`, unsupported shapes, invalid JSON,
duplicates, bounds and legacy cases produce explicit fallback. The Python parser
then determines the complete result or the existing incomplete/error contract.
No partial native projection is published.

## Process and accounting bounds

The request envelope is limited to 64 MiB and the response to 32 MiB. The Linux
adapter uses nonblocking writes and reads, so blocked standard input and an
oversized output cannot hold the caller indefinitely. It enforces the original
absolute deadline over process creation, request encoding/transfer, native work,
response decoding and result construction, and kills/reaps the child before
returning from failed process exchange. Python fallback retains that original
deadline and reports the entire parser call's elapsed time, including any native
attempt. Normal OS scheduling and process reaping can extend wall time slightly
beyond a requested deadline; no hard real-time guarantee is claimed.

Every native invocation and complete projection is counted. Explicit outside-scope
controls record fallback reasons. A selected native timing is rejected if the
expected native projection did not complete. The harness preserves those counts
even when that requirement fails. Both arms charge CPU for the evaluator process
and all children reaped during evaluation. Process startup, both JSON boundaries,
copies and Python result construction are included in full-route wall and CPU time.

The paired runner alternates AB/BA order within each workload over repeated blocks.
Every arm gets a fresh interpreter and store, one primary timed evaluation, no
warmup and no timed setup/signing/output hashing. It compares the hashes of every
`result.to_dict()` field and every persisted `guard_evidence` column without
normalization. Failed/censored pairs remain in the report and cannot receive a
numeric gate result. Source, harness and native artifact identities are checked
throughout collection and again at completion. Shared host measurements remain
diagnostic; small sample sets do not estimate a reliable p95.

## Build and finite qualification

The example uses only the repository's existing locked Rust dependencies and does
not modify any Cargo manifest or lockfile:

```sh
cargo test --release --locked --offline -p hol-guard-runtime --example package_lock_pilot
cargo build --release --locked --offline -p hol-guard-runtime --example package_lock_pilot
```

Run the Python projection/fallback tests with `GUARD_PACKAGE_PILOT_BINARY` pointing
to the built example, then invoke `scripts/bench_guard_package_pilot.py --suite native`
with identical baseline and candidate source roots and that explicit binary.
The `correction` suite separately compares source roots for the bundle model
optimization; it must not use the native flag. Both suites require a measurement
lock and write an atomic checkpoint after each paired case.

The original selection threshold remains at least 30% full local p95 or CPU benefit
with no more than 5% regression in the other metric, plus complete parity. A diagnostic
CPU threshold result does not establish installed distribution, reliable tail
latency, macOS/Windows qualification or permission to activate the native path.
Evidence and the bounded port decision are reported separately after measurement.
