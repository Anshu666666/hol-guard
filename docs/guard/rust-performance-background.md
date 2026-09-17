# Background evidence and policy work

This tranche implements the algorithm and storage work in RSP-121 through
RSP-128. It retains Python ownership of background persistence and policy
compilation. The native decision still returns independently of persistence.
RSP-129 has local mutation-to-ACK coverage; installed first-decision and platform
qualification remain part of the release qualification workstream.

## What changed

Command evidence admission derives correlation, command presence, and the
redacted local preview directly from the decoded payload. It retains immutable
facts rather than deep-copying and JSON-encoding unrelated tool output. A full
queue is rejected before inspecting that payload. The queue's byte budget now
counts the aggregate record and UTF-8 preview actually retained. This changes
the accounting unit from discarded input bytes to retained evidence bytes.
Command preview generation and receipt validation still run on the submitter;
their work is included in the diagnostic.

The worker groups at most 50 records per pass. Native receipts in that group use
one SQLite transaction, and invalid batch inputs are rejected before any insert.
An unsuccessful commit acknowledges none of the group. A successful commit
returns every acknowledged decision identity, including harmless duplicates.
Command activity keeps its existing transaction and rollup implementation.

The aggregate journal and local preview sidecar each flush once per batch.
Completed records are removed by one bounded, atomic journal checkpoint, rather
than one whole-journal rewrite per receipt. A failed checkpoint is retried
without calling the decision engine or reinserting the committed batch.
Appending after a full journal fails visibly; there is no unbounded spool.

## Persistence contract

| Milestone | Meaning | Crash behavior |
| --- | --- | --- |
| Memory accepted | `submit_*` returned true and incremented `accepted` | A crash before journaling can lose this evidence. The hook decision has already been made. |
| Journal durable | Aggregate and preview writes completed their file flushes; directory metadata is flushed where the platform supports it | Restart replays the durable records. A process death during an append may leave a truncated final record, which is counted as degraded. |
| Database committed | The SQLite transaction acknowledged receipt identities; `receipt_processed` advances | A crash before checkpoint may replay the same identity. SQLite uniqueness prevents another native receipt row. |
| Checkpoint complete | Committed identities were removed by atomic replacement, followed by sidecar cleanup | An orphan preview cannot recreate an aggregate record because recovery joins by record ID. |

`journal_durable` is the count newly journaled by this writer. `recovered` counts
startup records. `durable_pending` includes database-committed records awaiting a
successful checkpoint; `checkpoint_pending` identifies that subset.
`receipt_transactions` and `journal_checkpoints` expose batching without raw
request material. The generic `processed` counter also includes intentional
command-activity no-ops and must not be called a database insert count.

The default queue limits remain 2,000 records and 16 MiB. One in-flight group is
separate from the queued count; already durable retries remain eligible for
recovery. Each aggregate journal and preview sidecar is bounded by the configured
byte limit. The nominal batch wait remains 25 ms and the SQLite connection
timeout remains 50 ms. Shutdown waits only for its supplied timeout. A filesystem
flush can continue on the worker after that wait expires; this is not a promise
that the disk itself completes within the shutdown budget.

Journal mutation has one owner at a time under the existing per-path,
cross-process file lock. Multiple producer processes remain supported, including
CLI hooks alongside the daemon. SQLite serializes write transactions. This is
not a daemon-lifetime exclusive lease. A checkpoint rereads the bounded journal
under that lock so another producer's records survive. Stable native decision
IDs and stable newly journaled command-attempt IDs make concurrent replay
idempotent at the database transaction boundary.

New unpaired post records preserve their journal attempt ID and occurrence time
when replayed. This fixes the prior behavior that minted another activity ID on
each replay. Legacy journal records without an occurrence time keep their legacy
best-effort behavior; they do not gain an invented timestamp or an exactly-once
guarantee. Pre-tool prevention/retry correlation and native receipt identity
validation remain in their existing domains.

## Policy input contract

The current native effective policy projection reads home/workspace TOML and
managed policy. It does not consume receipt or activity rows. Publication also
uses the `sync_state.policy_integrity` marker to select signing material. When
only database/WAL metadata changes, the publisher reads that bounded domain
through SQLite's read-only WAL view. An unchanged marker skips full compilation.
An integrity-domain change withdraws the ACK before compilation even when the
TOML projection's digest is unchanged.

The publisher still watches home/workspace files, verifier-key state, managed
files, and resident generations. A one-second reconciliation pass independently
checks the integrity domain and managed authority, including Windows HKLM. It
does not depend on receipt activity or a delivered watcher hint. Existing
resident-generation fences, publication epochs, renewal/expiry handling and
retry backoff remain in force.

Managed authority is revalidated each compilation pass and shared across that
pass's workspace loads. An unchanged managed cache is not rewritten repeatedly.
Its captured file/content identity participates in the write-needed token, so
deleting or altering the cache while the machine source remains valid repairs
the durable last known policy before a later source removal.
Compiled workspace projections use the digest of captured home and workspace
TOML bytes, plus inode, device, ownership, mode, size, mtime and ctime of both a
link and its target, and the verified managed-policy content hash/status. The
config reader parses exactly those captured bytes. This avoids both Windows
metadata-only reuse and binding a digest to a different file read during
replacement. Capture is bounded to 1 MiB per file; larger inputs bypass the
projection cache and retain the ordinary config loader's behavior. Changed
identities are reloaded; unchanged scopes reuse their projections. Reconciliation withdraws
the ACK before rebuilding a changed scope discovered without a watcher hint.

The registration lifetime is the publisher lifetime. At most 1,024 workspaces
can be registered, and at most 1,025 compiled entries are retained including the
home scope. Active stricter overlays are never evicted to admit a new workspace.
Capacity exhaustion invalidates any in-flight publication epoch and closes the
barrier with `native_policy_snapshot_workspace_capacity`. Recovery requires a
new publisher lifecycle. Installed callers use their existing unavailable-policy
response contract. The limit is an explicit capacity outcome, not clean policy.

Future snapshot schemas that consume extension controls, policy rollout state,
or another database domain must add that domain's exact durable revision to
`_database_policy_marker`. Receipt row counts, database mtimes, and unrelated
heartbeat state must not become policy versions.

## Validation and measurement

`tests/test_guard_evidence_batching.py` covers batch deduplication, invalid-input
and late-transaction rollback, one-transaction grouping, subprocess death after
append/commit/checkpoint, checkpoint retries without reexecution, unpaired
activity replay, truncated journals, early rejected admission, preview symlinks,
and preview rollback when aggregate append fails. Existing writer tests cover
SQLite busy, disk-full, bounded shutdown, journal bounds and multi-producer
preservation. Policy tests exercise actual WAL writes, narrow domain changes,
lost hints, unchanged/changed workspace caching, capacity races, and background
config mutation through acknowledged publication.

Reproduce the local diagnostic from the repository root:

```bash
uv sync --frozen --extra dev --python 3.12
.venv/bin/python scripts/bench_guard_background_work.py \
  --baseline-ref 2e672d2d950c6ec471005ddba46e49bba16dc23b \
  --samples 30 \
  --output release-metadata/rust-performance-background-diagnostic.json
```

The script loads only the explicitly selected trusted repository baseline and
uses the same locked dependencies for both arms. It alternates arm order,
excludes three warmups, and emits wall/CPU p50 and p95 separately. Submission
uses synthetic 1 KiB through 16 MiB output, accepted native receipts, and a
saturated queue. Persistence is paused to isolate foreground submission.
Policy cases use 1, 10 and 100 workspaces and assert full effective-policy
equivalence before timing. The report records the source revision, dirty state,
Python/OS/architecture and sample counts.

These observations are labeled `qualification: false`. They are not installed
launcher measurements, offered-rate load, production traffic, cold process
startup, native first-decision evidence, cross-platform SLO evidence, or a
decision to build a Rust spool/compiler. RSP-129's installed first-decision
freshness and RSP-131/132's mixed-load qualification and language decision remain
required before making those claims.

The [recorded diagnostic](../../release-metadata/rust-performance-background-diagnostic.json)
pins clean source `1468242473d7780e80ded5e375f85a7b0f5a7760`. It observed
16 MiB submission p95 of 53.142 ms versus 0.358 ms, and 100-workspace policy-pass
p95 of 21.330 ms versus 7.703 ms. The one-workspace case had a p95 regression
(0.400 ms versus 0.657 ms) while its median improved (0.233 ms versus 0.147 ms).
The shared worker and 30 samples do not establish a global latency gate. Keep
that small-scope regression visible when qualifying the installed mixed load.
