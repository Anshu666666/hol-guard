# Receipt failure diagnostics: source review and proposed change

Review source: `590ce01334a7724f3f1349b2ab252110a5a268f5`.
This is an investigation and implementation plan. No production, test, probe,
workflow, acceptance, or core document has been changed.

## Observed evidence

The fresh Windows native wheel job `105553412556` reports 21 accepted and
processed native receipts, zero dropped, deduplicated, or durable-pending
receipts, and **one receipt failure**. Artifact `10540508932` is pinned by its
API-verified ZIP hash in the main collector. The exact decoded default-auto
report is 2,512 bytes, SHA-256
`d0b2d2e45df598f8719ea1168c0c9d7f2948c4d547b09d1fb05d3d0fe6cf5466`.
The prior 7a Windows report has the same receipt counts with **three failures**;
its SHA-256 is
`2909b4b256de964aff60abf003edec24f8ae31943e76a1912540da2dd3d08270`.
These separate cohorts are not pooled.

The full fresh Windows log is 67,493 bytes, SHA-256
`038a35a2f8db8740d6be61d7e9d68f37452c537eb20340e8c9ffb0c6f79632c6`.
It retains the aggregate report but no writer exception code or message.
The writer's relevant exception handlers discard the exception, so the
missing cause cannot be recovered from those handlers' output.

## What the current counters mean

| Event in the pinned writer | Global failures | Receipt failures | Receipt dropped |
| --- | ---: | ---: | ---: |
| Fresh journal append raises `OSError` | Number of fresh records | Number of fresh receipt records | Number of fresh receipt records |
| Receipt store/ack operation raises `Exception` | Number of receipt records in that attempt | Same number | 0 |
| Command activity persistence raises `Exception` | 1 | 0 | 0 |
| Journal checkpoint raises `OSError` | 1 per checkpoint attempt | 0 | 0 |
| Checkpoint reports invalid journal records | Number of invalid records | 0 | 0 |
| Recovery raises `OSError` | 1 | 0 | 0 |
| Recovery reports invalid, duplicate, or excess-capacity records | Number of records | 0 | 0 |
| Receipt validation fails at submission | 0 | 0 | 1 |
| Receipt submission is stopped or saturated | 0 | 0 | 1 |

Therefore the fresh `receipt_failures=1`, `receipt_dropped=0` snapshot
identifies **one failed receipt persistence attempt affecting one receipt**.
The append-drop branch cannot produce this snapshot without increasing
`receipt_dropped`. Checkpoint and invalid-journal failures do not increment
`receipt_failures`. The prior value three is three failed receipt-attempt
units; it does not establish whether one receipt was retried three times,
three receipts failed together, or another batching pattern occurred.

The persistence attempt covers the timeout context, store call, and explicit
acknowledgement check. The store validates/captures input, opens and configures
a connection, executes inserts, commits with shared outbox handling, closes
the connection, repairs permissions, and dispatches post-commit notifications.
An exception in this operation is not proof that the insert never committed.
Idempotent receipt identities make the subsequent retry safe.

The exception could be SQLite busy/locked, another SQLite failure, a value
validation problem, a non-SQLite store error, or an unacknowledged result.
The retained evidence does **not** identify which. In particular, Windows
alone and eventual drain do not prove SQLite contention.

`wait_for_receipt_corpus` intentionally waits for exact accepted/processed
counts with zero drops and durable pending; it does not require zero historical
failures. The existing tests explicitly preserve nonzero failures after drain.
`_installed_hook_corpus` snapshots this result **before `daemon.stop()`** and
returns the snapshot. It does not establish zero post-snapshot failures or
an error-free shutdown. This plan retains that acceptance and timing behavior.

## Minimal proposed implementation

1. Add two sparse, bounded-key counter maps to the writer's stats:
   `failure_diagnostics` and `receipt_failure_diagnostics`. Each key is an
   internal fixed `phase/code` pair. The first map mirrors the units already
   added to `failures`; the second mirrors the units already added to
   `receipt_failures`. These are cumulative failed attempt/record units, not
   unique lost receipts, and successful retry never clears them.
2. Instrument the existing failure branches at their existing condition-lock
   boundaries. Fixed phases are `journal_append`, `receipt_persistence`,
   `command_activity_persistence`, `journal_checkpoint`, `journal_recovery`,
   and the existing compatibility `journal_rewrite` helper. Record invalid
   recovery/checkpoint inputs with the fixed `invalid_record` code; recovery
   duplicate/capacity branches use their own fixed codes. Do not move the
   durability boundary, add I/O, or add a retry.
3. Classify exceptions without formatting them or retaining them. Fixed SQLite
   codes derive from an exact built-in `sqlite3` exception's integer
   `sqlite_errorcode`, reduced to its primary code: busy, locked, corrupt,
   not-a-database, read-only, full, I/O, cannot-open, constraint, or other SQLite.
   Fixed OS codes derive from an exact built-in OS exception's integer errno:
   permission, missing, no-space, read-only, or other OS. Fixed built-in value,
   type, runtime, and fallback codes cover other failures. Unknown subclasses
   map directly to `other_exception`; never invoke custom `__str__`, `repr`,
   attribute access, or arbitrary exception class-name formatting. The explicit
   acknowledgement failure uses a local fixed diagnostic marker at the
   existing raise site, without parsing an exception message or changing the
   existing raise/retry behavior.
4. Return detached copies of both counter maps from `stats()`. The number of
   keys is limited by the compile-time phase/code set; no request, receipt,
   exception, path, message, command, payload, class name, or raw numeric error
   value becomes a key or value. All values remain nonnegative integer counts.
5. The installed default-auto probe copies the new maps into an additive
   `evidence_failure_diagnostics` object in its report alongside the unchanged
   `receipt_metrics`. It distinguishes all-evidence failures from the receipt
   subset. Keep the current schema identity, existing fields, acceptance,
   pre-stop snapshot point, route count, 400 ms readiness budget, five-second
   receipt wait, and Windows handling unchanged. Current fake-writer tests gain
   explicit empty maps; missing diagnostic fields should be reported as
   unavailable, never fabricated as observed zeroes when reading older data.

The 50 ms SQLite override, 25 ms batch wait, 50-record maximum batch, queue
limits, exponential retry/backoff, drain deadline, record IDs, accepted,
processed, deduplication, drop, failure, durable-pending, degraded, transaction,
and checkpoint accounting all retain their existing values and branches.
This is diagnostics for the next occurrence; it does not identify or repair
the cause of either historical Windows failure and grants no qualification.

## Meaningful validation after implementation approval

- A real SQLite write lock held by an independent connection causes a bounded
  receipt-store busy exception; release it and verify eventual single-row
  persistence, retained failure count/code, unchanged dropped/pending counts,
  and the same retry timeout/backoff inputs. This is a local injected witness,
  not reproduction of the hosted Windows event.
- Inject an acknowledged-result failure, a value failure, and an unknown
  exception whose string/representation/attribute hooks raise. Verify fixed
  classifications and that diagnostics never execute those hooks or export
  sentinel secrets/paths supplied in exception arguments.
- Inject a journal append error and a checkpoint error separately. Append
  must retain the existing receipt drop/failure accounting; checkpoint must
  increment global diagnostics without claiming a receipt persistence failure,
  and retry must not repeat a committed insert.
- Inject invalid recovery/checkpoint records and recovery overflow/duplicate
  cases. Verify the diagnostic units reconcile with the original counters and
  do not reclassify unknown invalid records as native receipts.
- Verify stats snapshots cannot mutate the writer's internal diagnostics, and
  arbitrarily varied exception messages cannot increase key cardinality.
- Verify default-auto report plumbing retains a nonzero failure after drain,
  distinguishes unavailable diagnostics from zero, and preserves the exact
  original corpus-complete predicate, timing constants, and stop order.
- Run focused evidence-writer, receipt, and probe tests plus changed-file Ruff,
  format, and type checks under the shared validation lock. Do not run native
  installed qualification on this host, change deadlines, or retry the old
  hosted cohorts.

## Provenance

`source-and-artifact-provenance.json` records the ten exact Git blobs inspected,
their content hashes, and the retained artifact/log hashes. The `source/`
directory contains those immutable read-only source captures for review.
