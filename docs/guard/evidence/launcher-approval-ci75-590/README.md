# Launcher approval read contention: source 590 CI shard 75

This record preserves the two failures in the original hosted shard and a
separate, deterministic local SQLite witness. The repair makes the private
qualification controller retry an actual BUSY/LOCKED failure only before its
pending-row SELECT completes. The final four-module finite check passes
**73 tests in 8.80 seconds** under coverage. This is not a passing result for the
original hosted shard, the full local shard, or the end-to-end SLO campaign.

## Original source and hosted result

The original source is commit
`590ce01334a7724f3f1349b2ab252110a5a268f5`. The full hosted shard-75 log is retained
losslessly as `hosted-original-shard75.log.gz`; its decoded SHA-256 is
`07ad07483047db681656e22caa6f404e4fcb49e7c8de8f0d1ffa33bda72125b3`.
It reports **225 passed, 2 failed in 123.79 seconds**:

- `test_other_harness_tool_command_and_workspace_are_not_resolved` tried to
  access `request_id` on a result that did not contain it.
- `test_preexisting_deduplicated_request_is_never_selected` expected
  `qualification_launcher_approval_deadline` but received `unclassified_failure`.

The hosted trace did not retain the controller's error category, origin, or
diagnostic digest. It therefore does not prove that either hosted failure was
caused by SQLite contention. The two original assertions now include the safe
controller result when they fail; their identity/deadline requirements remain.

`original-source.json` binds six complete original sources to their lossless
archives. The verified exact hosted plan contains 227 node IDs; its SHA-256 is
`b474c7ee0d460b81be5dc536140cd767fbc4f8d158c9dc245cff5624f7c14a93`.
The retained plan receipt identifies GitHub artifact `10539824877` and the
verified parent ZIP digest
`e8ddc12f7ae494435db884adc3914aa0c575397f74d5a9ee285d464ab74f8f2e`.

## Separate local observations

The original two cases passed locally under coverage (2 passed, 1.25 seconds).
The original controller module also passed (21 passed, 3.55 seconds). The latter
run's first diagnostic plugin imported the module before coverage initialization
and emitted a retained coverage warning; it is not a complete coverage receipt.
The plugin was then corrected to instrument only at test setup, preserve the
existing failure evidence unchanged, and add only numeric SQLite diagnostics.

The **exact 227-node hosted plan** on the unchanged source produced
**224 passed, 3 failed in 78.13 seconds** locally. All 21 controller cases passed.
Two failures rejected the validation interpreter as
`codex_hook_interpreter_owner_untrusted`: its symlink target was owned by uid
65534 while the process ran as uid 0. No ownership policy was bypassed or changed.
The third was
`test_routine_typescript_error_grep_pipeline_stays_benign`; its cause was not
established in this investigation. The complete log, safe failure records, exact
plan, and command receipt remain in this record. No full-shard pass is claimed.

An earlier attempt to expand whole test modules instead of using the exact node
plan was interrupted locally without a returned pytest result. Its cancellation
and unknown execution state are retained in `module-expansion-interrupted.json`;
it receives no test credit. No hosted run was cancelled or rerun.

The deterministic witness pauses the real controller before its pending read,
creates an exact real approval row, acquires a real SQLite exclusive lock, and
lets the read proceed. On the original helper, the SQLite engine produced
`SQLITE_BUSY` (numeric code 5) at
`store_connection_schema._connect_once`, line 414. The controller immediately
ended with an unclassified failure even though the lock could be released before
its unchanged deadline. The original sanitized diagnostic digest was
`c9f12cbac88605d425a8c342931e771ee351f5232f2c5bd5e233ebdaf222daba`.
The approval row remained pending.

Four actual-lock regression cases then failed against the original helper:
release-and-resolve, deadline exhaustion, cancellation, and a preexisting
deduplicated row. Their full pre-fix test source and **4-failure, 0.98-second**
log are retained. This proves a local controller defect consistent with the
hosted symptoms; it does not retrospectively identify the hosted exception.

## Repair boundary and finite checks

The helper retains its exact new-row watermark, SQL identity predicates,
ambiguity rejection, identity rechecks, gated resolver, and post-resolution
durability checks. The original 8-second maximum, individual requested
deadlines, 0.05-second SQLite timeout override, and existing 0.01-second
cancellable polling delay are unchanged. The deadline is not restarted.

Only an `OperationalError` with an integer SQLite primary result code
`SQLITE_BUSY` (5) or `SQLITE_LOCKED` (6), including those primary codes in an
extended result code, can enter the retry path. No exception text is matched.
The private classification wrapper is constructed inside the pending read and
only before SELECT completion. Errors from context exit/commit housekeeping,
identity validation, or approval resolution remain terminal. The controller
retains the contention count, the last full numeric code, and the last existing
sanitized failure record. Deadline and cancellation reasons remain unchanged.

The pending probe retains the store's existing shared storage gate and calls
its existing `_connect_once` directly under the same timeout override. Before
yielding, that context opens the connection, records in-memory metrics, reads
`journal_mode`, and configures connection PRAGMAs. It cannot select, resolve,
claim, or commit an approval operation. The pending SQL itself is read-only and
does not return a request ID until context exit succeeds. All outbox hash
updates, transaction commit, wake notifications, and policy callbacks are after
the context yields and after `read_finished` has been set. A failure at those
points is terminal.

This distinction was added after reviewing the original `_connect` wrapper:
its separate fatal/I/O recovery branch can restore, initialize, or salvage a
database before yielding, so a numeric BUSY from that branch would not prove a
safe read failure. The superseded 72-pass candidate and its exact sources are
retained. A new no-recovery regression failed on that candidate (1 failure in
0.37 seconds) because the probe entered `_recover_fatal_sqlite_store`. The final
pending probe does not enter that recovery wrapper. Fatal/corrupt errors remain
terminal there; no production store API or other recovery call site changes.

The module supports the repository's Python 3.10 type target without accessing
the named SQLite constants added in Python 3.11. When an engine error lacks a
numeric code, it remains unclassified and terminal. The real-lock tests require
numeric contention behavior on the validated Python 3.12 runtime; an explicit
older-runtime branch checks fail-closed behavior when the module lacks that
numeric-code capability. It does not turn missing codes on Python 3.12 into a
successful contention witness.

The final coverage command runs these four modules:

- `tests/test_native_slo_launcher_approval.py`
- `tests/test_native_slo_launcher_empty_approval.py`
- `tests/test_native_slo_approval_fault_fixture.py`
- `tests/test_native_slo_launcher_review.py`

All **73 cases passed in 8.80 seconds**. This includes the original controller
predicates, four actual-lock outcomes, missing/READONLY/CORRUPT errors through
the actual pending-read boundary, resolver contention with exactly one attempt,
context-exit contention with exactly one attempt, and a fatal probe error that
never enters storage recovery. The ordinary gated
approval, exact row identity, ambiguous rows, cancellation, late durable
completion, empty-review, and fault cases remain active.

The final helper type check reports **0 errors, 30 warnings**; Ruff, formatting,
and whitespace checks pass. Exact commands, output, and tested source hashes are
in `fixed-validation.json` and the individual receipts. Earlier successful
candidate checks and the intervening two-error type result are retained under
their original, `pre-type-compat-`, or `pre-recovery-` names; they are not substituted for the
final source check.

Only the private qualification helper, its focused tests, and this evidence are
changed. Production store, approval policy, approval service, runtime paths,
campaign thresholds, and historical campaign records are unchanged. This repair
does not grant qualification credit or alter the open RSP-100/RSP-106 conclusions.

`manifest.json` hashes every retained file and the decoded bytes of every gzip
archive. `source-scope.json` records the final tested source hashes and verifies
that the original deadline/identity/resolver methods and unaffected test bodies
remain unchanged. No GitHub alert, disposition, rerun, cancellation, or
workflow mutation was performed by this investigation.
