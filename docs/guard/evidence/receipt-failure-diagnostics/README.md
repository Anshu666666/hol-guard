# Bounded receipt failure diagnostics

The Windows installed default-auto reports retain three failed receipt-attempt
units at `7a387128e2cf2ec79b890dfebe2697e8a49eb45d` and one at
`590ce01334a7724f3f1349b2ab252110a5a268f5`. Both snapshots show 21 accepted
and processed receipts, zero drops, and zero durable pending. Those historical
failures remain failures. Their exception classes and causes were not retained.

Source/test commit `fc208a98ca2bc1b9f93680c9581c9f4af471952c` adds fixed
phase/code counters so a subsequent occurrence can distinguish receipt store
errors, journal append drops, checkpoint errors, and invalid recovered records.
Its parent is the actual public 590 source above. This is a local diagnostic
change, with no installed execution or qualification claim for the new counters.

## What the observed counters establish

The pinned writer increments `receipt_failures` only when a fresh journal
append drops receipt records or when the receipt store/ack operation raises.
The zero receipt-drop count excludes the first branch at these snapshots.
Thus the observations identify failed receipt persistence attempt units;
checkpoint errors and invalid journal records only increment global failures.
The value three does not identify the affected batching or retry pattern.

The store operation includes validation, connection setup, insert, commit,
cleanup, and post-commit notification. An exception is not proof that the
insert never committed. The injected post-commit witness verifies that a retry
still stores one row per immutable receipt identity and retains the failure.
Neither the platform nor eventual drain establishes SQLite contention as the
cause of the hosted observations.

The default-auto report samples the writer before `daemon.stop()`. It keeps
that timing and the original corpus-complete predicate, which explicitly
permits historical failed attempts after successful drain. The snapshot is
not evidence of error-free shutdown. Separate Windows paired-probe readiness
failures have no demonstrated connection to these persistence observations.

## Resulting report fields

The existing `receipt_metrics` object is unchanged. The additive
`evidence_failure_diagnostics` object contains `all_evidence` and
`native_receipts` maps. Keys are fixed `phase/code` labels; values mirror the
existing global and receipt failure units. Successful retry never clears them.

For example, a locally injected single-receipt SQLite BUSY event is attributed
to `receipt_persistence/sqlite_busy`. An append that drops a receipt is
`journal_append/os_no_space`; a failed checkpoint is
`journal_checkpoint/os_read_only` in the all-evidence map, with no receipt
failure invented. These examples describe the finite injection tests, not the
cause of either hosted Windows report.

An empty map is observed zero. An absent or invalid map is `null`, meaning
unavailable. Missing numeric SQLite or OS codes receive the fixed
`sqlite_code_unavailable` or `os_code_unavailable` label. Unsupported exception
subclasses receive `other_exception`. The classifier never formats exception
text, retains exception objects, exports raw error numbers, or evaluates a
custom exception's attributes, class equality/hash, string, or representation.
SQLite primary numeric constants remain compatible with supported Python 3.10;
the actual validation runtime was Python 3.12.14, not a Python 3.10 runtime test.

The 50 ms SQLite override, 25 ms batch wait, 50-record batch cap, admission
limits, retry/backoff, drain deadline, durability boundary, callback order,
receipt identifiers, and all original counter increments remain unchanged.
The exact stripped-AST audit in `source-scope-proof.json.gz` verifies those
original writer/probe statements after removing only the listed additive
diagnostic instrumentation. It is not a substitute for reviewing the new
classifier, whose privacy behavior has independent failure-injection tests.

## Validation and limitations

| Check | Retained outcome |
| --- | --- |
| Initial diagnostics/probe tests | 58 passed in 1.78 seconds |
| Final diagnostics, writer, journal batching, receipt store, probe and boundary tests | 114 passed in 7.48 seconds |
| Final Ruff and format checks | Passed; five source/test files |
| Final type check | 0 errors, 54 warnings in the existing writer/probe files |
| Committed receipt boundary gate | Passed at exact local source commit `fc208a98ca2bc1b9f93680c9581c9f4af471952c`; original NHD contract scope |
| Original flow/source audit | Two instrumented ASTs match after explicit diagnostic removal; five store/journal/predicate files match exact original bytes |
| Desktop source bindings | All 395 match; none of the five changed files is bound; fixture SHA remains `2b60b7fa1eb771a3f8d0cff456a26997f31b914836c06d7857044ba2a1cce754`; no generator invoked |

The final tests use a real SQLite lock held by an independent connection and
release it to verify completed processing with retained failure counters.
They also cover single and batch acknowledgement failure after commit, a
post-commit exception, append and checkpoint errors, invalid/duplicate/capacity
recovery, global command activity accounting, rejected receipt admission,
detached snapshots, bounded labels, hostile exception callbacks, and unavailable
report fields. No deadline, retry policy, Windows acceptance, installed native
transport, or old cohort was modified to obtain these results.

The initial type check failed on nine Python 3.10 compatibility errors caused
by referencing newer `sqlite3` named constants. The fix uses the fixed public
primary integer values and retains a missing-code label. The initial format
check required test formatting. Those failed checks and the formatting mutation
are retained beside the final passing checks.

An initial exact byte comparison between the six inspected Python modules in
the pinned Windows wheel and 590 Git blobs failed because the wheel uses CRLF.
`installed-source-match.json` retains both byte hashes and proves that CRLF to
LF is the only difference. It does not claim original byte identity. The wheel
and enclosing artifact hashes were verified before that comparison.

## Evidence inventory

`manifest.json` records byte lengths and SHA-256 hashes for every retained file;
gzip entries also record decoded byte hashes. It includes the initial plan,
exact original source captures, candidate source hashes, tests and check logs,
source/binding audits, both immutable Windows reports, wheel source comparison,
and the original patch. `PLAN.initial.md` is the read-only plan written before
implementation approval; its initial-status wording is historical.

The new diagnostics have not yet observed a hosted Windows persistence error.
They establish attribution machinery and preserve failures; they do not repair
an identified historical cause or satisfy Rust performance/release gates.


## Lossless Windows report packaging

The publication whitespace check at `a21d2b7a3d1ea87b830cd1904b4213bdeebe7365`
flagged the final CRLF in each original Windows report. Both reports now use
lossless gzip storage:
[Windows 7a report](observed/windows-7a-native-default-auto.json.gz) and
[Windows 590 report](observed/windows-590-native-default-auto.json.gz).
Their decoded bytes, including CRLF, are unchanged. The manifest records both
saved and decoded hashes; no report field, source or test changed, and no
whitespace check was suppressed.

The exact original 49-record manifest is archived as
[manifest.before-crlf-packaging.json.gz](archives/manifest.before-crlf-packaging.json.gz).
Its decoded SHA-256 remains
`8df8390a54a71a6e3079c1716ee2e2fa9afc46f230df358ba40cbebe679f1598`.
The previous README is also retained as
[README.before-crlf-packaging.md.gz](archives/README.before-crlf-packaging.md.gz).
`packaging-verification.json` and `packaging/original-crlf-diff-check.log.gz`
retain the CRLF-only failure and exact-byte preservation checks. The current
manifest has 53 records; historical references to the original manifest remain
historical evidence and resolve through the archived manifest and decoded
report bytes.
