# Private numeric evidence durability

Each installed qualification block now creates an exclusive private
`<block>-numeric.jsonl` alongside its existing raw numeric JSON. The sidecar is
included by the existing encrypted private-sample archive inventory; it is not
added to the public report. Series names, value order, counts, aggregate output,
sample minima, deadlines, and success criteria remain unchanged.

Previously, the main numeric series remained only in memory until launcher,
load-profile, cold, and recovery work had all finished. A later timeout discarded
the preceding observations. The journal now records an offer before collection,
each returned observation or bounded batch after its timer stops, and validation
or failure afterward. Every journal append is flushed and fsynced before the
collector advances. Startup/readiness scalars are checkpointed when their
fixture becomes available. A final collection marker requires exact conservation
against the original raw numeric mapping, including duplicates and per-series
order; the mapping is then published exclusively with private permissions.

| Collection path | Checkpoint boundary |
|---|---|
| Daemon ingress and serial registered launchers | Each returned observation |
| Native-client control IPC | Existing batch of at most 100 values |
| Concurrent registered launchers | Existing wave of 16, after returned timers stop |
| Cold one-shot and recovery | Each captured stop timestamp, before semantic rejection |
| Fixture startup and policy readiness | Each returned fixture scalar |

An interrupted in-flight IPC batch can lose up to 100 unreturned native values;
an interrupted launcher wave can lose up to 16 uncollected values. A single
ingress observation can also stop before returning its value or route evidence.
Their offers remain explicit unknown outcomes. Earlier returned checkpoints
survive; missing observations are never replaced with zeroes or successful
samples. A launcher-wave exception preserves the prefix already collected by
the controller. The separate load-profile reports and side-scenario collectors
retain their existing evidence contracts; this change covers the block's main
raw numeric mapping.

The schema is `hol-guard.native-numeric-journal.v1`. It permits finite,
nonnegative numeric values and bounded series labels, with no payload, stdout,
stderr, local path, or exception message fields. Limits are 32 MiB per journal,
4,096 bytes per record, 300,000 records/total offered observations, 100,000
observations per declared series batch, and 100 values per checkpoint record.
Space for a terminal record is reserved when appending an observation. Creation
reuses the reviewed private archive file contract: POSIX mode 0600, explicit
Windows private DACL, exclusive creation, and retained-directory validation.
Finishing the journal closes its file and retained parent handles before sibling
aggregate publication, allowing the Windows atomic-rename contract to release
its directory barrier.

`recover_numeric_journal(path)` is an offline private-data API. It checks batch
identities, offsets, counts, terminal states, and numeric bounds. A missing
terminal remains incomplete; a partial final line is reported as truncated.
Unexpected middle-record corruption or count drift is rejected. A failed batch
cannot later be marked complete, and a closed batch cannot accept more values.
Write, flush, or fsync failure poisons the writer: it does not append a possibly
contradictory terminal after an uncertain write. Recovery always returns
`qualification_complete=false`, even when numeric collection completed. It does
not supply replacement aggregates to the paired qualifier or turn a failed
worker into a passing block.

Validation includes real `os._exit` interruption; late launcher/cold/recovery
failure; an interrupted second native batch after 100 retained values; rejected
semantic outcomes; short-write and fsync faults; finite-value/file/count bounds;
private exception exclusion; successful launcher/block count and order
conservation; and simulated storage cost after both lifecycle timer timestamps.
These are correctness tests with synthetic operations, not performance runs.
No measurement lock, timing limit, or qualification gate was changed. Actual
Windows execution and encrypted CI recovery of an interrupted block remain
qualification evidence to collect.

Recorded checks: **131 passed, one Windows-only test skipped** across numeric,
launcher, qualification, source-platform, and encrypted evidence suites; after
the final handle-lifetime correction, **23 numeric checks passed**. Scoped Ruff,
formatting, and BasedPyright passed (zero type errors/warnings). Independent
source review covered incomplete-batch consistency and uncertain-write handling.
