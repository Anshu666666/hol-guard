# Fixed B/F source comparison plan

This prepares one comparison of retained Python B with the inactive streaming
binding candidate F. No campaign or source export has started. The
[machine-readable plan](mcp-streaming-preparation-plan.json) fixes the complete
64-cell schedule before execution. E's adapter, worker, collector, tests and
historical raw measurements remain unchanged.

The new worker is `scripts/profile_guard_mcp_streaming_session.py`; the new
collector is `scripts/compare_guard_mcp_streaming_preparation.py`. The worker
imports `guard_mcp_streaming_preparation_pilot` explicitly when selected. Its
result identifies candidate F and hashes the adapter actually loaded. The
collector requires that hash and F's streaming-comparison identity, while B
must report no selected adapter. Neither Python module aliases nor an E result
renaming selects F. The optional worker CLI rejects an F flag with its unrelated
legacy cache matrix; the fixed F campaign uses the new collector.

## Runtime, oracle and source identities

B and F use the same complete frozen runtime export and the same Python
executable/dependencies. B selects the unchanged product default; F explicitly
installs its private adapter. This isolates candidate selection from unrelated
configuration changes and source filesystem placement. The exact exported
runtime commit, complete source/contract/project hashes, interpreter identity
and storage locations must be recorded before starting. This plan does not
pretend that an export or environment observation already exists.

The separate public API oracle uses the exact pre-owned B material from E's
retained campaign. All four source hashes are fixed in the plan, including
`mcp_tool_calls.py` SHA256
`02e5614996658bcda67c10357fac4d621db7d794e8264db6db6972bb1bb9e90e`.
The collector rejects a self-comparison or any other reference before executing
the 3,008-case oracle or starting a cell. It also checks the parent oracle's
loaded runtime modules against the selected runtime. This public oracle remains
distinct from F's previously completed private authority and child-pipe tests.

The plan pins all four harness files. The collector verifies those pins before
the oracle and retains their exact identities in the report. Runtime core,
harness and plan identities are checked before and after each cell; the full
export also requires before/after verification by the campaign coordinator.
Source exports must include required contract assets. The earlier E zero-cell
missing-contract failure remains historical evidence, not permission to start
from another incomplete export.

## Exact schedule and measurement rules

The schedule is E's complete original schedule with the experimental arm named
F. There are five independent process blocks, alternating B/F then F/B order
by block. Every cell uses a fresh proxy and actual synthetic child process.

| Workload | Uninstrumented warm calls per arm per block | Separate profiled warm calls per arm |
| --- | ---: | ---: |
| 1 KiB ASCII | 30 | 10 |
| 16 KiB ASCII | 30 | 10 |
| 128 KiB ASCII | 30 | 10 |
| Near-limit Unicode | 3 | 3 |
| Near-limit dense integers | 3 | 3 |
| Near-limit ASCII | No primary cell | 3 |
| Near-limit nested records | No primary cell | 3 |

Each cell adds one cold first call. There are 50 uninstrumented and 14 profiled
cells, 32 paired traces, and 554 expected forwards per arm, totaling 1,108. The
near-limit payload target remains 4,193,792 bytes with the existing compact-result
rule. Catalog size and every other worker default remain unchanged. No new
payload-length or content selection is inferred from the fixtures.

Latency uses the existing nearest-rank estimator and excludes the cold first
call. A large cell's p95 is the maximum of three warm observations, which does
not estimate a release tail. Tree CPU covers the proxy and recursive children
after catalog delivery through the final response, including cold first plus
warm calls; client CPU and cleanup remain outside that interval. Existing
after-catalog/after-response RSS and USS sampling and whole-worker OS peak RSS
remain unchanged. Neither phase costs nor waiting are subtracted from the route.

Profile cells remain separate from uninstrumented comparisons. Their phases
use the same exclusive main-thread accounting. F's initial retained bindings
and streaming freshness checks both enter `owned_input_binding`, so comparison
cost cannot disappear into an omitted phase. The 5 ms final quiet interval,
30-second benchmark client read, existing runtime forwarding and separate inline
approval budgets, and all cleanup deadlines remain unchanged.

Every cell obtains the shared POSIX measurement lock separately and yields for
the original 0.1 seconds afterward. Both arms use the same fixture filesystem.
Actual capacity, environment and placement must be recorded before launch;
the current storage constraint has not been declared sufficient for an export
or campaign. Results will not be pooled with E's differently placed sources.

## Failure accounting and interpretation

The collector refuses to overwrite an existing attempt and exposes no resume
path. Missing source, wrong oracle/harness or failed parity preflights persist
before any cell receives credit. Completed results with a wrong runtime,
unexpected adapter, missing F counters or selected fallback remain attached to
the failed cell with `measurement_valid: false`. Partial worker errors retain
their actual attempted, observed and forwarded counts and available F evidence.
Every adverse completed cell remains in the report; the schedule stops on a
failure and no replacement favorable sample is authorized by this plan.

Each completed pair compares the full existing correctness record. F must have
exactly one admission, category derivation, completed preparation and bound
forward per expected call, with no selected failure or fallback. A difference
or timeout remains a failure under the original rules.

The original target remains at least 30% p95 or tree-CPU improvement with at most
5% regression in the other primary metric. This source-only c1 experiment cannot
by itself establish the installed/platform/concurrency/tail/soak gates or
authorize general activation. B remains the default and RSP-100 remains OPEN
unless the original acceptance is satisfied by subsequent actual evidence.

After export and coordinator checks, the intended invocation is:

```sh
PYTHONPATH="$MCP_F_RUNTIME_SRC" TMPDIR="$MCP_F_FIXTURES" \
  "$MCP_F_PYTHON" \
  "$MCP_F_HARNESS/scripts/compare_guard_mcp_streaming_preparation.py" \
  --runtime-src "$MCP_F_RUNTIME_SRC" \
  --oracle-src "$MCP_F_ORACLE_SRC" \
  --samples 30 \
  --lock-file /workspace/scratch/c911dc702e23/performance-measurement.lock \
  --json "$MCP_F_NEW_REPORT"
```

These variables denote the reviewed frozen runtime, oracle, harness, verified
interpreter, common fixture directory and a fresh report path. They are not
populated by this preparation step. The source/accounting tests replace every
actual worker with stubs; their passing fake schedule is not a campaign result.

The final preparation gate passed 16 tests in 0.92 seconds under the shared lock.
It compares the complete worker AST against frozen E after removing only the
declared F import/flag, source metadata, binding-phase addition and unsupported
matrix-flag rejection. It also compares the full 64-cell schedule and defaults,
checks the pinned historical oracle identity, and exercises failed preflights,
wrong runtime/adapter/counters, partial results, fixed sample count and
no-overwrite behavior with stubbed workers. Ruff and formatting passed.
The [validation manifest and exact outputs](evidence/mcp-streaming-plan-validation/manifest.json)
retain the initial 13-test gate, the expanded review gate and final gate; these
test counts overlap. No actual worker, source export or campaign was launched.

Independent review verified the four final source/plan hashes, every harness
pin, the historical B oracle mapping, unchanged E worker/collector, and all five
retained validation artifacts. It found no remaining source or accounting
blocker after the oracle guard and unsupported matrix-flag correction. The
reviewer ran no duplicate tests or workers; this remains preparation evidence.
