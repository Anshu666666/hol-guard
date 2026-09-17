# MCP native selection decision for release 3.2

Decision recorded 2026-09-17: retain the optimized Python MCP proxy and defer
both new native MCP kernels and a full Rust proxy rewrite for release 3.2.
The measured remaining fingerprint/classification work does not establish a
material end-to-end native opportunity under the unchanged [PRD](PRD.md)
30% benefit requirement. This is a measured scope decision, not a failed Rust
benchmark: no native MCP candidate was implemented or measured by this experiment.

The existing catalog-generation invalidation, entrypoint identity, final
prewrite freshness check, approximately 5 ms quiet barrier, quarantine,
approval/claim composition, credentials, remote-session orchestration and
evidence persistence remain in their reviewed production paths. This decision
does not authorize removing them or moving mutable authority into a kernel.
Final candidate review and release qualification remain outstanding.

## Exact evidence and boundary

The [second CI evidence report](SECOND_CI_EVIDENCE.md) and its
[manifest](evidence/second-ci-24ba/manifest.json) retain the original outcome and
the separately corrected public projection. The measured source identities are:

| Identity | Exact value |
| --- | --- |
| Frozen Python baseline commit | `2e672d2d950c6ec471005ddba46e49bba16dc23b` |
| Baseline production tree | `ffa458bc310fc70c06829f6d4ccc07516d35bea3` |
| Optimized Python candidate commit | `24ba2d130a90f36b676139f03cabea98a2c3b00e` |
| Candidate production tree | `82bd6f2f4e3d81cc5fbc9380780f2315a37acc85` |
| Corrected public report SHA-256 | `76f4bf4f71756b8ea65a029e7edd4971899eb9a87ed84f25a7c149fac8e7c0dc` |
| Private source/environment manifest commitment | `91054275147f80acae12b672b8fd7806f2f23a8999972dca771cd176e1ed2a78` |

The [corrected report](evidence/second-ci-24ba/mcp-corrected-offline.json) comes
from the authenticated retained observations of
[workflow 35228364816](https://github.com/hashgraph-online/hol-guard/actions/runs/35228364816).
The original workflow remains failed: its public finalizer rejected two fixed
resource-accounting provenance fields. Correction
`b19bd59069db01a72ada9f3d93417f2ebfcb1866`, integrated as
`1498e226432a3731c982fb545ab9bb746848c86d`, admits and validates those fields.
It changes no measurement, estimator, workload, denominator or production
behavior. The corrected projection is not a new measurement or a green rerun.

The [experimental contract](mcp-proxy-rebaseline.md) invokes the actual
`CodexMcpGuardProxy.run_session` against real local child stdio, preserving
policy, receipts, inventory, catalog, identity, forwarding and cleanup. It
contains 30 workers, 240 sessions, 10,080 call outcomes and zero retained
failures. Five independent paired plain-run blocks cover eight traces; separate
instrumented and resource processes preserve their own boundaries. All 80 warm
resource windows are complete, with 134–331 samples and zero missing samples;
ten incomplete startup/churn lifecycle records remain explicitly incomplete.

This is Linux source-component evidence. Dictionary-input `run_session` does
not include the outer `serve` parser or final client-output serialization.
It does not qualify installed packages, other platforms, external-network or
remote HTTP behavior, or real human approval latency. The loopback trace uses
a real local TCP exchange and a synthetic service delay; the approval trace
uses a synthetic callback delay. Their waits are retained separately from CPU.

## What the measurements support

These selected ratios are candidate/baseline, with 95% intervals obtained by
2,000 bootstrap resamples of five independent paired plain-run blocks:

| Trace | Warm wall p50 ratio [95% interval] | Mean parent-process CPU ratio [95% interval] |
| --- | ---: | ---: |
| Catalog 10 | 0.966 [0.923, 1.027] | 0.956 [0.845, 1.040] |
| Catalog 1,000 | 0.538 [0.529, 0.565] | 0.447 [0.438, 0.477] |
| Payload 16 KiB | 0.675 [0.665, 0.725] | 0.615 [0.601, 0.667] |

Large-catalog and larger-payload gains establish a useful optimized Python
baseline. The small-catalog intervals cross 1, so there is no universal gain
claim. Twelve warm calls per plain block do not establish a qualified latency
tail. Candidate sampled peak RSS medians are approximately 2.8–3.5 MiB higher by
trace; that observation is retained rather than hidden by the CPU improvement.
The table's parent-process CPU is not relabeled as process-tree CPU, and these
Python-versus-Python comparisons do not satisfy a native selection gate.

The following residuals are calculated from candidate diagnostic
`exclusive_thread_cpu_ns.sum / count`, across all eight traces. Calls are
instrumented invocations, not unique requests. There are 520 diagnostic tool
calls; fingerprint and category classifiers each run 1,040 times. These are
component attribution observations, not uninstrumented latency estimates.

| Candidate phase | Invocations | Mean exclusive thread CPU per invocation |
| --- | ---: | ---: |
| Catalog fingerprint | 1,040 | 0.130 ms |
| Category classification | 1,040 | 0.173 ms |
| Signals from categories | 520 | 0.017 ms |
| Request identity | 520 | 0.318 ms |
| Policy-store lookup | 520 | 8.085 ms |
| Remaining policy-evaluation composition | 520 | 7.061 ms |
| Receipt persistence | 520 | 3.898 ms |
| Inventory persistence | 520 | 3.097 ms |
| Event persistence | 520 | 3.051 ms |
| Policy upsert, approval trace only | 65 | 17.567 ms |

The measured pure fingerprint/classification residual is small relative to the
remaining store, policy-composition and persistence work. The approximately
5 ms quiet wait is an ordering requirement, not 5 ms of removable CPU. These
facts support declining a new native boundary now. They do not establish a
formal upper bound on Rust benefit, explain all uninstrumented residual cost,
or prove that the adopted installed targets are met. SQL transaction, fsync and
filesystem internals are not individually isolated by these method-level spans.
Further attribution is appropriate before selecting a new optimization, but is
not a prerequisite for recording today's deferral.

## Task interpretation

All original [TODO](TODO.md) titles, acceptance conditions and dependencies stay
unchanged. Record these status consequences in the execution ledger:

| Task | Status for this decision | Meaning |
| --- | --- | --- |
| RSP-104: specify facts contract **if justified** | DEFERRED | No native MCP kernel is selected by the measured residual; no supported native facts API is claimed. |
| RSP-105: implement **selected** pure native kernels | DEFERRED | The conditional selection is deferred, so there is no selected kernel to implement in release 3.2. This is not implementation completion. |
| RSP-107: qualify native kernels against optimized proxy | DEFERRED | No native candidate exists in this selected release scope. No native benefit, parity or qualification pass is claimed. Reopening kernel selection reopens this requirement. |
| RSP-108: record full proxy rewrite decision | DONE, decision recorded | The required decision is to defer. A future justified rewrite requires a separate ADR and full protocol rollout scope. |

RSP-106 protocol/forwarding obligations are not declared complete by this note;
retain their ledger status and existing evidence. Deferring a conditional
implementation or its qualification does not satisfy its acceptance by proxy,
delete a dependency, or waive the tests required if that work is selected later.
RSP-108's decision can be recorded without inventing a native RSP-107 result:
its explicit default is deferral until justification exists. Installed
qualification, performance targets and final independent review remain separate.

## Conditions for reopening

1. Bind a reproducible residual to the actual affected MCP boundary, catalog and
   payload distributions, keeping deliberate waits, external service/human
   latency and store work distinct. Retain every offered attempt and failure.
2. Identify a concrete pure phase or coarse group of phases with a plausible
   material contribution after the current Python optimizations. If the proposed
   gain instead comes from store/persistence, first isolate that work; do not
   assume a language change removes its authority or durability requirements.
3. Specify bounded catalog/request facts and immutable identities. Keep
   credentials, remote-session orchestration and mutable authority outside the
   kernel. Review serialization, startup amortization and memory costs.
4. Compare the candidate against the optimized Python implementation at the real
   proxy boundary. Apply the unchanged PRD requirement of at least 30% lower p95
   or process-tree CPU per request, with no more than 5% regression in the other
   primary metric, using the required sample methodology and complete resources.
5. Preserve catalog/entrypoint changes, final prewrite ordering, approvals and
   claims, IDs, notifications, cancellation, malformed/oversized frames, EOF,
   backpressure, remote HTTP semantics and no replay after ambiguous writes.
   Supply the applicable installed/platform/update/rollback evidence and final
   independent review before production selection.

A full proxy rewrite additionally needs evidence that optimized Python and the
appropriate coarse-kernel alternatives cannot meet the adopted goals, a separate
ADR and complete protocol rollout scope, including reinspection of
[hosted MCP PR #2931](https://github.com/hashgraph-online/hol-guard/pull/2931).
The present evidence selects none of those migrations for release 3.2.
