# Preserve each admitted qualification run

At source `d0e37011b3d0f07c56831b9b53eca4f0c9fe4d7f`, adding the explicit
Claude experiment label triggered a skipped native-performance workflow. Its
PR-wide concurrency group nevertheless cancelled the earlier smoke workflow
[35233473603](https://github.com/hashgraph-online/hol-guard/actions/runs/35233473603)
attempt 1.
The original plan succeeded; all four wheel-build jobs were cancelled while
building. No pair, candidate scenario or transition measurement started. The
cancelled run remains a cancelled attempt, with retained build provenance.

The qualification workflow now identifies concurrency by GitHub run ID and run
attempt, with automatic cancellation disabled. A label event that skips the
plan, a later source push and a retry cannot replace an earlier offered run.
This follows the installed Claude experiment's existing retention contract.
The regression compares those four event/attempt groups under the same PR and
requires independent retention. Sample counts, worker budgets, product
deadlines, authority checks and artifact limits are unchanged.

This change preserves source-specific evidence even when a newer candidate is
published. Schedule deliberate full qualification only after correctness and
collection smoke results are understood; its existing per-job budgets still
apply. Cancelled build attempts do not contribute performance observations.
