# Scheduler notification-cycle correction

This source correction follows the untraced scheduling-sensitive CI failure at
[run 35213401782, job 105176074932](https://github.com/hashgraph-online/hol-guard/actions/runs/35213401782/job/105176074932).
The job finished with 105 passing tests and one failure. The 48-review
runner/scheduler case rejected an admission with
`daemon_hook_deadline_exhausted`. Its previous assertion did not preserve runner
or scheduler state, so the log cannot establish the sole cause of that failure.

The case uses eight spawned capacity-protocol workers and 48 synchronized callers.
The worker returns an immediate synthetic capacity response through the real
runner IPC and lifecycle; it does not evaluate native policy. The unchanged
startup wait is 30 seconds, scheduler admission deadline is 10 seconds, runner
outer deadline is 6 seconds, and runner evaluation timeout is 4 seconds. The
native policy publisher's 400 ms readiness barrier is not part of this case.

## Confirmed defect and correction

`RuntimeHookScheduler.acquire()` dispatches again after a condition-variable
wake. Previously, `_dispatch()` always notified every waiter, including when
capacity was full and no admission, expiry, or rejection occurred. Two queued
threads could therefore wake one another repeatedly without any producer or
capacity change. A bounded source experiment stopped after 64 notifications with
two requests still queued, zero admissions, and zero active capacity. Raising
capacity afterward completed both requests and released their retained bytes.
These are event counts, not performance measurements.

Dispatch now notifies only when it removes queued work through admission,
rejection, expiry, or cancellation. Permit release explicitly notifies after
dispatch because releasing retained bytes can unblock a byte reservation even
when no review is queued. Existing expiry/cancellation removal, reservation
release, queue ordering, client and lane fairness, service prediction, capacity
limits, and absolute deadlines are unchanged. The 48-review assertion now
includes bounded runner/scheduler counters if admission fails again.

## Validation and limits

Validation used the `b262acd7b51a1fac251c4569af10e0d6fe4776ce` source base with
this correction. Its scheduler source and existing scheduler/runner test files
matched incoming `5ee52a03` before the correction.

- The original 48-review case passed in isolation before the correction:
  **1 passed in 3.40 seconds**. The CI failure was not reproduced as a local
  deadline failure.
- Event-driven regressions force a single spurious wake with zero capacity or
  full capacity. Both failed on original code because unchanged dispatch issued
  another notification: **2 failed, 1 passed in 0.56 seconds**. The passing case
  checks that permit release wakes a byte waiter with no queued reviews.
- Focused scheduler and unchanged 48-review checks passed after the correction:
  **18 passed in 12.64 seconds**.
- The exact scheduling-sensitive CI test group, plus notification, cancellation,
  deadline, crash-recovery, clock-jump, and restart checks, passed:
  **121 passed in 22.12 seconds**.
- Scoped Ruff checks and formatting passed; scoped BasedPyright reported
  **0 errors, 0 warnings, 0 notes**.

Suite durations above are test-run records from a shared host. No latency
improvement, installed SLO qualification, or native-port selection follows from
them. The original 48-review requirement and every deadline remain unchanged.
The corrected candidate still requires the real GitHub scheduling-sensitive job.
