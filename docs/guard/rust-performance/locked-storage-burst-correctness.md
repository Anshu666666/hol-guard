# Locked-storage burst: bounded foreground corrections

This is a source correctness investigation against parent
`c964a61a3a4c19d721358e69c400d6059dfd1156`, not an installed performance
qualification. The original 24-request test, client timeout of 1.75 seconds,
response assertion of less than 1.6 seconds, health assertion of less than
0.5 seconds, SQL lock, and cleanup/recovery assertions remain unchanged.

## Observed failure boundaries

The isolated test reproduced its HTTP timeout. A C-level stack snapshot at
1.3 seconds found 13 request handlers in adapter import locking before
scheduler admission. A second diagnostic forwarded the original methods
unchanged and recorded stage entry/exit times: the 24 capacity lookups spent
up to 754 ms loading adapter implementations. Native mode was `off`; these
requests used the explicit Python test oracle and compatibility process route.
They did not wait for native policy publication.

Removing that import work alone did not consistently satisfy the test. Of
three subsequent original-burst runs, two failed and one passed. In the failed
run with the 1.3-second snapshot, 16 handlers were waiting for process admission,
one was awaiting an evaluator reply, and another was performing synchronous
RSS sampling through `observe_load` before writing its response. The supervisor
was independently sampling RSS as well. A parent pipe wait does not establish
what the evaluator was doing, and these observations do not establish SQLite
as the cause of every delay.

## Corrections and preserved contracts

- Capacity identity uses the existing static harness contract lookup. An exact
  parity test covers all 16 harnesses and 30 accepted names; unsupported names
  retain the `other` bucket. A separate cold-registry test prohibits adapter
  implementation imports during capacity lookup.
- Foreground load observations retain the latest bounded queue measurements
  and wake the existing supervisor. Process-tree RSS/CPU probes, subprocesses
  and capacity changes execute on that supervisor. Both queued and idle
  observations wake it, preserving backfill and scale-down notifications. The
  capacity policy, worker limits and pressure thresholds are unchanged.
- Compatibility evaluation consumes its existing 1.45-second ordinary-hook or
  2.75-second post-hook cap from the connection acceptance timestamp. It still
  honors an earlier caller deadline. The stage no longer receives a fresh
  allowance after authentication, path validation and primary admission. A
  challenge and hook sharing a connection retain the same acceptance time,
  matching the existing outer transport budget.

The deadline correction narrows the former stage-relative allowance. It does
not make configuration reads or response rendering instantaneous and does not
prove a universal response-time bound. Existing availability responses remain
availability responses; they are not successful native policy verdicts.

## Validation boundary

The complete correction passed the isolated original burst, including all
24 allow deliveries, the original health and latency assertions, zero process
timeouts, released active request accounting, and post-unlock recovery. The
1.3-second snapshot no longer showed adapter imports or RSS probes on request
threads. This single corrected run does not erase the earlier failures or
establish installed/CI reliability. The original burst also passed in the
subsequent consolidated run.

Deterministic tests separately cover a resource probe that remains blocked
while foreground observations return, exact alias parity, no implementation
imports on admission, and acceptance-based deadline propagation/rejection.
No 240-request fairness workload, installed timing run, or paired benchmark was
executed as part of this investigation.

The consolidated eight-module run reported **126 passed and 2 failed**. Its
failures were in direct fixed-size process-runner tests: the prewarmed fan-in
returned the expected decisions but exceeded its existing one-second wall
clock assertion (1.090 seconds), and transient spawn recovery reached its
third attempt and ready state but returned `daemon_hook_process_timeout` for
the subsequent review. These tests call `runner.review` directly with explicit
process limits; they do not execute the changed HTTP functions or adaptive
load-observation path. Their causes were not established by this investigation,
and no thresholds were changed. The result must not be described as an entirely
passing process-runner suite.

One isolated recheck of those two failures reported **1 passed and 1 failed**.
Spawn recovery passed. The fixed-size fan-in failed at its earlier success
assertion with 20 `daemon_hook_process_not_ready`, three
`daemon_hook_process_timeout` and one `daemon_hook_process_deadline_exhausted`
result. This remains an unresolved evaluator-path failure; the recheck must
not be reduced to a successful latency result or described as a proven flake.
