# Storage-liveness fixture corrections

[CI job 105198797301](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287428/job/105198797301)
reported two failures in `test_guard_daemon_storage_liveness.py` among 208 passes
and 11 skips. These corrections change tests only; production transport,
critical endpoint behavior, storage writers, and deadlines are unchanged.

The critical-liveness case failed while acquiring its test SQLite lock, before
either timed HTTP request. `daemon.start()` starts real asynchronous AIBOM,
supply-chain, cloud, and storage-maintenance workers. Their initial write
transactions can overlap the raw connection's 100 ms `begin exclusive` attempt;
the CI excerpt does not identify the specific writer. The fixture now acquires
the existing exclusive storage access gate to drain ordinary store connections,
acquires its SQLite lock once, then releases the gate before either request.
Background writers remain enabled and subsequently encounter the SQLite lock.
The connection timeout, one-second HTTP timeout, 500 ms endpoint assertions,
and two-second persisted-heartbeat recovery requirement are unchanged.

An event-driven regression holds a real store transaction, proves setup waits
for it, then proves the storage admission gate has been released while the test
SQLite lock remains held. This separates deterministic setup from the endpoint
liveness measurement without retrying failed requests.

The header-probe case used a blocking `socketpair` with `timeout=None`. The
production probe deliberately refuses those sockets: `dup()` shares the OS
blocking mode, so changing a blocking descriptor could affect a concurrent
parser. Real accepted connections already have a 400 ms Python timeout and an
OS nonblocking descriptor. The fixture now uses that existing production
timeout. Its obsolete `MSG_DONTWAIT` platform skip is removed because the probe
uses portable duplicate-socket peeking. Complete-header/trickle assertions and
the production blocking-socket refusal remain intact.

The separate 24-hook burst fixture now unconditionally stops its daemon on
startup, lock-acquisition, HTTP, or assertion failure, and closes its SQLite
blocker on early failure. Its requests, assertions, connection timeout, and
setup ordering are otherwise unchanged. A fault-injected call to that actual
test proves an early HTTP error propagates while both resources are released.

Validation and retained failures:

- Before correction, the two requested cases produced **one pass and one
  failure in 14.96 seconds**: the blocking-header fixture failure reproduced;
  the asynchronous SQLite setup race did not reproduce in that isolated run.
- The first broader local storage run produced **10 passes and one failure in
  27.89 seconds**. The different 24-hook burst case timed out reading an HTTP
  response at its unchanged 1.75-second timeout. That exploratory version also
  applied the setup gate to the burst case; this optional change was removed.
  Neither the timeout's cause nor a causal effect of that setup change is
  established. The original cleanup gap left the test process running after
  reporting its results; it was interrupted with exit 130.
- The corrected requested cases, storage-gate regression, remaining storage
  checks, and header-handoff suite passed: **17 passed, one burst case
  deselected, in 14.02 seconds**.
- After the cleanup correction, the injected-failure containment, storage-gate,
  and header-contract regressions passed: **three passed in 0.76 seconds**.

These are correctness-test records, not performance qualification. The real CI
burst and complete shard still require readback; the failed run is not replaced
by a claim that the complete storage suite passed.
