# Explicit configuration scope through hook and package reloads

This change transports the caller's optional configuration reader through the
active compatibility hook and package-evaluation paths. The daemon owns creation
and lifetime of the scope; these functions neither canonicalize paths nor create
new scopes. Each fresh policy reload still calls `load_guard_config`, including
post-claim and post-wait evaluation. The default reader remains `None` for ordinary
CLI use.

The native routing path also carries the exact optional `GuardConfigCapture` to
`HookWorker`, keeping its policy publisher bound to the same supplied capture.
Package evaluation receives only the parsed reader.

Covered routes:

- Both raw and normalized native routing attempts, worker creation, and Grok's
  local wait-config reload.
- Copilot fresh authority, generic post-claim authority, runtime artifact
  preparation, post-claim and post-wait rebuilding, and recursive evaluation.
- Package public/uncached evaluation, incomplete-lockfile and whole-snapshot
  failure handling, unidentified-package policy, and the cloud failure closure.
- Generic, Copilot, runtime-review and observe-mode local approval queues,
  including the existing continuation/notification plumbing owned separately.

The daemon HTTP client does not serialize callbacks; its server owns the receiving
scope. The separate Hermes proxy, headless dispatch-only resolver, and unused
Claude fallback are outside this entrypoint's active call graph and retain their
existing standalone behavior.

The `transport-ast.json` witness compares the eight production files to their
recorded base after removing only reader/capture keyword parameters, forwarded
arguments, and their supporting imports. Every remaining AST node matches. This
supports the narrow scope: policy composition, approval order, parsing budgets,
wait formulas, cache lifetime, and existing failure handling are unchanged. It is
not a substitute for execution tests.

Validation receipts retain the first failed fixture run and the corrected run.
The first run's three scoped package cases incorrectly tried setting the
home-only `security_level` through workspace configuration; the existing loader
correctly sanitized that key. The fourth fixture passed an intent-target object
to the cloud helper, whose boundary expects normalized target dictionaries. Only
the tests changed to correct these assumptions. An initial long test line was
formatted after Ruff reported it. A redundant light-command lock waiter was
cancelled before Ruff ran after the parent removed the light-command lock rule.

Heavy tests and type checking use the shared performance lock with `--close` and
a bounded acquisition wait. Recorded wrapper elapsed times include lock waiting;
pytest's own duration is the test duration. Logs and hashes are source validation
evidence, not a performance campaign or installed/platform qualification.

Final results: **166 passed in 48.79 seconds** in the corrected boundary and
adjacent suite. The unchanged native-compatibility and freshness files contributed
**24 passing cases** in the initial run, for **190 distinct cases with passing
results** across the retained runs. The initial run reported 30 passed and four
fixture failures in 31.22 seconds; six passing new boundary cases were rerun with
the four corrected cases. No production file changed between these runs.

Focused typing passed with **zero errors and 452 warnings**. The warnings are
retained in full; no separate baseline-warning equivalence claim is made.
Ruff and formatting passed for all 11 changed source/test files, with the corrected
fixture file rechecked after its test-only edits. `manifest.json` records exact
source, raw-output and dependency hashes. Shared dependency changes, if any,
between observation and final receipt are explicit in `dependency-final-check.json`.
