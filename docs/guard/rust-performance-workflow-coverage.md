# Rust performance workflow coverage

This implements the workflow selection audit in RSP-133 for `release/3.2`.
The reconciliation foundation is `c4bd916fb0d0f375a4e2de0d1e498a0a533f63c8`.
That foundation already selected native wheel checks for release pull requests,
but several authority, performance, recovery and Rust validation workflows
still restricted pull requests to `main`.

All 19 Rust/native validation workflows now accept `release/3.2` pull requests
and validate pushes to that release branch. Workflows that already accepted
pull requests on every branch retain that coverage. Existing special branch
triggers for the authority acceptance jobs remain available.

| Changed input | Selected checks |
| --- | --- |
| Rust crates and workspace metadata | Rust runtime tests, native authority, command/rule differential checks, installed wheel validation, performance and recovery |
| Native Python edge, persistent stream and policy publisher helpers | Runtime, relevant authority/identity tests, performance and recovery |
| Daemon hook workers, evidence writer and settings/posture inputs | Runtime, installed wheel validation, performance and recovery |
| Installed hook launchers and adapters | Runtime, relevant authority tests, installed wheel validation, performance and recovery |
| Evidence store helpers | Installed wheel validation, performance and recovery |
| Python command reference and matcher definitions | Command model differential, command shadow, rule contract, performance and recovery |
| Extension/MCP contracts and snapshot policy inputs | Performance and recovery |
| Benchmark oracle, launcher, phase, resource, load and qualification helpers | Performance and recovery |
| Native installation fixtures and shared test helpers | Relevant native contract, runtime and differential checks |
| Native release staging, build helpers and package dependency files | Native identity and release contract, plus installed wheel validation |
| Native implementation and package inputs used by Desktop and extension integrations | Desktop contracts, installed extension controls and extension builder validation |
| Desktop presentation, settings transactions and extension policy inputs | Desktop contract or installed extension control validation, respectively |

The native wheel, Rust authority ownership and decision-critical I/O workflows
retain their unfiltered pull-request triggers. Their checks therefore do not
depend on a particular runtime file appearing in a changed-file path filter.
The ordinary repository CI continues to cover the Python tests and dashboard.
The Desktop, installed extension control and installed extension builder checks
also validate release pushes. The extension builder source checks retain their
existing pull-request and manual triggers.

`tests/test_release_32_workflow_gates.py` exercises both event types and concrete
examples of previously omitted changes, including `native_resident_stream.py`,
`native_policy_snapshot_publisher_inputs.py`, `hook_worker_native.py`,
`runtime_hook_evidence_writer.py`, `native_benchmark_oracle.py` and
`qualify_guard_native.py`. It also retains the prohibition on enabling release
push publication through this gate expansion.

This change only selects validation. It does not alter job steps, performance
budgets, platform matrices, scheduled soak frequency, publishing triggers or
release permissions. Installed-route qualification and measured performance
results remain separate release requirements.
