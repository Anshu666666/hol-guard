# Windows fixture CPU accounting

This change measures the existing daemon-fixture Job Object. It does not change
qualification thresholds, the comparison formula, production process spawning,
or the boundary being timed. Windows execution and paired performance evidence
remain pending until CI runs the collector against both installed arms.

The previous collector retained CPU only for processes seen by psutil polling.
A child that started and exited between polls could disappear entirely. It
correctly reported `short_exited_descendants_cpu_complete=false`, which prevents
CPU comparison and the migration-benefit decision from qualifying. Independently
measured launcher latency can still qualify under `native_slo_acceptance.py`.

`DaemonFixture` already creates an unnamed Job Object, starts its root suspended,
assigns and verifies membership, then resumes it. Breakaway is disabled. The
parent retains that specific job until fixture cleanup. Reading it avoids
including the qualification driver, runner agent, unrelated tools, or an outer
runner job. Microsoft documents that cumulative user/kernel accounting includes
terminated members, and a parent job includes its nested child jobs:
[accounting structure](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_basic_accounting_information),
[nested job accounting](https://learn.microsoft.com/en-us/windows/win32/procthread/nested-jobs).

The scripts-only reader uses
[`QueryInformationJobObject`](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-queryinformationjobobject)
with the explicit retained handle and `JobObjectBasicAccountingInformation`.
It verifies the 48-byte ABI and returned length, live original process handle,
creation-time identity, job membership, ownership lifetime and nonregressing
cumulative counters. Any failure poisons that reader. It never queries a NULL
handle, enables breakaway, changes limits, duplicates a job, or alters handle
ownership. The sampling context must end before fixture cleanup closes the job.

The sampler subtracts cumulative user-plus-kernel 100ns ticks before converting
to seconds. It never adds per-PID CPU to the job total. CPU queries have their
own successful-sample count and failure state; a valid job counter does not
fabricate missing RSS, private-memory, thread or handle samples. The original
30-sample minima and positive-value comparison requirements remain intact.
Reports retain the explicit collector/scope and exclude process identifiers,
handle values and raw API error text. Fixture control overhead remains included.

The same callback is wired into warm daemon ingress, offered/concurrent load,
and mixed-load sampling. All use the existing fixture root and stop their
sampler before closing the fixture. Baseline and candidate use the same runner
and collector. The Windows resident CI job runs synthetic failure/conservation
tests and actual Windows short-lived/nested-job regressions before its Rust
checks. No local Windows execution or successful paired qualification is claimed.

Local validation: the collector, resource sampler, fixture lifecycle, mixed-load,
acceptance, qualification and source-capability suites passed 115 tests; the two
actual Windows direct/nested-job cases were skipped on Linux. Ruff and formatting
checks passed. The collector and sampler typecheck has zero errors (88 warnings).
The five touched fixture/sampling modules retain the same 14 pre-existing typing
errors as source base `ce8fce7f504bd67c213d67a60fbca34da724d25e`; comparing
diagnostic messages found no introduced error. Independent source review found
no blocker in the scope, ABI, lifecycle, cumulative accounting or failure gates.
These checks do not substitute for the Windows CI regressions or installed
baseline/candidate resource evidence.

macOS is unchanged. Its current observed-descendant metric remains incomplete.
Apple exposes child-usage fields through
[`rusage_info_v1`](https://developer.apple.com/documentation/kernel/rusage_info_v1)
and documents terminated-child accounting for
[`getrusage`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/getrusage.2.html).
A future live-tree collector needs a demonstrated reaping/reparenting and
identity-consistency contract before those fields can establish full coverage.
[`wait4`](https://developer.apple.com/library/archive/documentation/System/Conceptual/ManPages_iPhoneOS/man2/wait4.2.html)
offers a closed, fully reaped child-lifetime measurement, but that scope includes
startup and teardown and cannot silently replace the current warm-window metric.
