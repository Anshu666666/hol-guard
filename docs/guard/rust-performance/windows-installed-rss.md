# Windows installed-smoke process-tree memory

The installed Windows SLO job at PR head `107606388ad55f924a4e2924b4ff84e5fa08e6ff`
failed before recording its RSS baseline: the existing POSIX tree reader returns
unavailable on Windows and the root-only fallback returns zero. The original
positive-sample check correctly rejected that unavailable measurement.

The scripts-only Windows collector uses the already locked psutil 7.2.2
development dependency. It sums current `memory_info().rss` across the selected
root and its live descendants. On Windows this is `WorkingSetSize`, not
`PeakWorkingSetSize`. It separately returns `memory_info().private`, Windows
`PrivateUsage` committed bytes. It does not substitute commit bytes, historical
peak memory, or a sum of unrelated host processes for RSS. See the pinned
[psutil memory fields](https://psutil.readthedocs.io/stable/#psutil.Process.memory_info)
and Microsoft's
[PROCESS_MEMORY_COUNTERS_EX definitions](https://learn.microsoft.com/en-us/windows/win32/api/psapi/ns-psapi-process_memory_counters_ex).

Two attempts share a one-second sampling deadline and a 4,096-process bound.
The root creation identity stays fixed across both attempts. Fresh process
objects verify PID/creation-time/parent identities before and after reading;
the complete selected tree must match the final inventory. Duplicate identities,
invalid ancestry, cycles, vanished or denied processes, invalid counters,
overflow, excess size and late samples return unavailable. There is no fallback
to the measurement driver's PID or to only the requested root when descendants
cannot be read. The checks bound admission and subsequent work; they cannot
interrupt a single stalled operating-system call.

Threads and Windows handles are summed separately. The legacy POSIX descriptor
field remains zero/unsupported on Windows; handles are never mislabeled as file
descriptors. The unchanged soak gate requires a positive descriptor measurement,
so this repair cannot turn an unsupported Windows descriptor result into a
passing soak. Aggregate sums contain no process identifiers, paths, command lines
or raw operating-system errors. Working-set sums can count shared pages in each
process and are not a unique physical-memory total. This remains sampled memory,
with no claim to capture peaks between samples or a simultaneous atomic snapshot.

The legacy installed smoke creates its daemon within the driver process. Its
default root therefore includes the driver, in-process daemon, native residents
and other descendants. The public report now records that exact scope and the
current-working-set metric; it does not claim resident-only memory. The separate
qualification `DaemonFixture` and its Windows Job CPU collector are unchanged.

The 12% installed-smoke and 50% soak growth gates are unchanged. The baseline
continues to require a positive sample. Peak and final sampling now also reject
unavailable measurements instead of hiding zero behind a prior valid maximum.
No Windows soak qualification or cross-platform benefit is inferred from this
collector repair.

The Windows native-wheel job runs the new regressions before building the wheel.
Its actual Windows case starts a selected root, child and grandchild, touches a
24 MiB grandchild allocation, verifies the three-process memory/handle sample,
then verifies that the exited root is unavailable. The tree is enclosed in the
existing production Job Object for cleanup. Linux can exercise the synthetic
identity, ancestry, bounds, failure and field-selection tests; actual Windows
sampling and installed SLO results remain pending CI.

Local final validation recorded 115 passed, one Windows-only skip and one failure
in the existing Linux populated-store daemon stress subprocess test. That case
passed when rerun alone; its earlier failure remains unexplained and is not
erased by the rerun. The new collector, peak/final-sample and report-scope tests
passed. The unchanged soak descriptor requirement also has an explicit zero
rejection regression. Five changed source modules typecheck with zero errors
(111 warnings); Ruff, formatting, workflow ordering and diff checks passed.
Independent source review found no blocker and confirmed the cooperative
deadline and per-sample identity limits described above. None of this establishes
Windows runtime or installed performance qualification.
