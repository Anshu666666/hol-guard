# Darwin reaped-descendant CPU accounting

This is a source implementation and a platform correctness test contract for
RSP-011. No local macOS execution, performance measurement, installed resource
qualification or task closure is established by this change. The existing
native-wheel matrix runs the actual checks on both `macos-15-intel` and
`macos-15`; their retained results are required before claiming platform proof.

## Pinned Apple contract

The inspected Apple source is XNU `f6217f891ac0bb64f3d375211650a4c1ff8ca1ea`
(`xnu-12377.1.9`). These are primary source anchors, not assumptions based on
third-party counter descriptions:

- [resource.h:242–262](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/sys/resource.h#L242)
  defines `RUSAGE_INFO_V2` as a 16-byte UUID followed by eighteen unsigned 64-bit
  fields: 160 bytes. The reader selects flavor 2 and preserves the fixed ABI.
- [libproc.h:106–111](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.h#L106)
  declares `proc_pid_rusage(int, int, rusage_info_t *)`, returning zero on success
  or minus one with errno. The buffer argument is caller-owned struct storage;
  [the wrapper](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/libsyscall/wrappers/libproc/libproc.c#L137)
  passes its address directly to `__proc_info`.
- [fill_task_rusage](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/bsd_kern.c#L1249)
  copies the task's own CPU counters from `task_power_info_locked`, whose
  [assignments use Mach ticks](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/kern/task.c#L6811).
  There is no intervening nanosecond conversion. The preceding inspected XNU
  revision `e3723e1f17661b24996789d8afc084c0c3303b26` has the same assignments.
  `mach_timebase_info` supplies unsigned 32-bit numerator and denominator
  ([header](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/osfmk/mach/mach_time.h#L36)).
  The collector subtracts integer ticks first and converts the difference with
  `delta * numer / (denom * 1_000_000_000)`. Assuming nanoseconds would undercount
  on a machine whose timebase differs from 1:1.
- [update_rusage_info_child](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_resource.c#L1874)
  adds both the child's own CPU and its already accumulated child CPU to the
  parent. The [reap path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L2793)
  therefore transfers usage transitively. The separate
  [ignored-SIGCHLD path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L2577)
  also transfers these counters; it does not follow the traditional POSIX
  `getrusage(RUSAGE_CHILDREN)` omission.
- [proc_get_rusage](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_resource.c#L3456)
  can return cached zombie usage. The reader rejects nonzero exit timestamps
  because a zombie's CPU may already have transferred to its parent. The
  [security check](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L3820)
  remains authoritative: permission or missing-process errors produce unavailable
  CPU, not zero.

## Snapshot and interval contract

The collector retains psutil memory, descriptors and thread measurements. CPU
uses a separate `psutil_with_darwin_rusage_cpu` collector identity and never adds
psutil own-process maxima to the Mach total. The sum for one accepted snapshot
is each live member's own CPU plus its already reaped child CPU. A live child
has not yet transferred to its parent; after reaping it disappears from the
inventory and the parent holds the same contribution. An unobserved short child
can therefore be counted after reaping without having appeared in a sampled
process list.

Each attempt brackets two CPU passes with fresh PID/creation-time inventories.
Each native read requires a positive unchanged Mach start identity and no exit
timestamp. Child counters must be unchanged between the two passes; a reap
transfer, changing inventory, changed timebase or regressing own counters is
unavailable. The existing bounded inventory retry count is unchanged. Across
accepted samples, the root PID/creation/Mach-start identity, timebase and every
continuing member's counters must remain consistent. A later success cannot
erase an earlier missing or denied read. Exact integer ticks are retained until
the final subtraction; the public report contains no PID, start time or raw
per-process counters.

The completeness flag describes CPU represented by these kernel counters within
the observed, fixture-owned process tree. It does not establish global process
containment, capture work that escaped or was orphaned outside that tree, or
detect the kernel's documented lost-zombie-statistics condition. Fixtures must
retain the root and reap owned descendants. Thirty successful resource samples
and all existing memory/CPU availability conditions remain required separately.
The Linux and explicit Windows Job Object collectors retain their own semantics;
Darwin evidence is never labeled Linux or silently promoted to Windows job scope.

## Verification boundary

Host-independent tests exercise ABI offsets and prototypes, permission/missing
errors, Mach timebase conversion above the float exact-integer range, live-to-
reaped transfer conservation, PID identity changes, counter regression hidden by
sibling growth, and permanent incomplete reports after an unavailable sample.
The Darwin-only tests compare the live process CPU clock and exercise an owned
child/grandchild tree and an ignored child that is born and reaped between the
only two tree snapshots. The nested witness independently compares the parent
child-counter delta with actual `wait4` CPU usage. These are bounded correctness
checks, not qualification samples or performance estimates.

The MCP component's explicit source inventory additionally hashes both imported
platform CPU reader modules. Its public collector policy remains Linux-only;
this change does not reinterpret historical MCP evidence or pool old and new
source identities.
