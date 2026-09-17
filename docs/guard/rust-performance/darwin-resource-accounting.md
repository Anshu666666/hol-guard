# Darwin reaped-descendant CPU accounting

General Darwin process-tree CPU is **unavailable**, with finite reason
`darwin_reaped_cpu_ambiguous`. Actual fifth-checkpoint macOS correctness tests
found that ignored children contribute approximately twice their CPU to the
kernel's child counters. The reader preserves private raw counters, memory,
thread and descriptor measurements, but does not publish those ambiguous totals
as CPU seconds or mark complete descendant CPU. RSP-011 remains open. No local
performance measurement or installed resource qualification is claimed.

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
  therefore transfers ordinary waited usage transitively. The separate
  [ignored-SIGCHLD path](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_exit.c#L2577)
  first adds the same counters at line 2596, marks the child `P_LIST_DEADPARENT`,
  then calls `reap_child_locked` with the same original parent. That function
  adds them again at line 2805. Its `P_NOCLDWAIT` condition protects traditional
  `ruadd`, **not** `update_rusage_info_child`. This permits double rollup.
  [kern_sig.c:681](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_sig.c#L681)
  sets `P_NOCLDWAIT` for either `SA_NOCLDWAIT` or an explicit `SIG_IGN` handler.
- [proc_get_rusage](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/kern_resource.c#L3456)
  can return cached zombie usage. The reader rejects nonzero exit timestamps
  because a zombie's CPU may already have transferred to its parent. The
  [security check](https://github.com/apple-oss-distributions/xnu/blob/f6217f891ac0bb64f3d375211650a4c1ff8ca1ea/bsd/kern/proc_info.c#L3820)
  remains authoritative: permission or missing-process errors produce unavailable
  CPU, not zero.

## Snapshot and interval contract

The collector retains psutil memory, descriptors and thread measurements and
the separate `psutil_with_darwin_rusage_cpu` identity. It never adds psutil
own-process maxima to Mach totals. Raw snapshots sum each live member's own and
child counters for private diagnosis only. Ordinary `wait4` usage transfers
once; ignored-child usage can transfer twice. A parent may change its signal
disposition, create and lose a child, then restore its disposition entirely
between samples. Endpoint inventories and present flags cannot reconstruct
that history. Dividing every child counter by two would undercount ordinary
reaping; sampling current signal flags cannot correct historical totals.

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

Even a stable raw snapshot records `cpu_seconds=None`, with both descendant
completeness flags false and CPU's sample-minimum flag false. This also applies
when current child counters are zero: it does not authorize later ambiguous
intervals. Query failures retain their specific permission/identity reasons.
Thirty successful memory samples cannot qualify CPU, and no observed-PID CPU
estimate replaces missing complete CPU. A future correction needs independent
lifetime/exit accounting or an enforceable normal-reaping contract for every
parent in the owned tree. Neither exists in the general endpoint sampler.
Escaped/orphaned descendants and the kernel's lost-zombie-statistics condition
remain additional limits, rather than assumptions of zero CPU.
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
checks, not qualification samples or performance estimates. The ignored-child
witness classifies a unique once/twice result using the original 2 ms lower and
20 ms upper discrepancy bounds around each distinct expected value; it neither
widens the ordinary envelope nor rescales measured CPU. Unknown or overlapping
classifications fail. Either recognized class leaves general CPU unavailable.
The existing CI step uses `-rP` to retain finite expected/raw/classification
values for passing correctness witnesses, without process identifiers.

## Retained fifth-checkpoint result

At PR head `96a69725eab018674174dabc6f205a4087d6ff4b` (tested merge
`c9a4b508ec5e9f5e6526990f9a3fad8c8b97646d`), native-wheel run
[35247986691](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986691)
failed these original assertions before wheel build on both Mac targets:

| Target and job | Child process clock | Raw parent child-counter delta | Original result |
| --- | ---: | ---: | --- |
| [ARM / 105292962641](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986691/job/105292962641) | 51,244,000 ns | 102,642,416.6667 ns | 54 passed, 1 skipped, 2 failed |
| [Intel / 105292962768](https://github.com/hashgraph-online/hol-guard/actions/runs/35247986691/job/105292962768) | 189,394,000 ns | 379,164,912 ns | 55 passed, 1 skipped, 1 failed |

Own process-clock conversion and nested `wait4` conservation passed on both.
ARM's second failure was an invalid absent-process test assumption: PID 123
existed but denied metric access. That test now injects `NoSuchProcess`, leaving
the real permission-denied collector behavior unchanged. These original failed
outcomes remain evidence; this source correction is not an actual passing Mac
rerun, exact running-kernel source provenance, or a CPU qualification result.

The correction's focused Linux source checks passed 60 tests with three actual
Darwin witnesses skipped. Scoped reader/collector/fixture typing had zero errors
and 84 warnings; Ruff, formatting and diff checks passed. Independent source
review found no further blocker in missingness, classification or the fixed
PID fixture. These checks do not replace the next actual macOS CI execution.

The MCP component's explicit source inventory additionally hashes both imported
platform CPU reader modules. Its public collector policy remains Linux-only;
this change does not reinterpret historical MCP evidence or pool old and new
source identities.
