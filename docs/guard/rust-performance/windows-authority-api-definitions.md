# Windows authority FFI setup

The retained Windows installed Ollama report from run `35220287310`, job
`105198450037`, candidate `107606388ad55f924a4e2924b4ff84e5fa08e6ff`, failed
the existing 400 ms readiness limit during the disable transition. Ten native
cases had completed. The next binding expected local control revision 2, but
the retained binding still had revision 1 and generation 2 at 406 ms. A sampled
publisher stack passed through `_windows_dll`, directory binding, private-state
reading, and committed authority projection. This stack identifies work to
inspect; it does not establish which operation caused the elapsed time.

Source inspection found repeated `ctypes.WinDLL` construction, fresh ctypes
information-layout classes, and repeated assignment of four open-function
signatures for every handle open. The change retains only these definitions:

- Two fixed DLL wrappers, `kernel32` and `advapi32`, scoped to the current PID
  and exact loader object. Unknown names retain the previous uncached behavior.
- The two ctypes structure classes for file information and security attributes.
  Every operation still creates its own structure instance.
- One open-function tuple, reused only for the exact DLL and information-class
  identities. A replaced façade definition rebuilds the tuple.

Locks serialize first construction. Failed loads and failed signature setup do
not publish a new cache entry. Stable information classes are necessary when
sharing the DLL wrapper: otherwise concurrent calls could change a shared
function's pointer signature to different per-call ctypes classes.

The DLLs retain `use_last_error=True`. Python documents that this uses a
thread-local error copy and that DLL attribute lookup already caches function
objects within one wrapper. The Windows-only regression checks independent
error codes across eight threads using the shared wrapper. See the
[Python 3.12 ctypes loading contract](https://docs.python.org/3.12/library/ctypes.html#loading-shared-libraries).

No handle, directory binding, SID, descriptor, ACL result, file bytes, policy,
control revision, authority signature, or readiness decision enters the cache.
All ancestor opens and per-handle validation remain in place. Fault-injected
tests warm the definitions and then reject changed handle metadata and a later
owner/ACL failure. Windows-only tests read an updated private-state file through
fresh handles, run concurrent reads, reject a subsequently oversized file, and
read its valid replacement.

The setup-count witness makes 101 requests for the same open definitions and
observes eight signature assignments in total, the four pairs needed for one
setup. Replacing the information class performs the next eight assignments.
The fixed-library test makes 101 requests for each known DLL and observes one
loader invocation per DLL. These are deterministic operation counts, not a
latency estimate or proof that the readiness failure is resolved.

The Windows resident workflow runs the real Windows regressions before its
runtime build. Actual Windows execution and installed Ollama readiness remain
CI obligations. The 400 ms readiness limit, request deadlines, source binding,
security validation, and performance acceptance thresholds are unchanged.

Local validation on Linux: the final focused definition suite passed 11 tests
and skipped its two Windows-only cases. The first broader snapshot/authority
run passed 106 tests with three skips. After the remaining cache regressions
were added, the broader run passed 108 tests with three skips and failed
`test_publisher_startup_ack_and_mutation_push`: its existing two-second wait
after a configuration mutation ended with no ready snapshot. The exact test
subsequently passed in isolation on both the candidate (1.13 s) and unchanged
source (1.34 s). The broader failure remains unexplained; these isolated passes
do not erase it or establish that it was a pre-existing failure. No limit was
changed. Scoped production type checking reported zero errors and 248 warnings;
Ruff, formatting, workflow selection/order checks, and whitespace checks passed.
