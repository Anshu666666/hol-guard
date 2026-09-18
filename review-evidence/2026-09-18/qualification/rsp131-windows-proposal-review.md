# RSP-131 Windows SQLite observation: independent design review

Disposition: proceed only to a bounded, read-only VFS capability probe on actual
Windows x64. The current proposal does not yet justify installing forwarding
callbacks or claiming persistence counters. No Windows probe, observer, FFI, or
production change was performed in this review.

Reviewed proposal: `rsp131-persistence-observer-proposal.md`. Primary source:
SQLite commit `fd6f5492c4bf98c87476c55bade48934c622c313`, `src/os_win.c`,
Git blob `c9a6f70e0db9dc54dd8318355a61b85f5011c4c9`. This source is a design
reference; it does not establish the installed interpreter's implementation.

The existing separation of VFS requests, Win32 API calls, kernel operations,
accepted write bytes, and physical device writes is correct. Keep those metric
names and the explicit unavailable/partial states.

## Concrete constraints before callbacks

1. **The table belongs to the SQLite instance, not a connection.** In the pinned
   source, `winSetSystemCall`, `winGetSystemCall`, and `winNextSystemCall` ignore
   their VFS argument and operate on one static `aSyscall` table. Setter writes
   are unsynchronized. Hook installation/restoration needs quiescence of all
   users of that SQLite instance and exclusive ownership of table mutation.
   One idle connection, or draining only the measured connection, is insufficient.
   An in-flight counter alone cannot protect a thread that already loaded a
   callback pointer but has not entered it. Establish quiescence before restoring
   or unloading. A separate child limits failure consequences but does not make
   an in-process use-after-unload safe.

2. **Resolve the actual database's VFS.** `sqlite3_vfs_find(NULL)` reports the
   default, which need not be the VFS of an existing or URI-selected connection.
   On a real disposable file database, use documented `SQLITE_FCNTL_VFS_POINTER`
   and require the admitted VFS identity. An unsupported file-control, unexpected
   shim, or mismatched VFS is unavailable. Do not follow `pNext`, mutate the VFS
   struct, replace the VFS, or infer coverage from a matching name alone.

3. **Keep callback code loaded through restoration and complete quiescence.**
   A normal extension unloads when its loading connection closes. Retain that
   anchor connection until every workload connection/thread is drained and all
   pointers are restored and verified. If restoration fails, retain code until
   the dedicated child exits; do not close the anchor first. The documented
   permanent-loading return code is an alternative only if process-lifetime
   retention is explicitly accepted and reported, not described as successful
   unload. Do not enable automatic extension registration.

4. **Restore current pointers, with ownership checks.** In the pinned setter,
   `xSetSystemCall(vfs, name, NULL)` means restore the default, not restore a saved
   NULL current value. Require every admitted target to have a non-NULL current
   pointer. Save exact pointers, verify each still equals the installed wrapper
   before restoration, and verify the restored pointer. Never reset all defaults.
   There is no compare-and-swap API: checking before restoring is safe only under
   the exclusive mutation/quiescence rule. A competing replacement is incomplete
   diagnostic failure, not permission to overwrite another component's pointer.

5. **Preserve both incoming and outgoing last-error state.** Capture incoming
   `GetLastError` before observer bookkeeping and restore it immediately before
   the original function; capture outgoing error immediately after return and
   restore it after bookkeeping. Successful Win32 calls need not clear last
   error. Identity queries, clocks, locks, and helper allocation can change it.
   Use real compiled Windows SDK types and WINAPI signatures; never invoke a
   `sqlite3_syscall_ptr` as its erased `void(void)` type. Preserve outputs and
   the exact original call count. C callbacks must not raise into SQLite.

6. **A non-NULL OVERLAPPED argument is not proof of asynchronous I/O.** The
   pinned normal database open does not set FILE_FLAG_OVERLAPPED, but `winWrite`
   normally passes OVERLAPPED to supply offsets. Those synchronous writes return
   completed byte counts. Separately, the shared-memory open can use
   FILE_FLAG_OVERLAPPED with SQLITE_ENABLE_SETLK_TIMEOUT. Admit by the actual
   open lifetime and flags. ERROR_IO_PENDING is not a completed write or ordinary
   failure; unsupported completion paths must make coverage incomplete. Do not
   read or retain payload buffers or output fields before their documented valid
   point. Retries and partial successful calls remain separate actual calls.

7. **A handle number is not an open lifetime.** A successful CloseHandle can be
   followed by another thread reusing that value before post-call bookkeeping.
   The registry must retain the exact generation captured at call entry and must
   not delete or relabel a newer generation. Concurrent ambiguous reuse must fail
   completeness without changing the application's result. Failed closes retain
   their old generation. Do not hold a bookkeeping lock across blocking I/O to
   simplify this problem. The pinned table has no DuplicateHandle entry: define
   the admitted SQLite-only handle ownership boundary, detect/refuse unknown
   lifetimes, and do not claim arbitrary process-wide handle coverage.

8. **Mapping and sync omissions are observable limitations.** The pinned
   SQLITE_MMAP_READWRITE path can write through memcpy without WriteFile.
   `winSync` can call FlushViewOfFile and FlushFileBuffers separately, or return
   without either under SQLITE_NO_SYNC. Listing WriteFile and FlushFileBuffers
   is not sufficient completeness evidence. Record build/runtime mapping support
   and prove the exercised path or mark the metric incomplete. Changing pragmas
   to avoid those paths would change the measured workload and is not admitted.

## Next bounded Windows probe

Use a qualification-only C extension compiled with checked `sqlite3.h` and
`sqlite3ext.h`, the documented extension entry point and API table supplied by
the actual interpreter. Do not define SQLITE_CORE, link another SQLite engine,
or guess Python/SQLite structure layouts through ctypes. Pin compiler/SDK/header
hashes, target width, interpreter artifact identity, runtime SQLite source ID and
version. Unsupported extension loading or ABI/build mismatch is unavailable.

The dedicated, deadline-bounded child may create one generated file database and
query its VFS pointer. Inspect the version before accessing version-3 fields.
Require non-NULL xGetSystemCall and xNextSystemCall; report xSetSystemCall presence
without invoking it. Enumerate a bounded number of bounded names with duplicate
and cycle detection. Compare xGet results twice and report only stable/non-NULL
booleans, never pointer addresses. Query required names explicitly because the
pinned xNext skips undefined entries. Do not call any returned syscall pointer.

Persist only bounded version/build provenance, VFS name/version, relevant entry
presence, within-probe pointer equality results, and explicit unsupported reasons.
No database path, raw handle/address, SQL text/value, extension-loader exception
text, or environment dump belongs in the receipt. Whitelist or bound strings
derived from runtime metadata. Restore extension-loading permission after loading;
close the probe connection and confirm ordinary extension teardown. This probe
has no installed callbacks, no persistent SQL functions, and no counter claim.

If that proof succeeds, return an exact ABI/pointer/lifetime design plus finite
controls for incoming/outgoing last error, partial success, failed and racing
closes, reused handles, unsupported pending operations, mapping gaps, concurrent
connections, partial installation, and restoration ownership. Only then review
callback implementation. Keep observer overhead separate from existing latency
acceptance and do not subtract measured overhead from reported latency.

## Primary references

- [Pinned Windows implementation](https://github.com/sqlite/sqlite/blob/fd6f5492c4bf98c87476c55bade48934c622c313/src/os_win.c)
- [SQLite VFS structure and version contract](https://sqlite.org/c3ref/vfs.html)
- [SQLite file-control VFS pointer and diagnostic names](https://sqlite.org/c3ref/c_fcntl_begin_atomic_write.html)
- [Documented extension entry and unload lifetime](https://sqlite.org/loadext.html)
- [Windows WriteFile synchronization and completion rules](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-writefile)
- [Windows thread last-error semantics](https://learn.microsoft.com/en-us/windows/win32/api/errhandlingapi/nf-errhandlingapi-getlasterror)

Review scope is source/API analysis only. No actual Windows compilation,
enumeration, persistence experiment, or installed workload was run.
