# Windows shared command-authority lease repair

The round-three Windows installed-wheel run reached all 17 successful runtime
identity cases, then failed policy publication with the public fallback code
`native_request_invalid_json`. That code concealed the original native control
error; it is not evidence that the JSON was malformed. The separate native
protocol repair preserves a fixed allowlist of control error codes.

Source inspection found a concrete interoperability defect in the Python
authority fence: `shared=True` selected `msvcrt.LK_NBRLCK`. Microsoft documents
that constant as identical to the exclusive `LK_NBLCK` operation in its
[CRT locking constants](https://learn.microsoft.com/en-us/cpp/c-runtime-library/locking-constants?view=msvc-170).
Python could therefore retain an exclusive lease while Rust attempted the
intended overlapping shared lease during publication or command review.
This is a demonstrated primitive mismatch; the exact original installed
failure code remains unavailable until the repaired native diagnostics run.

The Python fence now uses `LockFileEx` on the existing verified private file
descriptor. Shared mode sets `LOCKFILE_FAIL_IMMEDIATELY`; exclusive mode adds
`LOCKFILE_EXCLUSIVE_LOCK`. Both acquire byte zero with length one, overlapping
Rust fs2 0.4.3's whole-file range. `UnlockFileEx` releases that exact range.
The synchronous handle and nonblocking flag prevent a pending operation from
outliving its `OVERLAPPED` structure. Directory binding, ACL checks, retained
file identity, timeout, same-thread reentry and process identity remain owned
by the existing authority fence.

`ci/native_runtime/probe_installed_command_control_lock.py` must run with the
installed Windows interpreter and `-I`. It rejects source/editable imports.
Four cases compare the installed Python authority fence to a separate child
using an independent raw Win32 whole-file lease: shared/shared succeeds;
shared/exclusive, exclusive/shared and exclusive/exclusive contend. Each case
then checks that an exclusive child can acquire after the parent releases.
Only fixed case flags and outcomes are emitted. This probe establishes the
Windows lease ABI and process exclusion; the subsequent default-auto probe
establishes actual installed Python/Rust publisher interoperability.

Local locked Python 3.12 validation: 59 tests passed across the Windows ABI
unit tests, authority I/O, publisher, and review/mutation fence suites. The
real Windows process test skipped on Linux. Ruff passed and BasedPyright
reported zero errors. Real Windows installed results are required before
closing platform acceptance.

## Round-four independent child opening repair

The next installed Windows run (`35206822343`, job `105154527989`, merge source
`f7293abfe50cfb8f6b05e99f3e1b9c0449ada61c`) passed runtime identity again, then
failed with `installed_command_control_lock_child_failed`. Its child stderr
was deliberately withheld, so the original open/lock stage and Win32 code
were not retained and cannot be inferred as an observed result.

Source inspection establishes a separate probe defect: the first production
lock creator retains `DELETE` access, while the independent child's CRT
`os.open` does not share deletion. Windows rejects that combination before
`LockFileEx`; [CreateFileW's sharing contract](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/nf-fileapi-createfilew)
requires sharing compatible with the access rights of every existing handle.
The raw child now opens the existing file with explicit read/write/delete
sharing, matching Rust's opening contract, then runs its independent whole-file
`LockFileEx` operation. Production private-file admission and lease code are
unchanged. The four shared/exclusive expectations and release checks remain.

Failure messages now preserve only the fixed `open`/`lock` stage and a bounded
numeric Win32 error. Unexpected open errors cannot count as successful lock
contention. Local ABI/oracle tests passed (24 tests); the one actual Windows
process test still skips on Linux. A fresh installed Windows job must verify
the corrected child and subsequent Python/Rust publication.
