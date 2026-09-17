# Scanner executable admission diagnostics

The sixth scanner smoke run, `35257232537`, used source
`9d3907a2e6ed1ec201281901cb878836a7dad32d` and merge
`64164db9cd11e3d05182a99dba100daa6011c83d`, with equal tree
`833ea191211db2a0613db8520d072f5edf485380`. Its shard
`105323827159` passed four actual Rust tests and 95 selected Python tests,
including all five new native working-input cases. Collection then failed
at `python_executable_identity_failed`, before correctness preflight or
any timed offer. All 24 planned attempts remain unoffered. Public and
encrypted uploads succeeded; collection and aggregate gates failed.

The retained encrypted snapshot has only `plan.json` and `worker.json`.
The latter records the stage, without executable metadata or a narrower
cause. Root ownership, writable permission bits, binary size, and identity
replacement are therefore **not established explanations** of that failure.
The original evidence is unchanged.

The next source amendment retains the reason from the original executable
admission/read. Public output permits only one of 17 fixed reason codes,
under the existing Python/native executable failure stage. Historical
records lacking a subreason remain unknown. Unknown codes, unexpected
public fields, and reasons attached to successful or unrelated failures
are rejected. The fixed attempt denominator and all completion, benefit,
and installed-qualification gates are unchanged.

Private diagnostic records contain only a finite operation phase, bounded
numeric errno, bytes read, a cleanup-failure boolean, and metadata already
obtained by the original path/descriptor operations. Each metadata snapshot
has fixed numeric device, inode, mode, owner, group, link-count, size, mtime
and ctime fields; out-of-domain numbers are explicitly unavailable. These
records use the existing encrypted snapshot and retention path. No raw
path, exception text, extra filesystem observation, retry, or toolchain
copy is introduced to identify a cause.

Executable admission still requires a resolved regular executable, current
or root ownership, no group/other write permission, positive link count,
and size from one byte through 64 MiB. Exact before/open/final identities
and the overflow-byte read bound remain mandatory. Existing root-owned
interpreters and Cargo hardlinks remain permitted. Private archive readers
retain their separate, stricter ownership/link contract.

Cleanup still attempts to close the original descriptor. A close failure
cannot turn a successful hash into success; if a read already failed, its
original cause remains primary and cleanup failure is retained separately.
Tests use actual temporary executable files and injected individual I/O
faults to verify the original-read metadata, no retries, exact cause
retention, encrypted/private projection boundaries, and 24 unoffered rows.
This diagnostic amendment does not establish that the next hosted run will
pass, select a native scanner, or satisfy installed/performance acceptance.
