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

## Seventh observation and isolated setup correction

The independent seventh run `35264203650`, at source
`79cb6921ff722a597b545350485864dcd9310bdc`, now records the original-read
subreason **`metadata_writable`**. It passed four actual Rust tests and 174
Python tests, then retained all 24 timed attempts as unoffered. Sealing and
both uploads succeeded; collection and aggregation correctly failed. This
identifies group or other write permission on the selected Python executable
in this run; it does not retroactively establish the sixth run's subreason.

The setup amendment reuses the existing
`native_slo_interpreter.prepare_private_interpreter` helper after the frozen
`uv sync`, inside the existing five-minute dependency/setup step. It copies
only the selected experiment venv's `bin/python` into an owned `0700` regular
file. The shared hosted interpreter and its permissions are untouched.
The helper verifies byte-for-byte hash equality and source stability;
the scanner's original, unchanged executable admission then verifies the
private copy. Both arms use this same venv and locked dependencies.

Two fixed, isolated interpreter probes compare executable invocation,
version, prefix/base prefix, stdlib/platstdlib paths and the exact venv
configuration digest before and after copying. Each probe has a ten-second
timeout; these are setup checks inside the unchanged step budget. The
provenance and raw path values are retained as `interpreter.json` in the
existing encrypted snapshot. The worker validates its byte identity against
`source.python_sha256` before any offer and retains its canonical hash.
Public projection publishes only this hash, checks it against the exact
sealed record, and rejects a missing, replaced or mismatched required proof.
The hash is per-run setup evidence, not a cross-run source-equivalence key.

An actual local isolated venv test reproduces the writable-source rejection
using an owned copy, then verifies unchanged source metadata/bytes, runtime
identity, stdlib paths, venv configuration and retained environment content.
The test cleans up its own interpreter copies immediately. It does not
modify a hosted executable or run scanner timing work. The pinned GitHub
`uv 0.9.26` workflow still needs the next actual CI observation; the local
correctness test makes no claim that this hosted setup correction has passed.

Separately, seventh native-wheel job `105347152805` passed the corrected
Windows reader selection: 12 reader and five route tests passed, with 25
explicit POSIX-only skips. The whole prebuild selection was 47 passed and
25 skipped; its later installed-job failure is a separate outcome. This is
actual Windows source correctness evidence, not native regex execution on
Windows or an installed/performance qualification result.
