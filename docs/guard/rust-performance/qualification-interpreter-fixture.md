# Qualification interpreter permissions

The frozen baseline in installed performance run
[35220287310, Linux job 105198449863](https://github.com/hashgraph-online/hol-guard/actions/runs/35220287310/job/105198449863)
failed before registered Codex launcher collection with `CodexHookIntegrityError`
at `codex_hook_file_integrity.validate_regular_file`, line 404. Its public
`diagnostic_digest` was
`3a7dada600dc5f78680385a54e01c8ce4ac4c14b77c2cca25d22f2ada6fc1222`.

## Evidence and causal boundary

`failure_evidence` hashes `str(error)`, and `CodexHookIntegrityError` passes its
fixed message unchanged to `RuntimeError`. Hashing the validator's finite set
of role-specific permission messages identifies `interpreter` exactly. The
validator resolves the invocation symlink before checking the executable. It
already permits group write for current-user interpreters and root:root
interpreters; world write is still rejected. The validator file is unchanged
from frozen baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b`.

The CI log reports both venvs using
`/opt/hostedtoolcache/Python/3.12.14/x64/bin/python3.12`, and the runner image is
`ubuntu24/20260907.300`. That image's pinned
[post-deployment configuration](https://github.com/actions/runner-images/blob/ubuntu24/20260907.300/images/ubuntu/scripts/build/configure-system.sh)
recursively sets `/opt` to mode 0777. These facts explain why the shared
interpreter can fail the existing validator even though its root-owned group
write is admitted. This is a source-and-log diagnosis; the failed job did not
retain a direct `stat` observation of the target.

The public artifact 10497305428 contains the failure and build metadata, with
ZIP SHA256
`496a748383d1581ed0d13695a1e410e813c6b57db16bb4a495df3bccce2cd9aa`.
Authorized local decryption of private artifact 10497400342 succeeded. Its ZIP
SHA256 is `854b9014e3e2fde3e4c58cca5864014044589c883009a32d88d5ff6b6f2e7f3e`;
the encrypted archive SHA256 is
`b7c22baf7ad8ac455fb0e9def9de30bbc1a226eff1c67d4cec15250398e7f07b`, and the
recovered manifest SHA256 is
`adf25fc7c811af34b4af150981c6e2a7cbc63f753c31ab822667180e92d92f48`.
The three recovered files contain 772 corpus records and two empty files. None
contains interpreter mode or ownership evidence. No private contents or key
material enter this report.

## Fixture correction

`scripts/native_slo_interpreter.py::prepare_private_interpreter` runs after
creating each qualification venv and before using it for installation or
registration. On POSIX it replaces only that environment's selected
`bin/python` with a byte-identical private 0700 regular executable. It leaves
the shared toolcache executable, frozen source, wheels, and production
validator unchanged. Windows venv executable/ACL provisioning is unchanged.
Both measured arms receive the same preparation outside every timed boundary.

The helper requires an owned, physical venv destination and rejects writable
parent directories, missing venv configuration, nonregular or untrusted-owner
sources, nonexecutables, and sources above 128 MiB. It copies in 1 MiB chunks,
checks source and invocation identities before replacement, verifies copied
SHA256 equality, and removes incomplete temporary files on failure. Its public
proof contains closed ownership classes, POSIX mode/regular/write flags,
byte count, and source/copy SHA256; it contains no filesystem paths. The
builder retains this proof in build metadata and prints it before subsequent
work, so another setup failure still leaves the observed source mode visible.

## Validation and limits

The focused interpreter, corpus-evidence, and workflow tests pass: 17 tests.
They preserve the exact historical diagnostic hash, demonstrate that the
unchanged validator rejects the unsafe shared fixture then accepts the
private copy, verify identical bytes and unchanged shared source metadata,
and exercise concurrent source change, copy I/O failure, bounded-source and
destination refusal. Real venv subprocesses run before and after both regular-file and external
symlink replacement, with identical executable, prefix, base prefix and Python
version. The symlink case uses an owned executable with mode 0777 and a
matching fixture standard-library layout. Ruff and
format checks pass; the new helper has zero type errors or warnings.

The initial real-venv test used symlinks to this sandbox's uid 65534-owned
interpreter while the test runs as uid 0. The helper correctly rejected that
source owner. The test now creates a normal owned venv executable copy before
checking executable/prefix preservation; the helper's ownership rules were
not relaxed.

No installed qualification or latency result is claimed by these source tests.
The next Linux CI run must confirm the actual source-mode proof and complete
registered launcher collection. Mac executable-copy compatibility and Windows
unchanged-path behavior also remain subject to their normal installed CI.
