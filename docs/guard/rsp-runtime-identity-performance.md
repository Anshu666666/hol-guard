# Runtime identity and posture performance: C investigation

The candidate removes repeated executable hashing only while an already verified
Linux child pins the exact installed image on a supported local filesystem.
Fresh process launches still require full executable validation. Platforms and
filesystems without the implemented proof keep full validation. This is a
bounded admission optimization; it is not a new runtime trust root.

The source is `194edcb3b2516d4a76213bec3c3329253a8929da`, based on the integrated
candidate `b9352329b`. The installed comparison uses baseline Python/Rust source
`2e672d2d950c6ec471005ddba46e49bba16dc23b` and candidate Python with the **same
baseline Rust executable**. That deliberate artifact choice isolates the Python
admission change and does not qualify later Rust/J changes in the release.

## Authority and lifetime

`NativeProcessAttestation` binds a specific owned `Popen` object to its Linux
process start marker, parent PID, executable image inode, installed path, full
SHA-256 identity, package version, and exact bounded manifest bytes. Device,
inode, owner, group, mode, size, mtime, and ctime are invalidation checks around
that live image proof. Those stat fields alone never authorize digest reuse.

Every new bundled Linux `auto` stream follows this sequence:

1. Perform the original full-byte runtime and manifest/capability admission with
   attestation reuse disabled.
2. Launch the actual child and verify that `/proc/PID/exe` and the installed path
   identify the same regular executable, with the current parent and start
   marker.
3. Repeat full admission while the actual executable is pinned. Require the same
   full status, package version, manifest binding, image metadata and start marker
   before and after verification. Even an unsupported filesystem must complete
   this new-child comparison before receiving a hook frame.
4. Register reusable proof only on an admitted filesystem. Other filesystems
   retain full status hashing. A registration error closes the child before any
   frame is sent.

An existing attested stream checks its exact registration, process/image/start,
package version and manifest before dispatch. File probes run without the
registry lock; a final exact-object registry check is the success linearization
point, so concurrent retirement cannot return a current proof. Status validation
retires proof on failed binary, manifest, capability, protocol or version checks.
Closing a stream removes registration before termination and cleanup. A changed
executable or manifest retires the pool; the pool's metadata hint grants no
authority to its replacement.

The process captured for a request and its response queue cannot be replaced by
a newly spawned child. If a child exits between status and dispatch, the next
spawn must pass fresh full admission. A cached digest never authorizes a new
process. The Rust managed resident's existing generation, endpoint, peer and
authenticated-state checks remain in place; this work does not replace them
with a Python path cache or count native-unavailable results as evaluated allows.

## Platform proof and limits

| Platform/filesystem | Reuse | Proof and retained work |
| --- | --- | --- |
| Linux ext2/ext3/ext4/xfs/btrfs/tmpfs | Conditional | The actual child pins a fully verified image; its start, image and installation remain bound on each use. The mounted image's filesystem is identified through its opened `/proc/PID/exe` descriptor and mount ID. |
| Linux overlay, network/FUSE filesystems, unknown mount type | No | Full validation remains. The allowlist intentionally excludes filesystems whose remote or copy-up behavior has not been qualified for this proof. |
| macOS | No | Full validation remains. No code-signing/process-image lifetime equivalence is claimed or implemented. |
| Windows | No | Full validation remains. No sharing-mode/process-image lifetime equivalence is claimed or implemented. |

Linux rejects opening a currently executed image for writing with `ETXTBSY`;
`/proc/PID/exe` refers to the executable image. A PID alone is insufficient because
`execve` can replace that image without changing the PID. The implementation
therefore binds both start and image identity and verifies them around full
admission. See [Linux open(2)](https://man7.org/linux/man-pages/man2/open.2.html),
[proc_pid_exe(5)](https://man7.org/linux/man-pages/man5/proc_pid_exe.5.html) and
[execve(2)](https://man7.org/linux/man-pages/man2/execve.2.html). The filesystem
allowlist is a conservative engineering restriction, not a claim that these
sources qualify every filesystem or platform deployment.

The trusted resident-client stream does not replace its own image; its loop
reads a frame, invokes the existing resident transport and writes a response.
This proof does not attempt to defend against a compromised kernel, privileged
process tracing or a compromised already executing trusted runtime. It preserves
the existing package/manifest trust model. A platform permission/proc inspection
failure cannot manufacture a reusable identity. OS ownership and signing/update
transitions still require testing on real release targets.

## Installed measurement method

`scripts/bench_guard_runtime_identity.py` runs with `python -I` in an isolated
installed wheel environment and rejects native binary/mode/test overrides. It
checks the loaded package location and manifest against the actual binary bytes.
Instrumentation counts real `_validate_binary` calls, SHA-256 update bytes,
manifest opens, package-version lookups and capability-cache hits/misses.

The baseline artifact is 6,171,560 bytes, SHA-256
`d3b3613713db36ea5ac836288a33ea03ab1d5e309cb3bba3575c0e315eb0a8b3`.
Both sides use version 3.0.1, Rust 1.88.0, CPython 3.12.14, the same locked Python
dependencies and the same runtime rule digest and build SHA. The paired runs
install both wheels on executable tmpfs. A separate overlay installation and a
candidate with no retained child test full-validation fallback.

`--live-client` starts the actual installed `resident-client-stream` child before
timing, then submits no hook frame. This is an installed **status component**
measurement; it excludes imports, interpreter startup, child launch/admission,
resident socket connection, hook evaluation, response validation and teardown.
CPU is the Python process's CPU, not process-tree CPU. The hash wrapper adds a
small instrumentation cost on both sides. A capability-cache hit is reported
separately from digest reuse.

Five independent pairs of 1,000 status calls alternate baseline/candidate order
under the shared measurement lock. An earlier batch overlapped another task's
tests and is excluded from the final paired timing evidence. Shared-host timings
remain diagnostic; they are not substituted for installed managed-hook latency,
memory, CPU-tree or all-platform acceptance. This host cannot create the local
resident socket required for that qualification.

Measured results and artifact provenance are recorded in
`performance/rsp-runtime-identity-source-evidence.json`.

| Installed status component | Baseline | Candidate with an attested tmpfs child |
| --- | ---: | ---: |
| Independent processes × warm status calls | 5 × 1,000 | 5 × 1,000 |
| Full executable validations | 5,000 | 0 |
| Executable bytes hashed | 30,857,800,000 | 0 |
| Manifest opens per status | 1 | 2 |
| Package-version lookups per status | 2 | 3 |
| Median of per-process CPU medians | 7.8113445 ms | 2.1654495 ms |
| Range of per-process CPU medians | 7.396177–10.0570905 ms | 2.1216835–2.1988915 ms |

The ratio of those CPU medians decreased by **72.28%** in this component. Pairwise
reductions ranged from 70.27% to 78.47%; these are observations, not confidence
intervals. The baseline variation remains visible despite serialization. The
candidate retains additional small-manifest/package checks to establish the
live proof instead of silently dropping validation. Raw per-call CPU/wall
samples are committed in `performance/rsp-runtime-identity-samples.jsonl` and
bound by SHA-256 in the aggregate report.

Both controls retained exactly 1,000 full validations and 6,171,560,000 executable
bytes hashed for 1,000 warm statuses: the installed overlay candidate with a live
child and the tmpfs candidate without a retained child. Their observed CPU
medians were 7.8976445 ms and 8.2924565 ms respectively. These controls show that
a warm capability cache or an unsupported live child alone cannot enable reuse.
Cold capability status also retained a full hash; no startup benefit is claimed.

## Request-time posture attribution

`scripts/bench_guard_posture_config.py` invokes the installed
`HookWorkerNativeMixin._review_native_edge`, supplies synthetic acknowledged or
missing bindings, and stops at its first native transport call. Real temporary
home/workspace TOML files and the real configuration loader are used. No decision
is fabricated. The report counts loader calls and exact home/workspace file
opens; nested loader CPU must not be added to total component CPU.

The integrated candidate already short-circuits the recording-only check when
an acknowledged snapshot's mode is `observe`. Enforce and missing-binding cases
still read current configuration. An enforce binding followed by a local Watch
change therefore retains the prior immediate recording-only behavior; an
observe binding followed by protected configuration remains observe until the
new binding is acknowledged. Removing all remaining reads would require choosing
and testing a different coherent visibility contract for these transitions.
That behavior change is not hidden inside the executable identity optimization.

| Posture slice case | Baseline config loads/home opens/workspace opens per call | Candidate per call | Delivered observe flag at native boundary |
| --- | --- | --- | --- |
| Acknowledged observe; local Watch | 1 / 1 / 1 | 0 / 0 / 0 | true |
| Acknowledged observe; local protected before new acknowledgement | 1 / 1 / 1 | 0 / 0 / 0 | true |
| Acknowledged enforce; local protected | 1 / 1 / 1 | 1 / 1 / 1 | false |
| Acknowledged enforce; local Watch before new acknowledgement | 1 / 1 / 1 | 1 / 1 / 1 | true |
| Missing acknowledgement; local protected | 1 / 1 / 1 | 1 / 1 / 1 | false |
| Missing acknowledgement; local Watch | 1 / 1 / 1 | 1 / 1 / 1 | true |
| Missing acknowledgement and no config files | 1 / 0 / 0 | 1 / 0 / 0 | false |

Each case has five blocks of 1,000 calls. The acknowledged-observe/Watch slice's
median of CPU medians was 0.244091 ms baseline and 0.001844 ms candidate. Unchanged
branches also varied in timing between processes, so the report attributes
this shortcut through its exact read counts and does not assign a performance
gain to unchanged configuration code. The fixtures exercise a strict workspace
security-level overlay; they do not replace publication or race/load tests.

## Validation and remaining acceptance

Focused validation at the source commit: **59 passed, 1 skipped**, Ruff passed,
and scoped type checking reported zero errors (103 warnings).
The skip is the actual owner-change fixture: this host's UID mapping rejects
the requested `chown` with `EINVAL`. The test remains enabled on hosts that can
exercise that transition. Tests cover same-size replacement, restored mtime,
symlink rebinding, executable/manifest permissions, exact manifest changes,
package drift, exit, changed start marker, concurrent replacement, concurrent
retirement, failed capabilities, invalid/throwing post-spawn verification, and
death between cached status and dispatch. macOS/Windows fallback routing is
checked without claiming those unit branches are real-platform qualification.

The independent review's concrete retirement race was corrected and given a
deterministic process/path regression test. Linux new-child full verification
also runs before unsupported-filesystem fallback, and verifier exceptions close
the child before dispatch.

| TODO range | Evidence status |
| --- | --- |
| RSP-025 | Status-component counts and timing measured on installed wheels. Ordinary evaluated warm/cold hook attribution remains open. |
| RSP-026 | Narrow Linux live-image design selected with explicit unsupported-platform fallback and documented limits. |
| RSP-027 | Implemented for the admitted Linux lifetime; broader installed release qualification remains open. |
| RSP-028 | Replacement/race regressions implemented; actual owner transition is skipped on this host and must run on an eligible target. |
| RSP-029 | All-target signing/freeze, refreshed manifests, rollback and first-request-after-update qualification remains open. |
| RSP-030 | Installed posture-slice attribution measured; full ordinary-route share and concurrent transition qualification remain open. |
| RSP-031–034 | Existing acknowledged observe shortcut is measured. Complete posture visibility, transformation ownership and transition/load acceptance remain open. |
| RSP-035 | No local managed resident socket or process-tree before/after qualification; run on release targets. |
| RSP-036 | Only proven repeated hashing is removed on eligible live generations. Other validation is retained; broad retirement acceptance remains conditional on RSP-035. |

The measured optimization avoids repeated work already performed by native
cryptographic code; moving the Python wrapper into another Rust boundary is not
required for that saving. No general native-port go/no-go is inferred from this
component result. Ship/activation qualification still requires the installed
ordinary-route gates, update defenses and supported-platform matrix above.
