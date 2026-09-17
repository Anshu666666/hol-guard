# Runtime identity and posture performance: C investigation

The candidate removes repeated executable hashing only while an already verified
Linux child pins the exact installed image on a supported local filesystem.
Fresh process launches still require full executable validation. Platforms and
filesystems without the implemented proof keep full validation. This is a
bounded admission optimization; it is not a new runtime trust root.

The measured source is `194edcb3b2516d4a76213bec3c3329253a8929da`, based on the integrated
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
2. Launch the actual child and inspect whether `/proc/PID/exe` and the installed
   path identify the same regular executable, with the current parent and start
   marker. A typed unavailable inspection is separate from an observed mismatch.
3. Repeat full admission while the actual executable is pinned. Require the same
   full status, package version, manifest binding and safe installation metadata
   before and after verification. Any observed image/start mismatch rejects the
   child. An unavailable kernel inspection retains full validation and cannot
   create a reusable proof. Even a fallback child must complete full admission
   before receiving a hook frame.
4. Register reusable proof only on an admitted filesystem. Other filesystems
   retain full status hashing. A failed identity/admission check closes the child
   before any frame is sent; lack of a reusable cache slot does not deny admission.

`/proc` inspection errors `EACCES`, `EPERM`, `ENOENT`, `ENOSYS` and `ENOTSUP` are
typed unsupported when the owned child remains live. Errors reading installation
metadata are never classified this way. Observed PID, parent, start or image
mismatches, unsafe owner/mode, malformed process metadata, unexpected I/O errors,
process exit, or failed full manifest/package/executable validation still reject
the child. An unsupported child is registered only as a blocker for digest reuse
on its path; it grants no identity authority. A final locked check prevents a
blocker registered during file probes from permitting a cached return.

Reusable attestations and full-validation blockers share a 256-entry bound. If
that registry saturates, full admission succeeds and digest reuse is disabled
for the remaining Python process lifetime. The latch avoids both rejecting a
fully admitted child and retaining an unbounded overflow registry. Existing
streams remain usable, but every later status performs full validation, including
after entries are retired. Only restarting the Python process resets the latch.

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
| Linux unavailable `/proc` image/start inspection | No | Full pre-launch and post-launch admission remains; a live fallback client prevents path-level digest reuse. Observed mismatches still reject. |
| Identity registry saturation | No for the remaining Python process lifetime | Full admission continues. A constant-size latch blocks reuse even for untracked clients; no valid child is rejected to preserve a cache slot. |
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
failure cannot manufacture a reusable identity. The unavailable-inspection
fallback preserves the prior full-validation admission contract without claiming
that the kernel established image proof. OS ownership and signing/update
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

The candidate measured in this report short-circuited the recording-only check when
an acknowledged snapshot's mode is `observe`. Enforce and missing-binding cases
still read current configuration. An enforce binding followed by a local Watch
change therefore retains the prior immediate recording-only behavior; an
observe binding followed by protected configuration remains observe until the
new binding is acknowledged. Removing all remaining reads would require choosing
and testing a different coherent visibility contract for these transitions.
That behavior change was not hidden inside the executable identity optimization.

**Superseded transition contract:** the later RSP-031
[acknowledged posture correction](rust-performance/acknowledged-posture-contract.md)
uses the sampled resident-ACKed mode for ordinary native delivery in both
directions. A local Watch update now awaits its ACK; missing acknowledgement
keeps the separate ordinary availability response. The table and timing results
below remain historical observations of the earlier asymmetric implementation,
not measurements of the correction.

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

The `Native runtime identity` workflow now selects the Linux live-image and
unsupported-inspection suites as well as the manifest contracts. A separate
hosted Linux invocation runs only the copied-executable ownership-transition
fixture with `sudo`, so an ordinary unprivileged runner does not silently skip
that transition. The fixture changes its disposable executable, not an installed
runtime or other host file.

All four existing native-wheel targets (Linux x64, macOS x64/arm64, Windows x64)
now invoke `ci/native_runtime/probe_installed_runtime_identity.py` with the actual
wheel interpreter and `-I`. This probe rejects editable imports and native/test
environment overrides. It counts full validations and actual SHA-256 input bytes
for three status calls per steady phase, starts real bundled stdio children,
checks exit/restart, replaces the image with identical bytes and restored mtime,
rejects manifest build/version mismatches and same-size byte corruption, and
restores the original artifact before a fresh child starts. macOS and Windows
must retain full status hashing; Linux reuses a digest only when it obtains an
eligible live proof. Windows may deny replacement of a live image; in that case
the probe records the OS denial and requires fresh admission after containment
and replacement. The fixed corpus accepts at most a 64 MiB executable and a
16 KiB manifest, and restores modified files in `finally`.

Each wheel job uploads `native-installed-identity.json`. This is an installed
status/stdio-child check: it sends no hook frame, opens no resident socket and
claims no latency or signing result. Its replacement/restoration cases use one
real wheel artifact. Upgrade and rollback between different signed release
versions remain unqualified until that two-artifact release matrix runs.

The probe's local implementation check passed all 17 recorded cases on Linux
with an installed tmpfs wheel containing the integrated Python implementation
from `bdb502bf8` and the unchanged baseline Rust binary from `2e672d2`. Its
[receipt](performance/rsp-installed-runtime-identity-linux-source-evidence.json)
binds the exact Python modules, manifest and 6,171,560-byte executable by SHA-256.
Three warm statuses with an eligible live proof hashed zero executable bytes;
each new or restarted child required two full validations (12,343,120 bytes).
Replacement-first status and corruption rejection each hashed all 6,171,560
bytes. These are operation counts, not new timing results or qualification of
the later native command program. The selected manifest/live/proc source suite
passed 60 tests with the existing ownership-fixture skip, and both digest-proxy
regressions passed. Scoped probe/diagnostic types reported zero errors (56
warnings), and the workflow policy checker passed. The four hosted target
results remain pending their next CI run.

The subsequent hardened-Linux and registry-capacity corrections are verified by
fault-injected `EACCES`/`EPERM`/`ENOENT`/`ENOSYS`/`ENOTSUP` at both process-stat and
image inspection, actual live children, exact pre/post/warm validation counts,
concurrent reuse-blocker registration, safe cache saturation, and affirmative
PID/start/inode/owner/mode rejection. This subsequent focused run passed **86
tests, with 1 ownership-fixture skip**; Ruff passed and scoped type checking
reported zero errors (40 warnings). The installed timing evidence above remains
bound to its recorded source; no updated timing or ordinary-route qualification
is inferred from these additional fallback tests.

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
