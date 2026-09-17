# Stopped installed-artifact transition probe

This is source readiness for a separate installed scenario. No successful
GitHub transition run is established by this change, and it supplies no latency
or overall program qualification result. It selectively incorporates the
three transition scripts and two focused tests from
`ae33987d0c8675c36a77375e03419aee920825f6`; it does not merge that branch or
adopt its execution-status claims.

## Scope and installation boundary

The verifier creates a third virtual environment outside the source checkout
and the paired baseline/candidate installations. It installs the candidate's
frozen development dependencies with `--no-install-project`, prepares a
private byte-identical POSIX interpreter, and installs each exact local wheel
with `--no-index --no-deps --force-reinstall`.

The ordered phases are:

1. Clean frozen-baseline installation.
2. Candidate upgrade.
3. Candidate reinstall.
4. Frozen-baseline artifact rollback.
5. Candidate restore.

Every phase runs a fresh isolated worker against the same disposable private
fixture home. There is no repair of failed migrations, authority bootstrap
after the first phase, revision-floor reset, or substitution of a successful
phase for a failed one. A failure stops subsequent installation offers.
The rollback phase is an attempted artifact replacement. It does not establish
version or native-program downgrade support; those flags remain false even
if the five stopped transitions pass.

Before opening the authority store, the worker checks that all imported
production modules originate in its installed wheel, that the package lies
inside the isolated prefix, and that the complete installed package digest
matches the wheel. The verifier separately hashes the wheel's unique bounded
runtime member, checks its build identity/size/digest against the bundled
manifest, and requires the observed native runtime bytes and resolved path to
match that exact bundled executable. The worker repeats installed identity
verification after completing and stopping the phase.

## State and authority observations

The fixture uses a generated production authority key and a generated local
approval password. This is explicit test provisioning, not interactive
enrollment qualification. It commits one real local Ollama control, preserves
its state across replacements, and enables it during the candidate-upgrade
phase. Authority health must remain protected and revisions cannot regress.
A password-authorized stale mutation must raise the exact revision-conflict
error, and readback must show unchanged revision and layers.

Each phase launches the already registered Claude Code PostToolUse command for
one benign and one sensitive-output fixture. It checks native routing, actual
harness delivery, and a freshly captured receipt matching the native edge and
expected runtime identity. Every receipt must become durable and have a new
decision ID. Later phases must preserve the original registration bytes and
all prior complete receipts.

The baseline has no public receipt getter. Its read-only SQL path is admitted
only for exact build `2e672d2d950c6ec471005ddba46e49bba16dc23b`, and only for the
two explicitly audited table shapes. Current baseline receipts pass the
installed baseline validator. A prior candidate binding is compared as a
complete previously validated object; the baseline never claims to interpret
that binding. Candidate getter failures cannot enter the legacy SQL path.

Phase history uses five immutable private checkpoints. Reads enforce a 64 KiB
limit, strict UTF-8 object JSON, unique keys, finite numbers, exact preceding
phase filenames, and stable file identities. Publication is exclusive and
uses the existing POSIX/Windows private evidence backend. These checkpoints
record fixture history; they are not a new rollback-resistant authority.

## Retirement, evidence and failures

The worker uses the production stop path and requires a contained native
retirement plus successful final cleanup. The controller admits phase success
only with a zero process exit, no timeout/output overflow/containment failure,
matching artifact identity, exact receipt counts, preserved registration,
protected authority, and the verified stop observation.

If a launched worker's retirement cannot be verified, the controller stops
subsequent phases and retains its private temporary fixture. It reports the
retention and original worker flags without exposing a path or claiming the
remaining process stopped. Confirmed retired fixtures are removed; cleanup
failure withdraws success while preserving completed phase evidence.

The optional `--private-evidence` argument must name a `private_samples`
directory. It retains the bounded immutable checkpoints as flat private files
for the existing encrypted-evidence workflow. These files contain generated
fixture credentials and exact receipts and must never be publicly uploaded.
The public report contains only reconstructed typed identity/status/count
fields. Unknown child text is discarded; failures retain diagnostic hashes.
A retention error preserves its completed file count, retains the source
fixture under a separate evidence-failure flag, and prevents success. Installer
containment failures also preserve their original timeout/containment/exit
flags and retain the prefix without attempting subsequent phases.

Run this scenario independently of timing pairs. Its CLI accepts the two
immutable wheels/build SHAs, a controller Python interpreter, candidate
`--dependency-root`, `--output`, and optional `--private-evidence`. Build and
workflow integration now uses the independent scenario described below.

## Validation status

The combined transition-driver, receipt and checkpoint tests pass: 93 tests.
The checkpoint helper separately passed 57 helper/backend tests during its
independent implementation. These totals overlap and must not be added.
Ruff, formatting and diff checks pass; the four executable modules have zero
type errors (existing dynamic-JSON and cross-version API warnings remain).
Source review covers the exact-build
receipt compatibility path; final outer-probe review is recorded in the
implementation handoff.

The actual five-phase sequence, preserved stores across frozen/current wheels,
Windows ACL execution, platform-native shutdown, and compatibility of rollback
remain unqualified until installed CI produces retained evidence. Live mixed
generations, replacement during active work, signing changes, interactive
enrollment, and headline timing are outside this scenario.

## Indexed four-platform CI scenario

The `artifact-transitions` job in `native-performance-qualification.yml`
consumes the same run/attempt/target wheel bundle produced by the indexed
build. It does not rebuild either wheel, participate in timing pairs, alter
Ollama results, or contribute to their aggregate gates. Pull requests must be
from the same repository and carry `rust-performance-qualification`; manual
and scheduled runs also offer the scenario. Its platform matrix is the same
Linux musl, Windows MSVC, macOS Intel and macOS ARM matrix as the wheel build.

`scripts/ci/installed_transition_ci.py` saves the five-phase/ten-case denominator
before bundle admission or installation. It verifies the exact checkout SHA,
both wheel/package/runtime identities, candidate lock digest, locked bundle
requirements and the exact Python patch version. The separate transition
environment uses candidate-locked development dependencies for **every**
phase, including baseline phases. Its installed distribution-version digest
must equal the candidate bundle's inventory before the first wheel install.
This is deliberately different from the timing pair's per-arm production
environments; the public scope states that distinction.

Each contained installer, dependency-inventory probe and phase worker retains
its existing 180-second deadline. There are at most thirteen such commands
(39 minutes of nominal command budgets). The scenario step is bounded to 65
minutes; this includes separate finite process cleanup overhead, and does not
redefine a command deadline. The job is 110 minutes; all declared step maxima
sum to 105 minutes, including separate ten-minute archival and four-minute
public/encrypted upload steps.

A complete result requires all five exact ordered phases, ten registered
cases, matching observed artifact/dependency identities, verified retirement,
and all five private checkpoints. Public files contain only bounded
identities, hashes, counts and statuses. The private archive contains the
initial denominator, exact bundle, result and checkpoints. Checkpoint, bundle,
plan and summary commitments are checked against the **same immutable byte
snapshot** passed to encryption. Replaced or missing files still leave the
remaining evidence eligible for encryption, but validation and the final gate
fail. If collection is interrupted, checkpoints alone cannot imply success;
only an already-written validated result may be recovered.

Both public and encrypted uploads run after success or failure, use distinct
artifact names, and are mandatory. The final always-run gate requires the
scenario, sealing and both upload steps to succeed, actual positive artifact
IDs, and the exact archive recipient, file count, byte length and SHA-256.
Raw fixture credentials and receipts are never included in public upload
patterns. Failure to retain evidence cannot qualify a scenario.

Source tests cover bundle/head/lock/interpreter/dependency rejection, all
retirement failures, partial and interrupted evidence, replacement between
validation and encryption, decryption of retained failed bytes, and the actual
workflow shell's rejection of each missing or failed upload. These are source
correctness checks; this change establishes no actual installed platform pass,
latency result, downgrade support or production activation.

The CI-wiring tranche's combined controller, dependency, workflow, existing
transition/checkpoint, bundle, privileged-workflow and archive suite passes
179 tests. Scoped typing of the three changed executable modules reports zero
errors (281 existing/dynamic-interface warnings); Ruff, formatting and diff
checks pass. Independent source review identified and then closed the archive
snapshot race using the exact-snapshot regression vectors described above.
These test totals overlap prior helper totals and must not be added.
