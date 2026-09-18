# Windows discovery producer privacy

The sixth installed Claude cohort at source `9d3907a2e6ed1ec201281901cb878836a7dad32d`
reported the same independent current-state witness in all five Windows jobs:
the Guard directory passed; discovery key and state file security checks were
rejected; config/key/state reads, state authentication and peer identity passed.
All five first native benign preflights returned availability. These observations
do not identify the exact failure within those native requests.

The experiment creates its Guard directory before constructing the store, then
`prepare_empty_command_authority` synchronously enters the existing Windows
private-directory provisioning path before daemon construction. The observed
directory pass therefore does not depend on an asynchronous publisher or on any
new fixture repair in this correction.

Source inspection separately identified that discovery-key creation and daemon
state replacement used POSIX modes without establishing a Windows private DACL.
Fresh Windows producers now create private files with the existing current-user
and SYSTEM descriptor, retain verified no-reparse ancestor handles, flush a
complete temporary, and publish through handle-relative rename. The producers
verify existing parents without repairing them. Generic config/store/start-lock setup creates
missing directories privately at birth and preserves existing-directory behavior.

The seventh Windows packaged bootstrap exposed a separate ordering requirement:
an ordinary pre-existing Guard home reaches daemon state clearing before any
synchronous directory provisioning. The daemon manager's existing
`_ensure_private_directory` operation now explicitly provisions that parent on
Windows. Shared directory helpers preserve their defaults; only this manager
operation selects parent-only provisioning. New directories remain private at
birth, and already-private directories need no ACL write.

An existing nonprivate parent must have an owner accepted by the established
current-principal/SYSTEM/Administrators contract. Its retained ancestry remains
open while the final directory is reopened exclusively for the ACL change. The
exclusive handle must identify the same directory, and its owner is checked again
before the setter. Restoring the ordinary directory barrier requires the same
identity and a private DACL. Missing identity, unavailable security metadata,
foreign ownership, or failed exclusive acquisition cannot trigger a fallback ACL
write. Contending directory handles can therefore cause provisioning to fail.

The eighth attempt showed that exclusive access alone does not preserve child
security with `SetSecurityInfo`: all five Windows launcher jobs failed the first
child snapshot comparison. The direct key and nested directory retained bytes,
identity and owner/group SIDs, but their inherited ACE flags were cleared and
their DACLs became protected. Each job completed 101 correctness tests, skipped
six platform cases, failed this one regression and offered no launcher samples.
The grandchild's security was unchanged. Those failures remain evidence.
Separately, eighth Main job `105366900597` passed the packaged Windows Core
bootstrap regression (`1 passed in 52.63s`) with its ordinary-directory setup.

Parent-only provisioning now selects the documented
[NtSetSecurityObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetsecurityobject)
user-mode operation with the existing exclusive handle and complete self-relative
descriptor. Its flags select only the DACL and DACL protection; ownership is
verified but never reassigned. An unavailable entry point or unsuccessful status
fails without a fallback setter. Shared `SetSecurityInfo` callers retain their
existing behavior. `SetKernelObjectSecurity` is not selected because its Microsoft
documentation advises against filesystem use.

This operation does not enumerate, open, rewrite or repair children. The live
Windows regression keeps its exact comparison of existing key and nested-child
bytes, file identities, raw owner/group SIDs, DACL bytes and descriptor control;
the inherited key must still be rejected. A separate regression exercises an
ordinary existing directory followed by fresh key/state publication. The existing
packaged bootstrap test keeps its ordinary-directory setup. The new setter must
pass these actual Windows checks before child preservation or the platform
bootstrap correction can be claimed.

Key publication remains exclusive. The existing-key branch and raced-winner read
retain their prior behavior; they do not repair, rewrite, rotate or newly attest
legacy keys. A legacy key can therefore remain outside the dormant native
launcher's supported privacy contract. State publication replaces the complete
new payload without reading or repairing the old destination. Windows UTF-8/CRLF
serialization, state fields, signing domain and POSIX paths remain unchanged.

The shared atomic helper's existing callers retain destination repair by default;
discovery explicitly disables it. Source and committed-file identity/DACL checks
still apply. A compatible rename-parent handle is acquired and matched to the
retained directory before its no-delete barrier is released; restoration checks
that identity again. Successful rename is recorded before restoration, so a later
failure cannot delete the committed file as temporary cleanup.

The rename-parent access follows Microsoft's documented traverse/read-attribute
guidance for [FILE_RENAME_INFORMATION](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information).
Focused tests cover no-clobber collision, unchanged existing keys, parent rejection,
handle lifetime and identity failures, and CRLF/signature preservation. A live
Windows test exercises fresh configuration followed by key/state publication;
execution on Windows remains required before claiming the cohort is repaired.

The permanent I/O contract inventories the new generic setup function's single
`is_dir` observation as synchronous discovery setup. The classification names
that exact function and primitive; source/content reads, nested functions and
neighboring helpers remain unclassified. The existence check does not admit a
key or establish private ancestry: the producer still verifies and retains its
parent binding. The exception is imported from its defining constants module,
preserving its exact class identity while making ownership analysis explicit.

## Ninth attempt and later test diagnostics

The ninth published head was `d33f64d5fb86a3f2baa6848382ce763e2ed9fc59`;
GitHub tested merge `009c7253ce2e132bffaea837b23b0a36b9bc16c2`, whose tree
matched the published tree. In installed Claude
[run 35275855558, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855558/attempts/1),
all five Windows jobs (`105386195483`, `105386195442`, `105386195367`,
`105386195341`, `105386195589`) again failed the original first child-snapshot
comparison: each reported **107 passed, 6 skipped, 1 failed**. These jobs offered
none of their 440 planned launcher requests. The `NtSetSecurityObject` source
change therefore has not demonstrated child preservation.

The direct key and nested directory retained file identities, owner/group SID
bytes and their existing file contents where applicable. The key's ACE flags
changed from `0x10` to `0x00`, and the nested directory's from `0x13` to `0x03`;
their descriptor control changed from `0x8004` to `0x9004`. The grandchild's
snapshot was unchanged. These are observations from the existing
`GetSecurityInfo` snapshots; they do not identify the operation responsible or
establish whether a stored-descriptor change, read side effect or representation
difference explains the failure. No assertion was normalized or waived.

Separately, ninth Main
[Windows job 105386195146](https://github.com/hashgraph-online/hol-guard/actions/runs/35275855362/job/105386195146)
passed its cross-platform suite (246 passed, 5 skipped) and Codex bridge smoke
(2 passed, 14 deselected), then failed the packaged bootstrap regression
(`1 failed in 30.80s`). Initial bootstrap, the first running-status assertion and
the first stop passed; the second bootstrap returned the expected schema, but
its original status reported `running=false`. That attempt did not retain the
other status fields. It supplies no evidence connecting this separate failure
to child security, and it does not replace the historical eighth bootstrap pass.

Later test-only commit `9987ab0ea2ac8728e1b10fadf89e1bec04d8212b` preserves
every original assertion, product call and stopping point. It adds four fixed
observation stages—before key verification, after key verification, after manager
provisioning and after discovery binding—for the three fixed children. Each
stage brackets an added `GetSecurityInfo` snapshot with the documented
[NtQuerySecurityObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject)
read: one 65,536-byte buffer per query, owner/group/DACL only, exact successful
status, no retry and handle closure on every outcome. At most 12 finite rows
retain equality predicates, control/revision, ACE flags/counts and query status;
descriptor bytes, SIDs, contents and paths stay local. Whole-descriptor byte
inequality alone is not an access-change finding. Missing, invalid and over-cap
observations remain explicit unknowns.

Both witnesses emit only on the original failure and preserve that exception
even if emission fails. The packaged test projects only its already-returned
retry-status object into fixed booleans and closed lifecycle labels; it adds no
status request, wait, deadline change or retry. Local source validation reported
107 passed and 7 platform skips, with Ruff check/format and unchanged-original-
assertion AST checks passing. **These added diagnostics have not executed on
Windows.** They change no production setter, establish no failure cause and
provide no new performance or platform qualification evidence.


## Tenth attempt: descriptor observations and bootstrap outcome

The tenth source was `095074cda6a751ffaf12b070ecc46a3091f12471`, with tree
`04d79da9c1cf212cce263c202bfdd5b4350007e3`. Installed Claude used that
published head; Main used merge `9e85de6f42910785e7ba4b53198ddcc05672607c`,
whose tree matched it. In installed Claude
[run 35283193497, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35283193497/attempts/1),
all five Windows jobs (`105409584340`, `105409584224`, `105409584304`,
`105409584231`, `105409584286`, runs 0–4 respectively) again failed the
original first child-snapshot equality assertion. Each reported **107 passed,
6 skipped, 1 failed**. Build/comparison stayed skipped; the five receipts reported
`no_observations`, zero files and no archive, leaving 440 planned requests unoffered.

All five new security witnesses were identical and complete: four stages for
three children, successful bounded native queries throughout. Every 148-byte
`NtQuerySecurityObject` descriptor matched its initial native-query bytes at all
stages. The two native queries bracketing each added `GetSecurityInfo` read
also matched each other.
File identities, owner/group SID bytes and file contents where applicable stayed
equal to the original snapshots. The observed API representations were:

| Object | Native query at every stage | Get before/after key verification | Get after manager and discovery binding |
| --- | --- | --- | --- |
| Direct key | Control `0x8004`; ACE flags `0x00` × 3 | Control `0x8004`; flags `0x10` × 3 | Control `0x9004`; flags `0x00` × 3 |
| Nested directory | Control `0x8004`; flags `0x03` × 3 | Control `0x8004`; flags `0x13` × 3 | Control `0x9004`; flags `0x03` × 3 |
| Grandchild | Control `0x8004`; flags `0x00` × 3 | Control `0x8004`; flags `0x10` × 3 | Control `0x8004`; flags `0x10` × 3 |

The native and Get representations already differed before provisioning. The
Get-only difference for the direct children first appeared after the manager
operation; the subsequent discovery binding added no observed change. These
measurements show unchanged native descriptor bytes at the observation points.
They do not show a stored child-descriptor mutation or identify an internal
Windows conversion routine. Microsoft's documented
[inheritance conversion](https://learn.microsoft.com/en-us/windows/win32/api/securitybaseapi/nf-securitybaseapi-converttoautoinheritprivateobjectsecurity)
can derive inheritance annotations from a parent while producing an equivalent
security descriptor; that is context for the distinction, not a traced call
inside `GetSecurityInfo`. The original equality gate remains failed, and no
flags were masked, children repaired or production setter changed.

Separately, tenth Main
[Windows job 105409585814](https://github.com/hashgraph-online/hol-guard/actions/runs/35283194145/job/105409585814)
passed cross-platform regressions (246 passed, 5 skipped in 28.01s), Codex bridge
smoke (2 passed, 14 deselected in 1.98s), and the packaged bootstrap regression
(**1 passed in 53.60s**). This preserves the ninth retry-status failure as a prior
observation; it supplies no new cause for that failure. The passing packaged
bootstrap does not qualify the unoffered installed launcher requests.

## Later source correction: exact native preservation oracle

The child-preservation test now compares the complete native self-relative
descriptor returned by
[NtQuerySecurityObject](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntquerysecurityobject),
alongside the original file identity and exact file contents. Microsoft's
contract specifies a copied self-relative descriptor and the returned byte
length. Owner/group/DACL are queried with the same `0x7` selection as the prior
Get snapshot; SACL is outside both tests' scope. This choice follows the five
identical tenth witnesses: native bytes stayed equal at every observation,
while the Get representation for direct children changed after provisioning.
It makes no claim about an undocumented implementation inside `GetSecurityInfo`.

Both preservation assertions compare every returned byte, including control,
ACE inheritance flags, reserved bytes and padding. No flags are masked and no
child is repaired. Query status, descriptor format, identity or payload-read
failures fail the test; the read handle closes on every outcome. Get snapshots
and the four-stage finite failure witness remain separate diagnostics. Parent
identity, discovery-key value and strict legacy-key rejection before and after
the existing product calls remain unchanged. Production setters, requests,
timeouts and retries are unchanged.

Focused regressions distinguish a Get-only representation difference from a
changed native protection bit, inherited ACE flag, access mask, owner, group,
reserved byte, padding, file identity or payload. They also reject mutation
during discovery-key loading and unexpected admission of the legacy key. Local
validation reported **78 passed, 6 platform skips**, with Ruff check/format and
diff checks passing; independent source/security review was clear. **The revised
preservation oracle still requires execution on Windows.** Historical eighth,
ninth and tenth failures remain recorded; this source correction establishes no
new launcher or performance qualification.

## Eleventh attempt: native preservation passes; launcher ambiguity retained

The eleventh published head was `23bef02c5edd2fb24dbfec768a9dbd5e80c2b31d`,
with tree `e3fa69336ff37d8e91add1ecd0a5a89b5cca35d9`. Installed Claude
[run 35287995010, attempt 1](https://github.com/hashgraph-online/hol-guard/actions/runs/35287995010/attempts/1)
executed the revised preservation oracle on all five Windows jobs:

| Run | Windows job | Contract-suite result |
| --- | --- | --- |
| 0 | `105424489043` | 108 passed, 6 skipped in 8.14s |
| 1 | `105424488769` | 108 passed, 6 skipped in 9.29s |
| 2 | `105424488978` | 108 passed, 6 skipped in 8.19s |
| 3 | `105424489027` | 108 passed, 6 skipped in 7.57s |
| 4 | `105424489054` | 108 passed, 6 skipped in 7.28s |

These are actual Windows source-contract executions before wheel construction.
Both child-preservation comparisons passed with complete native descriptor bytes,
file identity and payload equality. Parent identity, discovery-key value and
strict legacy-key rejection before and after provisioning remained asserted and
passed. Get-derived snapshots remain diagnostic. This closes the execution gap
for the test correction described above; it introduces no production setter
change. The original eighth, ninth and tenth failed attempts and their unoffered
requests remain historical evidence.

The later installed-wheel launcher comparison is a separate result: **19 jobs
succeeded and one failed**. All 15 POSIX jobs and Windows runs 0–3 completed
88 planned requests each, including 80 timed requests. Windows run 4 reached
78 of 88 planned attempts: 77 completed, one failed and 10 were unattempted.
Across all 20 jobs, that is **1,760 planned, 1,750 attempted, 1,749 completed,
one failed and 10 unattempted**. The Windows subtotal is 440 planned, 430
attempted and 429 completed.

The failed job retained eight completed preflight requests and 70 timed
observations: 69 completed timed requests and one failed timed attempt. Its four
timing batches were offered with 20 samples each before measurement; the retained
observed counts are 18 native Pre, 17 native Post, 18 optimized Python Pre and
17 optimized Python Post. All four batches remain failed/incomplete. Numeric
batch offers therefore do not imply the remaining launcher attempts occurred.
The 19 complete reports contain 1,520 timed observations; the additional 70
partial observations are retained separately, giving 1,590 observed durations,
of which 1,589 accompany completed requests. The failed run supplies no accepted
latency aggregate.

Its original failure is `qualification_route_accounting_was_ambiguous` at
`native_slo_daemon_fixture.witnessed_route:60`, during optimized Python
`PreToolUse`, sample 17. The launcher returned allow with exit code zero after
5,249.2177 ms, while `native_resident` increased from 77 to 79. The unique route
remains unknown because the existing one-increment gate rejected that delta.
Neither successful delivery nor the counter delta proves the cause of the
additional evaluation; this evidence does not establish a retry or authorize
relaxing the route gate. Fixture registration was restored.

The failed-run public summary exactly matched the authenticated private summary.
API ZIPs `10525735054` and `10524769559`, the six-member ciphertext receipt,
source/run/attempt binding and finite outcome/timing projection were verified;
the peer review checked retained ZIP/member hashes and accounting without a
second decryption. The retained projection is
`review/eleventh-ci/claude/windows-run4-authenticated-projection.json` (9,221
bytes; SHA-256 `37728126138a714246f01ef96885554a2bd4945a1de83030811852fdf761443a`).
All 20 decoded logs, exact public reports and final census are covered by
`review/eleventh-ci/claude/manifest.json`. Every report keeps
`qualification_complete=false`, `production_selected=false` and
`default_registration_changed=false`. Passing child preservation does not confer
latency qualification or production activation.
