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
