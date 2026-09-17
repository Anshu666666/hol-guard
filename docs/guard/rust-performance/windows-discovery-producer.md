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
complete temporary, and publish through handle-relative rename. Existing parents
are verified, never repaired. Generic config/store/start-lock setup creates
missing directories privately at birth and preserves existing-directory behavior.

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
