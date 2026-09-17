# Command-control refresh and native read leases

Sixth-source CI used head `9d3907a2e6ed1ec201281901cb878836a7dad32d`,
tree `833ea191211db2a0613db8520d072f5edf485380`, and equal-tree merge
`64164db9cd11e3d05182a99dba100daa6011c83d`. Two actual Intel macOS
requests returned the existing public native error
`native_command_control_mutation_in_progress`:

- Native-wheel run `35257232892`, job `105323757874`: the Cline PostToolUse
  250 KiB source witness made one admitted native request, with 71 ms elapsed
  and 2,976 ms remaining. The reply was an error object, the edge decoder
  rejected it, and no receipt was accepted.
- Indexed run `35257233257`, job `105327055279`: candidate case
  `cline.PostToolUse.block.16k` made one admitted native request, with 46 ms
  elapsed and 2,939 ms remaining. The same error prevented native route
  qualification; the delivered availability response remains a failed corpus
  result.

These observations establish the native shared-lock acquisition failure.
They do not identify which process or thread held the lock. No earlier
redacted error, availability response hash, or missing reply is assigned
this cause retrospectively.

The source audit found an independently reproducible contention path.
`GuardDaemonServer` periodically calls
`_GuardDaemonHTTPServer.refresh_extension_control_runtime`. Its registry
read previously used the default exclusive authority lease even when the
authenticated controls and manifest were unchanged. The native resident
uses a nonblocking shared lease, so that ordinary read excluded a native
decision just as an actual mutation would. The native policy publisher
already used the shared-read path; the older periodic runtime refresh did
not.

The periodic refresh now requests `read_only=True`. The existing store
guard raises `NativeCommandControlMutationRequiredError` before a semantic
write. Only that sentinel triggers a second complete authenticated read
under the original exclusive mode, after the shared call has unwound.
There is no in-place lock upgrade. Other errors and tampered/degraded
authority views retain their existing handling. CLI/API mutation callers,
native lock acquisition, marker verification, deadlines, availability
policy and delivery gates are unchanged.

The focused regression uses real store reads and a separate Python process
requesting the same OS shared lease. It demonstrates exclusion during the
old default read and admission during the changed periodic read for both
unenrolled and protected authority. Further tests verify that an actual
missing authenticated manifest refuses mutation under the shared lease,
is re-read and written under exclusive ownership, and is subsequently
verified through the unchanged reader. A deterministic injected mutation
also checks lease release and native-reader exclusion during the exclusive
interval. Error and nonprotected-view tests preserve their original outcomes.

This is a source correctness correction, not a measured latency claim or
proof that every CI lock failure had this holder. Installed cross-platform
qualification must run against the corrected source. Real control changes
continue to exclude concurrent native decisions until their existing
authenticated publication protocol completes.
