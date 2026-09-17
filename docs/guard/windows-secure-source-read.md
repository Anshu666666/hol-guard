# Windows secure source reads

The frozen `2e672d2` runtime has no Windows source-file reader. Its non-Unix
`secure_open` always returns `PathChanged`; `review_source` maps that failure
to `no_output_to_review`. The retained Windows qualification failure for
`claude-code.PostToolUse.benign.1m` reported a real native deny/block with that
reason. It is not a completed content review and must remain baseline failure
evidence. Previously green Windows native-wheel jobs ran identity, command
control locking, and default-auto probes; they did not run the installed SLO
runner's large source-reference cases.

The candidate adds a Windows implementation to `guard-secure-fs`. Its unsafe
system calls are isolated in the existing `guard-runtime-windows-process`
crate; `guard-secure-fs` retains its `forbid(unsafe_code)` boundary. There is no
runtime dependency cycle or new third-party dependency.

`open_bound_read_file` accepts absolute local-drive and verbatim-drive paths.
It rejects UNC/device namespaces, alternate streams, parent/interior-dot
components, duplicate separators, trailing dots/spaces, wildcards, control
characters, components longer than 255 UTF-16 units, paths longer than 32,767
units, and more than 256 components. Unsupported paths fail closed. These
restrictions do not change the workspace, sensitive-path, external-source,
or supported-source-type classifier.

The reader holds the root and every intermediate directory open. Each child
is opened using `NtCreateFile` relative to its retained parent, with a single
validated name and `FILE_OPEN_REPARSE_POINT`. Every opened object must be a
disk object of the expected type, without any reparse tag. Ancestors deny
delete sharing; the final read-only file additionally denies data-write
sharing. No permission repair, write access, creation, or truncation occurs.
The relative-name and no-reparse behavior follows the documented
[NtCreateFile contract](https://learn.microsoft.com/en-us/windows/win32/api/winternl/nf-winternl-ntcreatefile).

Identity uses `FileIdInfo`'s full 128-bit file ID and volume identifier,
size, link count, write/change times, attributes, and the owner/group/DACL
descriptor. The older 64-bit file index is insufficient on ReFS, as described
in the [Windows file-information documentation](https://learn.microsoft.com/en-us/windows/win32/api/fileapi/ns-fileapi-by_handle_file_information).
After reading, retained ancestry is checked again and a second handle-bound
walk must identify the same file and directories. Original and canonical
spellings must also identify the same file. Ordinary source files use the
kernel's existing access policy; this API does not impose the separate
owner-private authority policy.

The generic reader deliberately leaves hardlink policy to its caller, so it
can inspect packaged public files with an independently bound expected digest.
`guard-secure-fs` requires exactly one link. It preserves the existing scan
byte cap, maximum-plus-one bounded read, metadata checks, complete-byte SHA256,
and native semantic/deadline checks. A changed security descriptor or file
identity fails the read. Missing OS identity/security support also fails;
there is no direct-path or Python fallback.

Tests cover complete benign and secret source review, digest mismatch,
invalid UTF-8, hardlinks, exact 250k/1M/maximum-size reads, oversize rejection,
retained-handle write/delete/rename protection, preexisting writers, stale
identity, a real junction, permission revocation, and rejected path forms.
The Windows wheel workflow now invokes the installed SLO runner with the
same strict gates as the other native-wheel jobs and retains its report on
failure. Cross-compilation and Unix regressions do not establish Windows
execution, Windows race qualification, or installed source latency. Those
claims require the actual Windows runner and exact candidate wheel evidence.
