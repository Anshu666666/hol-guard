# Exact prepared foundation commit scan

Actual GitHub commit `3d11976aaf0e0beb91ebaab30d13666b90465909` has tree
`72749b8a0a3ae04c8d1a86832c7c1cf0270b987a`, identical to local corrective source
`0984ddd35c91fa5710d66a8dea204661726c5305`. Its sole parent is the published
foundation `cdd14176ef0e0a258d4655c64210524d7047a257`.

The full release-base range passes pinned Gitleaks 8.24.2 with zero findings and
exit zero in 9.634 seconds including shared-lock acquisition. The foundation
ignore input is unchanged. No suppression or security-alert disposition was added.
The actual GitHub object was fetched and its commit, tree and parent verified;
the local working tree remained clean. The exact command, binary/ignore hashes,
raw output and zero-finding JSON are retained here.

This scan preceded branch movement. The prior cdd Linux native soak was still
running and another push would cancel it, so publication was held independently
of this successful scan. Read the authoritative PR head and checks for current
state. This is a secrets scan of the specified commit range, not an installed
qualification, CodeQL pass or independent CODEOWNER approval.
