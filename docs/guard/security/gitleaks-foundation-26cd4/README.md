# Published foundation correction and full-range secrets scan

PR #2951 was advanced without force from cdd to actual GitHub commit
`26cd4dff3f138990a8e9f6a729a970c1dbd90fa4`. Its exact tree
`c8518c478ea19696e7087eb075f63b37b962d071` matches local
`7bf385f600782daaa2c688604735bb10ff776437`; its parent is the prepared correction
`3d11976aaf0e0beb91ebaab30d13666b90465909`, whose parent is cdd.

The complete release-base range passes pinned Gitleaks 8.24.2 with zero findings
and exit zero in 16.055 seconds including lock acquisition. The ignore input is
unchanged; no suppression or alert disposition was added. Exact command, tool,
input and output hashes are retained. The published head, release/3.2 base,
unmerged status and prepared PR-body text were read back and verified.

The cdd Linux soak completed naturally before this update. Its recorded scope
and three other platform failures remain historical. The new branch requires
its own hosted checks and independent review; this scan does not clear CodeQL,
provide Greptile 5/5, establish qualification or authorize deployment.
