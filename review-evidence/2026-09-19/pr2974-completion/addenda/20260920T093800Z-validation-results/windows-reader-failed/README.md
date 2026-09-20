# Windows reader proposal: failed first validation

Run 35501374231 / job 106053608942 executed once against source 60619956 (tree 375fe06d, parent 4d) and driver 634267a7. The archive's 33,070 bytes and SHA-256 match GitHub metadata, and all 14 original text members are retained byte-for-byte with CRLF preserved.

The product repair failed its required destination replacement behavior. Both actual readers held their original descriptor while the unchanged writer attempted replacement once in another process; both writers retained the original PermissionError/WinError 5 and nonzero exit. The source-only cohort reports 77 collected: 72 passed, 3 POSIX-only skips and 2 failures in 7.00 seconds. The two separate temporary-source CRT handle controls passed by retaining WinError 32. All four reader/child cleanup receipts and all 16 original/candidate audit/CRT parity cases passed separately.

Ruff and formatting pass. Typechecking fails with 11 optional-subscript errors in the audit comparison test helper and 868 warnings. All recorded before/after source, driver, dependencies and Python identities remain unchanged. The expected destination success, original deadlines and one-attempt behavior are unchanged. No control-gate.json exists because the original pytest process failed.

The share-delete proposal cannot be integrated as a successful repair on this evidence. The next work is a source and Windows API investigation of the exact held-destination/unchanged-writer operation, plus a narrow test-helper type correction. No expected-error change, permission relaxation, corpus rerun, installed qualification or historical normal WinError 32 attribution is established. Unicode/custom CRT and standalone generated Cursor remain separate acceptance questions.

A first temporary artifact-reference read returned HTTP 403; its fixed failure status is preserved without the temporary URL. The archive was subsequently obtained through the same Kantorcodes GitHub account via Composio and matched the authoritative archive digest. This is artifact retrieval only; the workflow ran once.
