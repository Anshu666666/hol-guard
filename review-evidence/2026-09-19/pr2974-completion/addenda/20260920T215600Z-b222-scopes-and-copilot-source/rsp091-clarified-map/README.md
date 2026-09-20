# RSP091: original requirement and current transport evidence

The mapped source and retained controls provide substantial partial coverage. This record identifies no product defect and does not close RSP091 or its prerequisites.

The original TODO requires testing “DACL/owner/SYSTEM rules, loopback authentication, exact package process, Unix private paths, permissions and peer identity.” It depends on RSP089 and RSP090. Section H is explicitly conditional on post-optimization profiles justifying more protocol complexity. PRD E5 preserves existing Unix and Windows guarantees; named pipes are optional. This map does not turn that conditional work into a new migration requirement.

| Original clause | Exact current implementation | Retained control scope | Remaining limit |
|---|---|---|---|
| DACL and owner | Same-handle protected DACL and current/SYSTEM trustees; Python exact mask/flags and duplicate refusal, Rust full-access containment/noninherited checks | Current400 Windows Rust owner/private-state positives and all12 config-directory controls, including actual extra-ACE rejection/repair | Not every parser branch or unrelated-user access scenario |
| SYSTEM rules | Deduplicated SYSTEM-owner descriptor; exact required trustee set | Existing modeled descriptor control and actual Rust owner-rule test | No SYSTEM-launched process evidence; original wording does not itself mandate elevated service execution |
| Loopback authentication |127.0.0.1/nonzero port, process checks, native nonce/HMAC and response correlation | Native refusal/deadline/no-retry rows; Linux response mismatch controls | Legacy Python malicious-server test targets compatibility transport and is not substituted for native proof |
| Exact package process | Canonical package path or explicitly selected digest, combined with start marker | Real process stale-marker control on Windows/Linux; separate installed identity cohort | Dedicated owned foreign-executable negative not established by selected retained rows |
| Unix private paths/permissions | Private modes, no-follow/type/inode/link checks, socket-owner association | Linux socket/lock controls and source-bound Python negatives | Windows POSIX skips provide no Unix execution; reader coverage does not prove all transport races |
| Unix peer identity | Linux PeerCredentials/macOS LocalPeerPid must match selected process before runtime-owner recheck | Real same-process Unix connection positive and deadline rejection | Dedicated different-process peer-PID rejection not found in reviewed controls |

The smallest concrete next control is a bounded test of the real Unix connector with valid selected process metadata and a different actual listener PID. It should refuse before authentication/request delivery, preserve the existing deadline and require owned-child cleanup. A positive control and any missing exact-package-process negative can use the same narrow fixture. This is a proposed test-only gap closure; no new control or workload ran in this review.

The selected38 source/config/test leaves are byte-identical between exact400 and current b222. Execution remains associated with its original run. The current400 normal installed20/21 failure is preserved; the fresh b222 installed21/21 and empty persistence maps do not explain it.

Python and Rust DACL parsing are not identical: the former requires exact full-access mask/flags and refuses duplicate trustees; the latter checks that the mask contains full access and that required trustees are present. This map does not treat that distinction as a proved vulnerability. The fresh Windows record is the exact-CRLF successor4c2ba0dd; normalized predecessor b458 is historical only.

The accompanying JSON maps dependencies, actual and modeled control boundaries, source identities and evidence packets. Native's original map is included unchanged, with one explicit authority correction: resident_state_identity.rs is an unreferenced older leaf; current process checks are in resident_process_identity.rs and state MAC authority is resident_state.rs.

Private chat is unavailable. The original PRD/TODO Git blobs are authoritative for this record; derived task overlays are not treated as the private transcript.
