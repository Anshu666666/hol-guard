# Installed checkpoint 9db62e

These records retain every uploaded JSON member from all eight hosted archives
at PR head `9db62e8844c2ba2627f55b6b00e58cb5b175185d`. Paired candidate wheels
build that exact head. Native-wheel CI reports GitHub test-merge build
`c9859a5b5d04526fa7e663d7c494e442ee4298c4`; its tree
`47ba580366672b3b92cb46e6bb1d19c670444e94` equals the PR tree. The GitHub commit
API independently confirms parents `4b89e0d2d496a85f04922b2e019a4aea15326bb9`
and the exact PR head. All four installed identity records name that actual
test-merge build. The original paired baseline remains
`2e672d2d950c6ec471005ddba46e49bba16dc23b`.

The [paired run](https://github.com/hashgraph-online/hol-guard/actions/runs/35239001782)
attempted both arms on every platform. All eight arms failed in their first
attempted block. There is no complete pair, speedup comparison, or whole-program
qualification. The builder still attempted independent installed checks after
those failures, and each retained report keeps its own result.

| Platform | Original baseline | Candidate | Installed Ollama lifecycle | Compatible stopped rollback |
| --- | --- | --- | --- | --- |
| Linux | `codex.PostToolUse.benign.1m` policy-action mismatch | `cursor.afterShellExecution.empty-output.empty` route mismatch | Two cases retained, then enabled readiness fails at 400.108 ms | All three phases pass |
| macOS ARM | `socket.getfqdn` construction deadline | `cursor.afterShellExecution.benign.256k` route mismatch | All 22 cases pass | All three phases pass |
| macOS Intel | `socket.getfqdn` construction deadline | Initial hook-process capacity unavailable during construction | Two cases retained, then enabled readiness fails at 407.413 ms | All three phases pass |
| Windows | Cold native resident stop is not contained | `cline.PostToolUse.benign.max` route mismatch | Two cases retained, then enabled readiness fails at 407 ms | All three phases pass |

All four Builder installation checks pass. The Ollama readiness budget remains
400 ms. Intel eventually returns a snapshot and reports the publisher ready,
but exceeds that deadline and correctly remains failed. Earlier completed cases
do not turn a failed lifecycle into a pass.

Linux now proves the disposable interpreter copy has identical executable bytes,
unchanged virtual-environment configuration and runtime, and passes the installed
production integrity validator. The shared interpreter remains unchanged. Both
paired environments and the independent transition environments retain their
own provisioning proofs; this successful fixture repair does not erase the
baseline semantic failure or candidate native refusal.

The installed scanner receipts pass 28 cases on each Unix host. Windows now
attests the installed package and both PE launchers, then fails later during its
case sequence. Its original 24-row receipt is retained, including its original
failure labeling; later fixture corrections do not rewrite it. The manifest
references the scanner owner's exact-byte receipt and build-metadata copies in
`docs/guard/evidence/scanner-installed-9db/`.

All four compatible rollback sequences use the exact pinned prior wheels with
build `a224cc2e01e1eb8d74182fa32d78f46e9b417348`. Each completes current candidate,
prior candidate, and current candidate phases while preserving protected control
state, registrations, durable receipts, and authenticated generation retirement.
The Windows environment selection correction is exercised successfully here.
This is stopped artifact replacement: live replacement, a version-number
downgrade, signing, enrollment, and cohort rollout remain unqualified.

Each separate original-baseline sequence completes clean baseline, candidate
upgrade, and candidate reinstall. Original-baseline rollback then rejects the
retained command binding with `native_policy_snapshot_unknown_field`. Prior
receipt readbacks and protected policy bytes remain intact. The publisher
thread retires, but the legacy stop returns 2 without authenticated complete
quiescence evidence. Every original-baseline failed phase, expected-negative
acceptance failure, and absence of candidate restoration remains recorded.
Neither the positive compatible rollback nor the restrictive legacy rejection
qualifies the complete transition acceptance suite.

Both macOS resolver experiments still fail. The exact configuration is selected,
root-owned, not writable by group or others, and held around both arms and the
read-only witness. Direct UDP self-probes pass. System `gethostbyaddr` and
`getnameinfo` probes expire without sending packets to the responder; numeric
controls succeed. Native stack sampling retains its actual bounded results.
Configuration cleanup completes. The immutable baseline and its original
30-second daemon-fixture startup budget remain unchanged; the separate lookup
children have five-second budgets. This record establishes no resolver repair.

The [native-wheel run](https://github.com/hashgraph-online/hol-guard/actions/runs/35239001886)
passes on Windows in its ordinary installed-check scope and on macOS ARM in its
installed SLO smoke scope. ARM still reports `qualification_complete: false`.
Linux fails its 64-request capacity conservation check after completing the
installed corpus, all 24 size samples, recovery, and pool warmup. It records
36 allowed deliveries, 28 explicit overload responses, no transport errors,
22 native-resident routes, 14 native fail-safe routes, and zero native overload
counter increments. Those 14 fail-safes cannot be attributed as reviewed native
allows or silently reclassified as overload. The original artifact lacks their
individual response reasons and client failure codes.

Intel completes its native-wheel SLO report but fails recovery latency
(1,120.758 ms against the unchanged 1,000 ms limit), resident share, and safe-corpus
gates. It retains one fail-safe. Its 64-request capacity wave separately conserves
32 native-resident allows and 32 explicit engine bypasses with no transport
errors. The successful ARM attempt and the two distinct failing SLO attempts
remain separate observations; none is resampled or substituted for another.

The [complete check inventory](github-check-inventory.json) records 37 Actions
workflows: 34 successful and three failed. All 207 observed check attempts have
finished: 178 successful, 20 skipped, and nine failed, including repeated Gitar
attempts. The main CI workflow has 110 successful jobs, three skipped jobs, and
one failed Sonar job. Desktop, Windows cross-platform checks, and all four
Security Gates jobs pass.

The separate CodeRabbit commit status says `Review skipped: draft pull request`;
its successful status does not represent a completed review. The PR remains
open and draft, with no automatic merge enabled and no qualification label.

The separate [SonarCloud check](https://github.com/hashgraph-online/hol-guard/runs/105267394714)
reports new security and reliability ratings C against required A. Its other
conditions pass: maintainability A, new coverage 82.3% against 80%, duplication
0% against a 3% maximum, and reviewed hotspots 100%. The separate
[CodeQL check](https://github.com/hashgraph-online/hol-guard/runs/105262485275)
reports three high alerts while the normal analysis workflow succeeds. These
counts do not establish alert identity, overlap with the foundation, or
introduction by this change. The dual immutable-snapshot diagnostic is retained
separately under `evidence/codeql-35239002083/`.

`manifest.json` verifies every original ZIP against its GitHub artifact API
digest and size, retains all 53 JSON members with decoded values unchanged,
references eight canonical scanner records, and records five original wheel
member hashes without copying binaries. Earlier checkpoints remain intact.
The capacity collector and other later corrections are subsequent source work;
they do not modify these original outcomes.
