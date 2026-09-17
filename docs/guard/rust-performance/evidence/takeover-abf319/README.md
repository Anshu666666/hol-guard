# Installed checkpoint abf319

These records preserve all four platform attempts at PR head
`abf319d5a345d761d88e26ba787026e98370c26f`. Paired candidate wheels build that exact head.
Native-wheel CI builds GitHub test-merge commit
`70b456e93a77fff48522ee7aa6ddeec6d157f6e6`; its Git tree
`62eb319323cc7c9de7513af6ef7f05009d411189` equals the PR tree. All four installed
identity records report that actual test-merge build. The comparison baseline
remains `2e672d2d950c6ec471005ddba46e49bba16dc23b`.

The [paired run](https://github.com/hashgraph-online/hol-guard/actions/runs/35229526455)
attempted both arms on every platform. Only the Windows baseline completed a
smoke block. Every candidate block failed, so no complete pair, speedup comparison,
or whole-program qualification exists. Independent checks ran after those sampling
failures and retain their own outcomes.

| Platform | Original baseline | Candidate | Installed Ollama lifecycle | Compatible artifact rollback |
| --- | --- | --- | --- | --- |
| Linux | Codex interpreter rejected; actual target mode `0777` | `omp.PostToolUse.block.max`: no native result | 22 cases pass | All three phases pass |
| macOS ARM | `socket.getfqdn` construction deadline | `cursor.afterShellExecution.block.max`: no native result | 22 cases pass | All three phases pass |
| macOS Intel | `socket.getfqdn` construction deadline | Daemon startup waits for hook-process capacity until deadline | Fails the disabled-phase readiness budget after 10 retained cases | All three phases pass |
| Windows | One completed smoke block | `claude-code.afterWriteFile.alias.1k`: no native result | Fails the enabled-phase readiness budget after two retained cases | No transition JSON uploaded; original exception retained below |

All four Builder installation checks pass. The failed Ollama readiness phases
retain their unchanged 400 ms budgets, measured elapsed times of 527.241 ms on
Intel and 407 ms on Windows, and the completed earlier cases. Those earlier cases
do not turn either overall lifecycle result into a pass.

The separate [installed scanner record](../../../evidence/rsp-scanner-installed-hosted-abf.json)
retains 28 passing cases on each Unix host. Windows fails initial attestation with
`PackageNotFoundError`, before any scanner case or identity result. Its probe
digest is the actual CRLF checkout digest. The manifest references the existing
exact-byte scanner receipts and build metadata as the canonical copies.

The three Unix compatible rollback sequences use the actual pinned prior
`a224cc2e01e1eb8d74182fa32d78f46e9b417348` wheel bytes from the earlier native-wheel
run. Each sequence completes current candidate, prior candidate, and current
candidate phases with protected control state, registrations, receipts, and
authenticated generation retirement. This is the stated stopped replacement
scope; it does not qualify live replacement, a version-number downgrade, signing,
enrollment, or cohort rollout.

The separate original-baseline sequences complete clean baseline, candidate
upgrade, and candidate reinstall. Original-baseline rollback then rejects the
retained native command binding with `native_policy_snapshot_unknown_field`.
All six prior receipts and the protected authority remain present, and the
before/after policy bytes match. The publisher thread retires, but the final
legacy stop command returns 2 with the exact digest of
`native_resident_stop_unavailable\n`. The aggregate correctly retains the failed
phase, leaves expected-negative acceptance false, and does not restore the
candidate. No authority field is stripped to make the legacy program run.

The immutable legacy entrypoint in `managed_resident.rs` requires discovered
generation state and an authenticated live shutdown response. After generation
state is removed, its unavailable result provides no new containment proof.
The active Python resident stream creates a separate session, and the native
containment module creates a supervisor process group inherited by its serving
child. An outer Python process group therefore does not establish complete
quiescence. Any later recovery fixture must positively account for those actual
owned processes and preserve the authenticated prior authority; these records
cannot authorize restoration by treating return code 2 as success.

Windows raises `qualification_transition_prior_cleanup_unverified` during the
compatible sequence. Its exception reporter then raises `ModuleNotFoundError`
while importing `codex_hook_file_integrity`, and the outer handler repeats that
reporting error. Consequently the uploaded ZIP contains no transition report.
The [original job log](https://github.com/hashgraph-online/hol-guard/actions/runs/35229526455/job/105229666354)
retains the failure chain. Later source review identifies the case-sensitive
`uv.exe` basename check: Windows `shutil.which` can return `uv.EXE`, preventing the
disposable `UV_PROJECT_ENVIRONMENT` from being set. The resulting synchronization
can remove the paired candidate package. The casefold correction and bounded
reporter correction are later local work; they do not alter this attempted run.

Both macOS resolver configurations were selected, root-owned, not writable by
group or others, and unchanged around the qualification command and read-only
witness. Numeric lookup succeeds; both system name lookups exceed their five
second deadlines without responder packets. One ARM `getnameinfo` sample captures
the allowlisted `python_lookup`, `libinfo_search`, `mdns_query`, and `kevent_wait`
categories. The other three native stack samples hit their own bounded deadlines
and preserve that result. Resolver cleanup completes on both hosts. The evidence
does not establish a resolver repair; the baseline bytes and fixture deadlines
remain unchanged.

The [native-wheel run](https://github.com/hashgraph-online/hol-guard/actions/runs/35229526436)
passes on Linux and Windows in their respective workflow scopes. Linux passes
its installed SLO smoke checks and the 100,000-request, 250,000-receipt soak with
zero errors, zero health failures, one stable daemon process, and no transient
health failures. Its SLO record still says `qualification_complete: false`.
Both macOS jobs fail the large source-reference witness with no native result:
ARM at `pi/PostToolUse/5m` sample 23 and Intel at `codex/PostToolUse/5m` sample 18.
Those wheel failures are distinct from the paired candidate failures above.

`manifest.json` verifies all eight downloaded ZIP digests against the GitHub
artifact API and retains all 51 JSON members with decoded values unchanged.
Eight records reference the scanner owner's canonical copies. Five original
wheel member digests are recorded without copying binaries. The earlier `ae33987`
and `5ee52` checkpoints remain unchanged historical evidence.

`desktop-local-validation.json` separately retains the full local validation
outcome after a 51,000-case Desktop fixture regeneration: five tests pass and one
fails the unchanged 45-second fresh-process budget. Both fresh-process result
hashes match the generated fixture, and only the expected bundle source binding
changes. No performance arm or failed local timing check was resampled.
