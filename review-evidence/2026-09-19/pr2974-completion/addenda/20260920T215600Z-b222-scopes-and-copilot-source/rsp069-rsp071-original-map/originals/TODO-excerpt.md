### RSP-068. Implement bounded native detector batches

Status: OPEN. Depends on: RSP-067.

Acceptance: Compile appropriate rules and parser logic, preserve Unicode/line counting/suppression, and reset overlap across logical files.



### RSP-069. Wire the real secrets CLI and exit behavior

Status: OPEN. Depends on: RSP-068.

Acceptance: Exercise installed hol-guard secrets and staged workflows. Preserve exits 0/2/3, default bounds and explicit user limits.



### RSP-070. Qualify hostile archive worker separately

Status: OPEN. Depends on: RSP-066,RSP-024.

Acceptance: Profile interpreter/member-loop cost; retain isolation, digest/inode binding, expansion checks and launch binding for any native worker.



### RSP-071. Run secret and scanner adversarial parity

Status: OPEN. Depends on: RSP-069,RSP-070.

Acceptance: Cover realistic/fixture credentials, unstaged changes, hardlinks/symlinks, invalid encodings, mutation, archive bombs and incomplete scans.



### RSP-072. Publish scanner go/no-go and coverage evidence

Status: OPEN. Depends on: RSP-071,RSP-010.

Acceptance: Report full CLI wall time and CPU versus optimized Python, complete finding equivalence, platforms and deliberately retained Python scopes.



## G. Native installed launchers

Priority: P1 conditional

Responsible role: Adapters and packaging engineer

Gate: Use actual installed entrypoints; preserve per-harness behavior.

Source anchors: guard/adapters/codex.py; claude_hook_argv.py; bounded_cli_hook_bridge.py; native_runtime.py; native-wheel-ci.yml. PRD §11; [S10](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_resident_stream.py),[S11](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/src/codex_plugin_scanner/guard/native_hook_edge.py),[S24](https://github.com/hashgraph-online/hol-guard/blob/2e672d2d950c6ec471005ddba46e49bba16dc23b/.github/workflows/native-wheel-ci.yml).



