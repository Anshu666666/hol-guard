# Installed priority malformed-input corpus

`scripts/native_slo_launcher_input.py` adds 16 semantic cases through actual
Codex and Claude Code launcher registrations. The caller supplies an otherwise
idle, isolated `DaemonFixture(runtime, setup="normal")` and a new private journal
path:

```python
report = run_registered_input_corpus(session, evidence_file=evidence_file)
```

The installer writes the real harness configuration. Each case reads that
configuration, executes its exact registered argv and environment through
`run_isolated_hook_process`, and reads the registration again after exit.
Installed runtime identity remains the caller's prerequisite. This helper does
not build a native executable, replace a daemon response, override a launcher,
or qualify source-tree imports as an installed artifact.

## Frozen source contracts

Each row below runs once for each registered PreToolUse and PostToolUse launcher,
for four executions per input kind. The event embedded in malformed ASCII and
oversize input matches the registration. Empty and nonobject input carry no
event; the production parser defaults to PreToolUse.

| Input | Codex Pre registration | Codex Post registration | Claude Pre registration | Claude Post registration |
| --- | --- | --- | --- | --- |
| Invalid ASCII JSON | Availability Pre allow | Availability Pre allow | Availability Pre allow | Empty object |
| JSON nonobject (`[]`) | Native unknown review, delivered Pre deny | Native unknown review, delivered Pre deny | Native unknown review, delivered Pre ask | Native unknown review, delivered Pre ask |
| Empty stdin | Native unknown review, delivered Pre deny | Native unknown review, delivered Pre deny | Native unknown review, delivered Pre ask | Native unknown review, delivered Pre ask |
| 1,000,001 ASCII bytes | Launcher Pre deny | Launcher Pre deny | Launcher Pre deny | Launcher Post block |

The complete JSON shape, exact reason text and exit status are frozen independently
of production renderers. For native reviews, only the exact new request ID, local
approval URL and optional local authentication fragment vary. These fields are
validated in memory and excluded from the report and journal. An unexpected
extra output field fails the case.

The source contracts come from `adapters/codex_daemon_hook_bridge.py` and
`adapters/claude_daemon_hook_bridge.py`, the daemon JSON body loader, native
unknown-action review, and `daemon/hook_native_review_approval.py`. Codex's
oversize branch runs before event parsing and currently emits a PreToolUse denial
with its daemon-authentication guidance. Claude's prefix parser recovers the
event from malformed input. Invalid JSON reaches the real HTTP rejection and CLI
fallback paths; its availability continuation is not a native decision.

## Native and approval evidence

All eight empty/nonobject cases require one `native_resident` route increment,
Rust decision authority, the exact unknown-action reason, intrinsic review and
the correct harness/PreToolUse action. The other eight cases require no native
decision and are recorded as `engine_bypassed`. No case counts as native allow.
An intrinsic review never becomes a successful availability case.

The empty cases arm `launcher_approval_begin` before launching the process and
read `launcher_approval_result` afterward. The existing fixture controller finds
an exact newly created native request row and applies the production local
resolution with `persist_policy=False` and action `block`. This releases Codex's
browser wait and prevents later cases from reusing an unresolved request. A
missing command can only be resolved as block. Its display target is exactly
`tool:tool`; a file, URL, named tool or mismatched action envelope is rejected.

For paired qualification, the block-only helper explicitly recognizes the
pinned baseline Codex envelope (`mcp_tool`, `tool`) and the repaired canonical
Codex envelope (`config_change`, null tool name). Both require command null,
the exact harness/event/workspace and unchanged complete envelope identity
before and after resolution. Claude retains the first profile only. This is
test-fixture compatibility for blocking; it provides no unknown-command allow
authority and does not alter issued cloud acknowledgments or native controls.

The corpus requires a durable ordinary local block. It does not claim successful
suspended-operation resume, one-time allow consumption, or exercise exported
native approval v3/v4 APIs. Those are separate lifecycle obligations.

## Bounds and failure accounting

The production input limit stays 1,000,000 bytes. Oversize input is exactly one
ASCII byte larger. Each process retains the existing 10-second outer deadline
and 2 MiB captured-output limit; the controlled resolver waits at most 8 seconds.
The post-process resolution read waits at most one additional second. These are
functional deadlines, not warm or cold SLO targets.

`SurfaceEvidence` creates an exclusive owner-private journal with bounded records,
size and count. Each offered case is durably recorded before launch; its terminal
record retains the stage, attempted exit and route even on failure. A changed
registration, timeout, containment failure, output overflow, wrong route,
unresolved or ambiguous request, or stdout mismatch fails the run. No subsequent
case is offered after terminal failure. Prior successes and the failed attempt
remain available to the qualification collector. The caller closes its disposable
fixture on every exit, including cancellation and failed resolution.

Output contains bounded aggregate observations and hashes. It omits raw stdin,
stdout, stderr, paths, approval URLs, credentials and full request identities.
The journal and process instrumentation are part of a semantic preflight and are
not used to assert latency tails.

## Evidence status and remaining work

Focused local tests cover all 16 frozen contracts, native/bypass separation,
changed registrations, failure accounting and process limits. Real-store helper
tests cover actual durable block resolution, exact new-row matching, envelope
profiles and rejection of missing-command allows. These tests do not establish
an installed daemon or socket pass.

Root qualification must invoke this helper with the candidate and pinned baseline
installed artifacts on all four supported platform targets, retain each private
failure journal and bind results to the artifact identities. The returned
`implemented_scope_passed` describes only the cases actually completed;
`qualification_complete` remains false. Raw invalid UTF-8 is explicitly outside
this text-stdin corpus and requires a separate byte-preserving process fixture.
Native approval v3/v4 consumption and release-wide latency, signing, upgrade and
rollback gates remain separate requirements.
