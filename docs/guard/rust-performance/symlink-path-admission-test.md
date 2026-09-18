# Authenticated symlink path admission test

The eleventh Main CI run at publication
`23bef02c5edd2fb24dbfec768a9dbd5e80c2b31d` fails one test in shard 60:
`test_guard_daemon_claude_hook_endpoint_accepts_guard_home_symlink_alias`.
The authenticated request returns HTTP 200 and the original UserPromptSubmit
event, but also includes `continue: true`, `policy_action: allow` and
`reason_code: daemon_hook_process_not_ready`. The shard retains 237 passing
tests, one skip and this one failure. The response does not establish that
symlink admission failed.

`GuardDaemonServer.start()` already calls `require_initial_capacity()`.
The same readiness reason can arise from several process-runner and evaluator
paths; the retained response does not identify which emitted it. This finding
does not establish a missing startup wait, a timeout cause or a production fix.

The revised test uses the existing neighboring workspace-sentinel test seam:
it controls only its own child start, initial-capacity requirement and review
result, then admits one slot through the real scheduler. It keeps the real
daemon socket, authenticated challenge, HTTP request, query parsing and path
validation. Exactly one captured review must receive the canonical guard-home
path, `workspace=None`, the original Claude harness and exact payload. The
original HTTP 200 and normal event-response assertions remain, followed by the
original daemon cleanup.

The change makes this test directly verify authenticated path admission and
response forwarding. It does not supply subprocess-readiness, semantic-review
or installed-performance evidence. Existing rejection, authentication, process
runner and installed tests keep those separate scopes. Production code,
timeouts, retry counts, availability responses and admission rules are unchanged.

The selected existing endpoint tests pass locally: **13 passed and 102
deselected**. Ruff, formatting and diff checks pass; independent source review
is clear. Actual execution of this revised test belongs to a later publication.
The eleventh failed first attempt remains recorded.
