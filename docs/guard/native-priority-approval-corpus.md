# Registered priority approval corpus

`run_registered_approval_corpus(runtime, *, evidence_file)` executes the two frozen command-review cases
using the actual installed Claude and Codex registrations. The command remains
`git diff --output=/tmp/guard-qualification.diff README.md`; the fixture never
executes that tool command. `LauncherApprovalControl` captures its exact action
identity and new-row watermark before the registered process starts, then
resolves only the matching real approval through the production service.

Claude must first deliver its actual `ask` response. After the matching approval
has durably resolved, a second execution of the same registered command and
frozen payload must deliver allow with ordinary approval reuse accepted. Both
attempts independently require a native review verdict and exactly one native
daemon route. The underlying review verdict is not relabeled as native allow.

Codex must complete its existing browser-wait path in one registered process.
The fixture suppresses GUI/browser opening through its environment, while
leaving the bridge's request polling and authenticated live-decision call
unchanged. Linux graphical-session variables are removed; the standard Python
`BROWSER` override selects a no-op interpreter for platforms that use it. The
exact installed launcher argv and registration are still read back and checked.

The private fixture wraps the actual `complete_codex_live_decision` function
only to record bounded return evidence; it never substitutes a result or
creates continuation authority. Qualification requires one non-replayed
successful allow completion for the exact request, fresh authorization,
persisted suspended-response/resumed continuation, and exactly two native
daemon routes: initial evaluation and fresh revalidation. The fixture observes
both original native verdicts and requires each to remain review. The legacy
process-runner route count must remain zero. Codex's delivered stdout must be the exact
sparse PreToolUse allow object. Its separately captured original native verdict
must still be review. A sparse response without these witnesses fails. The
observer supports the legacy finalizer seam for baseline failure evidence and
the new native finalizer seam for candidate execution; neither return value is
substituted.

Every process attempt writes an offered record before launch and a validated or
failed record afterward. Records include case and registration/argv digests,
bounded decoded stdout digest/byte count, exit and containment flags, elapsed
time, each attempt's route counters, native action, delivery, and approval
witnesses. Failures retain this evidence before propagating. Raw hook payloads,
commands, paths, credentials, and free-form stderr are excluded from aggregate
evidence. The existing 10-second process and 2 MiB combined-stream bounds remain;
the approval waiter keeps its separate fixed eight-second deadline.

The ordinary `run_registered_contract_corpus` keeps review continuation as an
explicit remaining obligation. The approval callable is separate so a pinned
baseline's unsupported continuation produces retained scenario failure evidence
without preventing unrelated timing runs. It never reclassifies that failure as
a pass. The candidate must independently pass this approval scenario.

The `browser_approval_continuation` obligation disappears from a successful
approval report only after both real review flows pass. `qualification_complete`
remains false because other registered-surface and release obligations are
separate. Unit tests validate orchestration and rejection paths; they do not
claim installed execution.

At the implementation base, an ordinary native Codex queue row had retry-only
continuation and no exact local-once authority. The real completion function
rejected it with `exact_approval_authority_missing`, even with a fresh allow
Boolean supplied. The fixture explicitly preserves and rejects that outcome.
The separately owned production correction must provision the existing proven
live-process continuation and exact gated authority; this benchmark never
constructs synthetic continuation records or substitutes the dormant native
v3/v4 approval API. Installed success remains subject to CI against that
coherent production change.
