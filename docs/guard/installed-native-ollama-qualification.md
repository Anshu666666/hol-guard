# Installed native Ollama lifecycle qualification

The RSP-118 check exercises the candidate wheel through the real authenticated
Claude `PreToolUse` daemon route. It reviews synthetic Ollama command strings;
it never launches Ollama, removes a model, or contacts a registry. The native
resident must supply each decision and its signed-policy receipt. A Python
matcher, substituted native result, or fail-safe route cannot satisfy the check.

`scripts/ci/verify_native_ollama_install.py` runs the worker with the candidate
installed interpreter in isolated mode, outside the source checkout. Production
package imports must resolve to that wheel. The source checkout supplies only
the qualification helpers and the expected artifact digests. The worker checks
the entire installed package inventory, exact native build SHA and executable
digest, contribution bytes and validation, compiled program bytes, catalog and
trust digests. Both `native-command-program-v1` and
`native-command-control-fence-v1` capabilities are required. It checks artifact
identity again after the lifecycle completes.

The authority is a private encrypted-file fixture with explicit initial
enrollment. Every subsequent control write obtains and consumes a real local
approval proof. Interactive enrollment and system keychain integration are
separate checks. The native policy ACK retains the production 400 ms readiness
boundary. No readiness budget or semantic gate is relaxed for this fixture.

| Phase | Local revision | Required outcome |
| --- | ---: | --- |
| Initial | 0 | External Ollama is inactive; push/rm receive the generic native review floor and no Ollama observations. |
| Enabled | 1 | Local enable activates the exact `command.ollama.push` / `command.ollama.rm` rules, including `.exe` / `.cmd` names. Help suppresses that owner's evidence while the independent generic review floor remains. |
| Approved retry | 1 | Resolve the real queued push review through `apply_approval_resolution`; an unchanged binding permits the existing local approval retry. The original native review receipt remains attributable. |
| Disabled | 2 | External disable removes Ollama observations. The earlier approval must not authorize the new binding; push queues a fresh generic review. |
| Updated | 3 | Re-enable with push permission disabled. Native push blocks before approval reuse; rm still reviews. |
| Settings rollback | 4 | Restore the enabled settings as a new revision. The original rules return with the current binding; old approvals do not bypass review. |
| Stale write | 4 | Reject a write expecting revision 1 and prove the next real hook still uses revision 4. |

The enabled and rollback phases also pair an Ollama command with an independent
destructive command. Its native block floor must survive owner rule evidence
and all approval handling. Its compatibility observation must carry exactly one
`matcher-failure` uncertainty, owned by
`command.shell-mutations.destructive-shell` on segment 1; all other cases require
zero uncertainty. This is a policy-text fixture, never shell execution.

Every reviewed hook must have exactly one recorded `native_resident` route,
exact delivered action/reason, validated rule attribution and program/control
binding, and a receipt linked to that real edge. The receipt must become durable
and round-trip through `GuardStore.get_native_decision_receipt`, including the
compact command binding and its original receipt identity. Every receipt must
carry the exact acknowledged full policy digest, which includes authority
epoch and fence identity beyond the compact control binding. Review cases also
require a real pending approval row. Approval reuse is explicitly identified as
the existing local queued-row behavior; it does not claim native v3/v4 approval
consume transactions are the production path.

The same driver separately runs the installed Extension Builder CLI and MCP
generation checks using the same interpreter and wheel digest. Both surfaces
must generate and validate, replay deterministically, and apply idempotently;
the maximum inventory probe must cover 256 operations. Builder authoring must
create no Guard state or fall back to source production imports. A native
failure preserves the independent Builder result, and either failure fails the
combined check.

The four-target `native-performance-qualification.yml` workflow runs this probe
after paired performance sampling, so the extra lifecycle does not warm the
performance candidate first. It still runs when paired sampling fails. Its
bounded aggregate is `aggregate/installed-ollama.json`, uploaded with the exact
run's other evidence. No raw command, approval password, fixture path, request
body, response body, or secret material is published. Worker execution is
contained with a 180-second outer deadline and a 256 KiB output bound.

For an already built candidate wheel and its isolated installed interpreter:

```sh
python scripts/ci/verify_native_ollama_install.py \
  --python /absolute/installed/bin/python \
  --wheel /absolute/artifacts/hol_guard-candidate.whl \
  --source-root /absolute/candidate-checkout \
  --source-sha "$CANDIDATE_SHA" \
  --output /absolute/artifacts/aggregate/installed-ollama.json
```

Unit tests qualify the frozen oracle, tamper rejection, real local control
proofs and monotonically increasing settings rollback, plus independent failure
reporting. They do not replace an installed native run. RSP-118 requires passing
artifacts on each claimed platform at the actual candidate SHA. Restoring
settings at revision 4 is not a package downgrade or a signed release rollback;
RSP-139 remains a separate lifecycle requirement.
