# Copilot permission handoff correction

Exact source base: 4001185e4f39cad51fd5eab314bf02b86b8a1674 / tree 7a328609488ffefecd3cdd12a9c7adba6a591e97. Only the bridge module and new test change. This is source regression evidence, not an installed result.

The real availability producer returns behavior=deny, interrupt=false, message and reason_code for both managed permission aliases. The original bridge drops those fields and converts its session-continuation reason to a Claude-shaped permissionDecision=allow. Both direct real-producer cases failed before the change. The correction preserves the existing explicit Copilot native denial and exit zero for recognized permission events. It creates no new allow path, policy decision, deadline or response schema. All other renderer paths remain unchanged. General malformed native field schemas are outside this narrow repair; existing malformed transport/nonobject rejection remains exercised.

Final source cohort: 185 passing tests, including 36 new controls. Both global/project registered entry points and both aliases are tested using real installers/entry code and modeled HTTP transport. These four tests do not claim installed subprocess or live socket evidence. Existing command, consistency and transport cohorts are retained. Final types: 0 errors, 67 warnings, 0 notes. Ruff check/format pass.

Retained original attempts: the initial two direct regressions fail; a later test draft had two global-registration assertions incorrectly expecting project-only workspace context (174 passed), corrected to match the actual distinct registration contexts (176 passed). Initial typing identified one request.data narrowing issue, corrected by an exact bytes assertion. All those records remain separate and unmodified.

The bounded RSP078 managed Cursor/Copilot permission and availability fixture is prepared separately. Corrected installed validation must use a wheel actually containing the new bridge bytes. No existing 400 wheel can be relabeled as containing this repair.
