# Installed artifact transition acceptance

The contract `hol-guard.installed-transition-acceptance.v1` accepts a stopped,
compatible artifact rollback and recovery after an explicitly rejected legacy
downgrade. It does not assert that the original baseline can run against newer
command authority. An actual host run must supply every required witness; source
tests alone do not qualify these transitions.

| Sequence | Required observations | Count |
| --- | --- | --- |
| Compatible artifacts, in a fresh private home | Current candidate starts; the pinned prior candidate runs with preserved authority and receipts; the current candidate restores | Three positive phases |
| Original-baseline sequence, in another private home | Clean baseline, candidate upgrade, candidate reinstall, candidate restore | Four positive phases |
| Original-baseline downgrade | The exact unsupported baseline rejects startup, preserves authority/receipts/registration, and proves resident containment before replacement | One expected negative phase |

The prior native wheels come from workflow run `35217841356` and four immutable
artifact IDs. Their selected bytes are pinned separately for each platform.
Their actual embedded build is `a224cc2e01e1eb8d74182fa32d78f46e9b417348`; the
associated PR head is `ae33987d0c8675c36a77375e03419aee920825f6`. The installed
runtime must confirm the actual build and native program capability before the
compatible sequence can pass. Reinstalling the same wheel cannot substitute for
the distinct prior artifact.

A missing or invalid historical download is a required transition failure.
The download step may continue so that independent paired, Ollama, and offline
scanner probes can still retain their own evidence. Selection and pinned-byte
validation run inside a separate bounded transition child, with a fifteen-second
deadline, before any installation transition starts. Only that transition CLI
receives the historical artifact root and platform. No mutable selection or
rebuild fallback is available. Its aggregate report retains the failure and
rejects suite acceptance; successful selection retains the pinned artifact
metadata inside `prior_artifact`. The final transition identities must still
match the selected wheel digest. Independent probe failures remain required
failures as well.

Every positive phase requires exact installed artifact identity, two native
registered-launcher decisions, complete durable receipt equality, preserved
registration, protected monotonic control authority, a real rejected stale write,
and verified retirement. The expected negative additionally requires a recognized
legacy policy-reader rejection, unchanged retained bound policy bytes, the six
prior complete receipts, a stopped publisher, and the exact legacy runtime's
authenticated idempotent `resident-stop` verification. Failure to establish any
of those facts stops continuation. No floor, binding, receipt, or registration is
removed to make an older artifact run.

`suite_acceptance.passed` can become true only after all seven positive phases
and the one verified negative are present in order, the candidate explicitly
confirms restoration after the rejection, every artifact and dependency lock
remains unchanged, and no other failure exists. The collector rechecks retained
worker identities, process outcomes, revision ordering, and counters before
acceptance. A missing or failed compatible rollback cannot be hidden by another
sequence's positive result.

The rejected legacy phase retains `passed: false` and its original failure.
The original sequence retains its all-positive `passed: false` and its four-of-five
positive completion count. Expected-negative acceptance has separate counters
and an explicit contract. With a prior artifact requested, the CLI exits
successfully only when that separate acceptance contract passes. Without a prior
artifact, expected-negative acceptance is unavailable and the historical
all-positive CLI gate remains in force.

Version downgrade, native program downgrade, live mixed generations, in-progress
replacement, enrollment, signing, headline timing, and whole-program qualification
remain unqualified by this fixture. The preserved `takeover-ae33987` observations
predate this acceptance contract and remain failed, incomplete host evidence.
