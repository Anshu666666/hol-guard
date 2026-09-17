# Request-local facts: remaining ownership requirement

RSP-100 remains OPEN in the retained runtime. Its original acceptance is:
"Compute categories/signals once for unchanged exact inputs; recompute after
any authority/catalog/input change." B still derives categories once for the
approval identity and again for fresh policy. C and D reduce this to one
derivation for supported unchanged authority preparations, but their universal
activation was rejected by the completed full-route comparisons. This is a
literal remaining implementation requirement, not only a dependency label.

## Why the current three snapshots exist

In frozen D, prepare_tool_call_risk_facts makes a strict owned copy and immutable
binding, computes ordered categories, then discards that copy and retains only
the binding/categories. build_tool_call_hash makes another owned matching copy.
The current-policy evaluator first invokes config.resolve_action_override, then
makes its own matching copy. All GuardArtifact fields, private metadata,
arguments, insertion order, scalar types and signed zero enter matching;
unsupported/custom/non-finite inputs take the legacy path.

Those checks defend an actual property of the current interfaces. The runtime
passes the original arguments object to both public consumers. Constructing a
new top-level artifact does not make every referenced schema or argument
container privately immutable. Public callers can retain aliases. A policy
resolver can mutate those inputs between preparation and current evaluation.
Matching must therefore both compare exact current inputs and make the matching
consumer use the same owned generation; a check against a live object followed
by reading that object would reintroduce the race.

The existing tests make these distinctions concrete:

- Mutation after preparation rejects the old facts for arguments, schema,
  description, catalog/environment, server identity and tool identity.
- Mutation after a successful match cannot change the matching consumer's
  already owned copy.
- A current-policy callback that changes arguments cannot reuse old facts.
- Type/order/nesting and signed-zero changes remain distinct; custom-container
  methods are not invoked by strict preparation.

Removing the two matching checks while retaining these public call paths does
not satisfy that contract. Nor does the tools-call boundary lock prove that a
caller/configuration callback has no mutable alias.

## A possible private boundary, and what is not proved

The measured failure does not prove that one derivation per private authority
preparation is impossible. A concrete next design is a coarse private authority
preparation that owns one exact strict-JSON artifact/argument generation and
ordered facts, and computes identity plus current decision from that generation
before exposing any mutable value. Its internal consumers could then avoid the
public optional-facts matching path. The public hash/evaluation helpers would
retain their existing matching/fallback behavior for external callers.

That is a different ownership contract, not a flag that tells the present public
helpers to trust a mutable dictionary. Before selecting it, the implementation
must trace every mutable value passed to browser normalization, temporary-grant
and saved-policy composition, and callbacks. Current configuration must still
resolve at its existing authority points. An input changed by a callback must
either start a fresh preparation or be rejected by an explicit generation
check; a preparation must not silently evaluate old arguments while later
forwarding a changed live params object. A private owned generation and the
actual arguments used for forwarding must be connected by a proved boundary.

The current source does not provide that complete private owner/consumer API.
The snapshot created during preparation is discarded, hash/current evaluation
receive caller-facing inputs, and evaluate_tool_call also performs browser,
temporary-grant and saved-row work around the narrowly matched current-policy
consumer. Merely carrying D's category tuple farther would leave those contracts
unchanged. This audit identifies a feasible design direction, not an implemented
or independently qualified alternative.

Facts must also end at one preparation. Existing initial, package, pending
approval, claim and post-claim call sites deliberately reconstruct authority.
Catalog generation/state/fingerprint, current policy, executable/entrypoint
identity and final prewrite freshness remain mandatory. No proposed private
owner may cache a policy/claim result or carry category authority across those
boundaries without exact new-input validation.

## Measured selection and exact task mapping

C's 128 KiB p95 regressed in all five blocks. D's dense 4 MiB diagnostic spent
5,042.54 ms per call in three snapshot/binding traversals and increased worker
peak RSS by 49.77 MiB; its ordinary controls also failed nonregression. These
measurements justify declining C/D runtime activation. They do not complete
RSP-100, remove its once-per-unchanged-input requirement, or establish a universal
no-go for a correctly owned private preparation. Keep B active while that
finite ownership correction remains open; do not weaken the matching proof to
obtain a faster result.

The completed native experiment likewise fails its benefit/nonregression gate
and does not repair RSP-100. The following mapping separates completed source
work, conditional no-go decisions and production activation. It is a recommended
ledger interpretation of the original acceptance text, not a change to the
acceptance criteria.

| Row | Recommended state and exact scope |
| --- | --- |
| RSP-098 | DONE for the named source startup/phase/wait measurements. Retain the initial41-cell historical harness-attribution gap and separate installed/qualification requirements. |
| RSP-100 | OPEN: the retained runtime still derives categories twice; the safe private owner/consumer correction is not implemented or rebaselined. |
| RSP-103 | DONE for actual optimized source proxy overhead/memory measurement and the scoped native decision. RSP-100 remains separately OPEN; that dependency does not make completed measurements still active. |
| RSP-104 | DONE for the justified, bounded experimental four-predicate request/reply and identity contract. Catalog hashing and all policy/credential/approval ownership remain in Python. No production native session schema is implied. |
| RSP-105 | DEFERRED for activation of this tested boundary after its measured no-go. A compiled prototype is integrated with the real source proxy in the explicit benchmark; no selected production kernel or installed activation is delivered. |
| RSP-106 | Retain DONE for the declared current Python protocol/forwarding coverage; add the finite compiled-helper and actual-stdio parity evidence. Do not infer full installed/native/platform coverage from it. |
| RSP-107 | DEFERRED for this prototype's positive qualification after the gate failed. The completed comparison is retained; it is not a qualified native result or a universal rejection of other kernels. |
| RSP-108 | DONE as a recorded decision to continue deferring the complete proxy rewrite. No evidence selects that transfer of orchestration; a future positive decision still needs the separate ADR and rollout scope. |

Supporting evidence: [C comparison](rust-performance-mcp-request-facts.md),
[D comparison](rust-performance-mcp-structural-facts.md),
[native comparison and controls](rust-performance-mcp-native-text.md), and
[source phase acceptance](mcp-source-benchmark-acceptance.md).
