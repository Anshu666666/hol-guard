# GuardPolicy compatibility policy

## Version boundary

`apiVersion: guard.hashgraphonline.com/v1alpha1` identifies one complete schema and semantic contract. Parsers must reject an unsupported `apiVersion` or `kind`; they must not guess, silently downgrade, or merge fields from another version.

During alpha, additions are permitted only when old conforming readers already have an explicit behavior. New core fields therefore require a new API version unless they are optional and all supported readers have shipped support. A changed effect, matcher, precedence rule, canonical byte, or trust rule is incompatible and requires a new major API version.

Deprecations are announced for at least one measured support window covering active Portal and Guard client versions. Legacy bundle v1 readers and writers remain available throughout that window. Removal of legacy fields, readers, writers, or bundle v1 is out of scope for this rollout and requires a separate approved proposal.

## Unknown fields

Unknown core fields are errors. Every object in `schema.json` closes `additionalProperties` except documented free-form string maps and recursively bounded extension values. Readers must not discard an unknown core field and continue enforcement.

Extensions use names matching `^x-[a-z0-9][a-z0-9.-]{0,62}$`. Valid extension values are JSON scalars, arrays, or objects within the schema's size and depth limits. Extensions:

- survive YAML format, import, export, and canonical JSON unchanged;
- participate in the document digest and bundle signature;
- never change core matching, effect, lifetime, authority, or precedence semantics unless separately registered;
- may be ignored semantically by a reader that does not implement the registered extension, but may not be removed before hashing or forwarding.

## Extension registration

An extension proposal must publish:

1. its globally unique `x-<owner>.<name>` key;
2. allowed locations and value schema;
3. deterministic semantics and failure behavior;
4. security and privacy analysis;
5. canonical fixtures and at least one consumer;
6. a collision and retirement plan.

Registration does not grant permission to weaken core policy. An extension that changes authority, precedence, signing, or rollback requires a new core API version.

## Conformance and ambiguity

Implementations report fixture mismatches against `fixtures/manifest.json` with the fixture path, expected result, observed result, implementation version, and platform. Ambiguity findings belong in the public RFC before stabilization. No alpha behavior becomes v1.0 solely because one implementation shipped it.

## Runtime capability inventory

Run `hol-guard policy capabilities --json` on the intended Core binary. Its
`guard_version` reports the declared package version, and
`local_row_projection` describes its local SQLite compiler. Record the exact
artifact digest and source commit to identify tested bytes; a version string
alone does not identify a binary. The existing `command-pattern-expressions.v1` capability
continues to describe the separate command-expression path. A schema field being
valid does not mean that every runtime path can enforce it.

The local inventory is descriptive. Always run `policy validate` against the
actual document: selector values, scope overrides, expiry, input bounds, and
combined row expansion still matter. The inventory is not permission to lower a
restriction or route a policy to another authority path.

| Target path | Match/effect/lifetime contract | Unsupported intent and boundary |
| --- | --- | --- |
| Local SQLite row projection | Enabled `allow`, `block`, `review`; `permanent` or UTC `until`. Supported nonempty matcher combinations are listed below and emitted in `supported_match_combinations`. | Other lifetimes fail `unsupported_policy_lifetime`. Unsupported matchers fail `unsupported_policy_match`; incompatible local scope overrides fail `unsupported_policy_scope_projection`. `ignore` and disabled rules emit no row. |
| Signed generic Cloud bundle with canonical row enforcement enabled | The same row compiler after verified installation-ID device filtering. Cloud envelope/signature/rollout/validity checks remain mandatory; they are not inferred from this inventory. | `devices` is a Cloud prefilter, not a local import matcher. Display labels are not installation IDs. A stale/invalid bundle or disabled canonical rollout does not become applied merely because its rule shape compiles. |
| Command-expression runtime | Existing command capability reports `all`/`any` and exact, startsWith, contains, endsWith, glob, regex operators with its timeout. | A command expression cannot become a local SQLite row. Local validation may report a command-runtime requirement; do not treat its empty row count as an applied command policy. |
| Managed extension controls | `guard.extension-controls.v1` and the target's negotiated catalog/control capabilities. Managed-restrictive controls are disable-only; shared enables require a configurable permission. | Catalog identity, delegation, runtime delivery and atomic application are separate checks. This local inventory does not certify a managed target or advertise generic rule lifetimes for it. |
| Native hook policy | Authenticated `PolicySnapshotV3` / `EffectiveNativePolicyV3`, plus the native hook's intrinsic action floor. | Native snapshot fields are not an unrestricted GuardPolicy matcher API. A local compiler success is not native publication proof; policy allow cannot lower an intrinsic native block. |

For the local row compiler, each row below permits every subset of the listed
fields, including an explicitly empty match (global). Selector entries are nonempty strings; empty/absent fields and extension overrides still
require document validation. Lists select alternatives and their product expands
into rows, subject to the document-wide 10,000-row cap.

| Maximal supported matcher set | Row representation |
| --- | --- |
| `artifacts`, `harnesses`, `workspaces` | Exact artifact rows, or workspace-constrained artifact rows when a workspace is selected. |
| `publishers`, `harnesses` | Publisher scope; publisher cannot combine with an artifact, workspace or tool-family constraint without losing a restriction. |
| `tools`, `harnesses`, `workspaces` | Registered tool-family rows, optionally restricted to a workspace. |

`artifacts` and `tools` cannot appear together. The supported tool aliases are
`file-read`, `mcp`, `mcp-tool`, `package-request`, `prompt`, `prompt-env-read`,
`prompt-file`, `shell`, and `tool-action`; `shell` maps to `tool-action` and the
others retain their family name. Arbitrary tool names are rejected, not converted
into a global match. A document may use multiple rules for distinct supported
scopes only when doing so preserves its intended semantics.

`tests/test_policy_capability_inventory.py` checks all 32 subsets of the five matcher fields against the actual compiler for three active effects
and both local lifetimes. The installed binary's inventory must still be checked
for a deployment; the package's source version alone does not prove that older
Desktop pins or fleet devices support this contract. Portal publication must
validate against intended targets and surface rule-specific failures. This change
publishes Core's inventory; it does not claim that Portal consumes it yet.
