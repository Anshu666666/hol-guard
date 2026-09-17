# First immutable-snapshot CodeQL diagnostic evidence

[Run 35239002083](https://github.com/hashgraph-online/hol-guard/actions/runs/35239002083)
completed all six analysis and artifact jobs successfully at PR2954 head
`9db62e8844c2ba2627f55b6b00e58cb5b175185d`. The executing workflow merge was
`c9859a5b5d04526fa7e663d7c494e442ee4298c4`. Each job separately checked the
fixed foundation `e449594e86c717e66e14598a4130475de79c536f` or implementation
`abf319d5a345d761d88e26ba787026e98370c26f` commit and Git tree. These are the
same tracked trees as the respective original analyzed merge commits; the
[manifest](manifest.json) preserves all source, original-run, job, check and
artifact identities separately.

**The original security checks remain unresolved.** The full diagnostic has
17 foundation Python results and 18 implementation Python results. Actions and
JavaScript/TypeScript each report zero for both snapshots. All 17 common
Python results match by rule and primary-location fingerprint. The one added
implementation result is `py/weak-sensitive-data-hashing` at
`native_command_control_authority.py:83`, fingerprint `f93bf79af7d2c8d6:1`.
All reported result rules carry security severity 7.5.

At the first diagnostic capture, these full-scan results could not be mapped to the separate original
[foundation check's two alerts](https://github.com/hashgraph-online/hol-guard/runs/105075778732)
or [implementation check's three alerts](https://github.com/hashgraph-online/hol-guard/runs/105229882410).
alert IDs. A subsequent supported GitHub API read now identifies the actual PR
merge-reference alerts: both PRs contain path-injection alerts **343 and 344**
at `config.py:495,498`; PR2954 also contains weak-hashing alert **356** at
`native_command_control_authority.py:83`. The
[correlation record](../../../security/codeql-pr-alert-correlation.json)
and [original API response](../../../security/codeql-pr-alerts-before.json)
retain the exact references, merge commits, locations and matching sink-file
hashes. The API does not expose SARIF fingerprints or complete taint paths;
this is a unique rule/location and exact-source correlation. The same reads
also retain inherited Actions alerts 288 and 289, which are absent from the
zero-result diagnostic Actions scans. No alert dismissal, suppression, query
change or production patch was made by the first diagnostic investigation.

## Exact retained bytes and first-run extraction limit

The six original ZIPs retain every SARIF byte and original `diagnostic.json`.
Readable `*-diagnostic.json` files are byte-for-byte copies of those ZIP
members. The ZIPs total **954,944 bytes** and the twelve decoded JSON members
**13,528,734 bytes**. Original API archive hashes, retained archive hashes and
each member's byte count/SHA-256 are in [manifest.json](manifest.json).
[findings.json](findings.json) is a derived inventory with original rules,
locations, sources, fingerprints and bounded source-review dispositions; it
does not modify the SARIF.

| Snapshot / language | Artifact ID | Results | Original archive |
| --- | --- | ---: | --- |
| Foundation / Actions | 10504128647 | 0 | [foundation-actions.zip](foundation-actions.zip) |
| Foundation / JavaScript | 10504898061 | 0 | [foundation-javascript-typescript.zip](foundation-javascript-typescript.zip) |
| Foundation / Python | 10504548227 | 17 | [foundation-python.zip](foundation-python.zip) |
| Implementation / Actions | 10504902828 | 0 | [implementation-actions.zip](implementation-actions.zip) |
| Implementation / JavaScript | 10504418054 | 0 | [implementation-javascript-typescript.zip](implementation-javascript-typescript.zip) |
| Implementation / Python | 10504848343 | 18 | [implementation-python.zip](implementation-python.zip) |

The first workflow used nested source checkouts. Its
[foundation Python log](https://github.com/hashgraph-online/hol-guard/actions/runs/35239002083/job/105262264198)
and [implementation Python log](https://github.com/hashgraph-online/hol-guard/actions/runs/35239002083/job/105262264285)
show `trace-command --use-build-mode --working-dir` selecting the outer
workspace. Python autobuild derived its include root from that working
directory and extracted the current diagnostic helper outside each pinned
tree. All reported finding sinks are in the pinned source, but **exclusive
extraction of that source was not proved**. The initial raw manifests predate
this observation and remain unchanged. The outer retention manifest records
the correction explicitly. The original foundation log also extracted
`stable_digest.py` with the observed ignore setting, so its presence alone is
not evidence of a new ignore mismatch.

The [root-checkout correction](../../codeql-foundation-diagnostic.md) stages the
fixed collector outside the tree, preserves the exact workflow definition via
the pinned action's supported definition field, and checks out the old snapshot
at the actual extractor working directory. It adds no exclusions. Its local
layout tests cannot substitute for a subsequent hosted extractor observation.

All twelve original JSON members were inspected before retention. There are no
embedded source `contents` or invocation environment maps; the bounded
credential-shaped pattern inspection found no matches. Connector download
URLs/tokens were not retained. This describes this artifact review, not a
repository-wide secret scan or a claim that source snippets can never carry
sensitive values.

## Bounded source triage

The review traces actual values and their consumers at both immutable
snapshots. A false-positive disposition below applies to that traced value,
not to every use of the utility and not to an inaccessible external alert.
Exact per-result details, source locations, fingerprints and sink-file hashes
are retained in the JSON files.

| Finding location (implementation line when shifted) | Traced role and disposition |
| --- | --- |
| `approval_gate_state.py:63` | The state value is a random TOTP lookup identifier; the separate seed goes to the encrypted secret store. The traced storage finding is a false positive. |
| `scripts/bench_guard_hooks.py:187` | Fixed synthetic benchmark credential text, with no user/environment credential source. The traced finding is a false positive. |
| `cli/commands_dispatch_mdm.py:37` | Public verified product version or public package-version fallback. The traced logging finding is a false positive. |
| `approval_scope_support.py:659` | Canonical metadata equality selects the stored approval target; it does not open caller-selected content. Inherited path validation, with filesystem-race limits retained. |
| `config.py:495,498` | Authenticated, canonical workspace and fixed project-config basenames precede real reads; policy keys are stripped. Leaf symlinks and `is_file`/open or directory replacement races are not excluded by held descriptors. |
| `runtime/local_temp_paths.py:13` | Absolute/no-parent-traversal and lexical temporary-root checks precede resolve and resolved containment. This is pathname validation. |
| `daemon/server.py:7563` (foundation 7550) | Authenticated request path reaches directory metadata/current-UID validation. No unauthenticated arbitrary-content read/write was substantiated by this flow. |
| `runtime/approval_context.py:785` | Complete argv digest invalidates approval on launch changes. Synthetic URL passwords start the reported traces, and real argv can contain credentials. This is not a password verifier; a public digest does not hide guessable argv. |
| `runtime/extension_control_authority.py:133,134` | Canonical record digest plus HMAC under a purpose-derived random authority key. A generic keyring getter traces the encoded anchor, not a human password. |
| `native_command_control_authority.py:83` (implementation only) | Domain-separated identifier of an exactly 32-byte random authority key inside separately authenticated control records. This is not a password verifier. |
| `review_event_integrity.py:21` | The traced `oauth_source` is a public namespace. The fixed/public binding-derived HMAC is a deterministic checksum, not secret-key authentication against someone able to rewrite payload and digest. |
| `runtime/runner.py:208` | Workspace/device identifiers select a rollout bucket. No credential verifier. |
| `runtime/runner.py:4129` | A real token is hashed exactly as the required DPoP `ath` claim. This protocol digest is not a password-storage defect. |
| `stable_digest.py:16,24` (foundation 15,23) | Workspace metadata enters signed-payload content hashes, snapshot IDs and cache fingerprints. Fixed-key deterministic identity is not secret authentication. |
| `store_base.py:392` | Real OAuth secret JSON still reaches the legacy SHA-256 verifier. This inherited compatibility limit is retained separately from false positives. |

The five path flows enter authenticated routes. Their core sink/guard functions
are unchanged across the two snapshots; config migration only adds optional
reader wiring. This review does not establish descriptor-based confinement or
disprove a race-specific issue. Canonical aliases are intentional, so a blanket
no-symlink rule is not justified by these flows alone. A race-specific threat
contract and regression would be needed before changing that reader behavior.

The TOTP seed store requests restrictive POSIX modes and uses Fernet. This
read-only trace does not establish effective Windows ACLs or hardware-backed
protection, and the state writer's chmod occurs after writing. Its finding is
classified from the identifier value, independently of those broader storage
properties.

The random-key control MACs and content identifiers must not be replaced with
password KDFs merely to satisfy a heuristic. The
[CodeQL query guidance](https://codeql.github.com/codeql-query-help/python/py-weak-sensitive-data-hashing/)
distinguishes limited-input passwords from other hash uses. In particular,
[RFC 9449 section 4.2](https://www.rfc-editor.org/rfc/rfc9449.html#section-4.2)
requires SHA-256 for the access-token `ath` value included in the signed DPoP
proof. Conversely, public-keyed checksums are not claimed to supply
[secret-key HMAC authentication](https://www.rfc-editor.org/rfc/rfc2104).

## The genuine legacy credential-verifier limit

`store_base.py:392` is byte-identical in foundation and implementation. Existing
OAuth secret JSON may contain a refresh token, private DPoP key and optional
access token; it is read from the existing protected secret store and checked
against persisted metadata. Current writes use scrypt. The read dispatch still
accepts legacy PBKDF2 and unprefixed raw SHA-256 fingerprints, and an ordinary
successful read does not unconditionally upgrade that stored hash. This is
real secret data reaching a fast legacy fingerprint, not a public-identifier
false positive. No human-password verifier or new raw-SHA-256 writer was
established in the reviewed production callers.

A compatibility-preserving retirement would first verify the old record, then
atomically migrate its metadata and cache identities, with missing/corrupt
secret recovery, interrupted migration, and rollback tests. Replacing or
removing the comparison alone would strand existing records. This diagnostic
does not establish a new exploitable credential-storage regression that
justifies an unmeasured migration change; the inherited limitation remains
visible and must not be counted as a resolved security check.

The retention verification rehashed all six archives and all twelve members,
parsed every JSON member, checked all six readable manifest copies against the
original ZIP bytes, and compared all 17 common rule/fingerprint pairs. No
application build, security-gate mutation or production behavior change was
part of that verification.
