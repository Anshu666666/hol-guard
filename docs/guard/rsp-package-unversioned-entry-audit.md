# RSP-050: versionless bundle-entry interpretation

The nine unversioned API cells cannot be replaced by full local evaluations of
regular bundle entries without versions. The original and current package
contracts do not support that match. RSP-050's full-route gap remains explicit;
this audit adds functional evidence, without changing its acceptance or product
semantics.

The original TODO asks for absent, exact, unversioned and deny matches at
independently varied dependency and bundle cardinalities. RSP-051 separately
requires preserving unversioned risk selection and emergency denies. PRD §9
does not define wildcard regular package records. The existing
[unversioned-route witness](rsp-package-unversioned-route.md) documents the
name-only cached API and its lack of a full-evaluator caller.

| Form | Original and current behavior |
| --- | --- |
| Regular package record with missing, null, empty or whitespace-only `version` | Bundle model rejects the record. |
| Regular package record with literal `version="*"`, queried for installed `1.2.8` | No cached match; the literal asterisk is not a wildcard. |
| Cached API query with `package_version=None` | Selects the highest-risk record for the package name. |
| Emergency deny without a version, queried for installed `1.2.8` | Blocks across versions; the existing separate deny cohort exercises this branch. |

`SupplyChainBundlePackage.from_dict` requires a nonempty version through
`_require_string`. The original `_package_matches` uses
`package_version is None or package.version == package_version`. The optimized
`SupplyChainBundleIndex.match` selects `highest_risk` only for a `None` query;
concrete versions use literal equality. Both full-evaluator call sites supply
resolved version strings. Counting emergency denies again under an unversioned
label would duplicate that branch rather than measure the missing name-only
full route.

The bounded witness ran once against original
`2e672d2d950c6ec471005ddba46e49bba16dc23b` and once against candidate
`7ed18bcbe1ad78c95d1a0a3c46903b39dfc2ffb4`. Each arm rejected four invalid record
forms and performed two full local evaluations using real artifact construction,
signed bundle verification, the evaluator and SQLite persistence. Unexpected
networking was forbidden. A transparent recorder observed cached API calls;
the only fixture override supplied the declared synthetic workspace ID.

The regular asterisk record did not match the concrete transitive dependency,
leaving only the separate blocked anchor and its one evidence row. Adding the
versionless emergency deny produced the anchor and transitive denial with two
evidence rows. Complete public results, observed lookup inputs and outputs, and
every persisted evidence column were exactly equal between arms. No fields were
normalized or removed for that comparison.

These are source functional observations. No CPU or wall-time samples, native
execution, package installation or nine-cell cardinality qualification are
claimed. The witness calls the real signature verifier; temporary signed
responses and signing keys were not retained for independent re-verification.

The recorded before/after checks were `git diff HEAD -- src` and
`git status --porcelain -- src`, together with the commit ID. They establish the
observed production-source scope at those two boundaries, not a clean whole
worktree or continuous file attestation. Candidate docs and tests had separate
work in progress. The [manifest](performance/rsp-package-unversioned-entry-manifest.json)
records the exact path scope, source subtree identities and named production
file hashes reconstructed afterward from each immutable commit. Those hashes
were not directly sampled by the original witness. The two imported fixture
helper files are listed separately: their commit hashes and a later worktree
equality check are supplemental provenance, not an at-collection dirty-state
check. No claim is made about unrelated files or a complete imported-module
inventory.

The retained [witness source](performance/rsp-package-unversioned-entry-witness-source.txt),
[original report](performance/rsp-package-unversioned-entry-baseline.json) and
[candidate report](performance/rsp-package-unversioned-entry-current.json) are
byte-for-byte copies of the original files; their byte counts and SHA-256 hashes
are in the manifest. The reports contain only the declared synthetic npm
command, package identifiers, relative dependency path, workspace label and
result/evidence values. They contain no private absolute paths, credentials or
private keys. Publication uses an identity projection, preserving all original
fields and failed-match observations. Packaging did not repeat or retime either
witness.

Completing a full-route name-only cohort would require an explicit acceptance or
product-contract decision. Adding a production `None` lookup or wildcard regular
record would change package evaluation semantics. This audit does not make that
change or reinterpret the existing deny cohort.
