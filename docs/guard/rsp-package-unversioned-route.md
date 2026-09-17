# Unversioned package API versus full local execution

RSP-050 remains open for its literal full-route unversioned matching requirement.
The nine existing unversioned cardinality cells measure name-only cached-bundle
queries with `package_version=None`. Those queries have no production caller in
the shared package evaluator. They must not be counted as nine full evaluator
measurements or as evidence-store qualification.

The original acceptance is: “Cover absent/exact/unversioned/deny matches with
100/1000/10000 dependencies and independently scaled bundles; record CPU and full
local evaluation.” The retained 36-cell matrix contains 27 attempted full local
evaluator cells and nine API diagnostics. Failed or censored arms remain unqualified.
No additional CPU measurements are invented for a route that does not exist.

## Existing production control flow

The two production calls to `evaluate_cached_supply_chain_bundle` are in
`guard/runtime/supply_chain_package_eval.py`:

- `_evaluate_with_bundle` skips the cached lookup when `_resolved_target_version`
  returns `None`. Otherwise it passes the returned string, including a literal
  registry tag when that is the normalized target.
- `_transitive_lockfile_results` passes the version string from a validated
  immutable `LockfileParseResult` entry.

The direct path therefore does not translate an unresolved target into the API's
name-only risk selection. A bare npm package token is normalized to `latest` in
`_targets_from_artifact`; a literal `latest` lookup is distinct from a `None` lookup.
The call-site inventory was checked across production source, not only the benchmark.
Adding a name-only production route would change the existing package contract and
requires its own product decision, parity work and performance qualification.

## Real artifact and store witness

The [executable witness](../../scripts/qualify_guard_package_unversioned_route.py)
ran against original source `2e672d2d950c6ec471005ddba46e49bba16dc23b` and optimized
source `af1106a5b2cb497d2e61cc33aa9914f727c0b205`. Both source identities were checked
before and after collection. Each run used normal `PackageIntent` artifact creation,
a signed bundle, the real bundle loader, `evaluate_package_request_artifact`, and
the SQLite evidence store. A transparent wrapper recorded the cached API's inputs
and outputs. The only fixture override supplied a synthetic workspace ID; no
package resolution, policy or trust function was replaced. Networking was forbidden.
The shared measurement lock covered both functional runs and fixture cleanup.

| Actual request and fixture | Observed cached lookup | Full result |
| --- | --- | --- |
| `npm install minimist`, empty lockfile | `minimist`, version `latest`; `no_cached_match` | `cloud_auth_error`, blocked under the fixture's existing premium policy because no cloud credentials were configured; one persisted evidence row |
| `npm install minimist@^1.2.0`, lockfile pins 1.2.8 | `minimist`, version `1.2.8` | Known-malware block; one persisted evidence row |
| `npm install anchor@1.0.0`, nested transitive minimist 1.2.8 | `anchor` at `1.0.0`, then `minimist` at `1.2.8` | Direct and transitive blocks; two persisted evidence rows |

The separately invoked name-only API query for minimist with `None` returns the
known-malware block from the same bundle. It performs no persistence. Its result
must not be confused with the full bare-install result, which reaches a different
fallback and reason even though both final actions happen to be `block`.

All three full public results, every persisted evidence column, observed lookup
inputs/outputs and the separate API decision are identical between the original
and optimized source. The raw reports retain complete values; no normalization or
excluded fields are needed. These six full evaluator calls are functional
reachability/parity witnesses, not cardinality or latency measurements. They do
not replace any of the original failed, censored or API-only observations.

## Retained evidence

- [Original source, all three complete results and evidence](performance/rsp-package-unversioned-route-original.json)
- [Optimized source, all three complete results and evidence](performance/rsp-package-unversioned-route-optimized.json)
- [Equality, identities and artifact digests](performance/rsp-package-unversioned-route-summary.json)

RSP-054's bounded native parser no-go remains as recorded in the
[native selection report](rsp-package-native-selection.md). It does not close
RSP-050's literal unversioned full-route gap or reject all possible native bundle
kernels. RSP-055–060 remain conditional production work after a justified go decision.
