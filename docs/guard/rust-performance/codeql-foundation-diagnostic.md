# Foundation CodeQL diagnostic

The new `CodeQL foundation SARIF diagnostic` workflow produces ordinary Actions
artifacts for the unresolved foundation security findings. It does not replace
or clear the existing Advanced Security check, change default setup, or upload
SARIF or databases to Code Scanning. Successful generation of a diagnostic
artifact does not establish that the security findings have been resolved.

The original [PR2951 check105075778732](https://github.com/hashgraph-online/hol-guard/runs/105075778732)
reports two high severity alerts at head
`e449594e86c717e66e14598a4130475de79c536f`. The GitHub connection exposes the
check summary but rejects its annotations and code-scanning endpoints through
its endpoint allowlist. This is a connector capability limit, not an observed
GitHub authorization rejection. All three analysis jobs in
[run35181898004](https://github.com/hashgraph-online/hol-guard/actions/runs/35181898004)
succeeded and uploaded SARIF, but that run retained no downloadable artifact.
Its analysis logs do not contain the two actual finding locations.

## Reproduction scope and source identity

The diagnostic automatically runs only for same-repository PR2954 targeting
`release/3.2`, and also supports manual dispatch without arbitrary ref inputs.
It runs three independent Ubuntu jobs, each limited to 30 minutes, for Actions,
JavaScript/TypeScript and Python. It checks out the immutable foundation into
`foundation-src`, verifies its commit and tree before analysis, and checks the
tracked source again when collecting results. It never builds or executes the
foundation application.

The original logs show checkout of GitHub merge commit
`b9395b11c216a52a0bea9eb937d7cd7cf6b2770b`, whose parents are release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the foundation head. Its Git tree
`b6a17d026500c1821d02b5a9202b544be0874377` is exactly the foundation head's tree.
The diagnostic therefore scans the same tracked source without relying on a
mutable pull-request merge ref.

The executing diagnostic workflow and its stdlib-only manifest helper are in a
separate sparse checkout at the workspace root. The pinned CodeQL action reads
its executing workflow from that root; putting only the older foundation there
would leave the new workflow file absent. `source-root` and `checkout_path`
both select `foundation-src`, so the diagnostic definition is outside the
analyzed source. Both checkouts disable persisted credentials.

## Observed configuration retained

| Setting | Original and diagnostic value |
| --- | --- |
| Checkout action | `df4cb1c069e1874edd31b4311f1884172cec0e10` |
| CodeQL init/analyze action | `8aad20d150bbac5944a9f9d289da16a4b0d87c1e` (observed action version 4.36.2) |
| CLI bundle | `codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst` |
| CLI version | `2.27.0`, checked against the init output |
| Original CLI build SHA | `b47b3e59262c95aff4eeb84ac72d09e25a9c37e9` (original log provenance) |
| Bundled query packs observed | Actions `0.6.35`, JavaScript `2.4.5`, Python `1.8.10` |
| Build mode and query selection | `none`; the bundle's default queries, with no additional packs or query filters |
| Existing exclusion | `src/codex_plugin_scanner/guard/stable_digest.py`, copied exactly from the original configuration |
| Legacy workspace alias | Retained, pointing to the isolated foundation source |

The tool URL is explicit so a later recommended CLI version cannot silently
replace the observed version. The diagnostic adds no source exclusions and
retains all generated results. It disables TRAP/dependency caching for an
independent extraction and explicitly disables diff-informed analysis. The
invoking event belongs to PR2954, so its diff is not a valid filter for PR2951's
source. The original run also fell back to full analysis after its diff exceeded
the 300-file API cap. The pinned action's [diff-informed switch](https://github.com/github/codeql-action/blob/8aad20d150bbac5944a9f9d289da16a4b0d87c1e/src/feature-flags.ts)
controls that filtering; this changes no security policy or query selection.

## No-upload behavior and retained evidence

The exact pinned action's [upload parser](https://github.com/github/codeql-action/blob/8aad20d150bbac5944a9f9d289da16a4b0d87c1e/src/actions-util.ts)
maps deprecated `upload: false` to **failure-only**, which can upload diagnostic
SARIF when analysis fails. This workflow uses `upload: never`,
`upload-database: false`, and `wait-for-processing: false` to fulfill the
requested no-upload behavior on both success and failure. The existing
production CodeQL workflow is unchanged.

Token grants are limited to `contents: read` and job-local `actions: read`.
The latter supports the pinned action's [workflow identity lookup](https://github.com/github/codeql-action/blob/8aad20d150bbac5944a9f9d289da16a4b0d87c1e/src/api-client.ts).
There are no security-event, check, content-write or administrative grants.
The action may attempt its ordinary status telemetry; its [status reporter](https://github.com/github/codeql-action/blob/8aad20d150bbac5944a9f9d289da16a4b0d87c1e/src/status-report.ts)
treats permission rejection as a warning. No permission is added to satisfy it.
Actual hosted coexistence with repository setup remains to be exercised.

An always-run collector records source identity, expected versus observed CLI
version, initialization/analysis outcomes, and the exact raw SARIF byte count
and SHA-256. It never rewrites the SARIF. Missing, invalid, or over-128-MiB SARIF,
changed source, failed phases, or a different CLI version leave an explicit
incomplete manifest and a failed job. The bounded reader never labels a prefix
hash as the full file digest. Valid findings remain in the artifact regardless
of their severity or count.

The final always-run upload retains only `*.sarif` and `diagnostic.json` under
the dedicated results directory, using existing pinned upload-artifact action
`043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`. Artifacts are named
`codeql-foundation-e449-<language>-<run>-<attempt>` and retained for 14 days.
Source trees, environment dumps and CodeQL databases are not part of this
artifact. If initialization or analysis fails, the manifest and accessible job
log preserve that limitation instead of reporting a clean scan.

This diagnostic can expose other existing foundation findings as well as the
two reported alerts. Their exact correspondence and remediation require
reviewing the generated SARIF; no speculative rule or source attribution is
made here. Local structural and collector validation precedes publication;
actual hosted execution and retrieval are separate pending evidence.

Local validation completed under the shared measurement lock: **106 tests
passed in 2.61 seconds**, covering this workflow/collector and the existing
workflow token/privilege policy suites. Ruff check and formatting passed;
repository-wide privileged-workflow policy passed; the collector's basedpyright
check reported zero errors and zero warnings. Tests exercise wrong/dirty source,
missing or malformed/oversized SARIF, version drift, failed analysis with valid
partial results, exact byte preservation and nonzero CLI failure status after
writing the manifest. An independent read found no concrete source-isolation or
permission defect. `actionlint` is unavailable locally; no hosted action or
CodeQL execution is claimed by these structural checks.
