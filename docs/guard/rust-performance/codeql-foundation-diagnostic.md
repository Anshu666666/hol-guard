# Immutable snapshot CodeQL diagnostic

The `CodeQL immutable snapshot SARIF diagnostic` workflow produces ordinary
Actions artifacts for two independently observed sets of unresolved security
findings: the foundation and the later implementation snapshot. It does not replace
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

The later [PR2954 check105229882410](https://github.com/hashgraph-online/hol-guard/runs/105229882410)
reports **three high severity alerts** at implementation head
`abf319d5a345d761d88e26ba787026e98370c26f`. Its three successful analysis jobs
in [run35229526605](https://github.com/hashgraph-online/hol-guard/actions/runs/35229526605)
do not establish that this separate security gate passed. The actual finding
locations and any overlap with the foundation's two alerts remain unknown.
This exact additional failure justifies scanning the second immutable tree;
the six jobs cover two source scopes rather than repeating the foundation scan.

## Reproduction scope and source identity

The diagnostic automatically runs only for same-repository PR2954 targeting
`release/3.2`, and also supports manual dispatch without arbitrary ref inputs.
A fixed two-profile by three-language matrix creates six independent Ubuntu
jobs, with at most three concurrent jobs and a 30-minute limit per job. Both
profiles scan Actions, JavaScript/TypeScript and Python. The immutable
snapshot replaces the initial sparse definition checkout at `GITHUB_WORKSPACE`
itself. Separate matrix jobs keep the two snapshots independent. The helper accepts only the fixed `foundation` and
`implementation` profile names, with no arbitrary Git ref option. It verifies
the selected commit and tree before analysis and checks the tracked source
again when collecting results. A clean checkout of one profile cannot satisfy
the other profile's pin. It never builds or executes either application.

The original logs show checkout of GitHub merge commit
`b9395b11c216a52a0bea9eb937d7cd7cf6b2770b`, whose parents are release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` and the foundation head. Its Git tree
`b6a17d026500c1821d02b5a9202b544be0874377` is exactly the foundation head's tree.
The diagnostic therefore scans the same tracked source without relying on a
mutable pull-request merge ref.

The implementation logs independently show checkout of analyzed merge commit
`70b456e93a77fff48522ee7aa6ddeec6d157f6e6`. That merge and pinned implementation
head `abf319d5a345d761d88e26ba787026e98370c26f` share tree
`62eb319323cc7c9de7513af6ef7f05009d411189`. Each diagnostic manifest retains
its selected source commit separately from its original analyzed merge.

| Profile | Original run | Original Actions / JavaScript / Python jobs | Original security check |
| --- | --- | --- | --- |
| Foundation `e449` | `35181898004` | `105075647482` / `105075647388` / `105075647242` | `105075778732`: two high alerts |
| Implementation `abf` | `35229526605` | `105229666643` / `105229666837` / `105229666277` | `105229882410`: three high alerts |

The workflow first captures the exact stdlib collector outside the source in
`RUNNER_TEMP`, verifies the copy's SHA-256, and captures the exact executing
workflow as gzip/base64 in `CODE_SCANNING_WORKFLOW_FILE`. The pinned action
[supports that definition field](https://github.com/github/codeql-action/blob/8aad20d150bbac5944a9f9d289da16a4b0d87c1e/src/workflow.ts);
otherwise its workflow lookup would fail after replacing the checkout with a
snapshot that predates this diagnostic. The definition field changes neither
the event nor the permissions and adds no source file to the analyzed tree.
Only the collector file is staged. Both checkouts disable persisted credentials.

The second checkout uses the fixed snapshot at the workspace root. Both
`source-root: .` and `checkout_path: github.workspace` now agree with the
[pinned action's actual `--working-dir`](https://github.com/github/codeql-action/blob/8aad20d150bbac5944a9f9d289da16a4b0d87c1e/src/codeql.ts).
This matters because the [pinned Python autobuild](https://github.com/github/codeql/blob/codeql-cli/v2.27.0/python/tools/autobuild.sh)
sets `LGTM_SRC` to its working directory; the extractor's
[default include root](https://github.com/github/codeql/blob/codeql-cli/v2.27.0/python/extractor/buildtools/index.py)
comes from that value. No include/exclude override or query change is added.

Before invoking the staged collector, the workflow verifies its captured hash
with `sha256sum`. Before analysis and during collection, the helper verifies
that source root, current directory, and `GITHUB_WORKSPACE` are the same,
that the collector is outside the source, and that its bytes and the workflow
definition still match the captured hashes. It also rejects untracked files,
including ignored files, and results written inside the source. The manifest
retains these finite layout checks. Actual extractor invocation verification
remains a separate hosted-log observation; the collector does not claim to
have inspected those logs.

The first actual run, [35239002083](https://github.com/hashgraph-online/hol-guard/actions/runs/35239002083),
used the earlier nested-checkout layout. Its six successful jobs and exact
original artifacts remain preserved in
[evidence/codeql-35239002083](evidence/codeql-35239002083/README.md).
The Python job logs show extraction of the current diagnostic helper outside
the pinned snapshot despite `source-root` selecting the nested tree. All
reported finding sinks are inside the pinned trees, but the first run cannot
prove exclusive extraction of those trees. This is a concrete correction to
the earlier source-isolation assumption and independent structural review;
the initial evidence is not rewritten or discarded. The root-checkout
correction requires a new hosted cohort to establish its actual extraction.

## Observed configuration retained

| Setting | Observed in both original runs and retained by the diagnostic |
| --- | --- |
| Checkout action | `df4cb1c069e1874edd31b4311f1884172cec0e10` |
| CodeQL init/analyze action | `8aad20d150bbac5944a9f9d289da16a4b0d87c1e` (observed action version 4.36.2) |
| CLI bundle | `codeql-bundle-v2.27.0/codeql-bundle-linux64.tar.zst` |
| CLI version | `2.27.0`, checked against the init output |
| Original CLI build SHA | `b47b3e59262c95aff4eeb84ac72d09e25a9c37e9` (original log provenance) |
| Bundled query packs observed | Actions `0.6.35`, JavaScript `2.4.5`, Python `1.8.10` |
| Build mode and query selection | `none`; the bundle's default queries, with no additional packs or query filters |
| Existing exclusion | `src/codex_plugin_scanner/guard/stable_digest.py`, copied exactly from the original configuration |
| Legacy workspace alias | Retained, pointing to the selected isolated source tree |

The tool URL is explicit so a later recommended CLI version cannot silently
replace the observed version. The diagnostic adds no source exclusions and
retains all generated results. It disables TRAP/dependency caching for an
independent extraction and explicitly disables diff-informed analysis. The
invoking event belongs to the current PR2954 head, so its diff is not a valid
filter for either older pinned tree. Both original runs fell back to full
analysis after their diffs exceeded the 300-file API cap. The pinned action's [diff-informed switch](https://github.com/github/codeql-action/blob/8aad20d150bbac5944a9f9d289da16a4b0d87c1e/src/feature-flags.ts)
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
The six jobs in run35239002083 completed alongside repository setup with no
security/database upload; the corrected checkout layout remains to be exercised.

An always-run collector records its fixed profile, source identity, original
analysis run/job/merge and security check, expected versus observed CLI version,
initialization/analysis outcomes, verified collector/workflow hashes and source
layout, and the exact raw SARIF byte count and SHA-256. The schema is `guard.codeql-snapshot-diagnostic.v1`; separate provenance
prevents one snapshot's successful analysis from covering the other snapshot's
failure. It never rewrites the SARIF. Missing, invalid, or over-128-MiB SARIF,
changed source or layout, failed phases, or a different CLI version leave an explicit
incomplete manifest and a failed job. The bounded reader never labels a prefix
hash as the full file digest. Valid findings remain in the artifact regardless
of their severity or count.

The final always-run upload retains only `*.sarif` and `diagnostic.json` under
the dedicated results directory, using existing pinned upload-artifact action
`043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`. Artifacts are named
`codeql-foundation-e449-<language>-<run>-<attempt>` for the foundation, preserving
its original planned labels, and
`codeql-implementation-abf-<language>-<run>-<attempt>` for the implementation.
Both are retained for 14 days.
Source trees, environment dumps and CodeQL databases are not part of this
artifact. If initialization or analysis fails, the manifest and accessible job
log preserve that limitation instead of reporting a clean scan.

This diagnostic can expose other existing findings in either snapshot as well
as each check's reported alerts. The first results contain 17 foundation and 18 implementation Python findings;
all 17 common findings have matching rule/fingerprint identities and one
implementation authority-key identifier adds a new result. Their exact mapping
to the original external checks was unavailable at first capture. A subsequent
[PR-reference API correlation](../security/codeql-pr-alert-correlation.json)
identifies path-injection alerts 343/344 in both PRs and weak-hashing alert 356
in PR2954, with exact source-file matches. The API does not expose the SARIF
fingerprints. The retained evidence records the bounded source triage and its
limitations. Both original alert-resolution flags remain
false regardless of diagnostic job success. Actual original SARIF retrieval is
complete for the first run; validation of the corrected extractor root is pending.

The foundation-only predecessor completed local validation under the shared
measurement lock: **106 tests passed in 2.61 seconds**, covering this workflow/collector and the existing
workflow token/privilege policy suites. Ruff check and formatting passed;
repository-wide privileged-workflow policy passed; the collector's basedpyright
check reported zero errors and zero warnings. Tests exercise wrong/dirty source,
missing or malformed/oversized SARIF, version drift, failed analysis with valid
partial results, exact byte preservation and nonzero CLI failure status after
writing the manifest. An independent read found no concrete source-isolation or
permission defect. `actionlint` is unavailable locally; no hosted action or
CodeQL execution is claimed by these structural checks.

The dual-snapshot followup completed **121 tests in 4.98 seconds** under the
shared measurement lock, including the existing workflow privilege/token
suites. Ruff formatting and lint passed, the repository privileged-workflow
policy passed, and the changed collector's basedpyright check reported zero
errors and zero warnings. New regressions verify the six distinct job/artifact
scopes, exact per-language run/job/check provenance, rejection of arbitrary
profile/ref inputs, rejection when one clean snapshot is presented as the
other, and preservation of the implementation's raw SARIF and three unresolved
alerts after a failed analysis. These checks do not execute CodeQL or establish
that either original alert set has been resolved. That validation preceded the first successful hosted run and does not conceal
the root-layout defect subsequently observed in its Python logs.

The exact expanded source-test outcome is retained in the [validation record](evidence/pilots-checkpoint/codeql-dual-validation.json). It does not substitute for hosted SARIF or clear either original alert check.

The root-checkout correction completed **134 tests in 3.64 seconds** under the
shared measurement lock, plus Ruff formatting/lint, the repository privileged
workflow policy, and a collector basedpyright result of zero errors/warnings.
New tests stage exact collector/workflow bytes, retain their identities after
source replacement, and reject nested roots, wrong working directories,
collector mutation, workflow mutation, helper files inside the source,
ignored/untracked extra files, missing captured hashes, and in-tree result
files. Every failed collection preserves the raw SARIF and an incomplete
manifest. These tests execute the collector and Git fixtures, not CodeQL.
The final run also verifies that the captured collector hash is checked in the
shell before either post-checkout collector invocation. The earlier run of
these 134 tests took 5.02 seconds; a preceding lint-only attempt caught and
corrected one import-order issue before tests ran.
