The immutable CodeQL diagnostic now requires the selected source tree to exist in the working directory before analysis. The first checkout uses a full tree. Source verification rejects active sparse checkout, skip-worktree or assume-unchanged entries, missing tracked paths, and an empty tracked file inventory. The same proof is recorded again when collecting results, so a clean Git status and a zero-result SARIF cannot establish completeness for an absent source tree.

The change is limited to the diagnostic workflow, collector, and its tests at code commit `89930f653023855ae95ff6a6434ca7a424543676`, based on `7a387128e2cf2ec79b890dfebe2697e8a49eb45d`. The cdd and d8 source pins, all three languages, CodeQL 2.27.0 and its pinned action, query selection, existing `stable_digest.py` exclusion, read permissions, disabled diff filtering, `upload: never`, and disabled database upload are unchanged. `preservation-proof.json` verifies that the parsed workflow differs only by removal of the first checkout's sparse inputs, and that the collector AST outside source identity and its new materialization helper is unchanged. Production source, Rust source, and all prior documentation remain unchanged.

The original [six-job run 35276260889](https://github.com/hashgraph-online/hol-guard/actions/runs/35276260889) is invalid as complete source analysis. Its pinned checkout action disabled sparse checkout and then removed `extensions.worktreeConfig`, exposing the older local `core.sparseCheckout=true` setting. The next checkout retained the requested HEAD and tree and reported clean tracked state while omitting the production files. All six full decoded job logs, all six API-digest-verified artifact ZIPs, all original manifests, and the two unchanged SARIF files are preserved under `original-35276260889/`.

| Original job | GitHub conclusion | Retained analysis result |
| --- | --- | --- |
| Foundation cdd, Actions — 105387532335 | Failure | CodeQL exit 32: no supported source detected; no SARIF |
| Foundation cdd, JavaScript/TypeScript — 105387531970 | Failure | CodeQL exit 32: no supported source detected; no SARIF |
| Foundation cdd, Python — 105387532266 | Failure | CodeQL exit 32: no supported source detected; no SARIF |
| Implementation d8, Actions — 105387532255 | Success | Zero-result SARIF lists only the diagnostic workflow and collector |
| Implementation d8, JavaScript/TypeScript — 105387532371 | Failure | CodeQL exit 32: no supported source detected; no SARIF |
| Implementation d8, Python — 105387532265 | Success | Zero-result SARIF lists only the diagnostic workflow and collector |

The two original manifests that claimed `diagnostic_analysis_complete=true` are retained byte for byte. Their outer preservation manifest explicitly marks the run invalid; those claims do not resolve any security alert.

The new real Git regression test reproduces a clean, pinned, unmaterialized tree. It fails against the original collector and passes with the repair. All 65 diagnostic tests pass, including independent checks for each rejected materialization state, preservation of failed raw SARIF, whitespace in tracked names, a tracked dangling symlink, source/language scope, and workflow upload restrictions. Ruff and formatting pass; focused basedpyright reports zero errors and zero warnings for the collector. The raw failed witness, final logs, exact before/candidate source bytes, command arguments, durations, and hashes are in `validation/`.

The actual checkout replay uses Git 2.51.1 with the repository's immutable cdd and d8 objects. It stages the exact collector outside the analyzed checkout and invokes its real verification command. Both old checkouts satisfy the old verifier despite absent production source. Both repaired checkouts fully materialize the same pinned objects and satisfy the new verifier.

| Snapshot and checkout | Tracked paths | Missing paths | `src/` paths present | `rust/` paths present |
| --- | ---: | ---: | ---: | ---: |
| cdd, original sparse sequence | 3,902 | 3,902 | 0 / 1,275 | 0 / 117 |
| d8, original sparse sequence | 4,793 | 4,791 | 0 / 1,299 | 0 / 197 |
| cdd, repaired full sequence | 3,902 | 0 | 1,275 / 1,275 | 117 / 117 |
| d8, repaired full sequence | 4,793 | 0 | 1,299 / 1,299 | 197 / 197 |

The first replay script incorrectly expected d8 to have no workflow file remaining; its diagnostic workflow does remain. The failed assertion, initial script, all completed command receipts, and corrected proof are retained under `reproduction/`. Correcting that evidence assertion did not change the repair or its validated tests.

Local validation proves checkout materialization and the collector's rejection behavior. It does not execute CodeQL, qualify the Rust migration, clear security findings, or replace the next hosted diagnostic's logs and SARIF. The original requirements, performance budgets, acceptance decisions, and release gates remain in force.
