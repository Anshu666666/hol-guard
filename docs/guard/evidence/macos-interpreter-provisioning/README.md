# Owned macOS qualification interpreters

The paired builder now requires the existing exact-byte interpreter provisioning check for both macOS targets as well as Linux. The separate transition environment uses the same supported-platform selection. Each environment receives an owned, non-writable-by-others copy of its already selected interpreter and must pass the actual installed integrity validator and runtime-binding checks. Production validation, wheel contents, shared framework permissions and performance acceptance remain unchanged.

This candidate starts from public source `590ce01334a7724f3f1349b2ab252110a5a268f5`, tree `7284a9c2bf2f301d84a500cafd56a6153785f3cf`. The source-reviewed proposal was written before implementation and is retained in [PLAN.md](PLAN.md). The new source is locally validated; actual macOS copy/runtime execution and the complete paired qualification remain unproven.

## Exact failure and source cause

The two candidate failures in [paired run 35330471726](https://github.com/hashgraph-online/hol-guard/actions/runs/35330471726) are distinct from their frozen baseline DNS constructor failures. Both candidate reports identify `codex_hook_file_integrity.validate_regular_file`, line 404, with reason `codex_hook_interpreter_permissions_unsafe`. Both report a symlink invocation resolving to a regular root-owned 0775 file whose writable group is neither root nor the current group. The validator correctly rejects this configuration. The metadata is explicitly sampled after rejection and does not claim a held-handle identity at the earlier check.

| Arm platform | Job | Artifact | Candidate failure report SHA-256 |
| --- | --- | --- | --- |
| macOS arm64 | 105553416699 | 10540663999 | `a945b268e58b6065ef633010479cf07c3e172ef4aedacfc6db8102b4797e0043` |
| macOS x64 | 105553416595 | 10542180119 | `468fc0ea49e3e9cf6eaead4083ce60c86973071443c80cc0b58e1c73c01247d8` |

Both job logs select CPython 3.12.10 from the framework installation and create separate `.venv` directories through the same `uv sync` builder. The invocation's literal symlink target was not exported, so the relationship to that framework path is a source-supported inference from the builder, setup log and failure metadata. Future copy receipts establish the actual source/copy relationship directly. The original reports and build metadata are retained losslessly here; the source observation record also binds their original archive members and complete job-log digests.

The source builder previously ran interpreter provisioning only for the Linux target. Both Macs skipped it. Linux artifact 10542130137 from the same run already proves the existing two-arm copy path at its distinct CPython 3.12.14 runtime: original/copied digests match, original targets and venv configuration remain unchanged, and the installed validators pass. That historical Linux result does not establish macOS behavior.

The validator file is byte-identical at frozen baseline `2e672d2d950c6ec471005ddba46e49bba16dc23b` and actual 590, SHA-256 `ba1375f80db3a8121091e330a8cd1c3c0b36250789267209f8972e23c141ba42`. Its ownership, group-write, world-write and executable checks are preserved.

## Correction and preserved boundaries

The internal helper is named `provision_venv_interpreter` and explicitly supports `linux` and `darwin`. Its receipt identifies Linux, macOS or an unsupported platform truthfully. All callers and test injection names use the new name. The private copy, configuration reads, source metadata checks, runtime probes, output/deadline limits and error handling retain their exact previous bodies.

Both declared macOS targets now receive the same required pair provisioning operation. Each arm is attempted and retained independently; missing, incompatible or failed proof still fails the required check. The source/copy digests must agree within each arm, and both arms must have identical original interpreter bytes. The Linux-only Claude pilot remains separately selected and does not become a macOS claim. The transition driver changes only its provisioning import, supported-platform condition, call name and descriptive text. Its retirement and acceptance functions remain unchanged.

The helper copies at most 128 MiB into a new file under the private venv's owned directories, sets only that copy to 0755, verifies exact bytes and source/invocation metadata, and atomically replaces the private invocation. It does not chmod, chown or replace the shared framework/tool-cache target. It compares the original/copy version, implementation, ABI, prefix/base-prefix/executable and SQLite/OpenSSL observations, then requires the unchanged validator from the installed arm. A failed framework-loader, prefix or validator check remains failed. The copy does not claim to duplicate or attest the entire shared-library/framework closure.

CPython 3.12.10's non-Windows venv implementation supports copying its base executable with mode 0755. The macOS framework launcher preserves the invocation for venv discovery while locating the underlying framework interpreter. These primary sources support the bounded copy attempt; they do not substitute for actual hosted runtime checks. [venv implementation](https://github.com/python/cpython/blob/v3.12.10/Lib/venv/__init__.py), [framework launcher](https://github.com/python/cpython/blob/v3.12.10/Mac/Tools/pythonw.c). Exact provider blob identifiers and excerpts are retained in `proposal-primary-sources.json`.

All registered-launcher, cold native one-shot, daemon startup, readiness, corpus, iteration and deadline sources remain byte-identical. Provisioning runs during installation setup and adds no hook, daemon, resident or decision-cache warmup. Fresh measured processes and complete existing timer boundaries are preserved. Installation verification can affect ordinary filesystem cache state, so no cold-filesystem or performance benefit is inferred.

## Validation

The pre-change regression run has **10 failures and six passes in 0.45 seconds**, demonstrating the missing Mac selection and receipt scope while retaining unsupported-platform and Linux coverage. The final focused suite has **154 passes in 3.56 seconds**; total command time is 7.224 seconds including lock/startup. The earlier 154-pass run in 3.44 seconds is a separate retained attempt.

The suite includes actual owned-file copying and unchanged integrity validation, actual Linux CPython copies with separately installed exact frozen/current validator modules, source/invocation mutation rejection, bounded output/deadlines and owned child retirement, both-arm failure retention, Mac dispatch success/failure projections, third-environment installation-before-provisioning-before-registration order, unchanged transition acceptance/recovery checks, all four builder selections and Linux-only pilot separation. The Mac dispatch tests substitute only the dispatch/runtime-probe collaborators and are explicitly source witnesses running on Linux; they do not report macOS execution or installed native HTTP qualification.

Ruff lint and formatting pass for all 11 changed Python files. The initial unused test import is retained in its failed lint output. Direct typing of the four scripts has **65 existing errors at both base and candidate**, with identical error messages. Warnings are 338 at base and 339 at candidate; the only added warning is another `argparse` target value typed as `Any` in the newly separated target selection. This is not a clean or full-production typing claim. Production source is unchanged.

`source-preservation.json` binds the unchanged helper functions, production/Rust/workflow files, original/current contract files, timing sources and the complete source inventory. The actual 395 Desktop evidence-bound source paths do not intersect this change, so this correction does not require regenerating the frozen Desktop corpus report. The helper-name edits in unrelated transition test fixtures have no other AST change.

The new macOS provisioning receipt remains required on a future hosted candidate. Both old Mac integrity failures and both original-baseline DNS failures remain retained. This source correction does not establish a completed pair, legacy retirement, signing/update/rollback qualification, security gate, independent approval, canary or release activation.
