# Exact diagnostic publication and secrets scan

Published diagnostic commit `54c0ce882f83edb341e148d5eae2817bdf0c6451` has parent implementation `7a387128e2cf2ec79b890dfebe2697e8a49eb45d` and tree `c0134e54d7b115c0077cec8e81b961b940bd40dd`, exactly equal to validated local code commit `89930f653023855ae95ff6a6434ca7a424543676`.

Pinned Gitleaks 8.24.2 scanned the full original release-base range through the actual GitHub commit with zero findings in 6.514 seconds, including lock acquisition. The ignore input is byte-identical to the parent; no suppression or alert disposition changed. The receipt describes the prepared commit before branch creation.

Subsequent readback verifies branch `codex/rsp-codeql-materialization-20260918` at that exact commit. One workflow dispatch started [run 35326220494](https://github.com/hashgraph-online/hol-guard/actions/runs/35326220494), attempt 1, at 2026-09-18 08:48:04 UTC. The retained initial run readback is queued; it is not a completed analysis or a passing external security gate. The workflow retains the original cdd/d8 snapshots, query configuration, three languages, and no security-result or database upload. No PR branch moved in this diagnostic publication.
