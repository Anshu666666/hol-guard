# Installed validation at f8f190a2

This checkpoint preserves results observed through 15:20 UTC on 20 September 2026 for [PR 2974](https://github.com/hashgraph-online/hol-guard/pull/2974). The PR source is `f8f190a286159b46bf14a624a62ba52b5d2371a3`, tree `341d2c02c79b0c510544df5297600d5a3a47f211`. Its sole parent is the integrated implementation `ad9d9238e5f6cb01d392d0ed6c01389bbb41ec7d`. The three changed test paths correct conformance binding; all product source remains byte-identical to that parent.

Read [PRD-STATUS.md](PRD-STATUS.md) for implementation and acceptance, [TODO.md](TODO.md) for the remaining execution, and [TAKEAWAY.md](TAKEAWAY.md) to resume with the exact source and evidence limits. The [144-task overlay](task-status-overlay.json) preserves original acceptance, dependencies and archived statuses. No task receives a new acceptance promotion here.

The new installed timing observation completed all 88 strict joins, but every original route latency ceiling still failed. The unchanged original 100-workspace lifecycle diagnostic passed expiry and service restart and failed three cells. Fresh Mac and Windows ordinary CI gates passed; the current Linux soak is still running at this snapshot. The earlier Linux soak was cancelled when root advanced the PR, and its partial artifact remains explicitly incomplete.

The scanner finding is the public source SHA-256 in the new conformance fixture. A one-fingerprint exception passed six scope controls and exact full-history scanning. It is prepared only; the PR head is held until the current native workflow finishes naturally. The later publication receipt must establish any eventual source change.

All earlier evidence remains in the [source integration checkpoint](../20260920T143000Z-integrated-source/). The exact recovered [original PRD, TODO, Takeaway and ledger](../20260920T065000Z-surviving-records/) remain authoritative. The private ChatGPT conversation and the unavailable historical 494-file packet were not recovered.
