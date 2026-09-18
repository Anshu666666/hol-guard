# Installed surface failure context

The Linux paired job at source `590ce01334a7724f3f1349b2ab252110a5a268f5`
failed `priority_input` in both installed arms and `registered_surfaces` in the
candidate. The aggregate retained the exception origin and digest, but omitted
the actual input case, registration, route counters and existing native witness.
Its private per-case journals were not among the uploaded artifacts. Those
historical observations remain unavailable; the digest does not identify a
specific failed case.

The source changes retain bounded context when these existing validation blocks
fail. The original exception category, diagnostic digest and source origin stay
in the envelope. A local wrapper preserves the original error message; exporters
retain the sanitized evidence. Original route, setup and native-result checks
still reject the same values.

`priority_input` uses its already captured `case_result`. A registered surface
that fails at the route assertion can read the existing observer once after
failure. This observation is labeled `after_failure`; it is not a readiness
refresh, retry or native evaluation. Failure of the observer, enrichment or
unchanged privacy validation cannot replace the primary error. Missing observer
counts remain null, rather than becoming successful zero counts.

The retained context contains the frozen corpus case, registration digest,
surface scope where applicable, expected and observed routes, existing route
counters, and native verdict labels or digests. It also copies the existing
bounded native-call fields and the `policy_refusal_diagnostic` and
`policy_refusal_count` fields produced by the separate readiness observer.
Response bodies, stdin, approval identifiers, paths and private journals are
not exported. Unknown route names become a count and an unrecognized label.

The two new exception handlers run outside successful process timing. Success
reports, command registrations, payload bytes, deadlines, approval behavior,
qualification flags and the six-level privacy bound are unchanged. The
[source preservation proof](source-preservation.json) verifies the original
validation block and unchanged surrounding source. The frozen baseline remains
`2e672d2d950c6ec471005ddba46e49bba16dc23b`.

Validation covers 70 passing finite tests and one platform-specific skip,
including the exact failing input case and counter retention, one observer read
after a registered route failure, unchanged successful observer counts, primary
error preservation, unknown route privacy and the full aggregate nesting.
Ruff checks and formatting passed for all six changed Python files. Basedpyright
reported zero errors, warnings or notes for the three changed scripts. The logs
and their digests are recorded in [validation.json](validation.json).

No performance cohort was run. No historical failure, global Copilot scope,
paired scope or migration gate is marked passed. The separate project command
context-loss investigation is not changed by this diagnostic patch.

Hosted provenance: [paired run 35330471726, Linux job 105553416538](https://github.com/hashgraph-online/hol-guard/actions/runs/35330471726/job/105553416538),
artifact `10542130137`, archive digest
`020f156ad916983c2a00de6ea0711ae332e49520125d8bcedbb2ad6d5e944eda`.
The complete terminal archive inventory and decoded receipts are retained in
`docs/guard/evidence/implementation-590ce0-hosted-final` on the integrated branch.
