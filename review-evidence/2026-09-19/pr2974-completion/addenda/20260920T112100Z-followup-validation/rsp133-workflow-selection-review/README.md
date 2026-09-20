# Workflow dependency selection review

On exact PR source `124472b8949805e0dd36052df6894b335d8b519d`, the main Python workflow collects the full tests directory into 96 shards, but executes those shards only on Linux/Python 3.12. The ordinary native wheel workflow runs four platforms with fixed test lists. These facts explain why the new Windows request-risk fixture failures were found by the separate portable validation.

All 51 workflow files and the pyproject/collection helpers are preserved byte-for-byte under [source](source/). [The review](REVIEW.json) records triggers, conditional job scope, findings and explicit limits. No source or workflow changes were made by this review, and RSP-133 is not promoted.

| Selected area | Existing selection | Concrete follow-up |
| --- | --- | --- |
| Integrated Rust deadline | Rust path filters plus unconditional native wheel workflow | Consume actual current-source normal results and preserve the completed source-specific matrix. |
| Request-risk pair and approval reuse | Main Linux suite; temporary four-platform candidate driver | Add scoped permanent platform/interpreter regression wiring with actual identity and meaningful controls. |
| Windows reader and writer | Fixed native Windows lists; general tests can skip on Linux | Wire the actual product controls and indirect dependencies into the ordinary Windows workflow with the coherent product proposal. |
| Ownership and decision-critical I/O | Unconditional release/3.2 PR workflows | Verify the final selected source and retain exact gate results. |
| Scheduling, distributions and rollback | Some jobs are conditional or schedule/dispatch only | Keep their original requirement-specific execution separate from ordinary PR success. |

The temporary Ex probe and pending corrected Python tests are not counted as product integration or final-source qualification. The current PR's broad cumulative diff is not proof of selection for every future isolated dependency change.
