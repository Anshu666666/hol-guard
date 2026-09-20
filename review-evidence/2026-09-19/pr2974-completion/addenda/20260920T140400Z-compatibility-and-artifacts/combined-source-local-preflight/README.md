# Combined staged-source local validation

Staged source tree a89fc1b31f245b98c044eea088b81e77be193013, based on PR commit124472b8949805e0dd36052df6894b335d8b519d, contains49 selected product paths. The GitHub tree creation independently returned the same tree identity. No PR branch was moved by this validation.

Linux/Python3.12.14 executed574 unique JUnit cases:511passed,63skipped,0failures,0errors. The skips are52 Windows-native cases and11 interpreter-specific producer cases. Modified Python formatting/lint passed. The ordinary full-source basedpyright gate analyzed1434files with0errors and30179warnings; warnings are not represented as errors or as absent. Before/after staged tree and tracked working files remained unchanged.

This is combined source correctness, not installed behavior, native execution, performance or final Windows acceptance. The staged Windows comparison is known to fail on Windows because two APIs return distinct raw native codes5/32; both actual original failure packets remain preserved. Original-contract review is addressing that stronger-than-required test oracle while retaining native errors, refusal and cleanup. Later source/test/workflow revisions must keep their own identities.

All test selectors, exact commands, stdout/stderr hashes, JUnit and49 working-file hashes are retained. No full source-wide warning-free claim, final artifact or task promotion is made.
