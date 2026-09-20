# Integrated absolute-deadline source validation

Run 35503330438 validates source 124472b8949805e0dd36052df6894b335d8b519d (tree a0c139c4e02535545c5b0e602c240a38affde5fe), a direct child of external 4afa20cf014ccba918bf2fa61552dafe66767930. Driver af1af84ea196783f86ba92d7a7f1f8e2fd24988d ran once. All four platform jobs succeeded.

| Platform | Focused controls | Full default workspace | Runtime crate subset | Commands |
| --- | ---: | ---: | ---: | ---: |
| Linux x86_64 | 9 passed | 318 passed, 6 ignored | 194 passed, 2 ignored | 32 |
| macOS ARM64 | 9 passed | 311 passed, 6 ignored | 187 passed, 2 ignored | 32 |
| macOS x86_64 | 9 passed | 311 passed, 6 ignored | 187 passed, 2 ignored | 32 |
| Windows x86_64 | 7 passed | 360 passed, 6 ignored | 201 passed, 2 ignored | 29 |

The focused controls are also in the workspace populations. All commands exited 0. Each lane ran immutable rustfmt checks, a successful pinned Rust 1.88 compilation before exact collection admission, actual serial controls, default workspace/all-target tests, default and all-feature workspace/all-target Clippy with warnings denied, and a release build/self-test. No before-source controls or workload campaign were repeated.

All four ZIP hashes were verified against GitHub metadata. This packet retains all 273 original text members and all four original job logs. Independent readers reconcile raw command streams, collection rosters, fixed case records, source and driver before/after bindings, compiler artifacts, test counts and release capabilities. ZIP and executable bytes are excluded; their verified or runner-recorded identities remain explicit.

These controls establish authenticated transport and managed result-deadline behavior. They do not establish native-policy latency, persistent stdout completion, the cause of earlier Linux startup failures, or full performance qualification. SUMMARY.json and each platform's independent-reconciliation.json give exact source and evidence scope.
