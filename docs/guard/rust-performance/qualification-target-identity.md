# Installed pair target identity

The fourth [qualification run](https://github.com/hashgraph-online/hol-guard/actions/runs/35240794284)
at candidate `2ebb01ff356101aea8d658ce639fe2c87188bd0d` built all four immutable
wheel bundles. Linux and Windows pair recording then failed with
`pair_installed_runtime_context_invalid`. The Linux baseline completed its
worker and retained its report before that controller rejection. Its candidate
arm remained unattempted. No completed comparison follows from this report.

Linux public artifact `10505583723`, job `105271491743`, contains
`aggregate/00-baseline.json`: 60,325 bytes, SHA-256
`499b8c2af75a7177b055e7074e3ade879829efbcf12beee3e3f1ce8a134699e0`.
The actual report identifies frozen source
`2e672d2d950c6ec471005ddba46e49bba16dc23b`, installed package origin, automatic
native mode, and resident target `x86_64-linux`. The bundle and pair context
identify the shipping Cargo target `x86_64-unknown-linux-musl`.

The resident's `resident_protocol.rs` constructs its label from Rust's
`std::env::consts::ARCH` and `OS`. Cargo distribution targets also name vendor
and ABI. Their spelling is intentionally different. The old pair validator
compared those two strings directly, so a valid installed report failed.

The corrected recorder and aggregator admit only these exact associations:

| Distribution target in the immutable bundle | Resident platform label |
| --- | --- |
| `x86_64-unknown-linux-musl` | `x86_64-linux` |
| `x86_64-apple-darwin` | `x86_64-macos` |
| `aarch64-apple-darwin` | `aarch64-macos` |
| `x86_64-pc-windows-msvc` | `x86_64-windows` |

Unsupported targets, crossed architectures/operating systems, and Cargo triples
presented as resident labels are rejected. There is no substring match,
normalization, platform inference, or new supported ABI. The distribution
target remains in the exact bundle/context identity, and the runtime label
remains in the original report. Complete wheel, runtime, installed package,
build, package version, Python version and dependency commitments remain
required. The fixed association cannot attest artifact bytes on its own.

Both priority and nonpriority pair recording and aggregation use the same
validator. Their numeric commitments, sample counts, runner cohort, encrypted
snapshot, and qualification gates are unchanged. The earlier failed manifests
are retained; this source correction does not rewrite them into successful
pairs or substitute source tests for a new installed comparison.

Validation passed 105 target, pair, selection and workflow tests, followed by
45 adjacent nonpriority worker/pair and installed-controller tests. These are
two distinct test invocations. The target tests exercise both measurement
arms on all four associations, all 12 crossed platform pairs, unsupported
targets and every retained artifact identity. The synthetic Linux fixture now
uses the actual resident spelling. Ruff and formatting checks passed; source
typing reported zero errors and 36 warnings. Independent agent source review
found no admission weakening. Actual corrected installed recording remains a
next-source CI obligation.
