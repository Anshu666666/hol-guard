# Lean implementation 9428 publication and reproducibility

The actual implementation published to PR2954 is
`9428b660fa6a261307627660ff7b258327ed9bd4`, tree
`051e3c6e2b40a19ff1d97b93d183279af7ccb36e`, with sole parent cleanup commit
`c9ed06bbcb7cef2ecbb93955fdad34be71710aa7`. The preparation, branch readback and PR
body readbacks are retained losslessly. They establish this publication boundary;
they do not predict the outcome of its later hosted cohort.

The exact actual-commit Gitleaks 8.24.2 scan covers the full range from release base
`4b89e0d2d496a85f04922b2e019a4aea15326bb9` through 9428 and returned zero findings in
4.533 seconds including lock wait. Its ignore digest is
`fb66f1abc0bfd3a366c666cba39f9b2cdfc577ae3d29dd96c59b2f5f03f1c16e`.
The receipt explicitly records that 96 exact audited historical fingerprints were
restored, suppression entries were added and the ignore changed from the c9
parent. It is not an unchanged-ignore scan. The restoration's original audit and
historical launcher limitations remain in force; no new patterns or alert
changes are implied. The scanner's byte/version checks, release base, actual
publication metadata and exact restoration source are recorded separately.

The complete six-record independent helper review is copied unchanged under
`independent-helper-review`. Its original manifest digest is
`e84273a80c6cbb8c95b713158a37cb77a192c5fe5627f92ce53e32b3477903c2`.
Initial and revised helper snapshots, the initial publication-metadata finding,
the revised static review, final prepared metadata inspection, and the actual
publication-object inspection are retained. Earlier pending states remain
historical; the later records establish the final 9428 binding. This is scan-helper
and receipt review, with no new production defect or runtime qualification claim.

Root's independent verification of the preceding e6d archive covers 657 manifest
records and 522 decoded members. The initial verification parser omitted an
existing uncompressed-digest alias and failed after checking the first stored
gzip bytes. The parser-attempt receipt and corrected verification remain distinct;
no package defect or qualification result is attributed to that parser failure.
The exact verifier source is retained for inspection. The adjacent
[rsp-lean-archive-links package](../rsp-lean-archive-links-20260918/README.md)
preserves the seven-document transformation, 226 URL redirects, exact original 119
catalog objects and 144 complete task objects, and its own reusable checker.

## Obtaining the exact local source objects

`source-reproduction/validated-local-source.bundle` preserves the nine local
commits from c9 through local source `2b64a9ff13497a01a9a44be092d54a1109fbe23f`,
including the combined 4edad and restoration 5e5 commits. The bundle advertises
HEAD 2b and has an explicit c9 prerequisite. Its exact byte length is 187901 and
SHA256 is `e24b0a7fd3bc843771dae5632669ac2aac3ef838281b86258eabfa304267f445`.
The original bundle-verification receipt and stdout/stderr are retained.
Verification stdout is lossless gzip so the Git tool's trailing space remains
exact without becoming a text-file whitespace error. No fresh
network clone was executed and no runtime qualification is added by that check.

A repository that already contains c9 can import those exact objects without
changing its checkout:

```sh
git bundle verify /path/to/validated-local-source.bundle
git fetch /path/to/validated-local-source.bundle HEAD
```

For the adjacent archive-link checker, use the corresponding lean checkout and
fetch the immutable archive commits it references, including aeb, e6d and e779.
Then run its documented read-only verification command with the package path.
The bundle supplies local 5e/2b ancestry that a fresh public clone would otherwise
lack; it does not substitute for the public archive objects or alter their pins.

## Inactive correctness evidence

The adjacent [owner package](../mcp-per-call-risk/README.md) and
[independent review](../mcp-per-call-independent-review/README.md) preserve the
completed finite correctness review through inactive candidate
`f186a64a812bc8c5d4f2537293e6ef58076a2531`. The owner README retains its earlier
checkpoint and pending-review wording; final independent records provide the
later disposition. Only evidence directories are copied here. No candidate
script, test-process adapter, production import or runtime source is activated.
The candidate remains inactive and untimed: pytest execution durations are not
request latency measurements, and no performance campaign or qualification gate
is credited.

## Archive publication and package integrity

The preceding archive e779 publication is separately preserved under
`preceding-archive`: actual tree `da6594764e4e92549dcff9f8a5a4733b0a2a0920`, parent
e6d, full release-base scan with zero findings in 6.262 seconds, and a verified
non-force ref update/readback. That evidence-branch scan used its unchanged 88b
ignore; it has a different source and control context from the lean 9428 scan.

This checkpoint adds evidence only. Its executable source, core records and
ignore remain the archived source69 context. Raw payload parts, upload bodies,
private fixtures and newer hosted results are excluded. Every file is indexed
relative to this directory, with stored and decoded byte digests for lossless
gzip files. The bundle and original helper-review manifest retain exact bytes.
