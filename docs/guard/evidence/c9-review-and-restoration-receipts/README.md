# c9 review, audited digest restoration, and preceding archive receipts

The PR metadata capture identifies exact source
`c9ed06bbcb7cef2ecbb93955fdad34be71710aa7`. Its accompanying collection contains
three issue comments, including the SonarCloud comment reporting a passed quality
gate. This preserves that current readback separately from older comments. A
comment's reported quality gate does not clear the failed Gitleaks job, native
performance/platform qualification, the 11 high CodeQL alerts, or human approval.
The exact terminal hosted cohort is retained in the adjacent
[cleanup-c9ed06b-hosted-final](../cleanup-c9ed06b-hosted-final/TERMINAL.md) package.

The restoration receipt describes local source commit
`5e5f5fe5beaaee38d526f4cd8fc34e99488ea0d9`, parent
`4edad2ca1dc075c69cbec7c3b59d1a59fc4d3505`. It restores exactly 96 audited historical
fingerprints removed by cleanup c9, preserves the cleanup ignore bytes as an
exact prefix and leaves all 1,306 removed evidence paths absent from the lean
branch. Before/after ignore bytes and the exact patch are losslessly preserved.
The patch is compressed so unified-diff blank context lines remain exact without
becoming whitespace errors in the archive. This archive does not apply that
ignore change to its own source69 context; its own ignore remains unchanged.

The underlying audit distinguishes 82 independently reconstructed source digests
from 14 recorded launcher artifact digests whose historical binary bytes were not
available for fresh rehashing. Its earlier execution/provenance limitations
remain in force. The restoration receipt still says its actual publication scan
was pending at capture. It must not be read as a later successful scanner run or
as resolution of the original runtime failures.

The independent scanner-helper review and both exact helper snapshots are
retained. The first review identified a gap in binding the scanner invocation to
final publication metadata. The revised helper requires pinned final publication
metadata, verifies the actual and local trees against it, retains the exact
restoration-tree check, and restricts later changes to seven specified lean
documents. The revised static review found no remaining issue in that scope and
still records final metadata/object inspection as pending. This is scanner-helper
and publication-receipt evidence, not a production defect or a scanner result.
The original scan helper remains unchanged.

The archive-publication subdirectory preserves the preceding evidence checkpoint
`e6d046acf602672e6daccdc8ca648dee92b19e02`, tree
`d486bad2b0fcb4a677bb0e2d0f32671756d2ca77`, parent
`aeb04b6b06bd15ae2a2ecf00e8671c7501239278`. Its actual full release-base Gitleaks
8.24.2 scan returned zero findings in 5.696 seconds including lock wait, using the
unchanged archive ignore. The before-ref was checked, the update was non-force,
and a later direct ref GET verified the expected head after an immediate GET
briefly retained the old value. That chronology is preserved in full.

Publication receipts also retain the lossless project-patch packaging correction,
one blob transport disconnect followed by a 404 readback and successful identical
retry, all eight bounded tree-construction groups, and the local premature scan
start that exited before scanner execution while its fetch was still running.
The required scan ran after successful fetch and actual-object verification.
None of those preparation attempts is a workflow rerun or qualification result.
Transport payload parts, binary upload bodies, and private fixture state are
excluded. The package inventory preserves the exact nine manifests at e6d.

Every indexed file is contained in this directory. `manifest.json` declares its
path base and records both stored gzip bytes and exact decoded lengths/digests.
Raw receipts are copied without rewriting their original claims or statuses.
The source69 executable/core archive context is unchanged; the lean source and
newer hosted cohorts have their own explicit source pins.
