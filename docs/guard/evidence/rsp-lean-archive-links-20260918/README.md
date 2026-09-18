# Lean release archive-link preservation

This package verifies the seven documentation files prepared on checkout `5e5f5fe5beaaee38d526f4cd8fc34e99488ea0d9`. The original 119 catalog objects and all 144 complete task objects remain exact to the published source69 archive `aeb04b6b06bd15ae2a2ecf00e8671c7501239278`. The full older core bytes remain at that immutable archive; this package does not rewrite its preservation receipt.

`redirects.json` records all 226 evidence URL replacements. `transformation.json` retains the exact inserted current overview, heading change and new machine checkpoint. The verifier reconstructs each old Markdown body allowing only those recorded link replacements and the single historical heading label; the old current_checkpoint object is preserved losslessly as one additional historical snapshot. Rendered task rows, catalog rows, local and immutable evidence links, manifest digests, core hashes and locator hashes are checked.

Every one of the 1306 paths removed by the user's signed cleanup remains absent. The original PRD/TODO and all executable/ownership paths remain unchanged by this documentation. Both ignore and attribute controls remain byte-exact to c9. The separately reviewed scan control at `5e5f5fe5beaaee38d526f4cd8fc34e99488ea0d9` retains all 59 original lines as an exact byte prefix and adds only the 96 exact prior historical fingerprints. The original restoration receipt is copied byte-for-byte; no new scan result is inferred.

Run the read-only checker against the corresponding lean checkout, with the pinned archive Git objects available:

```sh
python verify.py --root /path/to/lean-checkout --receipt-dir /path/to/this-package
```

`validation-result.json` is the actual checker output. The checker validates documentation and source preservation; it does not execute performance, installed-native, hosted, independent human approval or activation gates. All qualification/activation flags remain false. The complete source-bound integration and hosted records referenced by the new checkpoint have their own immutable archive identities and limits.

This package is intended for the separate evidence branch. No raw evidence, compressed dump or placeholder directory is restored to the release PR. The manifest indexes all retained package files; this README and the checker are included in that index.
