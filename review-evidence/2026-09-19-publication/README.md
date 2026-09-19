# Recovery archive publication audit

The recovered package and supplements were assembled as commit `2787be7f680f0d0b34991ed7ac18072ca30fa290`, tree `2aca3cd102c111e2cc103b86e366eaa7c2e8a7a1`, on parent `7e2c4989a1b799e7921795e7d77cd7b54b0603cd`. The frozen package preserves 428 logical records and seven original component manifests. The separate environment correction and plaintext scan remain distinct from that package.

The complete actual candidate history scan retained **one finding and exit 1** across 1,275 scanned commits and 62,128,291 bytes. All 52,101 reachable Git objects were available and the repository was not shallow. This is not a zero-findings scan.

The single finding belongs to earlier commit `f6dc83e57578625876a51c796518242501e703fc`, in `review-evidence/2026-09-18/hosted-diagnostics/intel-cache-only-35371285417-receipt.json` at line 280. It is the content SHA-256 value for `aggregate/installed-offline-secrets.json`. Independent review verified that value against the unique 17,965-byte member in the original archived ZIP, and verified unchanged receipt and archive bytes through the new candidate. No actual credential is represented by that value.

The finding, its raw redacted report, scan log and independent classification are preserved here. No ignore entry, rule or configuration was changed to suppress it. The Git-history scan does not decode compressed artifacts; the separate 2026-09-19-secret-scan supplement preserves its own complete plaintext scan and all 261 individually classified source-digest/synthetic-fixture findings.

The canonical release repair remains `8156ba5ec1e69908290d481bad421ba5f9bd93b2`, whose separate full-history scan had zero findings. This archive publication neither changes the release tree nor supplies missing installed qualification or independent release approval.
