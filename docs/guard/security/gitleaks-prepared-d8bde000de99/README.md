# Complete scan of the prepared GitHub checkpoint

Pinned Gitleaks **8.24.2** scanned the complete release-base range `4b89e0d2d496a85f04922b2e019a4aea15326bb9..d8bde000de992009be3b2ed009347d2b3707ef0d` and returned **zero findings**, exit code 0, in 12.69 seconds including lock acquisition. The scan used the actual GitHub commit object fetched from the repository. Its tree `1967a2127a325ae340d313bf73e80c60abb4d1f6` exactly matches local source/evidence commit `73e83ddfac66ef1e04771a2aa51e96cdb1fbee77`.

`receipt.json` records the full command, scanner digest and hashes of the unchanged raw report, log and ignore input. The ignore input contains the previously reviewed exact fingerprints, including the 68 actual-`647ff7d` entries whose independent metadata review is retained in the adjacent directory. No additional exception was added for this scan.

This scan preceded branch movement and the documentation/evidence child containing this receipt. That final actual child requires its own full-range scan. The result does not determine CodeQL or Sonar alert state, hosted required-check status, review approval, or installed qualification.
