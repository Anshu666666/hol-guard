# Exact foundation a001b publication

The full release-base range through actual GitHub commit `a001b2691f481b7b5a66dd14d68e48d61c44cb78` passes pinned Gitleaks 8.24.2 with zero findings in 14.487 seconds including lock acquisition. Its tree `24e28be411272ad055f47012603d35e0394de67b` equals validated local source `7c22fd3eb4a7682095b720fa7ba1fd542b9199f0`. The original ignore input is unchanged. No suppression or alert disposition was added.

The [receipt](receipt.json) binds scanner, commit, parent, tree, command, ignore and output hashes. [Publication readback](publication-readback.json) verifies PR #2951 moved without force from 26cd to a001b against release/3.2, with the exact prepared body and unmerged state. The receipt was captured before the branch moved; its false `branch_ref_moved` remains historical.

At the retained 21:09:39 UTC 26cd checkpoint, Linux soak and Kilo were running. A later final observation must retain their actual outcomes; publication does not convert a running or interrupted attempt into a pass. Production Python/Rust and native stress source remain identical to the earlier completed cdd soak, which has its own build and older acceptance contract. Fresh a001b hosted tests, current security checks and independent review remain required.
