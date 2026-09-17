# Exact implementation 7a387 publication

Actual PR #2954 head `7a387128e2cf2ec79b890dfebe2697e8a49eb45d` has tree `1ccec336c8a3aff22a4500b8f8350ae8fee3a345`, equal to validated local source/evidence commit `803c1716617bc80d3964013e159f70def45589d9`. Its parent is prepared checkpoint d8. The PR branch advanced without force from 9db, and its exact head, release base, body and draft/unmerged state were read back.

The [full-range scan receipt](receipt.json) records zero findings with pinned Gitleaks 8.24.2 across release base 4b89 through actual 7a387: 1,262 commits and approximately 58.76 MB scanned, 17.262 seconds including lock acquisition. The scanner binary and actual-commit ignore input are pinned; the ignore input is unchanged and no suppression or security-alert disposition was added. The raw receipt SHA-256 is `7f2cb632331784b00c1127484546a598c2af13982af53a92a2505559d9a15602`.

This receipt was generated before the branch moved; its false `branch_ref_moved` stays unchanged. [Publication readback](publication-readback.json) records the later verified update. The [manifest](manifest.json) binds all five original files byte for byte.

This evidence-only branch preserves the final scan without changing the tested PR head or interrupting its hosted runs. Its code and workflows remain exactly those of 7a387. It supplies no clean CodeQL/Sonar gate, installed qualification, independent approval, merge or release claim. Fresh hosted failures and subsequent results require their own records.
