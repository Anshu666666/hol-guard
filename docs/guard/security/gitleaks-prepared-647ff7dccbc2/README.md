# Exact prepared commit evidence review

Prepared GitHub commit `647ff7dccbc287401933ff807d11937227ac3348` has tree `a01f031eebb5dfae6aa8f1776cf223a9d7a1a49f`. The complete release-base-to-commit scan returned 109 matches and 68 unique fingerprints. Independent review checked every match and exact reported span. This directory retains the unchanged redacted scan, its receipt, a detailed proof and the precise fingerprints.

The matches contain 84 public Sonar issue identifiers, 20 installed module digests, three reconstructed Unix launcher digests, one retained CodeQL response digest and one Windows PE producer attestation. The Windows binary itself remains unavailable: full PE-byte recomputation is not claimed. The CodeQL response digest recomputes from all 59,786 bytes of the retained pre-read response.

Only these 68 actual-commit fingerprints are added to `.gitleaksignore`. There is no rule, directory or pattern-wide exception. This review does not determine any underlying Sonar or CodeQL alert disposition. A clean full scan of the actual final GitHub child commit remains required before the implementation branch moves.

The original verification program is retained verbatim as `verify.py.txt`. It records the original temporary evidence paths and is archival source, rather than a portable repository command. Its proof and input bytes remain unchanged.
