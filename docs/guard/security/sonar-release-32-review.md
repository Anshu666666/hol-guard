# Release 3.2 Sonar review

The analysis for PR 2970 at `24ba2d130a90f36b676139f03cabea98a2c3b00e`
completed successfully. Its quality gate failed on new-code reliability and
security ratings, both C against the required A. Coverage passed at 82.4%
against 80%; duplication passed at 0.0% against 3%; maintainability was A;
security-hotspot review was 100%. No threshold or exclusion was changed.

GitHub run `35228364797` contains 114 unique jobs: 110 successful, three skipped,
and one failed. Its only failed job is Sonar `105227738372`, quality-gate step 13.
This is the observed historical result, not a claim about a later candidate.

## Source correction

Finding `AaCvof9SGaZV1BelGvDn` correctly identified a self-comparison in the MCP
trace test. That assertion now checks pinned canonical wire hashes and byte
lengths for all eight trace definitions. It also checks sensitivity to call
count and regeneration from a distinct equivalent trace object. Existing
catalog-refresh assertions remain in place; no workload input changed.

## Individually reviewed findings

The accompanying JSON enumerates the remaining 42 finding IDs, their exact
locations, source hashes, rule and technical justification. The five reviewed
source files are identical at the analyzed commit and review base
`599509be545b9992076d7f9f71dd19ecfd34bbc2`. Reconstructing Sonar's source-lines
responses reproduced each complete source file byte for byte.

| Findings | Scope | Technical result |
| --- | --- | --- |
| 4 | Authenticated command-control marker guard | Missing, closed, changed-digest and changed-key markers must refuse the shared-read path. Matching committed state succeeds. The conditions are not constant. |
| 1 | MCP HTTP risk token | The literal detects outbound-network content. It opens no connection. Removing it would reduce detection coverage. |
| 1 | Local daemon HTTP binding | The daemon defaults to loopback and the server rejects non-loopback peers before dispatch. The override avoids reverse DNS and adds no external HTTP route. |
| 26 | HTTP parser fixture strings | These are inert matcher inputs, including malformed and destructive-command cases. No command or HTTP request is executed. |
| 10 | Seeded parser-fixture generators | Fixed seeds produce reproducible test vectors, not security material. CSPRNG substitution would break exact fixture regeneration. |

The new marker tests use actual private marker files, signed encoding and
verification with a fixed test key provider. They demonstrate each refusal,
matching-state success and refusal of matching fields signed by the wrong key.
The production guard is unchanged. The corrected trace assertion and six marker
tests passed together: **7 tests**. The earlier full MCP-test/new-marker batch
had 25 passes and one invalid-key-length error in the new wrong-signature test
setup; correcting that fixture to a valid, distinct 32-byte key produced the
focused result above. The new marker test module type-checked with zero errors
and zero warnings. Fixture-generator source review was independently repeated.

## Remaining action

The 42 false-positive dispositions have **not** been applied. This environment
has no Sonar MCP tool, authenticated Sonar CLI or existing Sonar token. The
source-bound manifest makes the proposed individual dispositions reviewable;
it does not suppress any analyzer finding. The corrected assertion also needs
a fresh analysis before its remote finding can be considered resolved. The
last observed quality gate remains **ERROR**.

Evidence: [failed Sonar job](https://github.com/hashgraph-online/hol-guard/actions/runs/35228364797/job/105227738372)
and [PR 2970 Sonar dashboard](https://sonarcloud.io/dashboard?id=hashgraph-online_hol-guard&pullRequest=2970).
Re-review these dispositions if the source hashes, marker validation,
non-loopback peer rejection, fixture execution behavior or PRNG usage changes.
