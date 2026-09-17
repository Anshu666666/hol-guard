# Review of the 42 RSP Sonar findings

The later [inline disposition record](sonar-reviewed-inline-dispositions.json)
applies four rule-specific comments to the six reviewed runtime false positives.
It pins the current source and confirms unchanged Python ASTs. Two overlapping
authority-condition lines cover four findings; the two HTTP-related findings
each have one exact annotation. The original inventory and review below retain
their historical open states. A new hosted scan must verify the resulting gate.

The retained [original inventory](sonar-rsp-9db-issues.json) has 42 open findings
for PR #2954 at `9db62e8844c2ba2627f55b6b00e58cb5b175185d`. The CI workflow is
[35239002030](https://github.com/hashgraph-online/hol-guard/actions/runs/35239002030),
Sonar job `105265428377`. The GitHub test merge is
`c9859a5b5d04526fa7e663d7c494e442ee4298c4`; its tree equals the PR head's
`47ba580366672b3b92cb46e6bb1d19c670444e94`. The job/head observation and tree
verification are distinct from Sonar's own task SCM-revision field.

The [review manifest](sonar-rsp-9db-review.json) preserves every issue ID, rule,
location, message and original status, plus the byte-exact inventory hash and
reviewed source hashes. Runtime and fixture files are identical between that
head and reviewed source `645ee401f234aaa4613d1d6b6f2a4e456f41e7fd`.

| Scope | Findings | Action or proposed disposition |
| --- | --- | --- |
| Two Rust matcher fixture generators | 26 `python:S5332`, ten `python:S2245` | Add exactly these generator paths to `sonar.test.inclusions`; retain analysis as tests. |
| MCP HTTP risk literal | One `python:S5332` | Propose false positive for the exact issue: string/regex classification performs no HTTP I/O. |
| Bounded daemon bind | One `python:S5332` | Propose false positive for the exact issue: existing local IPC with loopback rejection and retained request authentication. |
| Committed authority read | Four `pythonbugs:S2583` | Propose false positive for the exact issues: authenticated present bytes return a dictionary and can satisfy every retained comparison. |

## Correct test classification

`generate_remaining_matcher_fixtures.py` and `generate_specialized_fixtures.py`
under `rust/crates/guard-command/testdata/` generate checked-in differential test
vectors. They use fixed `random.Random` seeds (`32029` and `320109`) to choose
synthetic argument vectors. They do not generate passwords, keys, authentication
tokens or security nonces. HTTP literals are command-matcher test inputs and do
not dispatch requests. Their `--check` modes compare deterministic generated
vectors with the checked-in JSON corpus.

The configuration appends only those two exact paths to the existing test
inclusions. Source/test roots, all existing patterns and explicit exclusions
remain unchanged. Sonar classifies matching files as tests and avoids duplicate
production classification; applicable test analysis still runs. A new actual
scan must confirm the resulting scope and gate. This follows the [SonarQube Cloud
analysis-scope documentation](https://docs.sonarsource.com/sonarqube-cloud/managing-your-projects/project-analysis/setting-analysis-scope/excluding-files-based-on-patterns).
No fixture, deterministic seed, HTTP literal, generated case or runtime code is
changed to satisfy an analyzer heuristic.

## Six exact runtime dispositions proposed

`AaCv--s18w2aZZg76-NB`, `python:S5332`, is the HTTP alternative at
`mcp_tool_calls.py:1131`. `_literal_pattern` constructs escaped regex text;
`_matches_any` uses membership and `re.search`. The value is a detector input,
not a destination. Existing literal-prefilter and previous-regex parity tests
cover both HTTP and HTTPS. Removing the HTTP alternative would weaken detection.

`AaCv--Wk8w2aZZg76-NA`, `python:S5332`, is
`BoundedThreadingHTTPServer.server_bind` at `bounded_http.py:198`. Calling
`TCPServer.server_bind` keeps the local socket bind while avoiding the inherited
reverse-DNS metadata lookup. `verify_request` independently rejects non-loopback
peers before request processing. Protected daemon operations retain origin,
header-token and challenge checks. The bind metadata tests cover IPv4/IPv6; the
real-listener witness keeps its explicit environment limitation. This review
does not authorize an external cleartext service or bypass authentication.

`AaCv--wk8w2aZZg76-NF`, `AaCv--wk8w2aZZg76-NC`,
`AaCv--wk8w2aZZg76-ND` and `AaCv--wk8w2aZZg76-NE`,
`pythonbugs:S2583`, target the guard at
`native_command_control_authority_store.py:246–249`.
`read_private_state` returns bounded bytes from a present verified file;
`decode_authority` checks schema, canonical bytes and HMAC, then returns a
dictionary. `test_unchanged_projection_shares_lease_with_native_readers` reaches
the unchanged committed read while forbidding writes and holding a native-reader
lease. The `None`, phase, digest and key comparisons are mandatory failure paths;
none is removed. Existing byte-read, signature-tamper and shared-vector witnesses
support the concrete nonconstant branch.

No external disposition or rule suppression is applied by this commit. Before
applying these six proposed false-positive transitions, verify the current issue
IDs/rules/locations and analyzed source against the manifest. Retain before/after
API receipts and re-read the actual quality gate. Re-review any source or finding
change; no later issue inherits this review.

## Bounded validation

The existing config, loopback-bind, literal-prefilter, authenticated-authority and
shared-reader-lease witnesses pass **12 tests in 2.41 seconds**, with no skips. The
real-listener test passed in this run; its explicit environmental skip remains in
the test for hosts where it cannot execute. These checks ran under the shared
performance lock. The exact selection is retained in the review manifest. They
do not constitute a Sonar rescan, external disposition receipt or full runtime
qualification. The generated matcher fixtures and production sources are unchanged.
