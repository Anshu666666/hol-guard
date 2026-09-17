# Claude launcher fixture secret-scan exception

The single `generic-api-key` finding in the generated launcher reference fixture
is the `source_sha256` value for
`src/codex_plugin_scanner/guard/adapters/codex_daemon_hook_auth.py`.
The fixture generator computes this public digest directly from source bytes.
Both the source and fixture at commit
`107606388ad55f924a4e2924b4ff84e5fa08e6ff` reproduce that same digest, as do the
reviewed current files. It is not a credential, authentication token, or fixture
signing key. The detector interprets the authentication-related filename followed
by a high-entropy digest as a generic credential.

`.gitleaks.toml` extends the complete built-in ruleset. Its only addition is a
`generic-api-key` rule exception with `condition = "AND"`: the path must equal
the specific generated fixture path and the extracted value must equal the
single reviewed public digest. There is no path-only, wildcard-digest, global
rule, commit, or repository-wide exception. Existing historical fingerprints
remain unchanged. A future regenerated digest requires fresh review; the
exception is deliberately not expanded automatically.

The Security Gates workflow uses its pinned Gitleaks 8.24.2 binary to verify
the actual detector before its ordinary directory or isolated-history scan.
The regression proves that the default detector flags the original fixture,
the narrow exception accepts it, and all three negative controls remain
findings: a different generated credential-shaped value in the same file, a
different value in the same source field, and the original public value at
another path. An isolated two-commit repository verifies that removing the
fixture from HEAD still leaves a historical finding under defaults, which the
same exact exception handles. Reports are redacted, scanner output is captured,
and only fixed case names and counts are emitted.

The rule-extension and conjunctive-allowlist behavior follow the
[Gitleaks configuration contract](https://github.com/gitleaks/gitleaks#configuration).
Local validation uses the same pinned detector; actual GitHub Security Gates
must still pass on the published commit range.

The focused scanner and workflow suites passed 93 tests. Ruff, formatting,
fixture regeneration check and diff checks passed; the new checker typechecks
with zero errors (19 warnings). Scanning the actual introducing commit with the
default rules reproduced exactly one finding; scanning that same historical
commit with this exception returned zero. Independent source review found no
security-scope blocker. No fixture bytes or existing ignore entries changed.
