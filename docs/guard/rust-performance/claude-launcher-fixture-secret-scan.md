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

## Go-installed detector version metadata

The next actual Security Gates run at `24ba2d130` failed in the fixture
regression before either history or working-tree scanning. The workflow uses
`go install` at the pinned `v8.24.2` module, while the regression requires its
`version` command to identify `8.24.2`. Upstream's tagged
[`cmd/version.go`](https://github.com/gitleaks/gitleaks/blob/v8.24.2/cmd/version.go)
initializes that value to `version is set by build process`; plain `go install`
does not supply the release linker value. This explains the source-visible
mismatch; the old CI log exposed only the fixed verification failure message.

The installer now sets that one version symbol through `-ldflags -X` while
retaining the same pinned module. The checker still rejects any version other
than `8.24.2`. No detector rule, exception, global default, scan scope or failure
gate changes. The real stamped local 8.24.2 binary passes all 15 positive,
negative, cross-rule and history controls. Actual CI must verify the corrected
Go installation and then execute the original complete scans.
