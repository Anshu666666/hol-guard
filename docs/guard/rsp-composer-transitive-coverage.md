# Composer transitive identity coverage

Valid `composer.lock` entries such as `acme/parser` reached the complete parser
but were then discarded by a helper that treated an unscoped slash as a
filesystem path. With a direct anchor and 99 matched Composer dependencies, the
baseline returned only the anchor. A faster result with those lookups omitted
does not perform equivalent package review.

The transitive evaluator now selects name admission by lockfile ecosystem.
Packagist accepts its vendor-qualified package grammar and preserves the vendor
through canonical lookup, direct-dependency exclusion and emergency-deny
evidence. npm nested `node_modules` paths and other ecosystems keep their prior
rules. Absolute paths, traversal components, extra slashes, backslashes and
invalid package punctuation cannot become a different Packagist identity.

The name grammar follows the [official Composer schema](https://getcomposer.org/schema.json),
checked on 2026-09-17. The equivalent expression uses separator-led groups,
avoiding ambiguous nested repetition. Case normalization follows the existing
Packagist canonical identity contract. It does not change the common identity
parser, global package grammar or lockfile resource limits.

The regression suite invokes real Composer command parsing, a real signed
cached bundle, the package evaluator and persisted evidence. It covers same-leaf
names in different vendors, canonical direct identities, invalid path rejection,
and fresh/stale emergency denies retaining the vendor and recommended fix.
There is no installed executable or performance qualification claim.

The RSP-050/054 fixture oracle retains the original baseline coverage failure.
Its corrected candidate performs additional required lookups, so the two arms
remain noncomparable for performance. Do not rename Composer fixtures to
unqualified names, accept the missing dependencies as an oracle, or calculate a
speed ratio from the baseline's skipped work.
