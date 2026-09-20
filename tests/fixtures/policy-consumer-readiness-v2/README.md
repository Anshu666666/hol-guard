# Consumer readiness v2 wire contract

These synthetic interoperability vectors contain only a public test key. They do not assert a live ready runtime. Both implementations must preserve these files byte for byte.

Routes: `POST /api/guard/runtime/policy-consumer/challenges` accepts `issue` and returns `challenge`; `POST /api/guard/runtime/policy-consumer/observations` accepts `observation` and returns `ack`. `runtimeSessionId` is the existing public session identifier. All requests use the existing authenticated runtime session writer authority; a wire subject is never authority by itself.

JSON Schema defines exact field sets. Additional normative validation, required before signature verification or persistence:

- UTF-8 document is at most 16,384 bytes, nesting at most 12, no duplicate decoded object keys. JSON numbers use only canonical unsigned integer spellings (no minus, fractional or exponent notation), and are at most 9,007,199,254,740,991. Every string matching an ID/hash/counter pattern is ASCII. Unknown fields are rejected at every level.
- Decimal counters are canonical unsigned u64 strings, at most `18446744073709551615`. Native/resident/generation-floor counters are positive; publisher epochs may be zero. They must never pass through JavaScript numbers.
- `0 < expiresAtMs - issuedAtMs <= 60000` for a challenge. Ready requires non-null complete localContext and exact sourceInputDigest equality. Native generationFloor/policyDigest equal the publisher generation/policyDigest; both resident generations agree. Snapshot expiry must exceed challenge issuance. Server admission independently enforces its current clock and authority expiries.
- Signature uses fixed ES256/SHA256 and exactly 64 IEEE-P1363 bytes encoded as canonical unpadded base64url (86 characters, decode/re-encode identical). DER, padding, alternate algorithms and alternate encodings are refused.
- Signing bytes are the ASCII domain `guard-consumer-readiness-observation-v2` followed by one zero byte followed by canonical UTF-8 JSON of the body. Canonical JSON sorts object keys by code-unit order, preserves array order, has no extra whitespace and uses the strict integer-only values above. A single nested `challenge` retains its own challenge contractVersion, distinct from the outer observation body contractVersion.
- A ready ack has validUntilMs strictly greater than receivedAtMs. Unavailable ack has validUntilMs null. ChallengeSequence is a positive safe integer, subjectVersion namespaces its sequence. Server timestamps and exact echoed challenges cannot be supplied or extended by a caller.

A signed ready report is an authenticated agent's fresh observation permitting only delivery in the named narrow profile. It is not proof that a future policy has been applied, hardware attestation, or remote verification of a native HMAC. Native applied acknowledgments remain separate.

## Initial fixed profile support

The initial `guard.native-scoped-shell-exact.v1` profile is limited to the three
complete command strings `pwd`, `true`, and `whoami`, with exact UTF-8 SHA-256
selectors specified in `profile.json`. Leading/trailing whitespace, arguments,
wrappers, case changes and every other command digest are outside this profile.
The profile supports only Codex PreToolUse, the project Bash artifact, permanent
allow/block/review rules, and Enforce mode. The existing authenticated per-device
projection remains required. No observation contains command plaintext or an
arbitrary caller-supplied capability list. An authenticated observation cannot
admit a rule outside this fixed set, even if the native runtime supports other
shapes. This is delivery representability, not an applied-policy acknowledgement.

This profile boundary was pinned after the original schema and revision-2 wire
vectors were frozen. Their bytes and signing semantics are unchanged. Actual
installed-native producer and rule-effect controls are required for the profile;
source review or synthetic native responses are not execution evidence.

The authenticated agent session uses harness `hol-guard`; `codex` above names
only the supported native request/rule producer. These identities are not
aliases. The signed subject echoes the exact authenticated nullable runtimeId;
a null runtime must never be synthesized from a harness name or replaced by an
unrelated runtime grant. The server independently verifies the current parent
grant, registered machine, exact session and every non-null runtime binding.
