# Local Policy + Cloud Exceptions — Operator Guidance

Current operator source of truth for team/device policy delivery. Historical
Phase 0 implementation notes are labeled at the end and are not current
behavior.

In-review dependencies (not merged on `main` at this writing):
[hol-guard#2948](https://github.com/hashgraph-online/hol-guard/pull/2948)
(generic v2 publication admission),
[hol-guard#2949](https://github.com/hashgraph-online/hol-guard/pull/2949)
(canonical lane reporting and signed memory targets),
[hol-guard#2959](https://github.com/hashgraph-online/hol-guard/pull/2959)
(bundle vs memory lane ownership). Until those land, do not assume truthful
lane labels, exact multi-target memory projection, or additional v2 admission
hardening beyond the live-state check in `policy_bundle_is_enforceable`.

## What still holds

- Local Review/Inbox decides the live pause. That is not Policy.
- Evidence is the receipt and history workspace for what already happened. It is
  not Policy and not a place to author exceptions.
- Cloud exceptions are governed risk acceptances delivered in a signed bundle.
  Local Policy must not author broad exceptions on the device. Cloud scope
  remains `GuardExceptionScope`: `artifact`, `publisher`, or `harness`. Broader
  cwd/project/team scopes are unsupported until Cloud advertises them.
- Bundle authority is fail-closed. Signature, `bundleHash`, and `payloadHash`
  must verify. Unsigned top-level `policy`, `teamPolicyPack`, and `exceptions`
  fields are not enforcement authority.
- Do not edit local protected files, SQLite rows, or cached bundle JSON to
  “unstick” a device.

## Create → approve → sync → verify → recover

1. **Create** the policy or exception in Guard Cloud for the intended workspace.
   Leave it in `draft` / `pending_approval` until an owner approves it. A
   correctly signed unpublished document is not live: v1 `rolloutState` and v2
   `payload.spec.rolloutState` must be `enforcing`, `enforced`, or
   `rollback_available`. Omitting v2 `spec.rolloutState` remains live for
   already-published generic bundles.
2. **Approve** in Cloud. Approval does not mean every device applied it.
3. **Sync** on the device (`hol-guard sync` or the daemon receipt sync). The
   daemon admits only the connected workspace. Wrong-workspace, stale, expired,
   or unsigned payloads are refused and the last valid bundle stays in effect.
4. **Verify** without touching protected files:
   - Policy tabs show Remembered rules, Cloud exceptions (read-only), and Strict
     config.
   - Cloud exceptions appear only from the signed `cloudExceptions` projection.
   - Exact Cloud Review can resolve one pending pause (`allow_once` / `block`).
     That is not reusable policy or decision memory.
   - An immutable policy block is not a reviewable request and cannot be
     approved remotely. See the generated contract
     `docs/guard/contracts/guard-cloud-review.md`.
5. **Recover** a failed delivery:
   - Confirm the Cloud rollout is published (not draft).
   - Reconnect Guard to the intended workspace, then sync again.
   - If the bundle is stale or a newer revision exists, wait for reconnect and
     take the newest signed revision. Do not copy files between devices.
   - If native runtime is unavailable, treat that as missing release evidence,
     not a Python fallback. Reinstall the published wheel.
   - If exact review fails (`rejected_stale`, `rejected_binding`, unsupported
     continuation), retry from Cloud after the local request is current. Guard
     does not auto-continue the agent.

Unsupported effects this tree does not promise: automatic agent continuation
after Cloud allow, local exception authoring, absolute Cloud `block`/`review`
over a more-specific local `allow`, or silent skip of required release tests.

## Runtime map (current)

| Surface | Operator meaning |
| --- | --- |
| `GET /v1/policy` | Local remembered decisions plus read-only `cloud_exceptions` |
| `POST /v1/policy/sync` | Fetch and admit the signed bundle |
| `GET /v1/policy/cloud-exceptions` | Active Cloud exception DTO rows |
| `policy_bundle_parser.py` | v1 schema, hashes, RSA-PSS verify, live rollout |
| `policy_bundle_v2.py` | Generic v2 envelope and acknowledgements |
| Exact Cloud Review | One-request `guard.review.resolveExact` only |

Digest-only or untrusted refreshes are rejected. A still-current verified
bundle remains effective; otherwise remote materialized rows and Cloud
exceptions are cleared.

## Historical (2026-06, Phase 0 — do not treat as current)

The original boundary audit described dashboard gaps (local `PolicyExceptionForm`,
tab labeled Exceptions, missing Cloud DTO) and a portal worktree deferral. Those
were implementation notes for a slice that later shipped Remembered rules / Cloud
exceptions / Strict config UI, signed `cloudExceptions`, and fail-closed daemon
admission. Use the operator flow above, not the Phase 0 gap tables.
