# Policy delivery diagnosis and recovery

Policy delivery has separate connection, validation, local publication and
continuation stages. A saved policy, a successful upload and a running worker
establish different facts. Use the observed stage to choose a recovery action.

## Capture the current observation

Run the existing passive export on the affected installation:

```bash
hol-guard cloud-review status --support-export --json
```

The export reads retained state without reconnecting, changing consent, applying
policy or starting a worker. `guard_version` is the package's declared version;
record the installed artifact identity separately when investigating a release.
`observed_at` is the capture time. Identity and digest fields support correlation
in an authorized private support channel. They are not suitable for public issue
attachments. Review those identifiers before sharing the export.

The export omits raw commands, prompts, request bodies, credential material and
exception details. Sync counts accept nonnegative JSON integers, status fields
accept known values and timestamps require an explicit UTC offset. Malformed
stored values become `null`; arbitrary error text becomes
`unclassified_failure`. These observations do not replace authentication or
validate a policy's authority.

## Identify the stage

| Observed evidence | Meaning and responsible actor | Safe next action |
| --- | --- | --- |
| `failure_classes.auth`, consent reason or unavailable credentials | The local connection or review authorization needs the operator's attention. | Check the intended connection. Restore it through the ordinary sign-in flow when needed. Restore delivery with existing valid consent; renew consent only when a new authorization is intended. A revoked decision needs fresh authorization. |
| `failure_classes.invalid_policy` with a bounded `policy.last_error.reason` | A candidate was rejected. The reason can identify signing, integrity, validity, compatibility or target checks. | Use the existing rejection guidance. The workspace administrator corrects the candidate or signing configuration; the device operator updates an incompatible installation or corrects its clock. Fetch the corrected candidate through normal sync. |
| `failure_classes.wrong_target` | A recorded decision did not match its intended subject. | Return to the request's original device and workspace. Create a fresh request when its binding changed. Do not retarget a signed decision or reuse its approval proof. |
| `failure_classes.runtime_publication` | The recorded application summary reports rejection. Saving or receiving the policy did not prove application. | Inspect the bounded publication reason and local integrity status. Use the supported repair flow if required, then sync the current candidate and inspect its application evidence. |
| `failure_classes.continuation` | A retained, current-connection terminal event reports a failed continuation. | Inspect the original request's supported recovery action. Retry delivery of a saved result separately from execution. Do not approve or resume again merely because a result upload failed. |
| Degraded optional telemetry with independent application evidence | Observation delivery is delayed; it does not undo the separately recorded policy result. | Let normal background synchronization retry the affected telemetry lane. Follow storage or permanent-request error guidance when present. |

An absent failure flag is not a health certificate. In particular,
`cloud_review.continuation_evidence.runtime_state` stays `unknown`: retained
events cannot establish a currently running worker. Compacted, invalid,
superseded, future or differently bound events are excluded from this failure
observation. Missing policy detail does not mean that a team policy applied.

The error catalog supplies an owner, retryability, retained-authority meaning
and next action for recognized codes. Retryability describes the named
operation. It never grants permission to repeat a decision, renew consent or
replace a valid policy without the corresponding authorization.

## Verify recovery

Capture another export after the supported recovery action and compare the
same installation, workspace and candidate identity in the authorized channel.
Distinguish the failed candidate from any still-valid previously applied policy.
Confirm application through validated acknowledgement/publication evidence;
confirm a continuation through its exact request outcome. A success response
from connection, consent or upload alone does not establish either result.

Do not remove a matcher, disable verification, edit protected persistence,
delete receipts or replay an older revision to make a diagnostic turn green.
If the required evidence is unavailable, record that limit and the remaining
owner action.

## Current contracts and historical notes

Use [capabilities and authority](policy-capabilities-and-authority.md) to choose
the actual policy path, [delivery and consent recovery](cloud-review-delivery-recovery.md)
for worker recovery, [telemetry outage behavior](policy-sync-telemetry-outages.md)
for upload failures and the [invalid-bundle runbook](managed-controls-invalid-bundle-incident-runbook.md)
for rejected candidates. Import and export have their own
[scope-preservation contract](portable-policy-boundaries.md).

Branch names, implementation notes and earlier successful runs describe their
recorded source and environment. They do not certify another binary, active
deployment, fleet or native credential. The source tests below cover isolated
contracts; installed acceptance requires its own artifact and runtime evidence.

Source references:

- [`policy_support_export.py`](../../src/codex_plugin_scanner/guard/policy_support_export.py)
  selects the passive, current-connection projection.
- [`policy_runtime_error_catalog.py`](../../src/codex_plugin_scanner/guard/policy_runtime_error_catalog.py)
  and [`policy_bundle_parser.py`](../../src/codex_plugin_scanner/guard/policy_bundle_parser.py)
  define trusted guidance.
- [`test_guard_policy_support_export.py`](../../tests/test_guard_policy_support_export.py)
  covers passive reads, binding exclusion and retained continuation outcomes.
- [`test_policy_support_scalar_privacy.py`](../../tests/test_policy_support_scalar_privacy.py)
  checks malformed stored observations, secret canaries and valid scalar values.

These links describe the code under review. They do not claim that a support
operator or target installation has completed a recovery exercise.
