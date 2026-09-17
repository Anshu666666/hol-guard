# Policy sync during telemetry outages

Receipt upload, policy validation, policy application, and optional telemetry
have separate results in `hol-guard sync --json`. A pain-signal or event-upload
outage does not undo an accepted policy or discard its acknowledgement. The next
sync sends the saved acknowledgement and retries the pending telemetry through
the existing upload cursors.

`telemetry_status` is `degraded` when either optional upload cannot complete.
`pain_signals_upload_status` and `guard_events_upload_status` identify that lane,
and their corresponding `*_upload_reason` fields contain a stable reason code.
The existing `pain_signals_uploaded` count includes successful pages completed
before a later page failed. The existing `guard_events_v1` result remains
available. The CLI displays **Telemetry uploads delayed** beside the independent
policy application result.

Reason codes distinguish an unavailable endpoint (`telemetry_endpoint_unavailable`),
rate limiting (`telemetry_rate_limited`), service failure
(`telemetry_service_error`), transport failure (`telemetry_transport_error`),
and other upload failure (`telemetry_upload_failed`). These summary fields omit
server error bodies and credentials. Ordinary background sync retries pending
uploads; changing or republishing policy is unnecessary.

Authorization, endpoint trust, and plan failures still fail the sync operation.
HTTP 401 and 403 remain authorization errors even if an error message happens to
contain the digits `429`. They require the existing sign-in or entitlement
recovery path. A successful telemetry upload never establishes policy authority.
