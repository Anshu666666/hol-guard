//! Scoped resident evaluation with an exact immutable source commitment.

use crate::edge::{authoritative_event, canonical_harness, payload_kind, request_identity};
use crate::native_hook_receipt::receipt_from_scoped_pre_tool;
use guard_contracts::{
    GuardHookEnvelopeV2, GuardHookPayloadKindV2, NativeHookDecisionReceiptV1, PreToolResultV1,
};
use guard_policy_snapshot::PolicySnapshotV4;
use serde::Serialize;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ScopedDecisionBinding<'a> {
    policy_generation: u64,
    policy_digest: &'a str,
    source_input_digest: &'a str,
    runtime_identity: &'a str,
    resident_generation: u64,
    selected_decision_id: Option<u64>,
}

#[derive(Serialize)]
#[serde(deny_unknown_fields)]
struct ScopedEdgeResult<'a> {
    schema: &'static str,
    authority: &'static str,
    request_id: String,
    harness: String,
    event_name: String,
    payload_kind: GuardHookPayloadKindV2,
    result: PreToolResultV1,
    observed_policy_action: Option<&'static str>,
    receipt: NativeHookDecisionReceiptV1,
    policy_binding: ScopedDecisionBinding<'a>,
}

/// Only the versioned resident store may provide the authenticated snapshot.
pub(crate) fn evaluate(
    envelope: GuardHookEnvelopeV2,
    snapshot: &PolicySnapshotV4,
    resident_generation: u64,
) -> Result<Vec<u8>, String> {
    let harness = canonical_harness(&envelope.harness)?;
    let event_name = authoritative_event(&envelope)?;
    let kind = payload_kind(&envelope.raw_payload)?;
    if event_name != "PreToolUse" || kind != GuardHookPayloadKindV2::Inline {
        return Err("native_scoped_hook_route_unsupported".to_owned());
    }
    let (request_id, request_digest) = request_identity(&envelope)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "native_policy_clock_invalid".to_owned())?
        .as_millis();
    let now_ms = u64::try_from(now).map_err(|_| "native_policy_clock_invalid".to_owned())?;
    let intrinsic = guard_command::pretool::evaluate_pre_tool_envelope(
        &harness,
        &event_name,
        &envelope.raw_payload,
    );
    let evaluated = crate::policy_scoped_enforcement::apply_scoped_pre_tool_policy(
        snapshot, &envelope, &harness, intrinsic, now_ms,
    )?;
    // The receipt uses the verified full snapshot, never unverified fields
    // supplied beside a compact request reference.
    let mut receipt_envelope = envelope;
    receipt_envelope.policy_snapshot = serde_json::to_value(snapshot)
        .map_err(|_| "native_hook_edge_response_invalid".to_owned())?;
    let receipt = receipt_from_scoped_pre_tool(
        &receipt_envelope,
        &request_id,
        &request_digest,
        &harness,
        &kind,
        &evaluated.result,
        evaluated.observed_policy_action,
    )?;
    crate::encode_response(&ScopedEdgeResult {
        schema: "guard-hook-edge-result.v3",
        authority: "rust",
        request_id,
        harness,
        event_name,
        payload_kind: kind,
        result: evaluated.result,
        observed_policy_action: evaluated.observed_policy_action,
        receipt,
        policy_binding: ScopedDecisionBinding {
            policy_generation: snapshot.generation,
            policy_digest: &snapshot.policy_digest,
            source_input_digest: &snapshot.source_input_digest,
            runtime_identity: &snapshot.runtime_identity,
            resident_generation,
            selected_decision_id: evaluated.selected_decision_id,
        },
    })
}
