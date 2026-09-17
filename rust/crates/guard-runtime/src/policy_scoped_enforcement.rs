//! Compose one authenticated generic winner with current non-overridable floors.
//!
//! Specificity and recency choose the generic row before composition. Its
//! source kind cannot give it priority over another row. Signed exact-command
//! allows may satisfy ordinary review; they do not become one-shot approvals.

use crate::policy_enforcement::{
    configured_pre_tool_policy_action, validate_pre_tool_result_matrix,
};
use crate::policy_scoped_request::derive_scoped_policy_request;
use guard_contracts::{GuardHookEnvelopeV2, PreToolResultV1};
use guard_policy_snapshot::scoped_authority::{
    PolicyAction, PolicyScope, PolicySourceKind, ScopedPolicyRow,
};
use guard_policy_snapshot::PolicySnapshotV4;
use serde_json::Value;

#[cfg(test)]
#[path = "policy_scoped_enforcement_tests.rs"]
mod tests;

pub(crate) struct ScopedPolicyEvaluation {
    pub(crate) result: PreToolResultV1,
    /// The fully composed action before Watch projects policy-only restrictions.
    pub(crate) observed_policy_action: Option<&'static str>,
    /// Provenance only: the caller binds this ID to this exact admitted snapshot.
    pub(crate) selected_decision_id: Option<u64>,
}

fn action(value: &str) -> Result<PolicyAction, String> {
    match value {
        "allow" => Ok(PolicyAction::Allow),
        "warn" => Ok(PolicyAction::Warn),
        "review" => Ok(PolicyAction::Review),
        "require-reapproval" => Ok(PolicyAction::RequireReapproval),
        "sandbox-required" => Ok(PolicyAction::SandboxRequired),
        "block" => Ok(PolicyAction::Block),
        _ => Err("native_scoped_policy_action_invalid".to_owned()),
    }
}

fn name(value: PolicyAction) -> &'static str {
    match value {
        PolicyAction::Allow => "allow",
        PolicyAction::Warn => "warn",
        PolicyAction::Review => "review",
        PolicyAction::RequireReapproval => "require-reapproval",
        PolicyAction::SandboxRequired => "sandbox-required",
        PolicyAction::Block => "block",
    }
}

fn rank(value: PolicyAction) -> u8 {
    match value {
        PolicyAction::Allow => 0,
        PolicyAction::Warn => 1,
        PolicyAction::Review => 2,
        PolicyAction::RequireReapproval => 3,
        PolicyAction::SandboxRequired => 4,
        PolicyAction::Block => 5,
    }
}

fn join(left: PolicyAction, right: PolicyAction) -> PolicyAction {
    if rank(left) >= rank(right) {
        left
    } else {
        right
    }
}

fn signed_exact_allow(row: &ScopedPolicyRow) -> bool {
    row.action() == PolicyAction::Allow
        && matches!(
            row.source_kind(),
            PolicySourceKind::SignedBundle | PolicySourceKind::SignedMemory
        )
        && matches!(row.scope(), PolicyScope::Artifact | PolicyScope::Workspace)
        && row.exact_command_sha256().is_some()
        && row.artifact_hash().is_none()
}

/// Equivalent to the current Python saved-decision composition after authority validation.
fn compose(current: PolicyAction, selected: &ScopedPolicyRow) -> PolicyAction {
    let saved = selected.action();
    if saved == PolicyAction::Block {
        return saved;
    }
    if matches!(
        current,
        PolicyAction::Block | PolicyAction::SandboxRequired | PolicyAction::RequireReapproval
    ) {
        return join(current, saved);
    }
    if saved == PolicyAction::Allow {
        return if current == PolicyAction::Review && signed_exact_allow(selected) {
            saved
        } else {
            current
        };
    }
    join(current, saved)
}

/// The snapshot must have passed resident authentication and request fencing.
/// Unsupported semantics are errors, never a partial successful application.
pub(crate) fn apply_scoped_pre_tool_policy(
    snapshot: &PolicySnapshotV4,
    envelope: &GuardHookEnvelopeV2,
    canonical_harness: &str,
    intrinsic: PreToolResultV1,
    now_ms: u64,
) -> Result<ScopedPolicyEvaluation, String> {
    validate_pre_tool_result_matrix(&intrinsic)?;
    if !matches!(snapshot.mode.as_str(), "enforce" | "observe") {
        return Err("native_policy_mode_invalid".to_owned());
    }
    if snapshot.scoped_authority.managed().is_some() {
        return Err("native_scoped_managed_policy_unsupported".to_owned());
    }
    if snapshot
        .scoped_authority
        .rows()
        .iter()
        .any(|row| row.artifact_hash().is_some())
    {
        return Err("native_scoped_content_context_unsupported".to_owned());
    }
    if [
        "policy_action",
        "daemon_status",
        "fail_mode",
        "permission_mode",
        "permissionMode",
    ]
    .iter()
    .any(|key| envelope.raw_payload.get(*key).is_some())
    {
        return Err("native_scoped_request_posture_unsupported".to_owned());
    }
    let request = derive_scoped_policy_request(envelope, canonical_harness)?;
    let selected = snapshot
        .scoped_authority
        .select_generic(&request, now_ms)
        .map_err(|_| "native_scoped_policy_match_invalid".to_owned())?;
    // Existing configured artifact overrides use the same actual identity as
    // the scoped lookup, not a separately discovered display label.
    let mut configured_payload = envelope.raw_payload.clone();
    configured_payload["artifact_id"] = request
        .artifact_id()
        .map_or(Value::Null, |value| value.into());
    let configured = action(&configured_pre_tool_policy_action(
        &snapshot.effective_policy,
        &configured_payload,
        &intrinsic,
    )?)?;
    let intrinsic_action = action(&intrinsic.minimum_action)?;
    let current = join(configured, intrinsic_action);
    let composed = selected.map_or(current, |row| compose(current, row));
    let mut effective = join(composed, intrinsic_action);
    let observed_policy_action = (snapshot.mode == "observe").then(|| name(effective));
    if snapshot.mode == "observe"
        && rank(effective) > rank(intrinsic_action)
        && rank(intrinsic_action) <= 1
    {
        effective = PolicyAction::Warn;
    }
    let selected_decision_id = selected
        .filter(|row| effective != current && effective == row.action())
        .map(ScopedPolicyRow::decision_id);
    let mut result = intrinsic;
    if effective != intrinsic_action {
        result.reason_code = "native_scoped_policy_composed".to_owned();
        result.reason = "HOL Guard applied the current policy to this action.".to_owned();
    }
    result.minimum_action = name(effective).to_owned();
    result.policy_action = name(effective).to_owned();
    result.decision = if rank(effective) <= 1 {
        "allow"
    } else {
        "deny"
    }
    .to_owned();
    result.explicitly_benign = effective == PolicyAction::Allow;
    validate_pre_tool_result_matrix(&result)?;
    Ok(ScopedPolicyEvaluation {
        result,
        observed_policy_action,
        selected_decision_id,
    })
}
