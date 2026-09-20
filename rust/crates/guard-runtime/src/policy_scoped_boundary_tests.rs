//! Python-produced compiler inputs; no resident, signature or installed authority claim.

use super::*;
use guard_command::pretool::evaluate_pre_tool_envelope;
use serde_json::json;

fn snapshot(case: &Value) -> PolicySnapshotV4 {
    let vector: Value = serde_json::from_str(include_str!(
        "../../../../contracts/native-policy-snapshot/v4/policy-snapshot-vector.json"
    ))
    .unwrap();
    let mut value = vector["snapshot"].clone();
    value["mode"] = case["compiledMode"].clone();
    value["effective_policy"] = case["effectivePolicy"].clone();
    value["scoped_authority"] = json!({
        "schema":"guard-native-policy-authority.v1",
        "generic_precedence":"specificity-recency.v1", "rows":[], "managed":null
    });
    serde_json::from_value(value).unwrap()
}

fn envelope(case: &Value) -> GuardHookEnvelopeV2 {
    serde_json::from_value(json!({
        "schema":"guard-hook-envelope.v2", "harness":"codex", "event":"PreToolUse",
        "raw_payload":case["payload"], "policy_generation":1, "policy_snapshot":{},
        "source":{"cwd":std::env::temp_dir(),"home_dir":std::env::temp_dir(),"guard_home":std::env::temp_dir()}
    })).unwrap()
}

#[test]
fn actual_python_boundary_vectors_reach_native_composition() {
    let fixture: Value = serde_json::from_str(include_str!(
        "../../../../tests/fixtures/native_policy_boundary_vectors.json"
    ))
    .unwrap();
    let cases = fixture["cases"].as_array().unwrap();
    assert_eq!(cases.len(), 18);
    let mut output = Vec::new();
    for case in cases {
        let source = envelope(case);
        let policy = snapshot(case);
        assert_eq!(
            policy.mode,
            if case["inputMode"] == "observe" { "observe" } else { "enforce" }
        );
        let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
        assert_eq!(intrinsic.reason_code, "native_exact_safe_command");
        assert_eq!(intrinsic.minimum_action, "allow");
        let result = apply_scoped_pre_tool_policy(&policy, &source, "codex", intrinsic, 100).unwrap();
        assert_eq!(result.selected_decision_id, None);
        let actual = json!({
            "policyAction":result.result.policy_action,
            "minimumAction":result.result.minimum_action,
            "decision":result.result.decision,
            "observedPolicyAction":result.observed_policy_action,
            "nativeReasonCode":result.result.reason_code
        });
        assert_eq!(actual, case["expected"], "{}", case["name"]);
        let mut row = actual.as_object().unwrap().clone();
        row.insert("name".to_owned(), case["name"].clone());
        output.push(Value::Object(row));
    }

    // Content-bound artifact policy is an explicit unavailable capability here.
    // Neither the original nor a changed content hash becomes execution authority.
    let source = envelope(&cases[0]);
    let mut refusals = Vec::new();
    for (name, hash) in [("content-unchanged", "a".repeat(64)), ("content-changed", "b".repeat(64))] {
        let mut policy = snapshot(&cases[0]);
        let authority = json!({
            "schema":"guard-native-policy-authority.v1",
            "generic_precedence":"specificity-recency.v1", "managed":null,
            "rows":[{
                "decision_id":1,"harness":"codex","scope":"artifact","action":"allow",
                "source_kind":"signed-bundle","updated_at_us":1,
                "artifact_id":"codex:project:Shell","artifact_hash":hash,
                "workspace":null,"publisher":null,"expires_at_ms":null,
                "exact_command_sha256":null,"requires_exact_context":false
            }]
        });
        policy.scoped_authority = serde_json::from_value(authority).unwrap();
        let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
        let result = apply_scoped_pre_tool_policy(&policy, &source, "codex", intrinsic, 100);
        assert_eq!(result.err().as_deref(), Some("native_scoped_content_context_unsupported"));
        refusals.push(name);
    }
    let mut uncompiled = snapshot(&cases[0]);
    uncompiled.mode = "prompt".to_owned();
    let intrinsic = evaluate_pre_tool_envelope("codex", "PreToolUse", &source.raw_payload);
    let result = apply_scoped_pre_tool_policy(&uncompiled, &source, "codex", intrinsic, 100);
    assert_eq!(result.err().as_deref(), Some("native_policy_mode_invalid"));
    refusals.push("uncompiled-prompt");
    println!("POLICY_BOUNDARY_RESULTS={}", json!({"cases":output,"refusals":refusals}));
}
