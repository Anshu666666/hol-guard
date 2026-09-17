//! Derive scoped identities from supported original hook input.
//!
//! This first producer covers the ordinary benign shell path whose Python
//! producer uses a generic tool artifact. Runtime package/file/compound
//! producers and content-context identities require their own parity proof.
//! Unsupported requests fail closed; a supplied digest is never evidence.

use guard_command::exact_command::{exact_command_sha256, exact_shell_command_from_hook};
use guard_command::pretool::evaluate_pre_tool;
use guard_command::CommandModelRequestV1;
use guard_contracts::GuardHookEnvelopeV2;
use guard_policy_snapshot::scoped_authority::{
    ExactPolicyContextInputs, PolicyIdentityInputs, ScopedPolicyRequest,
};
use serde_json::Value;
use std::path::Path;

const UNSUPPORTED: &str = "native_scoped_request_identity_unsupported";

fn display_text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn generic_shell_artifact(envelope: &GuardHookEnvelopeV2, harness: &str) -> Result<String, String> {
    if envelope.harness != harness || envelope.event != "PreToolUse" {
        return Err(UNSUPPORTED.to_owned());
    }
    let cwd = envelope.source.cwd.as_deref().ok_or(UNSUPPORTED)?;
    // The generic producer requires a complete local execution context. A
    // missing working directory produces an unmodeled runtime artifact.
    if !Path::new(cwd).is_absolute() || !Path::new(cwd).is_dir() {
        return Err(UNSUPPORTED.to_owned());
    }
    let payload = envelope.raw_payload.as_object().ok_or(UNSUPPORTED)?;
    if payload.contains_key("guard_source_ref") || payload.contains_key("guard_payload_ref") {
        return Err(UNSUPPORTED.to_owned());
    }
    let command = exact_shell_command_from_hook(&envelope.raw_payload).ok_or(UNSUPPORTED)?;
    let tool = payload
        .get("tool_name")
        .or_else(|| payload.get("toolName"))
        .and_then(Value::as_str)
        .ok_or(UNSUPPORTED)?;
    // Claude treats unknown tools as MCP identities. This spelling has no
    // generic shell artifact on that producer and must not be invented.
    if harness == "claude-code" && tool.eq_ignore_ascii_case("exec_command") {
        return Err(UNSUPPORTED.to_owned());
    }
    let arguments = ["tool_input", "arguments", "tool_args", "toolArgs"]
        .iter()
        .find_map(|name| payload.get(*name))
        .and_then(Value::as_object)
        .ok_or(UNSUPPORTED)?;
    if arguments.len() != 1 {
        return Err(UNSUPPORTED.to_owned());
    }
    let native = evaluate_pre_tool(&CommandModelRequestV1 {
        command: command.to_owned(),
        dialect: "posix".to_owned(),
        transport: "shell_string".to_owned(),
        extraction_provenance: "guard-shell".to_owned(),
    })?;
    let model = native.command_model;
    if native.reason_code != "native_exact_safe_command"
        || !native.explicitly_benign
        || model.segments.len() != 1
        || !model.wrapper_chain.is_empty()
        || !matches!(
            model.segments[0].executable.as_deref(),
            Some("pwd" | "true" | "echo" | "printf" | "whoami" | "uname")
        )
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let scope = display_text(payload.get("source_scope")).unwrap_or("project");
    if scope != "project" {
        return Err(UNSUPPORTED.to_owned());
    }
    Ok(display_text(payload.get("artifact_id"))
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{harness}:{scope}:{tool}")))
}

/// Caller validates the envelope and preserves intrinsic/managed floors.
/// This does not authorize an action or establish resident application.
pub(crate) fn derive_scoped_policy_request(
    envelope: &GuardHookEnvelopeV2,
    canonical_harness: &str,
) -> Result<ScopedPolicyRequest, String> {
    let artifact = generic_shell_artifact(envelope, canonical_harness)?;
    let command = exact_shell_command_from_hook(&envelope.raw_payload).ok_or(UNSUPPORTED)?;
    let digest = exact_command_sha256(command).ok_or(UNSUPPORTED)?;
    ScopedPolicyRequest::from_native_identity(PolicyIdentityInputs {
        harness: canonical_harness,
        artifact_id: Some(&artifact),
        artifact_hash: None,
        workspace: envelope.source.cwd.as_deref(),
        publisher: display_text(envelope.raw_payload.get("publisher")),
        exact_command_sha256: Some(&digest),
        exact: ExactPolicyContextInputs::default(),
    })
    .map_err(|_| "native_scoped_request_identity_invalid".to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;
    use guard_policy_snapshot::scoped_authority::NativePolicyAuthority;
    use serde_json::json;

    fn envelope(payload: Value) -> GuardHookEnvelopeV2 {
        serde_json::from_value(json!({
            "schema":"guard-hook-envelope.v2", "harness":"codex", "event":"PreToolUse",
            "raw_payload":payload, "policy_generation":1, "policy_snapshot":{},
            "source":{"cwd":std::env::temp_dir(),"home_dir":std::env::temp_dir(),"guard_home":std::env::temp_dir()}
        })).unwrap()
    }

    fn authority(harness: &str, artifact: &str, digest: &str) -> NativePolicyAuthority {
        NativePolicyAuthority::from_slice(&serde_json::to_vec(&json!({
            "schema":"guard-native-policy-authority.v1", "generic_precedence":"specificity-recency.v1", "rows":[{
                "decision_id":1, "harness":harness, "scope":"artifact", "action":"allow",
                "source_kind":"signed-memory", "updated_at_us":1,
                "artifact_id":artifact, "artifact_hash":null, "workspace":null, "publisher":null,
                "expires_at_ms":null, "exact_command_sha256":digest, "requires_exact_context":false
            }],"managed":null
        })).unwrap()).unwrap()
    }

    #[test]
    fn matches_shared_actual_python_artifact_producer_vectors() {
        let fixture: Value =
            serde_json::from_str(include_str!("policy_scoped_request_fixture.json")).unwrap();
        assert_eq!(fixture["cases"].as_array().unwrap().len(), 29);
        for case in fixture["cases"].as_array().unwrap() {
            let mut source = envelope(case["payload"].clone());
            source.harness = case["harness"].as_str().unwrap().to_owned();
            let policy = authority(
                &source.harness,
                case["artifactId"].as_str().unwrap(),
                case["sha256"].as_str().unwrap(),
            );
            let request = derive_scoped_policy_request(&source, &source.harness).unwrap();
            assert!(
                policy.select_generic(&request, 1).unwrap().is_some(),
                "case {}",
                case["name"]
            );
        }
    }

    #[test]
    fn missing_execution_context_cannot_be_labeled_as_a_generic_artifact() {
        let payload = json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic"}});
        for cwd in [
            None,
            Some("/synthetic/missing-scoped-identity-directory".to_owned()),
        ] {
            let mut source = envelope(payload.clone());
            source.source.cwd = cwd;
            assert!(derive_scoped_policy_request(&source, "codex").is_err());
        }
    }

    #[test]
    fn original_command_and_actual_artifact_are_jointly_required() {
        let raw = "\tprintf 'Synthetic  exact bytes'\r\n";
        let payload = json!({"tool_name":"Shell","tool_input":{"command":raw}});
        let original = envelope(payload.clone());
        let policy = authority(
            "codex",
            "codex:project:Shell",
            &exact_command_sha256(raw).unwrap(),
        );
        let request = derive_scoped_policy_request(&original, "codex").unwrap();
        assert!(policy.select_generic(&request, 1).unwrap().is_some());
        for changed in [
            raw.trim().to_owned(),
            raw.replace("  ", " "),
            raw.replace("Synthetic", "synthetic"),
        ] {
            let candidate = envelope(json!({"tool_name":"Shell","tool_input":{"command":changed}}));
            let request = derive_scoped_policy_request(&candidate, "codex").unwrap();
            assert!(policy.select_generic(&request, 1).unwrap().is_none());
        }
        let mut changed = original.clone();
        changed.raw_payload["artifact_id"] = json!("synthetic:other");
        assert!(policy
            .select_generic(&derive_scoped_policy_request(&changed, "codex").unwrap(), 1)
            .unwrap()
            .is_none());
    }

    #[test]
    fn caller_digests_and_ambiguous_or_runtime_sources_cannot_create_authority() {
        let original = json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic"}});
        for payload in [
            json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic"},"arguments":{"command":"printf synthetic"}}),
            json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic","cmd":"printf synthetic"}}),
            json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic","nested":{"command":"ssh synthetic"}}}),
            json!({"tool_name":"Shell","tool_input":{"command":"printf synthetic; printf more"}}),
            json!({"tool_name":"Shell","tool_input":{"command":"ssh synthetic"}}),
            json!({"tool_name":"Shell","tool_input":{"command":"cat ~/.ssh/id_rsa"}}),
            json!({"tool_name":"Shell","tool_input":{"command":"sh -c 'printf synthetic'"}}),
            json!({"tool_name":"Shell","exact_command_sha256":"a".repeat(64)}),
        ] {
            assert!(derive_scoped_policy_request(&envelope(payload), "codex").is_err());
        }
        let mut forged = envelope(original);
        forged.raw_payload["exact_command_sha256"] = json!("a".repeat(64));
        let policy = authority("codex", "codex:project:Shell", &"a".repeat(64));
        assert!(policy
            .select_generic(&derive_scoped_policy_request(&forged, "codex").unwrap(), 1)
            .unwrap()
            .is_none());
    }
}
