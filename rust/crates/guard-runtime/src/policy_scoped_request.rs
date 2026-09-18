//! Derive scoped identities from supported original hook input.
//!
//! This producer covers bounded shell, local read and MCP paths whose Python
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
use serde_json::{Map, Value};
use std::path::Path;

#[path = "policy_scoped_tool_request.rs"]
mod tool_request;

const UNSUPPORTED: &str = "native_scoped_request_identity_unsupported";

fn display_text(value: Option<&Value>) -> Option<&str> {
    value
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

// The Python ingress maps each camel-case selector before constructing the
// artifact. Preserve that single value; conflicting aliases never pick a
// convenient default identity.
fn selector_text<'a>(
    payload: &'a Map<String, Value>,
    primary: &str,
    alias: &str,
) -> Result<Option<&'a str>, String> {
    match (payload.get(primary), payload.get(alias)) {
        (None, None) => Ok(None),
        (Some(value), None) | (None, Some(value)) => value
            .as_str()
            .map(str::trim)
            .filter(|value| !value.is_empty())
            .map(Some)
            .ok_or_else(|| UNSUPPORTED.to_owned()),
        _ => Err(UNSUPPORTED.to_owned()),
    }
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
    if model.segments.len() != 1
        || !model.wrapper_chain.is_empty()
        || model.path_overridden
        || !model.segments[0].environment_names.is_empty()
    {
        return Err(UNSUPPORTED.to_owned());
    }
    let benign = native.reason_code == "native_exact_safe_command"
        && native.explicitly_benign
        && matches!(
            model.segments[0].executable.as_deref(),
            Some("pwd" | "true" | "echo" | "printf" | "whoami" | "uname")
        );
    // A destination-only SSH action stays on the actual generic producer.
    // Flags, a remote command, wrappers and shell syntax require a different
    // typed runtime identity and cannot be projected into this path.
    let destination_only = native.reason_code == "native_command_review_required"
        && model.segments[0].executable.as_deref() == Some("ssh")
        && model.segments[0].arguments.len() == 1
        && model.segments[0].arguments[0].len() <= 255
        && model.segments[0].arguments[0].starts_with(|value: char| value.is_ascii_alphanumeric())
        && model.segments[0].arguments[0].bytes().all(|value| {
            value.is_ascii_alphanumeric() || matches!(value, b'@' | b'.' | b'_' | b'-')
        });
    if !benign && !destination_only {
        return Err(UNSUPPORTED.to_owned());
    }
    let scope = selector_text(payload, "source_scope", "sourceScope")?.unwrap_or("project");
    if scope != "project" {
        return Err(UNSUPPORTED.to_owned());
    }
    Ok(selector_text(payload, "artifact_id", "artifactId")?
        .map(str::to_owned)
        .unwrap_or_else(|| format!("{harness}:{scope}:{tool}")))
}

/// Caller validates the envelope and preserves intrinsic/managed floors.
/// This does not authorize an action or establish resident application.
pub(crate) fn derive_scoped_policy_request(
    envelope: &GuardHookEnvelopeV2,
    canonical_harness: &str,
) -> Result<ScopedPolicyRequest, String> {
    if crate::edge::authoritative_event(envelope)? != "PreToolUse" {
        return Err(UNSUPPORTED.to_owned());
    }
    let (artifact, digest) = if exact_shell_command_from_hook(&envelope.raw_payload).is_some() {
        let artifact = generic_shell_artifact(envelope, canonical_harness)?;
        let command = exact_shell_command_from_hook(&envelope.raw_payload).ok_or(UNSUPPORTED)?;
        (
            artifact,
            Some(exact_command_sha256(command).ok_or(UNSUPPORTED)?),
        )
    } else {
        (
            tool_request::generic_tool_artifact(envelope, canonical_harness).ok_or(UNSUPPORTED)?,
            None,
        )
    };
    ScopedPolicyRequest::from_native_identity(PolicyIdentityInputs {
        harness: canonical_harness,
        artifact_id: Some(&artifact),
        artifact_hash: None,
        workspace: envelope.source.cwd.as_deref(),
        publisher: display_text(envelope.raw_payload.get("publisher")),
        exact_command_sha256: digest.as_deref(),
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
    fn matches_shared_actual_non_shell_hook_producer_vectors() {
        let fixture: Value =
            serde_json::from_str(include_str!("policy_scoped_tool_fixture.json")).unwrap();
        let workspace =
            std::env::temp_dir().join(format!("guard-scoped-tool-vectors-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("guide.md"), "Synthetic local guide.\n").unwrap();
        assert_eq!(fixture["cases"].as_array().unwrap().len(), 24);
        for case in fixture["cases"].as_array().unwrap() {
            let mut source = envelope(case["payload"].clone());
            source.harness = case["harness"].as_str().unwrap().to_owned();
            source.source.cwd = Some(workspace.to_string_lossy().into_owned());
            let request = derive_scoped_policy_request(&source, &source.harness)
                .unwrap_or_else(|reason| panic!("{}: {reason}", case["name"]));
            assert_eq!(request.artifact_id(), case["artifactId"].as_str());
        }
        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn non_shell_identity_refuses_ambiguous_sensitive_and_unmodeled_sources() {
        for payload in [
            json!({"tool_name":"Read","tool_input":{"path":".env"}}),
            json!({"tool_name":"Read","tool_input":{"path":"../guide.md"}}),
            json!({"tool_name":"Read","tool_input":{"path":"private_key.txt"}}),
            json!({"tool_name":"Read","tool_input":{"path":"guide.md","command":"printf synthetic"}}),
            json!({"tool_name":"Read","tool_input":{"path":"guide.md"},"arguments":{"path":"guide.md"}}),
            json!({"tool_name":"mcp__synthetic__inspect","toolName":"mcp__synthetic__ping","tool_input":{}}),
            json!({"tool_name":"mcp__synthetic__inspect","tool_input":{"command":"printf synthetic"}}),
            json!({"tool_name":"mcp__synthetic__inspect","tool_input":{"nested":{"path":"guide.md"}}}),
            json!({"tool_name":"mcp__synthetic__inspect","tool_input":{},"source_scope":"user"}),
            json!({"tool_name":"npm","tool_input":{}}),
        ] {
            assert!(derive_scoped_policy_request(&envelope(payload), "codex").is_err());
        }
        let mut forged = envelope(json!({"tool_name":"mcp__synthetic__inspect","tool_input":{}}));
        forged.raw_payload["exact_command_sha256"] = json!("a".repeat(64));
        let policy = authority(
            "codex",
            "codex:project:mcp__synthetic__inspect",
            &"a".repeat(64),
        );
        assert!(policy
            .select_generic(&derive_scoped_policy_request(&forged, "codex").unwrap(), 1)
            .unwrap()
            .is_none());
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
            json!({"tool_name":"Shell","tool_input":{"command":"ssh synthetic true"}}),
            json!({"tool_name":"Shell","tool_input":{"command":"ssh -F synthetic.conf synthetic"}}),
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

    #[test]
    fn raw_compatibility_aliases_match_actual_python_identity_vectors() {
        let fixture: Value =
            serde_json::from_str(include_str!("policy_scoped_alias_fixture.json")).unwrap();
        let workspace =
            std::env::temp_dir().join(format!("guard-scoped-aliases-{}", std::process::id()));
        std::fs::create_dir_all(&workspace).unwrap();
        std::fs::write(workspace.join("guide.md"), "Synthetic guide.\n").unwrap();
        let cases = fixture["cases"].as_array().unwrap();
        assert_eq!(cases.len(), 12);
        for case in cases {
            let mut source = envelope(case["payload"].clone());
            source.harness = case["harness"].as_str().unwrap().to_owned();
            source.source.cwd = Some(workspace.to_string_lossy().into_owned());
            let actual = derive_scoped_policy_request(&source, &source.harness).unwrap();
            assert_eq!(actual.artifact_id(), case["artifactId"].as_str());
        }
        std::fs::remove_dir_all(workspace).unwrap();
    }

    #[test]
    fn aliases_cannot_invent_project_identity_or_choose_a_conflicting_selector() {
        let sources = [
            json!({"tool_name":"Bash","tool_input":{"command":"printf synthetic"}}),
            json!({"tool_name":"mcp__synthetic__inspect","tool_input":{}}),
        ];
        for payload in sources {
            for changes in [
                json!({"sourceScope":"user"}),
                json!({"source_scope":"project","sourceScope":"project"}),
                json!({"source_scope":"project","sourceScope":"user"}),
                json!({"artifact_id":"first","artifactId":"second"}),
                json!({"artifact_id":"same","artifactId":"same"}),
                json!({"artifactId":false}),
                json!({"sourceScope":false}),
            ] {
                let mut source = envelope(payload.clone());
                source
                    .raw_payload
                    .as_object_mut()
                    .unwrap()
                    .extend(changes.as_object().unwrap().clone());
                assert!(derive_scoped_policy_request(&source, "codex").is_err());
            }
            for key in [
                "event",
                "eventName",
                "hook_event_name",
                "hookEventName",
                "hook_name",
                "hookName",
            ] {
                let mut source = envelope(payload.clone());
                source.raw_payload[key] = json!("PostToolUse");
                assert!(derive_scoped_policy_request(&source, "codex").is_err());
            }
        }
    }
}
