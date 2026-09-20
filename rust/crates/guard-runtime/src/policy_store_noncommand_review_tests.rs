use super::super::command_authority_tests::publish_marker;
use super::super::command_floor_tests::control_snapshot;
use super::super::*;
use guard_contracts::NativeReviewScopeV1;
use serde_json::json;

fn request(root: &Path, snapshot: &PolicySnapshotV3, payload: Value) -> GuardHookEnvelopeV2 {
    GuardHookEnvelopeV2 {
        schema: GUARD_HOOK_ENVELOPE_V2_SCHEMA.into(),
        request_id: None,
        harness: "cursor".into(),
        event: "PreToolUse".into(),
        raw_payload: payload,
        deadline_budget_ms: Some(750),
        policy_generation: snapshot.generation,
        policy_snapshot: json!({
            "generation": snapshot.generation,
            "policy_digest": snapshot.policy_digest,
            "runtime_identity": snapshot.runtime_identity,
        }),
        source: GuardHookSourceMetadataV2 {
            cwd: Some(root.join("workspace").to_string_lossy().into()),
            home_dir: root.to_string_lossy().into(),
            guard_home: root.to_string_lossy().into(),
            source_ref_external_allowed: false,
        },
    }
}

#[test]
fn current_signed_noncommand_reviews_have_distinct_receipt_scope() {
    let root = test_root("noncommand-review");
    let key = install_test_key(&root, 84);
    let store = PolicySnapshotStore::new(&root, &"a".repeat(64)).unwrap();
    let snapshot = control_snapshot(1, 1, 1, "enabled", &key, &root);
    publish_marker(&store, &snapshot, "committed");
    let ack: PolicySnapshotAckV1 = serde_json::from_slice(
        &store
            .push(&json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": snapshot}))
            .unwrap(),
    )
    .unwrap();
    assert_eq!(ack.generation, snapshot.generation);
    assert_eq!(ack.policy_digest, snapshot.policy_digest);
    let cases = [
        (
            "network",
            json!({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/docs", "prompt": "read"}}),
            true,
        ),
        (
            "network_url",
            json!({"tool_name": "WebFetch", "tool_input": {"url": "https://example.com/docs"}}),
            true,
        ),
        (
            "ollama",
            json!({"tool_name": "Bash", "tool_input": {"command": "ollama push guard-fixture-model"}}),
            false,
        ),
        (
            "read",
            json!({"tool_name": "Read", "tool_input": {"file_path": ".env"}}),
            true,
        ),
        (
            "mcp",
            json!({"tool_name": "mcp__filesystem__read", "tool_input": {"path": "README.md"}}),
            true,
        ),
        (
            "mcp_command",
            json!({"tool_name": "mcp__filesystem__read", "tool_input": {"command": "cat .env"}}),
            false,
        ),
    ];
    let mut fixtures = Vec::new();
    for (name, payload, noncommand) in cases {
        let envelope = request(&root, &snapshot, payload);
        let encoded = crate::edge::evaluate_envelope_with_store(envelope.clone(), &store).unwrap();
        let edge: GuardHookEdgeResultV2 = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(edge.result["policy_action"], "review");
        assert_eq!(edge.receipt.policy_generation, snapshot.generation);
        assert_eq!(
            edge.receipt.policy_digest.as_ref(),
            Some(&snapshot.policy_digest)
        );
        assert_eq!(
            edge.receipt.review_scope,
            noncommand.then_some(NativeReviewScopeV1::Noncommand)
        );
        assert_eq!(edge.receipt.command_extensions.is_none(), noncommand);
        let receipt_value = serde_json::to_value(&edge.receipt).unwrap();
        assert_eq!(receipt_value.get("review_scope").is_some(), noncommand);
        if name == "mcp_command" {
            assert_eq!(edge.result["action"]["action_type"], "mcp_tool");
        }
        fixtures.push(json!({
            "case": name, "edge": edge,
            "payload": envelope.raw_payload, "source": envelope.source,
            "snapshot": {
                "generation": snapshot.generation, "policy_digest": snapshot.policy_digest,
                "runtime_identity": snapshot.runtime_identity, "rule_digest": snapshot.rule_digest,
                "mode": snapshot.mode,
            },
        }));
    }
    let stale = request(
        &root,
        &snapshot,
        json!({"tool_name":"Read", "tool_input":{"file_path":".env"}}),
    );
    let next = control_snapshot(2, 1, 1, "enabled", &key, &root);
    publish_marker(&store, &next, "committed");
    store
        .push(&json!({"schema": POLICY_SNAPSHOT_PUSH_SCHEMA, "snapshot": next}))
        .unwrap();
    assert!(crate::edge::evaluate_envelope_with_store(stale, &store).is_err());
    // Optional test-only stdout fixture enables Python to consume these exact
    // Rust-produced bytes. It never adds a runtime command or changes transport.
    if std::env::var("HOL_GUARD_NONCOMMAND_RECEIPT_FIXTURE").as_deref() == Ok("1") {
        println!(
            "HOL_GUARD_NONCOMMAND_RECEIPTS={}",
            serde_json::to_string(&fixtures).unwrap()
        );
    }
    fs::remove_dir_all(root).unwrap();
}
