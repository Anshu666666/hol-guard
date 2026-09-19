//! Share real mutation setup while preserving distinct client refusal contracts.

use super::*;

pub(super) fn assert_completed_mutation_refuses_response(strict_currentness: bool) {
    for version in [3, 4] {
        for event in ["PreToolUse", "PostToolUse"] {
            for withdraw in [false, true] {
                let prefix = if strict_currentness {
                    "client-changed-strict"
                } else {
                    "client-changed"
                };
                let root = test_root(&format!("{prefix}-{version}-{event}-{withdraw}"));
                let (store, key, snapshot) = installed(&root, version);
                let payload = envelope(&root, &snapshot, event);
                let prepare = || {
                    let independent = PolicySnapshotStore::new_with_resident_generation(
                        &root,
                        &"a".repeat(64),
                        47,
                    )
                    .unwrap();
                    let mutation = if withdraw {
                        super::super::withdrawal_tests::request(&independent, 10, &key)
                    } else {
                        serde_json::json!({"schema":POLICY_SNAPSHOT_PUSH_SCHEMA,
                            "snapshot":signed_snapshot(10, &key, &root)})
                    };
                    (independent, mutation)
                };
                // Only the strict case excludes fixture setup from the client budget.
                let prepared = if strict_currentness {
                    Some(prepare())
                } else {
                    None
                };
                let mut evaluated = false;
                let result = request(&root, &payload, deadline(), |_| {
                    let response = evaluate_resident_bytes(&payload, Some(&store)).unwrap();
                    evaluated = true;
                    let (independent, mutation) = prepared.unwrap_or_else(prepare);
                    if withdraw {
                        independent.withdraw(&mutation).unwrap();
                    } else {
                        independent.push(&mutation).unwrap();
                    }
                    // The unmodified transport boundary would return these actual result bytes.
                    assert_eq!(
                        serde_json::from_slice::<Value>(&response).unwrap()["receipt"]
                            ["policy_generation"],
                        1
                    );
                    drop(independent);
                    Ok(response)
                });
                assert!(evaluated);
                if strict_currentness {
                    assert_eq!(result.unwrap_err(), MISMATCH);
                } else {
                    // Real durable mutation may consume the unchanged 750 ms budget.
                    // Either refusal is safe; an old authoritative result never is.
                    assert!(matches!(
                        result.unwrap_err().as_str(),
                        MISMATCH | "native_client_deadline_exceeded"
                    ));
                }
                fs::remove_dir_all(root).unwrap();
            }
        }
    }
}
