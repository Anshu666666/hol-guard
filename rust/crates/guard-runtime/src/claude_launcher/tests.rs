use super::*;
use response::{final_response, http_failure};
use serde_json::Value;

pub(super) fn reference() -> Value {
    serde_json::from_str(include_str!(
        "../../../../../contracts/launchers/claude-native-launcher.v1.fixtures.json"
    ))
    .unwrap()
}

#[test]
fn actual_python_hook_object_cases_never_downgrade_denial_to_availability() {
    for case in reference()["hook_body_cases"].as_array().unwrap() {
        let event = Event::parse(case["event"].as_str().unwrap()).unwrap();
        let raw = hex::decode(case["raw_hex"].as_str().unwrap()).unwrap();
        let result = response_json::admit(raw);
        match case["native_profile"].as_str().unwrap() {
            "pass" => assert_eq!(hex::encode(result.unwrap()), case["python_hex"], "{case}"),
            "unsupported" => {
                assert_eq!(result, Err(Failure::UnsupportedResponse), "{case}");
                let rendered = final_response(event, &Failure::UnsupportedResponse);
                if event == Event::Pre {
                    assert_eq!(rendered["hookSpecificOutput"]["permissionDecision"], "deny");
                } else {
                    assert_eq!(rendered["decision"], "block");
                }
            }
            "availability" => {
                let error = result.unwrap_err();
                assert!(matches!(error, Failure::Availability(_)));
                let expected: Value = serde_json::from_slice(
                    &hex::decode(case["python_hex"].as_str().unwrap()).unwrap(),
                )
                .unwrap();
                assert_eq!(final_response(event, &error), expected);
            }
            _ => unreachable!(),
        }
    }
}

#[cfg(windows)]
#[test]
fn windows_public_manifest_reader_accepts_cache_links_without_private_acl_repair() {
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).unwrap();
    let directory = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-claude-package-{}", hex::encode(suffix)));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("runtime-manifest.json");
    let link = directory.join("cached-manifest.json");
    std::fs::write(&path, b"{}").unwrap();
    std::fs::hard_link(&path, &link).unwrap();
    assert_eq!(files::read(&path, 2, false).unwrap(), b"{}");
    assert!(files::read(&path, 1, false).is_err());
    assert!(files::read(&path, 2, true).is_err());
    std::fs::remove_dir_all(directory).unwrap();
}

#[test]
fn final_shapes_preserve_python_availability_integrity_and_limit_distinctions() {
    let fixture = reference();
    for case in fixture["response_cases"].as_array().unwrap() {
        let event = Event::parse(case["event"].as_str().unwrap()).unwrap();
        let reason = Box::leak(case["reason"].as_str().unwrap().to_owned().into_boxed_str());
        let failure = match case["kind"].as_str().unwrap() {
            "availability" => Failure::Availability(reason),
            "integrity" => Failure::Integrity(reason),
            "limit" => Failure::Limit(reason),
            _ => unreachable!(),
        };
        assert_eq!(final_response(event, &failure), case["response"], "{case}");
    }
    assert_eq!(
        fixture["stage_classification"]["initial_state_error"],
        "transport-failure"
    );
    assert_eq!(
        fixture["stage_classification"]["contacted_identity_error"],
        "authenticated-control-plane-failure"
    );
    for error in ["bad_status_line", "header_line_too_long", "incomplete_read"] {
        assert_eq!(
            fixture["framing_classification"][error],
            "transport-failure"
        );
    }
    assert_eq!(
        fixture["framing_classification"]["oversized_response"],
        "authenticated-control-plane-failure"
    );
}

#[test]
fn http_classification_preserves_overload_precedence() {
    for case in reference()["http_classification_cases"].as_array().unwrap() {
        let result = http_failure(
            case["status"].as_u64().unwrap() as u16,
            case["detail"].as_str().unwrap().as_bytes(),
        );
        match case["kind"].as_str().unwrap() {
            "authenticated-control-plane-failure" => {
                assert!(matches!(result, Failure::Integrity(_)))
            }
            "transport-failure" | "overload" => assert!(matches!(result, Failure::Availability(_))),
            _ => unreachable!(),
        }
    }
}

#[test]
fn signed_python_unicode_and_nested_fields_match_exactly() {
    let fixture = reference();
    let key = discovery::key(fixture["test_key_hex"].as_str().unwrap().as_bytes()).unwrap();
    let peer = serde_json::from_value(fixture["peer"].clone()).unwrap();
    for case in fixture["signed_cases"].as_array().unwrap() {
        for (field, omitted, expected) in [
            ("state", "state_signature", "state_signing_hex"),
            ("challenge", "proof", "challenge_signing_hex"),
        ] {
            assert_eq!(
                hex::encode(canonical::signing_bytes(&case[field], omitted).unwrap()),
                case[expected]
            );
        }
        let state = discovery::state(
            &case["state"],
            &key,
            case["state"]["guard_home"].as_str().unwrap(),
            &peer,
        )
        .unwrap();
        let proof = discovery::challenge(
            &case["challenge"],
            &key,
            &state,
            case["nonce"].as_str().unwrap(),
            Event::Pre,
            case["now_ms"].as_u64().unwrap(),
        )
        .unwrap();
        assert_eq!(proof, case["challenge"]["proof"]);
        assert!(discovery::challenge(
            &case["challenge"],
            &key,
            &state,
            case["nonce"].as_str().unwrap(),
            Event::Post,
            case["now_ms"].as_u64().unwrap()
        )
        .is_err());
        assert!(discovery::challenge(
            &case["challenge"],
            &key,
            &state,
            case["nonce"].as_str().unwrap(),
            Event::Pre,
            1_700_000_005_001
        )
        .is_err());
        let mut tampered = case["state"].clone();
        tampered["unknown_signed_field"]["proof"] = json!("tampered");
        assert!(discovery::state(&tampered, &key, state.guard_home.as_str(), &peer).is_err());
    }
}

#[test]
fn unsupported_signed_domains_reject_without_guessing_canonical_bytes() {
    for value in [
        json!({"a":1.5}),
        json!({"nested":[-0.0]}),
        json!({"a":1e20}),
    ] {
        assert!(canonical::signing_bytes(&value, "proof").is_err());
    }
    for raw in [
        br#"{"a":"\ud800"}"#.as_slice(),
        br#"{"a":1,"a":2}"#,
        br#"{"a":NaN}"#,
    ] {
        assert!(crate::strict_json_value(raw).is_err());
    }
    assert_eq!(
        canonical::signing_bytes(&json!({"a":"\u{7f}"}), "proof").unwrap(),
        br#"{"a":"\u007f"}"#
    );
}

#[test]
fn prepared_query_matches_python_utf8_quote_plus_profile() {
    assert_eq!(
        config::query(Path::new("/fixture/a b"), Path::new("/fixture/café"), None).unwrap(),
        "guard-home=%2Ffixture%2Fa+b&home=%2Ffixture%2Fcaf%C3%A9"
    );
    assert!(Event::parse("pre_tool_use").is_none());
    assert!(Event::parse("PermissionRequest").is_none());
}

#[cfg(unix)]
#[test]
fn private_reads_reject_links_modes_and_bounds_without_repair() {
    use std::os::unix::fs::{symlink, PermissionsExt};
    let mut suffix = [0; 8];
    getrandom::fill(&mut suffix).unwrap();
    let directory = std::env::temp_dir()
        .canonicalize()
        .unwrap()
        .join(format!("guard-claude-private-{}", hex::encode(suffix)));
    std::fs::create_dir(&directory).unwrap();
    std::fs::set_permissions(&directory, std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.join("state.json");
    std::fs::write(&path, b"{}").unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(files::read(&path, 2, true).unwrap(), b"{}");
    assert!(files::read(&path, 1, true).is_err());
    let link = directory.join("link.json");
    symlink(&path, &link).unwrap();
    assert!(files::read(&link, 2, true).is_err());
    std::fs::remove_file(&link).unwrap();
    std::fs::hard_link(&path, &link).unwrap();
    assert!(files::read(&path, 2, true).is_err());
    // Cache hardlinks are admitted only as immutable public package bytes;
    // config::load subsequently requires their complete pinned SHA-256.
    assert_eq!(files::read(&path, 2, false).unwrap(), b"{}");
    std::fs::remove_file(&link).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
    assert!(files::read(&path, 2, true).is_err());
    assert_eq!(
        std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o644
    );
    std::fs::remove_dir_all(directory).unwrap();
}
