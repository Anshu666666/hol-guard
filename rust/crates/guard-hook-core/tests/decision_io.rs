use guard_contracts::NativeHookRequestV1;
use guard_hook_core::review_post_tool;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

fn fixture_root(name: &str) -> PathBuf {
    // macOS temporary roots may contain /var -> /private/var. Resolve the
    // platform-owned root before adding fixtures; source symlinks stay visible.
    let temporary_root = fs::canonicalize(std::env::temp_dir()).unwrap();
    let root = temporary_root.join(format!("guard-hook-core-{name}-{}", std::process::id()));
    fs::create_dir_all(&root).unwrap();
    root
}

fn request(payload: Value) -> NativeHookRequestV1 {
    NativeHookRequestV1 {
        protocol_version: 1,
        request_id: Some("test".into()),
        harness: "claude-code".into(),
        event_name: "PostToolUse".into(),
        payload,
        cwd: None,
        home_dir: "/tmp".into(),
        guard_home: "/tmp/guard".into(),
        source_ref_external_allowed: false,
        observe_mode: false,
        deadline_budget_ms: Some(750),
    }
}

fn digest(bytes: &[u8]) -> String {
    let mut hasher = Sha256::new();
    hasher.update(bytes);
    hex::encode(hasher.finalize())
}

fn source_request(cwd: &Path, output_sha256: String, output_chars: i64) -> NativeHookRequestV1 {
    let mut value = request(json!({
        "tool_input": {"file_path": "source.rs"},
        "guard_source_ref": {
            "version": 1,
            "path": "source.rs",
            "output_sha256": output_sha256,
            "output_chars": output_chars
        }
    }));
    value.cwd = Some(cwd.to_string_lossy().into_owned());
    value.home_dir = cwd.to_string_lossy().into_owned();
    value
}

#[test]
fn source_replacement_between_observations_is_not_equivalent() {
    let root = fixture_root("replacement");
    let path = root.join("source.rs");
    let original = b"fn original() {}\n";
    fs::write(&path, original).unwrap();
    fs::write(&path, b"fn replacement() {}\n").unwrap();

    let response = review_post_tool(&source_request(&root, digest(original), 18));

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn source_growth_after_expected_output_is_not_equivalent() {
    let root = fixture_root("growth");
    let path = root.join("source.rs");
    let original = b"safe";
    fs::write(&path, b"safe growth").unwrap();

    let response = review_post_tool(&source_request(&root, digest(original), 4));

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    let _ = fs::remove_dir_all(root);
}

#[test]
fn invalid_utf8_source_is_fail_closed_without_materializing_bytes() {
    let root = fixture_root("encoding");
    let path = root.join("source.rs");
    fs::write(&path, [0xf0_u8, 0x28, 0x8c, 0x28]).unwrap();

    let response = review_post_tool(&source_request(&root, "a".repeat(64), 4));
    let serialized = serde_json::to_string(&response).unwrap();

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    assert!(!serialized.contains("f0"));
    let _ = fs::remove_dir_all(root);
}

#[cfg(any(unix, windows))]
#[test]
fn classified_source_is_read_scanned_and_bound_to_exact_digest() {
    let root = fixture_root("valid-source");
    let path = root.join("source.rs");
    let original = b"fn main() {}\n";
    fs::write(&path, original).unwrap();
    let classified = guard_secure_fs::classify_source_path("source.rs", &root, Some(&root), false);
    assert!(classified.allowed);
    assert_eq!(
        classified.resolved_path,
        Some(fs::canonicalize(&path).unwrap())
    );
    let read = guard_secure_fs::read_bounded(&path, original.len()).unwrap();
    assert_eq!(read.bytes, original);
    assert_eq!(read.sha256, digest(original));
    let response = review_post_tool(&source_request(
        &root,
        digest(original),
        original.len() as i64,
    ));
    assert_eq!(response.decision, "allow");
    assert_eq!(response.reason_code, "source_full_scan_allow");
    assert_eq!(response.reviewed_output_sha256, Some(digest(original)));
    let _ = fs::remove_dir_all(root);
}

#[cfg(any(unix, windows))]
#[test]
fn source_secret_is_denied_after_successful_secure_read() {
    let root = fixture_root("secret-source");
    let path = root.join("source.rs");
    let bytes = format!("const TOKEN: &str = \"ghp_{}\";\n", "A".repeat(36));
    fs::write(&path, &bytes).unwrap();
    assert_eq!(
        guard_secure_fs::read_bounded(&path, bytes.len())
            .unwrap()
            .sha256,
        digest(bytes.as_bytes())
    );
    let response = review_post_tool(&source_request(
        &root,
        digest(bytes.as_bytes()),
        bytes.len() as i64,
    ));
    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "source_secret_match");
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn symlink_source_is_fail_closed() {
    let root = fixture_root("symlink");
    let target = root.join("target.rs");
    let source = root.join("source.rs");
    fs::write(&target, b"safe").unwrap();
    std::os::unix::fs::symlink(&target, &source).unwrap();
    assert!(matches!(
        guard_secure_fs::read_bounded(&source, 4),
        Err(guard_secure_fs::SecureReadError::SymlinkInPath)
    ));

    let response = review_post_tool(&source_request(&root, digest(b"safe"), 4));

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    let _ = fs::remove_dir_all(root);
}

#[cfg(unix)]
#[test]
fn symlink_source_ancestor_is_fail_closed() {
    let root = fixture_root("symlink-ancestor");
    let directory = root.join("real");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("source.rs"), b"safe").unwrap();
    let alias = root.join("alias");
    std::os::unix::fs::symlink(&directory, &alias).unwrap();
    assert!(matches!(
        guard_secure_fs::read_bounded(&alias.join("source.rs"), 4),
        Err(guard_secure_fs::SecureReadError::SymlinkInPath)
    ));

    let mut request = source_request(&root, digest(b"safe"), 4);
    request.payload["tool_input"]["file_path"] = json!("alias/source.rs");
    request.payload["guard_source_ref"]["path"] = json!("alias/source.rs");
    let response = review_post_tool(&request);

    assert_eq!(response.decision, "deny");
    assert_eq!(response.reason_code, "no_output_to_review");
    let _ = fs::remove_dir_all(root);
}
