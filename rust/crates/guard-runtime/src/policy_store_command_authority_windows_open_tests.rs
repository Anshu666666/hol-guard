//! Real Windows overlapping opens through the original command authority path.

use super::{control_snapshot, install_test_key, publish_marker, test_root};
use crate::policy_store::PolicySnapshotStore;
use guard_policy_snapshot::PolicySnapshotV3;
use std::fs::{self, File, OpenOptions};
use std::io;
use std::os::windows::fs::OpenOptionsExt;
use std::path::Path;
use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::utilities::current_process_sid;
use windows_permissions::wrappers::{GetSecurityInfo, SetSecurityInfo};
use windows_permissions::{LocalBox, SecurityDescriptor};

// Match the existing-file branch of Python _windows_open_private_fd:
// read + write + WRITE_DAC, all three share flags, and no reparse traversal.
const PYTHON_EXISTING_ACCESS: u32 = 0x8000_0000 | 0x4000_0000 | 0x0004_0000;
const PYTHON_EXISTING_SHARING: u32 = 0x0000_0001 | 0x0000_0002 | 0x0000_0004;
const OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const LOCK_NAME: &str = "extension-control-authority.lock";

fn record(stage: &'static str, result: serde_json::Value) {
    println!(
        "HOL_GUARD_WINDOWS_COMMAND_LOCK_CONTROL {}",
        serde_json::json!({"stage": stage, "result": result})
    );
}

fn io_failure(stage: &'static str, error: &io::Error) {
    record(
        stage,
        serde_json::json!({
            "succeeded": false,
            "error_kind": match error.kind() {
                io::ErrorKind::PermissionDenied => "permission_denied",
                io::ErrorKind::NotFound => "not_found",
                io::ErrorKind::AlreadyExists => "already_exists",
                io::ErrorKind::InvalidInput => "invalid_input",
                io::ErrorKind::InvalidData => "invalid_data",
                io::ErrorKind::WouldBlock => "would_block",
                _ => "other",
            },
            "raw_os_error": error.raw_os_error(),
        }),
    );
}

fn require_io<T>(result: io::Result<T>, stage: &'static str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            io_failure(stage, &error);
            panic!("Windows command-lock control operation failed");
        }
    }
}

fn require_native<T>(result: Result<T, String>, stage: &'static str) -> T {
    match result {
        Ok(value) => value,
        Err(error) => {
            let code =
                if guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES.contains(&error.as_str()) {
                    error.as_str()
                } else {
                    "unregistered_error"
                };
            record(stage, serde_json::json!({"succeeded": false, "code": code}));
            panic!("Windows command-lock native operation failed");
        }
    }
}

fn require_private<T, E>(result: Result<T, E>, stage: &'static str) -> T {
    match result {
        Ok(value) => value,
        Err(_) => {
            record(
                stage,
                serde_json::json!({"succeeded": false, "raw_os_error": null}),
            );
            panic!("Windows command-lock private fixture operation failed");
        }
    }
}

struct PythonExistingHandle {
    file: File,
    _binding: guard_runtime_windows_process::PrivateDirectoryBinding,
}

fn python_existing_handle(root: &Path) -> PythonExistingHandle {
    let binding = require_native(
        crate::resident_state::bind_windows_existing_directory(root, root),
        "python_equivalent_ancestry_binding",
    );
    let mut file = require_io(
        OpenOptions::new()
            .read(true)
            .write(true)
            .access_mode(PYTHON_EXISTING_ACCESS)
            .share_mode(PYTHON_EXISTING_SHARING)
            .custom_flags(OPEN_REPARSE_POINT)
            .open(binding.path().join(LOCK_NAME)),
        "python_equivalent_existing_open",
    );
    let metadata = require_io(file.metadata(), "python_equivalent_metadata");
    assert!(metadata.is_file() && !metadata.file_type().is_symlink());
    assert_eq!(metadata.len(), 1);
    // These fixtures are created for the current SID. Check that owner before
    // reapplying the same protected owner/SYSTEM DACL through the held handle.
    let owner = require_private(current_process_sid(), "python_equivalent_owner_sid");
    let applied = require_private(
        GetSecurityInfo(
            &file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Owner,
        ),
        "python_equivalent_owner_query",
    );
    assert!(applied.owner().is_some_and(|value| value == owner.as_ref()));
    let owner_text = owner.to_string();
    let system_entry = if owner_text == "S-1-5-18" {
        ""
    } else {
        "(A;;FA;;;SY)"
    };
    let descriptor = require_private(
        format!("O:{owner_text}D:P(A;;FA;;;{owner_text}){system_entry}")
            .parse::<LocalBox<SecurityDescriptor>>(),
        "python_equivalent_private_descriptor",
    );
    require_private(
        SetSecurityInfo(
            &mut file,
            SeObjectType::SE_FILE_OBJECT,
            SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
            None,
            None,
            Some(descriptor.dacl().expect("control private DACL missing")),
            None,
        ),
        "python_equivalent_private_dacl_reapply",
    );
    require_native(
        crate::resident_state::verify_windows_private_file(&file),
        "python_equivalent_same_handle_private_verification",
    );
    PythonExistingHandle {
        file,
        _binding: binding,
    }
}

fn with_fixture(
    case: &'static str,
    operation: impl FnOnce(&Path, &PolicySnapshotStore, &PolicySnapshotV3),
) {
    let root = test_root(case);
    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        let key = install_test_key(&root, 92);
        let store = require_native(
            PolicySnapshotStore::new(&root, &"a".repeat(64)),
            "store_initialization",
        );
        let snapshot = control_snapshot(1, 1, 1, "enabled", &key, &root);
        publish_marker(&store, &snapshot, "committed");
        operation(&root, &store, &snapshot);
    }));
    // All operation-local file and ancestry handles drop before cleanup.
    let cleanup = fs::remove_dir_all(&root);
    if let Err(error) = &cleanup {
        io_failure("fixture_cleanup", error);
    }
    record(
        "fixture_finished",
        serde_json::json!({"case": case, "operation_succeeded": outcome.is_ok(), "cleanup_succeeded": cleanup.is_ok()}),
    );
    if let Err(error) = outcome {
        std::panic::resume_unwind(error);
    }
    assert!(cleanup.is_ok(), "control fixture cleanup failed");
}

#[test]
fn existing_python_write_handle_allows_native_authority_open() {
    with_fixture("existing-write-open", |root, store, snapshot| {
        let python = python_existing_handle(root);
        let native = require_native(
            store.command_authority_lease(snapshot),
            "native_shared_with_existing_writer",
        );
        assert!(native.is_some(), "command authority binding missing");
        drop(native);
        require_io(
            fs2::FileExt::try_lock_exclusive(&python.file),
            "released_native_allows_python_exclusive",
        );
        require_io(
            fs2::FileExt::unlock(&python.file),
            "python_exclusive_release",
        );
    });
}

#[test]
fn python_shared_lease_allows_native_shared_authority() {
    with_fixture("shared-overlap", |root, store, snapshot| {
        let python = python_existing_handle(root);
        require_io(
            fs2::FileExt::try_lock_shared(&python.file),
            "python_shared_admission",
        );
        let native = require_native(
            store.command_authority_lease(snapshot),
            "native_shared_with_python_shared",
        );
        assert!(native.is_some(), "command authority binding missing");
        require_io(fs2::FileExt::unlock(&python.file), "python_shared_release");
        drop(native);
        require_io(
            fs2::FileExt::try_lock_exclusive(&python.file),
            "both_shared_released_allow_exclusive",
        );
        require_io(
            fs2::FileExt::unlock(&python.file),
            "python_exclusive_release",
        );
    });
}

#[test]
fn python_exclusive_lease_reaches_native_mutation_contention() {
    with_fixture("exclusive-contention", |root, store, snapshot| {
        let python = python_existing_handle(root);
        require_io(
            fs2::FileExt::try_lock_exclusive(&python.file),
            "python_exclusive_admission",
        );
        match store.command_authority_lease(snapshot) {
            Err(error) if error == "native_command_control_mutation_in_progress" => {}
            result => {
                let _ = require_native(result, "native_exclusive_conflict");
                panic!("native shared authority bypassed Python exclusive lease");
            }
        }
        require_io(
            fs2::FileExt::unlock(&python.file),
            "python_exclusive_release",
        );
        let native = require_native(
            store.command_authority_lease(snapshot),
            "released_python_allows_native_shared",
        );
        assert!(native.is_some(), "command authority binding missing");
    });
}

#[test]
fn native_shared_authority_excludes_python_exclusive_lease() {
    with_fixture("native-shared-first", |root, store, snapshot| {
        let native = require_native(
            store.command_authority_lease(snapshot),
            "native_shared_admission",
        );
        assert!(native.is_some(), "command authority binding missing");
        let python = python_existing_handle(root);
        let conflict = fs2::FileExt::try_lock_exclusive(&python.file)
            .expect_err("Python exclusive lease bypassed native shared authority");
        assert_eq!(
            conflict.raw_os_error(),
            Some(33),
            "expected ERROR_LOCK_VIOLATION"
        );
        drop(native);
        require_io(
            fs2::FileExt::try_lock_exclusive(&python.file),
            "released_native_allows_python_exclusive",
        );
        require_io(
            fs2::FileExt::unlock(&python.file),
            "python_exclusive_release",
        );
    });
}
