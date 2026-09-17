#![cfg(windows)]

use guard_runtime_windows_process::open_bound_read_file;
use std::fs;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

struct Fixture(PathBuf);

impl Fixture {
    fn new(name: &str) -> Self {
        let root =
            std::env::temp_dir().join(format!("guard-bound-read-{name}-{}", std::process::id()));
        fs::create_dir_all(&root).unwrap();
        Self(root)
    }

    fn file(&self) -> PathBuf {
        let path = self.0.join("source.rs");
        fs::write(&path, b"fn main() {}\n").unwrap();
        path
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

#[test]
fn reads_exact_bytes_and_full_identity_from_retained_handle() {
    let fixture = Fixture::new("identity");
    let path = fixture.file();
    let mut opened = open_bound_read_file(&path).unwrap();
    assert!(opened.parent().metadata().unwrap().is_dir());
    let before = opened.identity().unwrap();
    let mut bytes = Vec::new();
    opened.read_to_end(&mut bytes).unwrap();
    assert_eq!(bytes, b"fn main() {}\n");
    assert_eq!(before.links, 1);
    assert_eq!(before.size, bytes.len() as u64);
    assert_ne!(before.id, [0; 16]);
    opened.validate_unchanged(&before).unwrap();
}

#[test]
fn generic_reader_allows_hardlinks_without_conferring_source_policy() {
    let fixture = Fixture::new("hardlinks");
    let path = fixture.file();
    let other = fixture.0.join("other.rs");
    fs::hard_link(&path, &other).unwrap();
    let first = open_bound_read_file(&path).unwrap();
    let second = open_bound_read_file(&other).unwrap();
    assert_eq!(first.identity().unwrap(), second.identity().unwrap());
    assert_eq!(first.identity().unwrap().links, 2);
}

#[test]
fn file_and_ancestor_rename_delete_and_write_are_denied_while_bound() {
    let fixture = Fixture::new("retained");
    let directory = fixture.0.join("parent");
    fs::create_dir(&directory).unwrap();
    let path = directory.join("source.rs");
    fs::write(&path, b"safe").unwrap();
    let mut opened = open_bound_read_file(&path).unwrap();
    assert!(fs::rename(&directory, fixture.0.join("renamed")).is_err());
    assert!(fs::rename(&path, directory.join("renamed.rs")).is_err());
    assert!(fs::remove_file(&path).is_err());
    assert!(fs::OpenOptions::new().write(true).open(&path).is_err());
    assert!(opened.write_all(b"changed").is_err());
    drop(opened);
    fs::rename(&directory, fixture.0.join("renamed")).unwrap();
}

#[test]
fn preexisting_writable_handle_prevents_secure_read() {
    let fixture = Fixture::new("writer");
    let path = fixture.file();
    let writer = fs::OpenOptions::new().write(true).open(&path).unwrap();
    assert!(open_bound_read_file(&path).is_err());
    drop(writer);
    assert!(open_bound_read_file(&path).is_ok());
}

#[test]
fn stale_identity_is_rejected_after_same_name_replacement() {
    let fixture = Fixture::new("replacement");
    let path = fixture.file();
    let before = open_bound_read_file(&path).unwrap().identity().unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"fn replacement() {}\n").unwrap();
    let replacement = open_bound_read_file(&path).unwrap();
    assert!(replacement.validate_unchanged(&before).is_err());
}

#[test]
fn security_change_is_rejected_and_kernel_denies_new_data_reads() {
    use windows_permissions::constants::{SeObjectType, SecurityInformation};
    use windows_permissions::wrappers::{GetNamedSecurityInfo, SetNamedSecurityInfo};
    use windows_permissions::{LocalBox, SecurityDescriptor};

    let fixture = Fixture::new("security");
    let path = fixture.file();
    let opened = open_bound_read_file(&path).unwrap();
    let before = opened.identity().unwrap();
    let original = GetNamedSecurityInfo(
        &path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl,
    )
    .unwrap();
    // Deny only data reads to Everyone, while allowing restoration and cleanup.
    // No production code writes or repairs a security descriptor.
    let denied: LocalBox<SecurityDescriptor> = "D:P(D;;0x1;;;WD)(A;;FA;;;OW)".parse().unwrap();
    SetNamedSecurityInfo(
        &path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl | SecurityInformation::ProtectedDacl,
        None,
        None,
        denied.dacl(),
        None,
    )
    .unwrap();
    let changed = opened.validate_unchanged(&before).is_err();
    let new_read_denied = open_bound_read_file(&path)
        .is_err_and(|error| error.kind() == std::io::ErrorKind::PermissionDenied);
    SetNamedSecurityInfo(
        &path,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Dacl,
        None,
        None,
        original.dacl(),
        None,
    )
    .unwrap();
    assert!(changed);
    assert!(new_read_denied);
}

#[test]
fn rejects_junction_ancestry_without_following_it() {
    let fixture = Fixture::new("junction");
    let target = fixture.0.join("target");
    let junction = fixture.0.join("junction");
    fs::create_dir(&target).unwrap();
    fs::write(target.join("source.rs"), b"safe").unwrap();
    let status = std::process::Command::new("cmd.exe")
        .args(["/d", "/c", "mklink", "/J"])
        .arg(&junction)
        .arg(&target)
        .status()
        .unwrap();
    assert!(status.success(), "junction fixture must be established");
    assert!(open_bound_read_file(&junction.join("source.rs")).is_err());
    fs::remove_dir(junction).unwrap();
}

#[test]
fn rejects_devices_unc_streams_parent_paths_and_ambiguous_components() {
    for path in [
        r"\\server\share\source.rs",
        r"\\?\UNC\server\share\source.rs",
        r"\\.\PhysicalDrive0",
        r"C:source.rs",
        r"C:\source.rs:secret",
        r"C:\parent\..\source.rs",
        r"C:\parent\.\source.rs",
        r"C:\parent\\source.rs",
        r"C:\parent.\source.rs",
        r"C:\source.rs ",
        r"C:\parent?\source.rs",
        r"C:\",
    ] {
        assert!(open_bound_read_file(Path::new(path)).is_err(), "{path}");
    }
}
