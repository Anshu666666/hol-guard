use guard_secure_fs::{read_bounded, SecureReadError};
use std::fs::{self, OpenOptions};
use std::io::Write;

fn fixture_root(name: &str) -> std::path::PathBuf {
    let temporary_root =
        fs::canonicalize(std::env::temp_dir()).unwrap_or_else(|_| std::env::temp_dir());
    temporary_root.join(format!("guard-secure-fs-{name}-{}", std::process::id()))
}

#[test]
fn bounded_read_rejects_truncation_limit_before_materializing_more_bytes() {
    let dir = fixture_root("truncation");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"0123456789").unwrap();

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[test]
fn bounded_read_rejects_source_growth_beyond_limit() {
    let dir = fixture_root("growth");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    fs::write(&path, b"safe").unwrap();
    let mut file = OpenOptions::new().append(true).open(&path).unwrap();
    file.write_all(b" growth").unwrap();
    drop(file);

    assert!(matches!(
        read_bounded(&path, 4),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}

#[cfg(any(unix, windows))]
#[test]
fn source_size_boundaries_are_complete_and_never_truncated() {
    let dir = fixture_root("exact-sizes");
    fs::create_dir_all(&dir).unwrap();
    let path = dir.join("source.rs");
    for size in [250_000, 1_000_000, guard_rules::MAX_SCAN_BYTES] {
        let bytes = vec![b'x'; size];
        fs::write(&path, &bytes).unwrap();
        let read = read_bounded(&path, size).unwrap();
        assert_eq!(read.bytes, bytes);
        assert_eq!(read.identity.size, size as u64);
        assert!(matches!(
            read_bounded(&path, size - 1),
            Err(SecureReadError::TooLarge)
        ));
    }
    fs::write(&path, vec![b'x'; guard_rules::MAX_SCAN_BYTES + 1]).unwrap();
    assert!(matches!(
        read_bounded(&path, usize::MAX),
        Err(SecureReadError::TooLarge)
    ));
    let _ = fs::remove_dir_all(dir);
}
