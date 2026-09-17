//! Read-only launcher file access. No permission repair or state creation.
use super::response::Failure;
use std::path::Path;

pub(super) fn read(path: &Path, maximum: usize, private: bool) -> Result<Vec<u8>, Failure> {
    if !path.is_absolute() {
        return Err(Failure::Integrity("launcher path is not absolute"));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if !private {
            return read_package_file(path, maximum);
        }
        let parent = path
            .parent()
            .ok_or(Failure::Integrity("launcher path has no parent"))?;
        let before = std::fs::symlink_metadata(path).map_err(read_error)?;
        let directory = std::fs::symlink_metadata(parent).map_err(read_error)?;
        if private
            && (directory.uid() != nix::unistd::geteuid().as_raw()
                || before.uid() != directory.uid()
                || directory.mode() & 0o077 != 0
                || before.mode() & 0o077 != 0)
        {
            return Err(Failure::Integrity(
                "launcher authority file is not owner-private",
            ));
        }
        let result = guard_secure_fs::read_bounded(path, maximum)
            .map_err(|_| Failure::Integrity("launcher file read could not be verified"))?;
        if result.identity.dev != Some(before.dev()) || result.identity.ino != Some(before.ino()) {
            return Err(Failure::Integrity("launcher file identity changed"));
        }
        let after = std::fs::symlink_metadata(path).map_err(read_error)?;
        if private && (after.uid() != before.uid() || after.mode() & 0o077 != 0) {
            return Err(Failure::Integrity("launcher file ownership changed"));
        }
        Ok(result.bytes)
    }
    #[cfg(windows)]
    {
        use std::io::Read;
        let mut bound =
            guard_runtime_windows_process::open_bound_read_file(path).map_err(read_error)?;
        let before = bound.identity().map_err(read_error)?;
        if private {
            if before.links != 1 {
                return Err(Failure::Integrity(
                    "launcher authority file has multiple links",
                ));
            }
            crate::resident_state::verify_windows_private_file(bound.parent()).map_err(|_| {
                Failure::Integrity("launcher authority directory is not owner-private")
            })?;
            crate::resident_state::verify_windows_private_file(bound.file())
                .map_err(|_| Failure::Integrity("launcher authority file is not owner-private"))?;
        }
        if before.size > maximum as u64 {
            return Err(Failure::Integrity("launcher file bound or type is invalid"));
        }
        let mut bytes = Vec::new();
        bound
            .file_mut()
            .take(maximum as u64 + 1)
            .read_to_end(&mut bytes)
            .map_err(read_error)?;
        if bytes.len() > maximum {
            return Err(Failure::Integrity("launcher file bound exceeded"));
        }
        bound.validate_unchanged(&before).map_err(read_error)?;
        Ok(bytes)
    }
    #[cfg(not(any(unix, windows)))]
    {
        let _ = (maximum, private);
        Err(Failure::Integrity("launcher platform is unsupported"))
    }
}

#[cfg(unix)]
fn read_package_file(path: &Path, maximum: usize) -> Result<Vec<u8>, Failure> {
    use std::io::Read;
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    // Immutable package files may be hardlinked by the wheel installer. Their
    // complete expected byte hash is bound by the private launcher config.
    let before = std::fs::symlink_metadata(path).map_err(read_error)?;
    if !before.is_file()
        || before.file_type().is_symlink()
        || before.len() > maximum as u64
        || before.mode() & 0o022 != 0
        || ![0, nix::unistd::geteuid().as_raw()].contains(&before.uid())
    {
        return Err(Failure::Integrity("launcher package file is invalid"));
    }
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
        .open(path)
        .map_err(read_error)?;
    let opened = file.metadata().map_err(read_error)?;
    let fingerprint = |metadata: &std::fs::Metadata| {
        (
            metadata.dev(),
            metadata.ino(),
            metadata.mode(),
            metadata.uid(),
            metadata.len(),
            metadata.mtime(),
            metadata.mtime_nsec(),
            metadata.ctime(),
            metadata.ctime_nsec(),
        )
    };
    if fingerprint(&before) != fingerprint(&opened) {
        return Err(Failure::Integrity("launcher package file changed"));
    }
    let mut bytes = Vec::new();
    (&file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(read_error)?;
    if bytes.len() > maximum
        || fingerprint(&opened) != fingerprint(&file.metadata().map_err(read_error)?)
        || fingerprint(&opened)
            != fingerprint(&std::fs::symlink_metadata(path).map_err(read_error)?)
    {
        return Err(Failure::Integrity("launcher package file changed"));
    }
    Ok(bytes)
}

fn read_error(error: std::io::Error) -> Failure {
    if error.kind() == std::io::ErrorKind::NotFound {
        Failure::Availability("daemon discovery is unavailable")
    } else {
        Failure::Integrity("launcher file cannot be read securely")
    }
}
