//! Native Unix listener ownership, independent of a reusable endpoint name.

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UnixEndpointIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
    pub(crate) owner: u32,
}

#[cfg(unix)]
impl UnixEndpointIdentity {
    pub(crate) fn capture(path: &std::path::Path) -> Result<Self, String> {
        use std::os::unix::fs::{FileTypeExt, MetadataExt};
        let metadata = std::fs::symlink_metadata(path)
            .map_err(|_| "native_socket_identity_unavailable".to_owned())?;
        if !metadata.file_type().is_socket() {
            return Err("native_socket_identity_invalid".to_owned());
        }
        Ok(Self {
            device: metadata.dev(),
            inode: metadata.ino(),
            owner: metadata.uid(),
        })
    }

    pub(crate) fn remove_if_same(&self, path: &std::path::Path) -> bool {
        if Self::capture(path).as_ref() != Ok(self) {
            return false;
        }
        std::fs::remove_file(path).is_ok()
    }
}

#[cfg(unix)]
pub(crate) struct OwnedUnixEndpoint {
    path: std::path::PathBuf,
    pub(crate) identity: UnixEndpointIdentity,
}

#[cfg(unix)]
impl OwnedUnixEndpoint {
    pub(crate) fn capture(path: &std::path::Path) -> Result<Self, String> {
        Ok(Self {
            path: path.to_owned(),
            identity: UnixEndpointIdentity::capture(path)?,
        })
    }
}

#[cfg(unix)]
impl Drop for OwnedUnixEndpoint {
    fn drop(&mut self) {
        let _ = self.identity.remove_if_same(&self.path);
    }
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::net::UnixListener;
    use std::path::PathBuf;

    fn fixture() -> PathBuf {
        let mut nonce = [0u8; 8];
        getrandom::fill(&mut nonce).unwrap();
        let path = std::env::temp_dir().join(format!("ep-{}", hex::encode(nonce)));
        fs::create_dir(&path).unwrap();
        path
    }

    #[test]
    fn dropping_owned_endpoint_preserves_replacement_socket() {
        let directory = fixture();
        let path = directory.join("s");
        let original = UnixListener::bind(&path).unwrap();
        let ownership = OwnedUnixEndpoint::capture(&path).unwrap();
        fs::rename(&path, directory.join("original")).unwrap();
        let replacement = UnixListener::bind(&path).unwrap();
        let identity = UnixEndpointIdentity::capture(&path).unwrap();
        drop(ownership);
        assert_eq!(UnixEndpointIdentity::capture(&path).unwrap(), identity);
        drop(replacement);
        drop(original);
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn dropping_owned_endpoint_removes_only_its_socket() {
        let directory = fixture();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let ownership = OwnedUnixEndpoint::capture(&path).unwrap();
        drop(listener);
        drop(ownership);
        assert!(!path.exists());
        fs::remove_dir_all(directory).unwrap();
    }

    #[test]
    fn cleanup_does_not_follow_a_replacement_symlink() {
        let directory = fixture();
        let path = directory.join("s");
        let listener = UnixListener::bind(&path).unwrap();
        let ownership = OwnedUnixEndpoint::capture(&path).unwrap();
        fs::rename(&path, directory.join("original")).unwrap();
        std::os::unix::fs::symlink(directory.join("original"), &path).unwrap();
        drop(ownership);
        assert!(fs::symlink_metadata(&path)
            .unwrap()
            .file_type()
            .is_symlink());
        assert!(UnixEndpointIdentity::capture(&directory.join("original")).is_ok());
        drop(listener);
        fs::remove_dir_all(directory).unwrap();
    }
}
