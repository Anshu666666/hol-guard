use std::ffi::OsString;
use std::io;
use std::os::windows::ffi::OsStrExt;
use std::path::{Component, Path, PathBuf, Prefix};

pub(super) fn invalid_path() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "unsupported secure read path")
}

/// Accept only an absolute local drive path. No Win32 device, UNC, ADS,
/// wildcard, dot/space alias, parent traversal, or relative-drive namespace.
pub(super) fn split_path(path: &Path) -> io::Result<(PathBuf, Vec<OsString>)> {
    // Path::components normalizes interior dots and duplicate separators for
    // ordinary DOS paths. Check the actual spelling before that normalization.
    let spelling: Vec<u16> = path.as_os_str().encode_wide().collect();
    let offset = if spelling.starts_with(&[92, 92, 63, 92]) {
        7
    } else {
        3
    };
    if spelling.len() <= offset || spelling.len() > 32_767 {
        return Err(invalid_path());
    }
    for name in spelling[offset..].split(|c| matches!(c, 47 | 92)) {
        if name.is_empty() || name == [46] || name == [46, 46] {
            return Err(invalid_path());
        }
    }
    let mut parts = path.components();
    let Some(Component::Prefix(prefix)) = parts.next() else {
        return Err(invalid_path());
    };
    let drive = match prefix.kind() {
        Prefix::Disk(drive) | Prefix::VerbatimDisk(drive) if drive.is_ascii_alphabetic() => drive,
        _ => return Err(invalid_path()),
    };
    if !matches!(parts.next(), Some(Component::RootDir)) {
        return Err(invalid_path());
    }
    let root = PathBuf::from(format!("\\\\?\\{}:\\", char::from(drive)));
    let mut names = Vec::new();
    for component in parts {
        let Component::Normal(name) = component else {
            return Err(invalid_path());
        };
        let wide: Vec<u16> = name.encode_wide().collect();
        if wide.is_empty()
            || wide.len() > 255
            || wide.last().is_some_and(|c| matches!(c, 32 | 46))
            || wide
                .iter()
                .any(|c| *c < 32 || matches!(*c, 34 | 42 | 47 | 58 | 60 | 62 | 63 | 92 | 124))
        {
            return Err(invalid_path());
        }
        names.push(name.to_os_string());
        if names.len() > 256 {
            return Err(invalid_path());
        }
    }
    if names.is_empty() {
        return Err(invalid_path());
    }
    Ok((root, names))
}
