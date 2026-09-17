use std::ffi::OsStr;
use std::fs::File;
use std::io;
use std::mem::size_of;
use std::os::windows::ffi::OsStrExt;
use std::os::windows::io::{AsRawHandle, FromRawHandle, RawHandle};
use std::path::{Path, PathBuf};
use std::ptr::null_mut;

use winapi::shared::ntdef::{HANDLE, OBJECT_ATTRIBUTES, UNICODE_STRING};
use winapi::um::fileapi::{CreateFileW, OPEN_EXISTING};
use winapi::um::handleapi::INVALID_HANDLE_VALUE;
use winapi::um::winbase::FILE_FLAG_BACKUP_SEMANTICS;
use winapi::um::winnt::{
    FILE_READ_ATTRIBUTES, FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_TRAVERSE, GENERIC_READ,
    READ_CONTROL, SYNCHRONIZE,
};

use super::private_files::validate_handle;
use super::read_file_identity::{read_identity, ReadFileIdentity};
use super::read_file_path::{invalid_path, split_path};

const FILE_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
const FILE_SYNCHRONOUS_IO_NONALERT: u32 = 0x20;

#[repr(C)]
struct IoStatusBlock {
    status: isize,
    information: usize,
}

#[link(name = "ntdll")]
extern "system" {
    fn NtCreateFile(
        file: *mut HANDLE,
        access: u32,
        attributes: *mut OBJECT_ATTRIBUTES,
        status: *mut IoStatusBlock,
        allocation: *mut i64,
        file_attributes: u32,
        sharing: u32,
        disposition: u32,
        options: u32,
        ea: *mut u8,
        ea_length: u32,
    ) -> i32;
    fn RtlNtStatusToDosError(status: i32) -> u32;
}

/// Read-only disk file opened beneath retained, non-reparse directory handles.
/// Generic public-file access: no DACL repair, private-owner requirement, or
/// hardlink policy. Callers must keep this object alive throughout their read.
pub struct BoundReadFile {
    file: File,
    path: PathBuf,
    ancestry: Vec<(File, ReadFileIdentity)>,
}

impl std::ops::Deref for BoundReadFile {
    type Target = File;

    fn deref(&self) -> &File {
        &self.file
    }
}

impl std::ops::DerefMut for BoundReadFile {
    fn deref_mut(&mut self) -> &mut File {
        &mut self.file
    }
}

impl BoundReadFile {
    /// Borrow the retained immediate parent for a caller's verify-only policy.
    /// The reader requested no directory write or ACL-repair access.
    pub fn parent(&self) -> &File {
        &self
            .ancestry
            .last()
            .expect("bound read retains its root and parent")
            .0
    }

    pub fn file(&self) -> &File {
        &self.file
    }

    pub fn file_mut(&mut self) -> &mut File {
        &mut self.file
    }

    pub fn identity(&self) -> io::Result<ReadFileIdentity> {
        validate_handle(&self.file, false)?;
        read_identity(&self.file)
    }

    /// Recheck every retained directory and a new handle-bound walk of the
    /// same name. A same-name replacement or drive mapping change cannot be
    /// mistaken for the handle whose bytes were read.
    pub fn validate_unchanged(&self, expected: &ReadFileIdentity) -> io::Result<()> {
        if &self.identity()? != expected {
            return Err(changed());
        }
        for (directory, identity) in &self.ancestry {
            validate_handle(directory, true)?;
            if !identity.same_directory(&read_identity(directory)?) {
                return Err(changed());
            }
        }
        let current = open_bound_read_file(&self.path)?;
        if current.identity()? != *expected || current.ancestry.len() != self.ancestry.len() {
            return Err(changed());
        }
        for ((_, before), (_, after)) in self.ancestry.iter().zip(&current.ancestry) {
            if !before.same_directory(after) {
                return Err(changed());
            }
        }
        Ok(())
    }
}

fn changed() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, "secure read identity changed")
}

pub fn open_bound_read_file(path: &Path) -> io::Result<BoundReadFile> {
    let (root, names) = split_path(path)?;
    let root_file = open_root(&root)?;
    let root_identity = read_identity(&root_file)?;
    let mut ancestry = vec![(root_file, root_identity)];
    for (index, name) in names.iter().enumerate() {
        let final_component = index + 1 == names.len();
        let parent = &ancestry.last().ok_or_else(invalid_path)?.0;
        let file = open_relative(parent, name, !final_component)?;
        if final_component {
            return Ok(BoundReadFile {
                file,
                path: path.to_path_buf(),
                ancestry,
            });
        }
        let identity = read_identity(&file)?;
        ancestry.push((file, identity));
    }
    Err(invalid_path())
}

fn open_root(path: &Path) -> io::Result<File> {
    let wide = super::wide_path(path)?;
    // SAFETY: The UTF-16 root is NUL terminated. No handle inheritance or
    // security descriptor is requested; the returned handle is owned once.
    let raw = unsafe {
        CreateFileW(
            wide.as_ptr(),
            FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE,
            FILE_SHARE_READ | FILE_SHARE_WRITE,
            null_mut(),
            OPEN_EXISTING,
            FILE_FLAG_BACKUP_SEMANTICS | FILE_OPEN_REPARSE_POINT,
            null_mut(),
        )
    };
    if raw == INVALID_HANDLE_VALUE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreateFileW returned this newly-owned handle exactly once.
    let file = unsafe { File::from_raw_handle(raw as RawHandle) };
    validate_handle(&file, true)?;
    Ok(file)
}

fn open_relative(parent: &File, name: &OsStr, directory: bool) -> io::Result<File> {
    let mut wide: Vec<u16> = name.encode_wide().collect();
    let length = u16::try_from(wide.len() * 2).map_err(|_| invalid_path())?;
    let mut name = UNICODE_STRING {
        Length: length,
        MaximumLength: length,
        Buffer: wide.as_mut_ptr(),
    };
    let mut attributes = OBJECT_ATTRIBUTES {
        Length: size_of::<OBJECT_ATTRIBUTES>() as u32,
        RootDirectory: parent.as_raw_handle() as HANDLE,
        ObjectName: &mut name,
        Attributes: 0x40, // OBJ_CASE_INSENSITIVE; deliberately no inheritance.
        SecurityDescriptor: null_mut(),
        SecurityQualityOfService: null_mut(),
    };
    let mut status = IoStatusBlock {
        status: 0,
        information: 0,
    };
    let mut raw = null_mut();
    let access = if directory {
        FILE_TRAVERSE | FILE_READ_ATTRIBUTES | READ_CONTROL | SYNCHRONIZE
    } else {
        GENERIC_READ | SYNCHRONIZE
    };
    // SAFETY: All FFI buffers remain valid through the synchronous call;
    // RootDirectory is borrowed from retained ancestry. The name is one
    // validated component, so reparse processing cannot traverse an ancestor.
    let result = unsafe {
        NtCreateFile(
            &mut raw,
            access,
            &mut attributes,
            &mut status,
            null_mut(),
            0,
            if directory {
                FILE_SHARE_READ | FILE_SHARE_WRITE
            } else {
                FILE_SHARE_READ
            },
            1, // FILE_OPEN: never creates or truncates.
            FILE_OPEN_REPARSE_POINT
                | FILE_SYNCHRONOUS_IO_NONALERT
                | if directory { 1 } else { 0x40 }, // DIRECTORY/NON_DIRECTORY_FILE
            null_mut(),
            0,
        )
    };
    if result < 0 {
        // SAFETY: Pure conversion of the returned NTSTATUS.
        return Err(io::Error::from_raw_os_error(
            unsafe { RtlNtStatusToDosError(result) } as i32,
        ));
    }
    // SAFETY: NtCreateFile succeeded and transfers exactly one owned handle.
    let file = unsafe { File::from_raw_handle(raw as RawHandle) };
    validate_handle(&file, directory)?;
    Ok(file)
}
