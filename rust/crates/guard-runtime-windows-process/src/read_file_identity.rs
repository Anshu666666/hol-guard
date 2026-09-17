use std::fs::File;
use std::io;
use std::mem::{size_of, zeroed};
use std::os::windows::io::AsRawHandle;

use winapi::shared::minwindef::FALSE;
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::{GetFileInformationByHandle, BY_HANDLE_FILE_INFORMATION};
use winapi::um::winbase::GetFileInformationByHandleEx;
use windows_permissions::constants::{SeObjectType, SecurityInformation};
use windows_permissions::wrappers::GetSecurityInfo;

// FILE_ID_INFO and FILE_BASIC_INFO use the Windows SDK layout. FileIdInfo is
// required: the older 64-bit file index is not unique on ReFS.
#[repr(C)]
struct FileIdInfo {
    volume: u64,
    id: [u8; 16],
}

#[repr(C)]
struct FileBasicInfo {
    creation: i64,
    access: i64,
    write: i64,
    change: i64,
    attributes: u32,
}

/// Identity of one already-open disk file, including its access policy.
/// This carries no owner-private policy and never changes an ACL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadFileIdentity {
    pub volume: u64,
    pub id: [u8; 16],
    pub size: u64,
    pub write_time: i64,
    pub change_time: i64,
    pub attributes: u32,
    pub links: u32,
    security: String,
}

impl ReadFileIdentity {
    pub(super) fn same_directory(&self, other: &Self) -> bool {
        self.volume == other.volume
            && self.id == other.id
            && self.attributes == other.attributes
            && self.security == other.security
    }
}

pub(super) fn read_identity(file: &File) -> io::Result<ReadFileIdentity> {
    let raw = file.as_raw_handle() as HANDLE;
    // SAFETY: All three plain SDK-layout output buffers are valid and the
    // borrowed handle remains open for the synchronous information queries.
    let (id, basic, info) = unsafe {
        let mut id: FileIdInfo = zeroed();
        let mut basic: FileBasicInfo = zeroed();
        let mut info: BY_HANDLE_FILE_INFORMATION = zeroed();
        if GetFileInformationByHandleEx(
            raw,
            18, // FileIdInfo
            &mut id as *mut _ as *mut _,
            size_of::<FileIdInfo>() as u32,
        ) == FALSE
            || GetFileInformationByHandleEx(
                raw,
                0, // FileBasicInfo
                &mut basic as *mut _ as *mut _,
                size_of::<FileBasicInfo>() as u32,
            ) == FALSE
            || GetFileInformationByHandle(raw, &mut info) == FALSE
        {
            return Err(io::Error::last_os_error());
        }
        (id, basic, info)
    };
    let security = GetSecurityInfo(
        file,
        SeObjectType::SE_FILE_OBJECT,
        SecurityInformation::Owner | SecurityInformation::Group | SecurityInformation::Dacl,
    )
    .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "file security unavailable"))?;
    let security = security
        .as_sddl()
        .map_err(|_| io::Error::other("file security encoding unavailable"))?
        .to_string_lossy()
        .into_owned();
    Ok(ReadFileIdentity {
        volume: id.volume,
        id: id.id,
        size: (u64::from(info.nFileSizeHigh) << 32) | u64::from(info.nFileSizeLow),
        write_time: basic.write,
        change_time: basic.change,
        attributes: basic.attributes,
        links: info.nNumberOfLinks,
        security,
    })
}
