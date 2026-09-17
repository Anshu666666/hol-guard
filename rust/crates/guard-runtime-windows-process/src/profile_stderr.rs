//! One child writer and one noninheritable parent reader per diagnostic pipe.
use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle, RawHandle};
use std::ptr::null_mut;
use winapi::shared::minwindef::FALSE;
use winapi::um::handleapi::SetHandleInformation;
use winapi::um::minwinbase::SECURITY_ATTRIBUTES;
use winapi::um::namedpipeapi::CreatePipe;
use winapi::um::winbase::HANDLE_FLAG_INHERIT;

#[cfg(test)]
#[path = "profile_stderr_tests.rs"]
mod tests;

pub(super) fn pipe(security: &mut SECURITY_ATTRIBUTES) -> io::Result<(File, OwnedHandle)> {
    let mut read = null_mut();
    let mut write = null_mut();
    // SAFETY: Outputs and initialized security descriptor are live. Success
    // creates two distinct handles, adopted exactly once below.
    if unsafe { CreatePipe(&mut read, &mut write, security, 0) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    // SAFETY: CreatePipe returned these handles exactly once.
    let read = unsafe { File::from_raw_handle(read as RawHandle) };
    let write = unsafe { OwnedHandle::from_raw_handle(write as RawHandle) };
    // SAFETY: read is owned here. Only write enters the child's explicit
    // inherited list; errors drop both handles before spawn.
    if unsafe { SetHandleInformation(read.as_raw_handle() as _, HANDLE_FLAG_INHERIT, 0) } == FALSE {
        return Err(io::Error::last_os_error());
    }
    Ok((read, write))
}
