use super::super::{
    create_null_handle, spawn_managed_child, spawn_managed_child_with_stderr, ManagedChild,
};
use super::*;
use std::env;
use std::ffi::{OsStr, OsString};
use std::io::{Read, Write};
use std::mem::size_of;
use std::sync::mpsc;
use std::time::Duration;
use winapi::shared::minwindef::{DWORD, TRUE};
use winapi::shared::ntdef::HANDLE;
use winapi::um::fileapi::GetFileType;
use winapi::um::handleapi::GetHandleInformation;
use winapi::um::synchapi::CreateEventW;
use winapi::um::winbase::{FILE_TYPE_CHAR, FILE_TYPE_PIPE, FILE_TYPE_UNKNOWN};
use winapi::um::winnt::GENERIC_WRITE;

const CHILD_ENV: &str = "HOL_GUARD_TEST_PROFILE_STDERR_SENTINEL";
const MARKER: &[u8] = b"native-profile-capture-probe\n";
const TEST_TIMEOUT: Duration = Duration::from_secs(5);

fn security() -> SECURITY_ATTRIBUTES {
    SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    }
}

fn flags(handle: HANDLE) -> DWORD {
    let mut value = 0;
    // SAFETY: Each caller retains the owned handle through this query.
    assert_ne!(unsafe { GetHandleInformation(handle, &mut value) }, FALSE);
    value
}

fn read_bounded(reader: File) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (send, receive) = mpsc::sync_channel(1);
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = reader.take(4097).read_to_end(&mut bytes).map(|_| bytes);
        let _ = send.send(result);
    });
    receive
}

struct RestoreEnvironment(Option<OsString>);

impl Drop for RestoreEnvironment {
    fn drop(&mut self) {
        match self.0.take() {
            Some(value) => env::set_var(CHILD_ENV, value),
            None => env::remove_var(CHILD_ENV),
        }
    }
}

struct StopChild(ManagedChild);

impl Drop for StopChild {
    fn drop(&mut self) {
        let _ = self.0.terminate_with_timeout(TEST_TIMEOUT);
    }
}

#[test]
fn native_client_profile_stderr_pipe_has_only_child_end_inheritable() {
    let (read, write) = pipe(&mut security()).expect("create diagnostic pipe");
    assert_eq!(
        flags(read.as_raw_handle() as HANDLE) & HANDLE_FLAG_INHERIT,
        0
    );
    assert_eq!(
        flags(write.as_raw_handle() as HANDLE) & HANDLE_FLAG_INHERIT,
        HANDLE_FLAG_INHERIT
    );
    // SAFETY: Both pipe ends remain owned through the calls.
    assert_eq!(
        unsafe { GetFileType(read.as_raw_handle() as HANDLE) },
        FILE_TYPE_PIPE
    );
    assert_eq!(
        unsafe { GetFileType(write.as_raw_handle() as HANDLE) },
        FILE_TYPE_PIPE
    );
    let completed = read_bounded(read);
    drop(write);
    assert_eq!(
        completed
            .recv_timeout(TEST_TIMEOUT)
            .expect("pipe EOF is bounded")
            .unwrap(),
        b""
    );
}

#[test]
fn native_client_profile_stderr_capture_and_default_keep_handle_list() {
    if let Some(value) = env::var_os(CHILD_ENV) {
        let value = value.to_str().expect("synthetic marker is UTF-8");
        let (mode, sentinel) = value
            .split_once(':')
            .expect("synthetic marker has two fields");
        let sentinel = sentinel
            .parse::<usize>()
            .expect("synthetic handle is numeric") as HANDLE;
        let mut sentinel_flags = 0;
        // SAFETY: Query only; never adopt or close the supplied sentinel value.
        let leaked = unsafe {
            GetHandleInformation(sentinel, &mut sentinel_flags) != FALSE
                && GetFileType(sentinel) == FILE_TYPE_UNKNOWN
        };
        assert!(!leaked, "unlisted parent event reached child");
        assert!(matches!(mode, "capture" | "ordinary"));
        // SAFETY: Standard handles are borrowed and remain owned by the process.
        unsafe {
            assert_eq!(
                GetFileType(std::io::stdin().as_raw_handle() as HANDLE),
                FILE_TYPE_PIPE
            );
            assert_eq!(
                GetFileType(std::io::stdout().as_raw_handle() as HANDLE),
                FILE_TYPE_CHAR
            );
            assert_eq!(
                GetFileType(std::io::stderr().as_raw_handle() as HANDLE),
                if mode == "capture" {
                    FILE_TYPE_PIPE
                } else {
                    FILE_TYPE_CHAR
                }
            );
        }
        std::io::stderr()
            .lock()
            .write_all(MARKER)
            .expect("write fixed synthetic marker");
        return;
    }

    let mut attributes = security();
    // Keep the sentinel above the child's ordinary startup handle range.
    let _padding: Vec<_> = (0..128)
        .map(|_| create_null_handle(GENERIC_WRITE, &mut attributes).unwrap())
        .collect();
    // SAFETY: Initialized attributes live through CreateEventW; success is adopted once.
    let event = unsafe { CreateEventW(&mut attributes, FALSE, FALSE, std::ptr::null()) };
    assert!(!event.is_null());
    // SAFETY: CreateEventW returned this valid handle exactly once.
    let event = unsafe { OwnedHandle::from_raw_handle(event as RawHandle) };
    assert_eq!(
        flags(event.as_raw_handle() as HANDLE) & HANDLE_FLAG_INHERIT,
        HANDLE_FLAG_INHERIT
    );
    let executable = env::current_exe().expect("locate test executable");
    let test_name = "windows::profile_stderr::tests::native_client_profile_stderr_capture_and_default_keep_handle_list";
    let arguments = [
        OsStr::new("--exact"),
        OsStr::new(test_name),
        OsStr::new("--nocapture"),
        OsStr::new("--test-threads=1"),
    ];
    let _restore = RestoreEnvironment(env::var_os(CHILD_ENV));

    for capture in [false, true] {
        let mode = if capture { "capture" } else { "ordinary" };
        env::set_var(
            CHILD_ENV,
            format!("{mode}:{}", event.as_raw_handle() as usize),
        );
        let mut child = StopChild(
            if capture {
                spawn_managed_child_with_stderr(&executable, &arguments)
            } else {
                spawn_managed_child(&executable, &arguments)
            }
            .expect("spawn real probe child"),
        );
        env::remove_var(CHILD_ENV);
        drop(child.0.take_stdin());
        let completed = if capture {
            let read = child
                .0
                .take_stderr()
                .expect("diagnostic parent reader is retained");
            assert_eq!(
                flags(read.as_raw_handle() as HANDLE) & HANDLE_FLAG_INHERIT,
                0
            );
            assert!(
                child.0.take_stderr().is_none(),
                "reader ownership transfers once"
            );
            Some(read_bounded(read))
        } else {
            assert!(
                child.0.take_stderr().is_none(),
                "ordinary stderr remains NUL"
            );
            None
        };
        assert!(child
            .0
            .wait_success_with_timeout(TEST_TIMEOUT)
            .expect("probe child wait is bounded"));
        if let Some(completed) = completed {
            let bytes = completed
                .recv_timeout(TEST_TIMEOUT)
                .expect("capture and EOF are bounded")
                .unwrap();
            assert_eq!(bytes, MARKER);
        }
    }
}
