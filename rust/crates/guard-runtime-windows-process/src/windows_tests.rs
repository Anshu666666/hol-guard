use super::*;
use std::env;
use std::io::Write;
use winapi::um::fileapi::GetFileType;
use winapi::um::handleapi::GetHandleInformation;
use winapi::um::synchapi::CreateEventW;
use winapi::um::winbase::FILE_TYPE_UNKNOWN;

const SENTINEL_ENV: &str = "HOL_GUARD_TEST_UNLISTED_HANDLE";

#[test]
fn inherited_handle_is_not_leaked() {
    if let Ok(raw_handle) = env::var(SENTINEL_ENV) {
        let handle = raw_handle.parse::<usize>().expect("test handle is numeric") as HANDLE;
        let mut flags = 0;
        let inherited = unsafe {
            GetHandleInformation(handle, &mut flags) != FALSE
                && GetFileType(handle) == FILE_TYPE_UNKNOWN
        };
        assert!(!inherited, "unlisted parent handle reached managed child");
        return;
    }

    let mut security = SECURITY_ATTRIBUTES {
        nLength: size_of::<SECURITY_ATTRIBUTES>() as DWORD,
        lpSecurityDescriptor: null_mut(),
        bInheritHandle: TRUE,
    };
    let mut open_handles = Vec::new();
    for _ in 0..128 {
        open_handles.push(create_null_handle(GENERIC_WRITE, &mut security).unwrap());
    }
    let sentinel = unsafe { CreateEventW(&mut security, FALSE, FALSE, null()) };
    assert!(!sentinel.is_null());
    let sentinel = unsafe { OwnedHandle::from_raw_handle(sentinel as RawHandle) };
    env::set_var(
        SENTINEL_ENV,
        (sentinel.as_raw_handle() as usize).to_string(),
    );

    let executable = env::current_exe().unwrap();
    let arguments = [
        OsStr::new("--nocapture"),
        OsStr::new("inherited_handle_is_not_leaked"),
    ];
    let mut child = spawn_managed_child(&executable, &arguments).unwrap();
    let mut stdin = child.take_stdin().unwrap();
    stdin.flush().unwrap();
    drop(stdin);
    assert!(child
        .wait_success_with_timeout(std::time::Duration::from_secs(2))
        .unwrap());
    env::remove_var(SENTINEL_ENV);
    drop(open_handles);
}
