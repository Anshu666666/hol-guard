use super::*;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

struct Reset;
impl Drop for Reset {
    fn drop(&mut self) {
        STATE.with(|state| *state.borrow_mut() = None);
        LOST.with(|lost| lost.set(false));
    }
}
fn scope_at(started: Instant, deadline: Instant) -> Reset {
    STATE.with(|state| *state.borrow_mut() = None);
    LOST.with(|lost| lost.set(false));
    begin(started, deadline);
    Reset
}
fn scope() -> Reset {
    let started = Instant::now();
    scope_at(started, started + Duration::from_millis(750))
}

#[test]
fn absent_and_nested_observations_do_not_invent_complete_data() {
    let _reset = scope();
    STATE.with(|state| *state.borrow_mut() = None);
    assert!(snapshot(None).is_none());
    let now = Instant::now();
    begin(now, now + Duration::from_millis(750));
    begin(now, now + Duration::from_millis(750));
    assert!(snapshot(None).unwrap().observation_lost);
    STATE.with(|state| {
        let _borrow = state.borrow_mut();
        event(Event::PollEntered, 1);
    });
    assert!(snapshot(None).unwrap().observation_lost);
}

#[test]
fn actual_zero_state_observation_is_distinct_from_missing_call() {
    let _reset = scope();
    event(Event::States, 0);
    let report = snapshot(None).unwrap();
    assert_eq!(&report.events[Event::States as usize][..2], &[1, 0]);
    assert_eq!(report.events[Event::Paths as usize], [0; 4]);
    assert_eq!(report.original_budget_us, 750_000);
    assert!(!report.child_observed && !report.complete_run && !report.headline_timing_eligible);
}

#[test]
fn counters_saturate_and_unknown_codes_never_export_supplied_text() {
    let _reset = scope();
    assert!(CODES.windows(2).all(|pair| pair[0] < pair[1]));
    for (index, code) in CODES.iter().enumerate() {
        assert_eq!(code_index(Some(code)), index as u32 + 2);
    }
    start(Stage::ReadState);
    end(Stage::ReadState, Some("private-path-token-sentinel"));
    end(Stage::ReadState, Some(&"x".repeat(MAX_CODE_BYTES + 1)));
    event(Event::Paths, usize::MAX);
    event(Event::Paths, 1);
    retry("native_client_connect_failed", false);
    retry("native_client_auth_nonce_failed", true);
    let report = snapshot(Some("arbitrary secret error")).unwrap();
    assert_eq!(report.original_error, 1);
    assert_eq!(report.phases[Stage::ReadState as usize][5], 1);
    assert_eq!(report.events[Event::Paths as usize][1], MAX_COUNT);
    assert!(report.counter_or_clock_overflow);
    assert_eq!(&report.retries[3..], &[0, 1]);
    let encoded = serde_json::to_string(&report).unwrap();
    assert!(!encoded.contains("sentinel") && !encoded.contains("secret"));
    assert!(encoded.len() <= MAX_RECORD_BYTES);
}

#[test]
fn enabled_original_result_and_exchange_error_are_preserved_once() {
    let _reset = scope();
    let calls = Cell::new(0);
    let error = crate::resident_client::ResidentClientError {
        code: "native_client_auth_nonce_failed".to_owned(), retryable_teardown: true,
    };
    let pointer = error.code.as_ptr();
    let result: Result<Vec<u8>, _> = crate::windows_startup_exchange!({
        calls.set(calls.get() + 1);
        Err(error)
    });
    let returned = result.unwrap_err();
    assert_eq!(returned.code.as_ptr(), pointer);
    assert_eq!(returned.code, "native_client_auth_nonce_failed");
    assert!(returned.retryable_teardown);
    assert_eq!(calls.get(), 1);
    let report = snapshot(None).unwrap();
    assert_eq!(&report.phases[Stage::Exchange as usize][..3], &[1, 1, 1]);
    let calls = Cell::new(0);
    let result = crate::windows_startup_call!(Lease, {
        calls.set(calls.get() + 1);
        Ok::<_, String>(vec![7, 8])
    });
    assert_eq!(result, Ok(vec![7, 8]));
    assert_eq!(calls.get(), 1);
}

struct OneWrite { calls: usize, mode: u8 }
impl Write for OneWrite {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.calls += 1;
        assert!(bytes.starts_with(PREFIX) && bytes.ends_with(b"\n"));
        assert!(bytes.len() <= MAX_RECORD_BYTES);
        match self.mode {
            0 => Ok(bytes.len()),
            1 => Ok(0),
            _ => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
        }
    }
    fn flush(&mut self) -> std::io::Result<()> { panic!("observer must not flush"); }
}

#[test]
fn successful_partial_and_failed_exports_make_one_write_without_retry() {
    let _reset = scope();
    let report = snapshot(Some("native_resident_start_timeout")).unwrap();
    for mode in [0, 1, 2] {
        let mut output = OneWrite { calls: 0, mode };
        write_report(&mut output, &report);
        assert_eq!(output.calls, 1);
    }
}

#[test]
fn actual_private_invalid_state_keeps_original_discovery_result() {
    use std::fs;
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let home = std::env::temp_dir().join(format!("guard-startup-observer-{}-{unique}", std::process::id()));
    crate::resident_state::ensure_private_directory(&home, true).unwrap();
    let digest = crate::resident_state::runtime_digest().unwrap();
    let directory = crate::resident_state::state_scope(&home, &digest).unwrap();
    let path = directory.join("generation-invalid.json");
    let mut file = crate::resident_state::private_file(&path, true, &home).unwrap();
    file.write_all(b"{invalid").unwrap();
    drop(file);
    // The fixture is real private Windows storage. Only the existing discovery
    // call is observed; the invalid input still disappears from its result.
    let _reset = scope();
    let result = crate::windows_startup_call!(Discovery,
        crate::resident_state::discover_home_states_prefer(&home, Some(&digest)));
    let report = snapshot(None);
    let cleanup = fs::remove_dir_all(&home);
    assert!(cleanup.is_ok());
    let report = report.unwrap();
    assert!(result.unwrap().is_empty());
    assert_eq!(&report.phases[Stage::ReadState as usize][..3], &[1, 1, 1]);
    assert_eq!(report.phases[Stage::ReadState as usize][5], code_index(Some("native_resident_state_invalid")));
    assert_eq!(&report.events[Event::States as usize][..2], &[1, 0]);
    assert!(!report.observation_lost && !report.counter_or_clock_overflow);
}

#[test]
fn actual_expired_request_preserves_failure_and_releases_its_lease() {
    use std::fs;
    let unique = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
    let home = std::env::temp_dir().join(format!("guard-startup-expired-{}-{unique}", std::process::id()));
    crate::resident_state::ensure_private_directory(&home, true).unwrap();
    let deadline = Instant::now();
    let _reset = scope_at(deadline, deadline);
    let result = crate::managed_resident::client_request_at_deadline(
        &home,
        br#"{"schema":"guard-hook-envelope.v2","schema":"other"}"#,
        deadline,
    );
    let report = snapshot(result.as_ref().err().map(String::as_str));
    let remaining = fs::read_dir(home.join("resident-client-leases.v1")).and_then(|entries| {
        entries.map(|entry| entry.map(|entry| entry.file_name())).collect::<std::io::Result<Vec<_>>>()
    });
    let cleanup = fs::remove_dir_all(&home);
    assert!(cleanup.is_ok());
    assert_eq!(remaining.unwrap(), vec![std::ffi::OsString::from(".leases.lock")]);
    let report = report.unwrap();
    assert_eq!(report.original_budget_us, 0);
    assert_eq!(result, Err("native_client_deadline_exceeded".to_owned()));
    assert_eq!(&report.phases[Stage::Lease as usize][..3], &[1, 1, 0]);
    assert_eq!(report.events[Event::LeaseDropped as usize][..2], [1, 1]);
    assert_eq!(report.phases[Stage::Spawn as usize], [0; 7]);
    assert_eq!(report.phases[Stage::RuntimeDigest as usize], [0; 7]);
    assert!(!report.observation_lost && !report.counter_or_clock_overflow);
}
