//! Fixed-memory, parent-thread-only diagnostic state. No original operation
//! runs while an observation borrow is held; final export makes one write.
use serde::Serialize;
use std::cell::{Cell, RefCell};
use std::io::Write;
use std::time::Instant;

const MAX_COUNT: u32 = 65_535;
const MAX_RECORD_BYTES: usize = 4_096;
const MAX_CODE_BYTES: usize = 128;
const PREFIX: &[u8] = b"HG_WINDOWS_STARTUP_V1 ";
const STAGES: usize = 16;
const EVENTS: usize = 9;

#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Stage {
    Lease,
    RuntimeDigest,
    PrivateScope,
    Discovery,
    ReadState,
    ValidateState,
    ProcessIdentity,
    Token,
    Exchange,
    StartupLock,
    StaleLock,
    RestartBudget,
    Generation,
    Spawn,
    AbortTerminate,
    AbortRetire,
}
#[derive(Clone, Copy)]
#[repr(usize)]
pub(crate) enum Event {
    Scopes,
    Paths,
    States,
    NoResponse,
    RejectedState,
    PollEntered,
    PollNoResponse,
    PollExpired,
    LeaseDropped,
}

const CODES: [&str; 48] = [
    "native_client_auth_nonce_failed",
    "native_client_auth_rejected",
    "native_client_auth_timeout_failed",
    "native_client_connect_failed",
    "native_client_deadline_exceeded",
    "native_client_frame_read_failed",
    "native_client_frame_write_failed",
    "native_client_peer_identity_failed",
    "native_client_peer_identity_mismatch",
    "native_client_random_failed",
    "native_client_response_binding_failed",
    "native_client_response_digest_mismatch",
    "native_resident_child_cleanup_failed",
    "native_resident_clock_invalid",
    "native_resident_generation_invalid",
    "native_resident_live_request_failed",
    "native_resident_managed_exit_failed",
    "native_resident_owner_process_invalid",
    "native_resident_private_root_missing",
    "native_resident_process_identity_mismatch",
    "native_resident_process_identity_unavailable",
    "native_resident_runtime_digest_invalid",
    "native_resident_runtime_identity_mismatch",
    "native_resident_runtime_invalid",
    "native_resident_runtime_path_failed",
    "native_resident_runtime_read_failed",
    "native_resident_runtime_stat_failed",
    "native_resident_socket_dir_owner_mismatch",
    "native_resident_socket_dir_stat_failed",
    "native_resident_spawn_auth_failed",
    "native_resident_spawn_failed",
    "native_resident_spawn_stdin_failed",
    "native_resident_start_in_progress",
    "native_resident_start_timeout",
    "native_resident_state_dir_stat_failed",
    "native_resident_state_encode_failed",
    "native_resident_state_endpoint_invalid",
    "native_resident_state_invalid",
    "native_resident_state_list_failed",
    "native_resident_state_mac_invalid",
    "native_resident_state_prune_failed",
    "native_resident_state_read_failed",
    "native_resident_state_stat_failed",
    "native_resident_state_token_invalid",
    "native_resident_state_transport_invalid",
    "native_resident_state_write_failed",
    "native_resident_stop_unavailable",
    "native_resident_supervisor_wait_failed",
];

#[derive(Clone, Copy)]
struct Observation {
    started: Instant,
    deadline: Instant,
    phases: [[u32; 7]; STAGES],
    events: [[u32; 4]; EVENTS],
    retries: [u32; 5],
    overflow: bool,
}

thread_local! {
    static STATE: RefCell<Option<Observation>> = const { RefCell::new(None) };
    static LOST: Cell<bool> = const { Cell::new(false) };
}

fn code_index(code: Option<&str>) -> u32 {
    match code {
        None => 0,
        Some(value) if value.len() <= MAX_CODE_BYTES => CODES
            .binary_search(&value)
            .map_or(1, |index| index as u32 + 2),
        Some(_) => 1,
    }
}

fn mark_lost() {
    let _ = LOST.try_with(|lost| lost.set(true));
}

fn update(call: impl FnOnce(&mut Observation)) {
    let result = STATE.try_with(|state| {
        let Ok(mut value) = state.try_borrow_mut() else {
            mark_lost();
            return;
        };
        if let Some(value) = value.as_mut() {
            call(value);
        }
    });
    if result.is_err() {
        mark_lost();
    }
}

fn elapsed_at(state: &mut Observation, now: Instant) -> u32 {
    let micros = now.saturating_duration_since(state.started).as_micros();
    if micros > u128::from(u32::MAX) {
        state.overflow = true;
    }
    micros.min(u128::from(u32::MAX)) as u32
}

fn increment(value: &mut u32, amount: usize, overflow: &mut bool) {
    let available = (MAX_COUNT - *value) as usize;
    if amount > available {
        *overflow = true;
    }
    *value += amount.min(available) as u32;
}

pub(crate) fn begin(started: Instant, deadline: Instant) {
    let result = STATE.try_with(|state| {
        let Ok(mut value) = state.try_borrow_mut() else {
            mark_lost();
            return;
        };
        if value.is_some() || deadline < started {
            mark_lost();
            return;
        }
        *value = Some(Observation {
            started,
            deadline,
            phases: [[0; 7]; STAGES],
            events: [[0; 4]; EVENTS],
            retries: [0; 5],
            overflow: false,
        });
    });
    if result.is_err() {
        mark_lost();
    }
}

pub(crate) fn start(stage: Stage) {
    update(|state| {
        let now = elapsed_at(state, Instant::now());
        let row = &mut state.phases[stage as usize];
        if row[0] == 0 {
            row[3] = now;
        }
        increment(&mut row[0], 1, &mut state.overflow);
    });
}

pub(crate) fn end(stage: Stage, error: Option<&str>) {
    let code = code_index(error);
    update(|state| {
        let now = elapsed_at(state, Instant::now());
        let row = &mut state.phases[stage as usize];
        increment(&mut row[1], 1, &mut state.overflow);
        row[4] = now;
        if code != 0 {
            if row[2] == 0 {
                row[5] = code;
            }
            row[6] = code;
            increment(&mut row[2], 1, &mut state.overflow);
        }
    });
}

pub(crate) fn event(event: Event, amount: usize) {
    update(|state| {
        let now = elapsed_at(state, Instant::now());
        let row = &mut state.events[event as usize];
        if row[0] == 0 {
            row[2] = now;
        }
        row[3] = now;
        increment(&mut row[0], 1, &mut state.overflow);
        increment(&mut row[1], amount, &mut state.overflow);
    });
}

pub(crate) fn retry(error: &str, teardown: bool) {
    let code = code_index(Some(error));
    update(|state| {
        if state.retries[0] == 0 {
            state.retries[1] = code;
            state.retries[3] = u32::from(teardown);
        }
        state.retries[2] = code;
        state.retries[4] = u32::from(teardown);
        increment(&mut state.retries[0], 1, &mut state.overflow);
    });
}

#[derive(Serialize)]
struct Report {
    schema: &'static str,
    parent_only: bool,
    child_observed: bool,
    complete_run: bool,
    headline_timing_eligible: bool,
    qualification_complete: bool,
    original_error: u32,
    original_budget_us: u64,
    observed_elapsed_us: u32,
    observed_remaining_us: u64,
    phases: [[u32; 7]; STAGES],
    events: [[u32; 4]; EVENTS],
    retries: [u32; 5],
    counter_or_clock_overflow: bool,
    observation_lost: bool,
}

fn snapshot(error: Option<&str>) -> Option<Report> {
    let observation = STATE
        .try_with(|state| state.try_borrow().ok().and_then(|value| *value))
        .ok()
        .flatten()?;
    let mut observation = observation;
    let now = Instant::now();
    Some(Report {
        schema: "hol-guard-native-windows-startup.v1",
        parent_only: true,
        child_observed: false,
        complete_run: false,
        headline_timing_eligible: false,
        qualification_complete: false,
        original_error: code_index(error),
        original_budget_us: observation
            .deadline
            .saturating_duration_since(observation.started)
            .as_micros()
            .min(u128::from(u64::MAX)) as u64,
        observed_elapsed_us: elapsed_at(&mut observation, now),
        observed_remaining_us: observation
            .deadline
            .saturating_duration_since(now)
            .as_micros()
            .min(u128::from(u64::MAX)) as u64,
        phases: observation.phases,
        events: observation.events,
        retries: observation.retries,
        counter_or_clock_overflow: observation.overflow,
        observation_lost: LOST.try_with(Cell::get).unwrap_or(true),
    })
}

fn write_report(output: &mut impl Write, report: &Report) {
    let Ok(encoded) = serde_json::to_vec(report) else {
        return;
    };
    if PREFIX.len() + encoded.len() + 1 > MAX_RECORD_BYTES {
        return;
    }
    let mut bytes = Vec::with_capacity(PREFIX.len() + encoded.len() + 1);
    bytes.extend_from_slice(PREFIX);
    bytes.extend_from_slice(&encoded);
    bytes.push(b'\n');
    let _ = output.write(&bytes);
}

pub(crate) fn emit(error: Option<&str>) {
    if let Some(report) = snapshot(error) {
        write_report(&mut std::io::stderr(), &report);
    }
}

#[cfg(test)]
#[path = "native_windows_startup_observation_tests.rs"]
mod tests;
