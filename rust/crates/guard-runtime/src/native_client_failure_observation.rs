//! Fixed, first-only observations at the actual live-exchange collapse boundary.
//! No free-form code, request, path, or exception text is retained or exported.
//! One best-effort stderr write follows the original public CLI error line.

#[cfg(not(all(feature = "diagnostic-phases", target_os = "macos")))]
#[macro_export]
macro_rules! observe_native_live_failure {
    ($error:expr, $state:expr) => {
        Err("native_resident_live_request_failed".to_owned())
    };
}

#[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
#[macro_export]
macro_rules! observe_native_live_failure {
    ($error:expr, $state:expr) => {{
        $crate::native_client_failure_observation::record(&$error, &$state);
        Err("native_resident_live_request_failed".to_owned())
    }};
}

#[cfg(not(all(feature = "diagnostic-phases", target_os = "macos")))]
#[macro_export]
macro_rules! emit_native_live_failure {
    () => {};
}

#[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
#[macro_export]
macro_rules! emit_native_live_failure {
    () => {
        $crate::native_client_failure_observation::emit();
    };
}

#[cfg(any(test, all(feature = "diagnostic-phases", target_os = "macos")))]
mod enabled {
    use serde::Serialize;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, AtomicU8, Ordering};

    const MAX_CODE_BYTES: usize = 128;
    const MAX_RECORD_BYTES: usize = 1024;
    const KNOWN_CODES: [&str; 23] = [
        "native_client_auth_nonce_failed",
        "native_client_auth_rejected",
        "native_client_auth_timeout_failed",
        "native_client_connect_failed",
        "native_client_deadline_exceeded",
        "native_client_deadline_invalid",
        "native_client_endpoint_invalid",
        "native_client_frame_invalid",
        "native_client_frame_read_failed",
        "native_client_frame_write_failed",
        "native_client_peer_identity_failed",
        "native_client_peer_identity_mismatch",
        "native_client_random_failed",
        "native_client_request_too_large",
        "native_client_response_binding_failed",
        "native_client_response_digest_mismatch",
        "native_client_response_too_large",
        "native_client_timeout_failed",
        "native_client_transport_invalid",
        "native_client_unix_unavailable",
        "native_resident_process_identity_mismatch",
        "native_resident_process_identity_unavailable",
        "native_resident_runtime_path_failed",
    ];
    #[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
    static OBSERVER: Observer = Observer::new();

    struct Observer {
        claimed: AtomicBool,
        ready: AtomicBool,
        generation: AtomicU64,
        process_id: AtomicU32,
        owner_process_id: AtomicU32,
        transport: AtomicU8,
        first: AtomicU16,
        additional_observation_lost: AtomicBool,
    }

    impl Observer {
        const fn new() -> Self {
            Self {
                claimed: AtomicBool::new(false),
                ready: AtomicBool::new(false),
                generation: AtomicU64::new(0),
                process_id: AtomicU32::new(0),
                owner_process_id: AtomicU32::new(0),
                transport: AtomicU8::new(0),
                first: AtomicU16::new(0),
                additional_observation_lost: AtomicBool::new(false),
            }
        }

        fn record(
            &self,
            code: &str,
            retryable_teardown: bool,
            generation: u64,
            process_id: u32,
            owner_process_id: u32,
            transport: &str,
        ) {
            let index = if code.len() <= MAX_CODE_BYTES {
                KNOWN_CODES
                    .binary_search(&code)
                    .unwrap_or(KNOWN_CODES.len())
            } else {
                KNOWN_CODES.len()
            };
            let value = ((index as u16 + 1) << 1) | u16::from(retryable_teardown);
            // Exactly one attempt. A competing or subsequent observation never
            // overwrites the first and never waits, retries, or allocates.
            if self
                .claimed
                .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                self.additional_observation_lost
                    .store(true, Ordering::Relaxed);
                return;
            }
            self.first.store(value, Ordering::Relaxed);
            self.generation.store(generation, Ordering::Relaxed);
            self.process_id.store(process_id, Ordering::Relaxed);
            self.owner_process_id
                .store(owner_process_id, Ordering::Relaxed);
            self.transport.store(
                match transport {
                    "loopback" => 1,
                    "unix" => 2,
                    _ => 0,
                },
                Ordering::Relaxed,
            );
            self.ready.store(true, Ordering::Release);
        }

        fn snapshot(&self) -> Option<Report> {
            if !self.ready.load(Ordering::Acquire) {
                return None;
            }
            let value = self.first.load(Ordering::Relaxed);
            let index = usize::from((value >> 1) - 1);
            Some(Report {
                schema: "hol-guard-macos-recovery-failure.v1",
                complete_run: false,
                headline_timing_eligible: false,
                stage: "live_exchange_pre_collapse",
                known_code: KNOWN_CODES.get(index).copied().unwrap_or("unknown"),
                retryable_teardown: value & 1 != 0,
                retained_observations: 1,
                maximum_retained_observations: 1,
                additional_observation_lost: self
                    .additional_observation_lost
                    .load(Ordering::Relaxed),
                snapshot_atomic: false,
                scope: "first_observed_non_retryable_live_exchange_error",
                generation: self.generation.load(Ordering::Relaxed),
                process_id: self.process_id.load(Ordering::Relaxed),
                owner_process_id: self.owner_process_id.load(Ordering::Relaxed),
                transport: match self.transport.load(Ordering::Relaxed) {
                    1 => "loopback",
                    2 => "unix",
                    _ => "unknown",
                },
                state_fields_coherent: true,
                owner_liveness_observed: false,
            })
        }
    }

    #[derive(Serialize)]
    pub(crate) struct Report {
        schema: &'static str,
        complete_run: bool,
        headline_timing_eligible: bool,
        stage: &'static str,
        known_code: &'static str,
        retryable_teardown: bool,
        retained_observations: u8,
        maximum_retained_observations: u8,
        additional_observation_lost: bool,
        snapshot_atomic: bool,
        scope: &'static str,
        generation: u64,
        process_id: u32,
        owner_process_id: u32,
        transport: &'static str,
        state_fields_coherent: bool,
        owner_liveness_observed: bool,
    }

    #[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
    pub(crate) fn record(
        error: &crate::resident_client::ResidentClientError,
        state: &crate::resident_state::ResidentState,
    ) {
        OBSERVER.record(
            &error.code,
            error.retryable_teardown,
            state.generation,
            state.process_id,
            state.owner_process_id,
            &state.transport,
        );
    }

    #[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
    pub(crate) fn emit() {
        let Some(report) = OBSERVER.snapshot() else {
            return;
        };
        write_report(&mut std::io::stderr(), &report);
    }

    fn write_report(output: &mut impl Write, report: &Report) {
        let Ok(encoded) = serde_json::to_vec(report) else {
            return;
        };
        if encoded.len() > MAX_RECORD_BYTES {
            return;
        }
        let mut bytes = b"HG_MAC_RECOVERY_V1 ".to_vec();
        bytes.extend_from_slice(&encoded);
        bytes.push(b'\n');
        // One write invocation after run() returned and after the original
        // generic error was printed. Ignore partial/error results; no retry.
        let _ = output.write(&bytes);
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn missing_observations_are_unobserved() {
            assert!(Observer::new().snapshot().is_none());
        }

        #[test]
        fn claimed_but_unpublished_state_is_not_observed() {
            let observer = Observer::new();
            observer.claimed.store(true, Ordering::Relaxed);
            observer.generation.store(42, Ordering::Relaxed);
            assert!(observer.snapshot().is_none());
        }

        #[test]
        fn simultaneous_records_keep_one_complete_state_tuple() {
            let observer = std::sync::Arc::new(Observer::new());
            let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
            let workers: Vec<_> = (1..=2)
                .map(|n| {
                    let observer = std::sync::Arc::clone(&observer);
                    let barrier = std::sync::Arc::clone(&barrier);
                    std::thread::spawn(move || {
                        barrier.wait();
                        observer.record(
                            KNOWN_CODES[n - 1],
                            false,
                            n as u64,
                            n as u32 + 10,
                            n as u32 + 20,
                            "unix",
                        );
                    })
                })
                .collect();
            barrier.wait();
            for worker in workers {
                worker.join().unwrap();
            }
            let report = observer.snapshot().unwrap();
            let n = report.generation;
            assert!(n == 1 || n == 2);
            assert_eq!(report.process_id, n as u32 + 10);
            assert_eq!(report.owner_process_id, n as u32 + 20);
            assert_eq!(report.known_code, KNOWN_CODES[n as usize - 1]);
            assert!(report.additional_observation_lost);
        }

        #[test]
        fn every_fixed_code_and_retryable_bit_round_trips() {
            assert!(KNOWN_CODES.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(KNOWN_CODES.len() < (u16::MAX as usize >> 1));
            for code in KNOWN_CODES {
                assert!(code.len() <= MAX_CODE_BYTES);
                for retryable in [false, true] {
                    let observer = Observer::new();
                    observer.record(code, retryable, 42, 123, 456, "unix");
                    let report = observer.snapshot().unwrap();
                    assert_eq!(report.known_code, code);
                    assert_eq!(report.retryable_teardown, retryable);
                    assert!(!report.additional_observation_lost);
                    assert_eq!(
                        (
                            report.generation,
                            report.process_id,
                            report.owner_process_id,
                            report.transport
                        ),
                        (42, 123, 456, "unix")
                    );
                    assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_RECORD_BYTES);
                }
            }
        }

        #[test]
        fn unknown_and_oversized_codes_do_not_export_input() {
            for code in ["private sentinel request path".to_owned(), "x".repeat(129)] {
                let observer = Observer::new();
                observer.record(&code, false, 42, 123, 456, "private endpoint");
                let report = observer.snapshot().unwrap();
                assert_eq!(report.known_code, "unknown");
                assert_eq!(report.transport, "unknown");
                let encoded = serde_json::to_string(&report).unwrap();
                assert!(!encoded.contains(&code));
                assert!(encoded.len() <= MAX_RECORD_BYTES);
            }
        }

        struct OneWrite {
            calls: usize,
            mode: u8,
        }

        impl Write for OneWrite {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.calls += 1;
                assert!(bytes.starts_with(b"HG_MAC_RECOVERY_V1 "));
                assert!(bytes.ends_with(b"\n"));
                assert!(bytes.len() <= MAX_RECORD_BYTES + 20);
                match self.mode {
                    0 => Ok(bytes.len()),
                    1 => Ok(0),
                    _ => Err(std::io::Error::from(std::io::ErrorKind::Interrupted)),
                }
            }

            fn flush(&mut self) -> std::io::Result<()> {
                panic!("diagnostic must not add a flush");
            }
        }

        #[test]
        fn short_failed_and_successful_writes_are_never_retried() {
            let observer = Observer::new();
            observer.record(KNOWN_CODES[0], false, 42, 123, 456, "unix");
            for mode in [0, 1, 2] {
                let mut output = OneWrite { calls: 0, mode };
                write_report(&mut output, &observer.snapshot().unwrap());
                assert_eq!(output.calls, 1);
            }
        }

        #[test]
        fn additional_observation_sets_loss_without_replacing_first() {
            let observer = Observer::new();
            observer.record(KNOWN_CODES[0], false, 42, 123, 456, "unix");
            observer.record(KNOWN_CODES[1], true, 43, 124, 457, "loopback");
            let report = observer.snapshot().unwrap();
            assert_eq!(report.known_code, KNOWN_CODES[0]);
            assert!(!report.retryable_teardown);
            assert!(report.additional_observation_lost);
            assert_eq!(report.retained_observations, 1);
            assert_eq!(
                (
                    report.generation,
                    report.process_id,
                    report.owner_process_id,
                    report.transport
                ),
                (42, 123, 456, "unix")
            );
        }
    }
}

#[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
pub(crate) use enabled::{emit, record};

#[cfg(all(test, not(all(feature = "diagnostic-phases", target_os = "macos"))))]
mod macro_tests {
    #[test]
    fn default_macro_erases_error_and_state_expressions() {
        let result: Result<(), String> =
            crate::observe_native_live_failure!(unknown_error(), unknown_state());
        assert_eq!(
            result,
            Err("native_resident_live_request_failed".to_owned())
        );
    }
}

#[cfg(all(test, feature = "diagnostic-phases", target_os = "macos"))]
mod feature_macro_tests {
    #[test]
    fn original_error_and_state_expressions_are_observed_once_without_mutation() {
        let error = crate::resident_client::ResidentClientError {
            code: "native_client_frame_read_failed".to_owned(),
            retryable_teardown: false,
        };
        let state = crate::resident_state::ResidentState {
            schema: "fixture".to_owned(),
            generation: 7,
            process_id: 8,
            process_start_marker: "private".to_owned(),
            owner_process_id: 9,
            owner_process_start_marker: "private".to_owned(),
            runtime_sha256: "private".to_owned(),
            transport: "unix".to_owned(),
            endpoint: "private".to_owned(),
            token_hex: "private".to_owned(),
            created_ms: 0,
            state_mac: "private".to_owned(),
        };
        let calls = std::cell::Cell::new(0);
        let observe_error = || {
            calls.set(calls.get() + 1);
            &error
        };
        let observe_state = || {
            calls.set(calls.get() + 1);
            &state
        };
        let result: Result<(), String> =
            crate::observe_native_live_failure!(observe_error(), observe_state());
        assert_eq!(calls.get(), 2);
        assert_eq!(
            result,
            Err("native_resident_live_request_failed".to_owned())
        );
        assert_eq!(error.code, "native_client_frame_read_failed");
        assert_eq!(state.generation, 7);
        assert_eq!(state.token_hex, "private");
    }
}
