//! Fixed, first-only observations at the actual live-exchange collapse boundary.
//! No free-form code, request, path, or exception text is retained or exported.
//! One best-effort stderr write follows the original public CLI error line.

#[cfg(not(all(feature = "diagnostic-phases", target_os = "linux")))]
#[macro_export]
macro_rules! observe_native_live_failure {
    ($error:expr) => {
        Err("native_resident_live_request_failed".to_owned())
    };
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
#[macro_export]
macro_rules! observe_native_live_failure {
    ($error:expr) => {{
        $crate::native_client_failure_observation::record(&$error);
        Err("native_resident_live_request_failed".to_owned())
    }};
}

#[cfg(not(all(feature = "diagnostic-phases", target_os = "linux")))]
#[macro_export]
macro_rules! emit_native_live_failure {
    () => {};
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
#[macro_export]
macro_rules! emit_native_live_failure {
    () => {
        $crate::native_client_failure_observation::emit();
    };
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
mod enabled {
    use serde::Serialize;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};

    const MAX_CODE_BYTES: usize = 128;
    const MAX_RECORD_BYTES: usize = 768;
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
    static OBSERVER: Observer = Observer::new();

    struct Observer {
        first: AtomicU16,
        additional_observation_lost: AtomicBool,
    }

    impl Observer {
        const fn new() -> Self {
            Self {
                first: AtomicU16::new(0),
                additional_observation_lost: AtomicBool::new(false),
            }
        }

        fn record(&self, code: &str, retryable_teardown: bool) {
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
                .first
                .compare_exchange(0, value, Ordering::Relaxed, Ordering::Relaxed)
                .is_err()
            {
                self.additional_observation_lost
                    .store(true, Ordering::Relaxed);
            }
        }

        fn snapshot(&self) -> Option<Report> {
            let value = self.first.load(Ordering::Relaxed);
            if value == 0 {
                return None;
            }
            let index = usize::from((value >> 1) - 1);
            Some(Report {
                schema: "hol-guard-native-live-failure.v1",
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
    }

    pub(crate) fn record(error: &crate::resident_client::ResidentClientError) {
        OBSERVER.record(&error.code, error.retryable_teardown);
    }

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
        let mut bytes = b"HG_LIVE_FAILURE_V1 ".to_vec();
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
        fn every_fixed_code_and_retryable_bit_round_trips() {
            assert!(KNOWN_CODES.windows(2).all(|pair| pair[0] < pair[1]));
            assert!(KNOWN_CODES.len() < (u16::MAX as usize >> 1));
            for code in KNOWN_CODES {
                assert!(code.len() <= MAX_CODE_BYTES);
                for retryable in [false, true] {
                    let observer = Observer::new();
                    observer.record(code, retryable);
                    let report = observer.snapshot().unwrap();
                    assert_eq!(report.known_code, code);
                    assert_eq!(report.retryable_teardown, retryable);
                    assert!(!report.additional_observation_lost);
                    assert!(serde_json::to_vec(&report).unwrap().len() <= MAX_RECORD_BYTES);
                }
            }
        }

        #[test]
        fn unknown_and_oversized_codes_do_not_export_input() {
            for code in ["private sentinel request path".to_owned(), "x".repeat(129)] {
                let observer = Observer::new();
                observer.record(&code, false);
                let report = observer.snapshot().unwrap();
                assert_eq!(report.known_code, "unknown");
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
                assert!(bytes.starts_with(b"HG_LIVE_FAILURE_V1 "));
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
            observer.record(KNOWN_CODES[0], false);
            for mode in [0, 1, 2] {
                let mut output = OneWrite { calls: 0, mode };
                write_report(&mut output, &observer.snapshot().unwrap());
                assert_eq!(output.calls, 1);
            }
        }

        #[test]
        fn additional_observation_sets_loss_without_replacing_first() {
            let observer = Observer::new();
            observer.record(KNOWN_CODES[0], false);
            observer.record(KNOWN_CODES[1], true);
            let report = observer.snapshot().unwrap();
            assert_eq!(report.known_code, KNOWN_CODES[0]);
            assert!(!report.retryable_teardown);
            assert!(report.additional_observation_lost);
            assert_eq!(report.retained_observations, 1);
        }
    }
}

#[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
pub(crate) use enabled::{emit, record};

#[cfg(test)]
mod macro_tests {
    #[test]
    fn macro_preserves_the_original_public_error_and_diagnostic_input() {
        let _error = crate::resident_client::ResidentClientError {
            code: "native_client_frame_read_failed".to_owned(),
            retryable_teardown: false,
        };
        let result: Result<(), String> = crate::observe_native_live_failure!(_error);
        assert_eq!(
            result,
            Err("native_resident_live_request_failed".to_owned())
        );
        assert_eq!(_error.code, "native_client_frame_read_failed");
        assert!(!_error.retryable_teardown);
    }

    #[cfg(all(feature = "diagnostic-phases", target_os = "linux"))]
    #[test]
    fn diagnostic_input_expression_is_evaluated_once() {
        let calls = std::cell::Cell::new(0);
        let result: Result<(), String> = crate::observe_native_live_failure!({
            calls.set(calls.get() + 1);
            crate::resident_client::ResidentClientError {
                code: "native_client_frame_read_failed".to_owned(),
                retryable_teardown: false,
            }
        });
        assert_eq!(calls.get(), 1);
        assert_eq!(
            result,
            Err("native_resident_live_request_failed".to_owned())
        );
    }

    #[cfg(not(all(feature = "diagnostic-phases", target_os = "linux")))]
    #[test]
    fn default_macro_erases_the_diagnostic_expression() {
        let result: Result<(), String> =
            crate::observe_native_live_failure!(no_such_expression_must_be_erased());
        assert_eq!(
            result,
            Err("native_resident_live_request_failed".to_owned())
        );
    }
}
