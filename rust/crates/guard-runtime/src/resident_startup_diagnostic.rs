//! Fixed observations for the explicit diagnostic persistent-client command.
//!
//! Default-build macros expand to the original expression or nothing. The
//! diagnostic stream uses the ordinary managed path, bytes and deadline, then
//! writes bounded stderr records after the original stdout frames. No native
//! request, retry, endpoint, token, process identity or payload is added.

#[cfg(not(feature = "diagnostic-phases"))]
#[macro_export]
macro_rules! observe_resident_startup {
    ($phase:ident, $operation:expr) => {
        $operation
    };
}

#[cfg(feature = "diagnostic-phases")]
#[macro_export]
macro_rules! observe_resident_startup {
    ($phase:ident, $operation:expr) => {
        $crate::resident_startup_diagnostic::observe(
            $crate::resident_startup_diagnostic::Phase::$phase,
            || $operation,
        )
    };
}

#[cfg(not(feature = "diagnostic-phases"))]
#[macro_export]
macro_rules! record_resident_startup_io {
    ($error:expr) => {};
}

#[cfg(feature = "diagnostic-phases")]
#[macro_export]
macro_rules! record_resident_startup_io {
    ($error:expr) => {
        $crate::resident_startup_diagnostic::record_io($error)
    };
}

#[cfg(not(feature = "diagnostic-phases"))]
#[macro_export]
macro_rules! record_resident_startup_fatal {
    ($error:expr) => {};
}

#[cfg(feature = "diagnostic-phases")]
#[macro_export]
macro_rules! record_resident_startup_fatal {
    ($error:expr) => {
        $crate::resident_startup_diagnostic::record_fatal($error)
    };
}

#[cfg(not(feature = "diagnostic-phases"))]
#[macro_export]
macro_rules! observe_resident_startup_io {
    ($operation:ident, $expression:expr) => {
        $expression
    };
}

#[cfg(not(feature = "diagnostic-phases"))]
#[macro_export]
macro_rules! observe_resident_stream_request {
    ($enabled:expr, $sequence:expr, $payload:expr, $started:expr, $deadline:expr, $report:ident, $operation:expr) => {
        $operation
    };
}

#[cfg(feature = "diagnostic-phases")]
#[macro_export]
macro_rules! observe_resident_stream_request {
    ($enabled:expr, $sequence:expr, $payload:expr, $started:expr, $deadline:expr, $report:ident, $operation:expr) => {
        if $enabled && $sequence < $crate::resident_startup_diagnostic::MAX_FRAMES {
            let (result, observation) = $crate::resident_startup_diagnostic::capture_at(
                $payload,
                $started,
                $deadline,
                || $operation,
            );
            $report = Some(observation);
            result
        } else {
            $operation
        }
    };
}

#[cfg(feature = "diagnostic-phases")]
#[macro_export]
macro_rules! observe_resident_startup_io {
    ($operation:ident, $expression:expr) => {
        $crate::resident_startup_diagnostic::observe_io(
            $crate::resident_startup_diagnostic::IoOperation::$operation,
            || $expression,
        )
    };
}

#[cfg(feature = "diagnostic-phases")]
mod enabled {
    use crate::resident_client::ResidentClientError;
    use serde::Serialize;
    use sha2::{Digest, Sha256};
    use std::cell::RefCell;
    use std::io::{self, Write};
    use std::time::{Duration, Instant};

    pub(super) const MAX_EVENTS: usize = 16;
    pub(super) const MAX_REPORT_BYTES: usize = 16_384;
    pub(crate) const MAX_FRAMES: usize = 128;
    const MAX_DURATION_US: u64 = 60_000_000;

    thread_local! {
        static ACTIVE: RefCell<Option<Collector>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum Phase {
        Connect,
        Authenticate,
        RequestWriteFlush,
        CommittedResponseRead,
    }

    #[derive(Clone, Copy, Serialize)]
    #[serde(rename_all = "snake_case")]
    pub(crate) enum IoOperation {
        Unspecified,
        ReadTimeoutConfiguration,
        StreamRead,
        WriteTimeoutConfiguration,
        FlushTimeoutConfiguration,
        StreamWrite,
        StreamFlush,
        BufferedAfterSetterError,
    }

    #[derive(Clone, Copy, Serialize)]
    struct IoFailure {
        operation: IoOperation,
        kind: &'static str,
        os_code: Option<i32>,
    }

    #[derive(Serialize)]
    struct Event {
        phase: Phase,
        started_us: u64,
        duration_us: u64,
        succeeded: bool,
        error_code: Option<&'static str>,
        retryable_teardown: bool,
        io_failure: Option<IoFailure>,
    }

    #[derive(Serialize)]
    pub(crate) struct Report {
        schema: &'static str,
        scope: &'static str,
        operation_succeeded: bool,
        operation_error: Option<&'static str>,
        operation_elapsed_us: u64,
        deadline_budget_ms: u64,
        payload_bytes: usize,
        payload_sha256: String,
        events: Vec<Event>,
        maximum_events: usize,
        dropped_events: usize,
        original_fatal_code: Option<&'static str>,
        unassigned_io_failure: Option<IoFailure>,
        detail_incomplete: bool,
        original_operation_result_preserved: bool,
        headline_timing_eligible: bool,
        qualification: bool,
        retries_added: bool,
        deadlines_changed: bool,
    }

    struct Collector {
        started: Instant,
        events: Vec<Event>,
        dropped: usize,
        incomplete: bool,
        io_failure: Option<IoFailure>,
        fatal_code: Option<&'static str>,
    }

    fn fixed_code(code: &str) -> &'static str {
        guard_contracts::NATIVE_RESIDENT_LIFECYCLE_ERROR_CODES
            .iter()
            .chain(guard_contracts::NATIVE_APPROVAL_ERROR_CODES.iter())
            .chain(guard_contracts::NATIVE_COMMAND_CONTROL_ERROR_CODES.iter())
            .chain(["native_resident_private_root_missing"].iter())
            .copied()
            .find(|candidate| *candidate == code)
            .unwrap_or("unregistered_error")
    }

    fn micros(duration: Duration) -> u64 {
        duration.as_micros().min(u128::from(MAX_DURATION_US)) as u64
    }

    fn io_kind(kind: io::ErrorKind) -> &'static str {
        match kind {
            io::ErrorKind::TimedOut => "timed_out",
            io::ErrorKind::WouldBlock => "would_block",
            io::ErrorKind::Interrupted => "interrupted",
            io::ErrorKind::UnexpectedEof => "unexpected_eof",
            io::ErrorKind::BrokenPipe => "broken_pipe",
            io::ErrorKind::ConnectionReset => "connection_reset",
            io::ErrorKind::ConnectionAborted => "connection_aborted",
            io::ErrorKind::ConnectionRefused => "connection_refused",
            io::ErrorKind::PermissionDenied => "permission_denied",
            io::ErrorKind::InvalidInput => "invalid_input",
            io::ErrorKind::Unsupported => "unsupported",
            _ => "other",
        }
    }

    pub(crate) fn record_io(error: &io::Error) {
        ACTIVE.with(|active| {
            if let Ok(mut active) = active.try_borrow_mut() {
                if let Some(collector) = active.as_mut() {
                    if collector.io_failure.is_some_and(|failure| {
                        failure.kind == io_kind(error.kind())
                            && failure.os_code == error.raw_os_error()
                    }) {
                        return;
                    }
                    collector.io_failure = Some(IoFailure {
                        operation: IoOperation::Unspecified,
                        kind: io_kind(error.kind()),
                        os_code: error.raw_os_error(),
                    });
                }
            }
        });
    }

    pub(crate) fn observe_io<T>(
        operation: IoOperation,
        expression: impl FnOnce() -> io::Result<T>,
    ) -> io::Result<T> {
        let result = expression();
        ACTIVE.with(|active| {
            if let Ok(mut active) = active.try_borrow_mut() {
                if let Some(collector) = active.as_mut() {
                    collector.io_failure = result.as_ref().err().map(|error| IoFailure {
                        operation,
                        kind: io_kind(error.kind()),
                        os_code: error.raw_os_error(),
                    });
                }
            }
        });
        result
    }

    pub(crate) fn record_fatal(error: &ResidentClientError) {
        ACTIVE.with(|active| {
            if let Ok(mut active) = active.try_borrow_mut() {
                if let Some(collector) = active.as_mut() {
                    // Preserve the first fatal code even if earlier retryable
                    // attempts exhausted the bounded phase event allowance.
                    collector.fatal_code.get_or_insert(fixed_code(&error.code));
                }
            }
        });
    }

    pub(crate) fn observe<T>(
        phase: Phase,
        operation: impl FnOnce() -> Result<T, ResidentClientError>,
    ) -> Result<T, ResidentClientError> {
        let started = ACTIVE.with(|active| {
            active.try_borrow_mut().ok().and_then(|mut active| {
                active.as_mut().map(|collector| {
                    collector.io_failure = None;
                    Instant::now()
                })
            })
        });
        let result = operation();
        if let Some(started) = started {
            ACTIVE.with(|active| {
                if let Ok(mut active) = active.try_borrow_mut() {
                    if let Some(collector) = active.as_mut() {
                        if collector.events.len() == MAX_EVENTS {
                            collector.dropped = collector.dropped.saturating_add(1);
                            return;
                        }
                        let duration = started.elapsed();
                        if duration.as_micros() > u128::from(MAX_DURATION_US) {
                            collector.incomplete = true;
                        }
                        collector.events.push(Event {
                            phase,
                            started_us: micros(started.duration_since(collector.started)),
                            duration_us: micros(duration),
                            succeeded: result.is_ok(),
                            error_code: result.as_ref().err().map(|error| fixed_code(&error.code)),
                            retryable_teardown: result
                                .as_ref()
                                .err()
                                .is_some_and(|error| error.retryable_teardown),
                            io_failure: collector.io_failure.take(),
                        });
                    }
                }
            });
        }
        result
    }

    #[cfg(test)]
    pub(super) fn capture(
        payload: &[u8],
        operation: impl FnOnce(Instant) -> Result<Vec<u8>, String>,
    ) -> (Result<Vec<u8>, String>, Report) {
        let started = Instant::now();
        let budget = crate::managed_resident::client_timeout(payload);
        capture_at(payload, started, started + budget, || {
            operation(started + budget)
        })
    }

    pub(crate) fn capture_at(
        payload: &[u8],
        started: Instant,
        deadline: Instant,
        operation: impl FnOnce() -> Result<Vec<u8>, String>,
    ) -> (Result<Vec<u8>, String>, Report) {
        let budget = deadline.saturating_duration_since(started);
        ACTIVE.with(|active| {
            *active.borrow_mut() = Some(Collector {
                started,
                events: Vec::with_capacity(MAX_EVENTS),
                dropped: 0,
                incomplete: false,
                io_failure: None,
                fatal_code: None,
            });
        });
        let result = operation();
        let elapsed = started.elapsed();
        let collector = ACTIVE
            .with(|active| active.borrow_mut().take())
            .expect("owned startup observation");
        let report = Report {
            schema: "hol-guard.resident-stream-request-diagnostic.v1",
            scope: "explicit_persistent_client_original_frame_operation",
            operation_succeeded: result.is_ok(),
            operation_error: result.as_ref().err().map(|code| fixed_code(code)),
            operation_elapsed_us: micros(elapsed),
            deadline_budget_ms: budget.as_millis() as u64,
            payload_bytes: payload.len(),
            // Hash only after the original stdout frame has been written.
            payload_sha256: String::new(),
            events: collector.events,
            maximum_events: MAX_EVENTS,
            dropped_events: collector.dropped,
            original_fatal_code: collector.fatal_code,
            unassigned_io_failure: collector.io_failure,
            detail_incomplete: collector.incomplete
                || collector.dropped > 0
                || elapsed.as_micros() > u128::from(MAX_DURATION_US),
            original_operation_result_preserved: true,
            headline_timing_eligible: false,
            qualification: false,
            retries_added: false,
            deadlines_changed: false,
        };
        (result, report)
    }

    #[cfg(test)]
    pub(super) fn export(report: &Report, output: &mut impl Write) {
        if let Ok(mut encoded) = serde_json::to_vec(report) {
            if encoded.len() < MAX_REPORT_BYTES {
                encoded.push(b'\n');
                let _ = output.write_all(&encoded);
            }
        }
    }

    pub(super) fn finish_frame_into(
        mut report: Option<Report>,
        sequence: usize,
        payload: &[u8],
        response: &[u8],
        frame_result: &Result<(), String>,
        output: &mut impl Write,
    ) {
        if sequence > MAX_FRAMES {
            return;
        }
        let value = if sequence == MAX_FRAMES {
            serde_json::json!({
                "schema": "hol-guard.resident-stream-diagnostic-limit.v1",
                "maximum_frames": MAX_FRAMES,
                "dropped_frame_reports": true,
            })
        } else {
            if let Some(report) = report.as_mut() {
                report.payload_sha256 =
                    crate::resident_state_encoding::hex_bytes(&Sha256::digest(payload));
            }
            serde_json::json!({
                "schema": "hol-guard.resident-stream-diagnostic-frame.v1",
                "frame_sequence": sequence,
                "maximum_frames": MAX_FRAMES,
                "response_bytes": response.len(),
                "response_sha256": crate::resident_state_encoding::hex_bytes(&Sha256::digest(response)),
                "stdout_frame_written": frame_result.is_ok(),
                "report": report,
            })
        };
        if let Ok(mut encoded) = serde_json::to_vec(&value) {
            if encoded.len() < MAX_REPORT_BYTES {
                encoded.push(b'\n');
                let _ = output.write_all(&encoded);
            }
        }
    }

    pub(crate) fn finish_frame(
        report: Option<Report>,
        sequence: usize,
        payload: &[u8],
        response: &[u8],
        frame_result: &Result<(), String>,
    ) {
        finish_frame_into(
            report,
            sequence,
            payload,
            response,
            frame_result,
            &mut io::stderr().lock(),
        );
    }
}

#[cfg(feature = "diagnostic-phases")]
pub(crate) use enabled::{
    capture_at, finish_frame, observe, observe_io, record_fatal, record_io, IoOperation, Phase,
    MAX_FRAMES,
};

#[cfg(test)]
#[path = "resident_startup_diagnostic_tests.rs"]
mod tests;
