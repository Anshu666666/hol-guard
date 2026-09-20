#[cfg(not(feature = "diagnostic-phases"))]
#[test]
fn default_build_erases_observation_and_retains_one_original_expression() {
    let mut calls = 0;
    let original = String::from("original-result");
    let address = original.as_ptr();
    let result = crate::observe_resident_startup!(Connect, {
        calls += 1;
        original
    });
    crate::record_resident_startup_io!(panic!("default diagnostic expression evaluated"));
    crate::record_resident_startup_fatal!(panic!("default diagnostic expression evaluated"));
    assert_eq!(calls, 1);
    assert_eq!(result.as_ptr(), address);
    let result = crate::observe_resident_startup_io!(StreamRead, result);
    assert_eq!(result.as_ptr(), address);
}

#[cfg(feature = "diagnostic-phases")]
mod enabled {
    use super::super::enabled::{capture, export, MAX_EVENTS, MAX_REPORT_BYTES};
    use super::super::{observe, observe_io, record_fatal, record_io, IoOperation, Phase};
    use crate::resident_client::ResidentClientError;
    use serde_json::Value;
    use std::fs;
    use std::io::{self, Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    const PAYLOAD: &[u8] = br#"{"operation":"health","request":{},"deadline_budget_ms":2000}"#;

    fn fixed_error() -> ResidentClientError {
        ResidentClientError {
            code: "native_client_frame_read_failed".to_owned(),
            retryable_teardown: false,
        }
    }

    #[test]
    fn observation_keeps_same_operation_result_and_original_payload_budget() {
        let original = Vec::from(b"original-response");
        let address = original.as_ptr();
        let mut calls = 0;
        let (result, report) = capture(PAYLOAD, |deadline| {
            calls += 1;
            assert!(deadline.saturating_duration_since(Instant::now()) <= Duration::from_secs(2));
            assert!(Instant::now() < deadline);
            observe(Phase::Connect, || Ok(original)).map_err(|error| error.code)
        });
        assert_eq!(calls, 1);
        let returned = result.unwrap();
        assert_eq!(returned.as_ptr(), address);
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["deadline_budget_ms"], 2000);
        assert_eq!(value["payload_bytes"], PAYLOAD.len());
        assert_eq!(value["events"].as_array().unwrap().len(), 1);
        assert_eq!(value["events"][0]["phase"], "connect");
        assert_eq!(value["events"][0]["succeeded"], true);
        assert_eq!(value["qualification"], false);
        assert_eq!(value["deadlines_changed"], false);
        assert_eq!(value["retries_added"], false);
    }

    #[test]
    fn bounded_events_preserve_first_fatal_code_and_never_export_raw_errors() {
        let original = String::from("private-secret-error");
        let address = original.as_ptr();
        let (result, report) = capture(PAYLOAD, |_| {
            for _ in 0..MAX_EVENTS + 3 {
                let _ = observe::<()>(Phase::Authenticate, || {
                    record_io(&io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "private-secret-path",
                    ));
                    Err(fixed_error())
                });
            }
            record_fatal(&fixed_error());
            record_fatal(&ResidentClientError {
                code: "private-other-error".to_owned(),
                retryable_teardown: false,
            });
            Err(original)
        });
        let returned = result.unwrap_err();
        assert_eq!(returned.as_ptr(), address);
        let mut output = Vec::new();
        export(&report, &mut output);
        assert!(output.len() <= MAX_REPORT_BYTES);
        let text = std::str::from_utf8(&output).unwrap();
        assert!(!text.contains("private-"));
        let value: Value = serde_json::from_slice(&output).unwrap();
        assert_eq!(value["events"].as_array().unwrap().len(), MAX_EVENTS);
        assert_eq!(value["dropped_events"], 3);
        assert_eq!(value["detail_incomplete"], true);
        assert_eq!(
            value["original_fatal_code"],
            "native_client_frame_read_failed"
        );
        assert_eq!(value["operation_error"], "unregistered_error");
        assert_eq!(value["events"][0]["io_failure"]["kind"], "unexpected_eof");
    }

    #[test]
    fn only_the_owned_thread_and_explicit_capture_are_observed() {
        assert_eq!(
            observe(Phase::Connect, || Ok::<_, ResidentClientError>(7)),
            Ok(7)
        );
        let (_, report) = capture(PAYLOAD, |_| {
            thread::spawn(|| {
                let _ = observe::<()>(Phase::Connect, || Err(fixed_error()));
                record_fatal(&fixed_error());
            })
            .join()
            .unwrap();
            Ok(Vec::new())
        });
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["events"], serde_json::json!([]));
        assert_eq!(value["original_fatal_code"], Value::Null);
    }

    #[test]
    fn failed_diagnostic_export_does_not_replace_the_operation_error() {
        struct FailedOutput;
        impl Write for FailedOutput {
            fn write(&mut self, _: &[u8]) -> io::Result<usize> {
                Err(io::Error::from(io::ErrorKind::BrokenPipe))
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let (result, report) = capture(PAYLOAD, |_| {
            Err("native_client_deadline_exceeded".to_owned())
        });
        export(&report, &mut FailedOutput);
        assert_eq!(result, Err("native_client_deadline_exceeded".to_owned()));
    }

    #[test]
    fn timeout_configuration_and_read_errors_remain_distinct_after_outer_mapping() {
        for (operation, expected) in [
            (
                IoOperation::ReadTimeoutConfiguration,
                "read_timeout_configuration",
            ),
            (IoOperation::StreamRead, "stream_read"),
        ] {
            let mut calls = 0;
            let (_, report) = capture(PAYLOAD, |_| {
                observe::<()>(Phase::CommittedResponseRead, || {
                    let result = observe_io::<()>(operation, || {
                        calls += 1;
                        Err(io::Error::from_raw_os_error(22))
                    });
                    assert_eq!(result.as_ref().unwrap_err().raw_os_error(), Some(22));
                    record_io(result.as_ref().unwrap_err());
                    Err(fixed_error())
                })
                .map(|()| Vec::new())
                .map_err(|error| error.code)
            });
            assert_eq!(calls, 1);
            let value = serde_json::to_value(report).unwrap();
            assert_eq!(value["schema"], "hol-guard.resident-startup-diagnostic.v2");
            let failure = &value["events"][0]["io_failure"];
            assert_eq!(failure["operation"], expected);
            assert_eq!(failure["kind"], "invalid_input");
            assert_eq!(failure["os_code"], 22);
        }
    }

    fn accept_bounded(listener: &TcpListener) -> TcpStream {
        listener.set_nonblocking(true).unwrap();
        let deadline = Instant::now() + Duration::from_secs(2);
        loop {
            match listener.accept() {
                Ok((stream, _)) => {
                    stream.set_nonblocking(false).unwrap();
                    stream
                        .set_read_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    stream
                        .set_write_timeout(Some(Duration::from_secs(1)))
                        .unwrap();
                    return stream;
                }
                Err(error)
                    if error.kind() == io::ErrorKind::WouldBlock && Instant::now() < deadline =>
                {
                    thread::sleep(Duration::from_millis(1));
                }
                Err(error) => panic!("bounded diagnostic fixture accept failed: {error}"),
            }
        }
    }

    #[test]
    fn actual_managed_authentication_failure_retains_leaf_phase_without_replay() {
        let home = std::env::temp_dir().join(format!(
            "hol-guard-startup-observation-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        crate::resident_state::ensure_private_directory(&home, true).unwrap();
        let digest = crate::resident_state::runtime_digest().unwrap();
        let scope = crate::resident_state::state_scope(&home, &digest).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        crate::resident_state::publish_state(
            &scope,
            1,
            std::process::id(),
            &digest,
            "loopback",
            listener.local_addr().unwrap().to_string(),
            &[19; crate::AUTH_TOKEN_BYTES],
        )
        .unwrap();
        let peer = thread::spawn(move || {
            let mut stream = accept_bounded(&listener);
            let mut nonce = [0; crate::AUTH_NONCE_BYTES];
            stream.read_exact(&mut nonce).unwrap();
            stream.write_all(&[0; crate::AUTH_PROOF_BYTES - 1]).unwrap();
        });
        let (result, report) = capture(PAYLOAD, |deadline| {
            crate::managed_resident::client_request_at_deadline(&home, PAYLOAD, deadline)
        });
        peer.join().unwrap();
        fs::remove_dir_all(home).unwrap();
        assert_eq!(
            result,
            Err("native_resident_live_request_failed".to_owned())
        );
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(
            value["original_fatal_code"],
            "native_client_frame_read_failed"
        );
        let events = value["events"].as_array().unwrap();
        assert_eq!(events.len(), 2);
        assert_eq!(events[0]["phase"], "connect");
        assert_eq!(events[0]["succeeded"], true);
        assert_eq!(events[1]["phase"], "authenticate");
        assert_eq!(events[1]["error_code"], "native_client_frame_read_failed");
        assert_eq!(events[1]["io_failure"]["kind"], "unexpected_eof");
        // read_exact synthesizes EOF after a successful zero-byte read;
        // do not label that as a failed underlying read syscall.
        assert_eq!(events[1]["io_failure"]["operation"], "unspecified");
        assert_eq!(events[1]["retryable_teardown"], false);
    }
}
