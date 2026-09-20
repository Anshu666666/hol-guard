//! Feature-only, thread-local attribution for original client read failures.
//! No new I/O, clocks, retries, formatting of errors, or error replacement.

#[cfg(not(all(feature = "diagnostic-phases", target_os = "macos")))]
#[macro_export]
macro_rules! observe_native_read_phase {
    ($phase:ident, $operation:expr) => { $operation };
}
#[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
#[macro_export]
macro_rules! observe_native_read_phase {
    ($phase:ident, $operation:expr) => {
        $crate::native_client_read_observation::with_phase(
            $crate::native_client_read_observation::Phase::$phase, || $operation)
    };
}
#[cfg(not(all(feature = "diagnostic-phases", target_os = "macos")))]
#[macro_export]
macro_rules! observe_native_read_origin {
    ($origin:ident, $operation:expr) => { $operation };
}
#[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
#[macro_export]
macro_rules! observe_native_read_origin {
    ($origin:ident, $operation:expr) => {
        $crate::native_client_read_observation::observe_origin(
            $crate::native_client_read_observation::Origin::$origin, $operation)
    };
}
#[cfg(not(all(feature = "diagnostic-phases", target_os = "macos")))]
#[macro_export]
macro_rules! observe_native_read_value {
    ($action:ident $(, $value:expr)?) => {};
}
#[cfg(all(feature = "diagnostic-phases", target_os = "macos"))]
#[macro_export]
macro_rules! observe_native_read_value {
    ($action:ident $(, $value:expr)?) => {
        $crate::native_client_read_observation::$action($($value)?)
    };
}

#[cfg(any(test, all(feature = "diagnostic-phases", target_os = "macos")))]
mod enabled {
    use std::cell::Cell;
    use std::io;

    pub(crate) const PHASES: [&str; 4] = ["unobserved", "server_proof", "response_header", "response_body"];
    pub(crate) const ORIGINS: [&str; 9] = ["unobserved", "pre_read_deadline", "timeout_setter", "timeout_recovery", "underlying_read", "post_read_deadline", "underlying_eof", "read_exact", "timeout_recovery_eof"];
    pub(crate) const KINDS: [&str; 19] = ["unobserved", "not_found", "permission_denied", "connection_refused", "connection_reset", "connection_aborted", "not_connected", "addr_in_use", "addr_not_available", "broken_pipe", "already_exists", "would_block", "invalid_input", "invalid_data", "timed_out", "interrupted", "unexpected_eof", "other", "unlisted_kind"];

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    #[repr(u8)]
    pub(crate) enum Phase { ServerProof = 1, ResponseHeader = 2, ResponseBody = 3 }
    #[derive(Clone, Copy)]
    #[repr(u8)]
    pub(crate) enum Origin { PreReadDeadline = 1, TimeoutSetter = 2, TimeoutRecovery = 3, UnderlyingRead = 4, PostReadDeadline = 5 }
    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    pub(crate) struct Failure {
        pub(crate) phase: u8,
        pub(crate) origin: u8,
        pub(crate) kind: u8,
        pub(crate) raw_os_error: Option<i32>,
    }
    #[derive(Clone, Copy, Default)]
    struct Active { phase: u8, origin: u8, eof: bool, read_path: u8 }
    thread_local! {
        static ACTIVE: Cell<Active> = Cell::new(Active::default());
        static LAST_FAILURE: Cell<Option<Failure>> = const { Cell::new(None) };
    }
    struct Restore(Active);
    impl Drop for Restore {
        fn drop(&mut self) { ACTIVE.with(|active| active.set(self.0)); }
    }
    pub(crate) fn with_phase<T>(phase: Phase, operation: impl FnOnce() -> T) -> T {
        let previous = ACTIVE.with(|active| active.replace(Active { phase: phase as u8, ..Active::default() }));
        let _restore = Restore(previous);
        operation()
    }
    pub(crate) fn begin_read() {
        ACTIVE.with(|active| { let mut value = active.get(); value.origin = 0; value.eof = false; value.read_path = 0; active.set(value); });
    }
    pub(crate) fn observe_origin<T>(origin: Origin, result: io::Result<T>) -> io::Result<T> {
        ACTIVE.with(|active| {
            let mut value = active.get();
            if matches!(origin, Origin::UnderlyingRead | Origin::TimeoutRecovery) { value.read_path = origin as u8; }
            if result.is_err() { value.origin = origin as u8; }
            else if matches!(origin, Origin::TimeoutRecovery) { value.origin = 0; }
            active.set(value);
        });
        result
    }
    pub(crate) fn observe_read_result(result: &io::Result<usize>) {
        if matches!(result, Ok(0)) {
            ACTIVE.with(|active| { let mut value = active.get(); value.eof = true; active.set(value); });
        }
    }
    fn kind(error: &io::Error) -> u8 {
        use io::ErrorKind::*;
        match error.kind() {
            NotFound => 1, PermissionDenied => 2, ConnectionRefused => 3,
            ConnectionReset => 4, ConnectionAborted => 5, NotConnected => 6,
            AddrInUse => 7, AddrNotAvailable => 8, BrokenPipe => 9,
            AlreadyExists => 10, WouldBlock => 11, InvalidInput => 12,
            InvalidData => 13, TimedOut => 14, Interrupted => 15,
            UnexpectedEof => 16, Other => 17, _ => 18,
        }
    }
    pub(crate) fn observe_exact_result(result: &io::Result<()>) {
        let Err(error) = result else { return; };
        ACTIVE.with(|active| {
            let active = active.get();
            if active.phase == 0 { return; }
            let origin = if active.origin != 0 { active.origin } else if active.eof { if active.read_path == 3 { 8 } else { 6 } } else { 7 };
            LAST_FAILURE.with(|last| last.set(Some(Failure { phase: active.phase, origin, kind: kind(error), raw_os_error: error.raw_os_error() })));
        });
    }
    pub(crate) fn take() -> Option<Failure> { LAST_FAILURE.with(|last| last.take()) }

    #[cfg(test)]
    mod tests {
        use super::*;
        use std::sync::Arc;
        #[derive(Debug)]
        struct Witness(Arc<()>);
        impl std::fmt::Display for Witness {
            fn fmt(&self, _: &mut std::fmt::Formatter<'_>) -> std::fmt::Result { panic!("error text must not be inspected") }
        }
        impl std::error::Error for Witness {}

        #[test]
        fn forwarding_preserves_error_payload_and_operation_count() {
            let identity = Arc::new(());
            let calls = Cell::new(0);
            let error = with_phase(Phase::ServerProof, || {
                begin_read();
                calls.set(calls.get() + 1);
                let result: io::Result<()> = observe_origin(Origin::UnderlyingRead, Err(io::Error::new(io::ErrorKind::Other, Witness(Arc::clone(&identity)))));
                observe_exact_result(&result);
                result
            }).unwrap_err();
            assert!(Arc::ptr_eq(&error.get_ref().unwrap().downcast_ref::<Witness>().unwrap().0, &identity));
            assert_eq!(calls.get(), 1);
            assert_eq!(take(), Some(Failure { phase: 1, origin: 4, kind: 17, raw_os_error: None }));
        }
        #[test]
        fn original_raw_os_error_is_preserved_without_text() {
            let original = io::Error::from_raw_os_error(54);
            let expected_kind = kind(&original);
            with_phase(Phase::ResponseHeader, || {
                begin_read();
                let result: io::Result<()> = observe_origin(Origin::UnderlyingRead, Err(original));
                observe_exact_result(&result);
                assert_eq!(result.unwrap_err().raw_os_error(), Some(54));
            });
            assert_eq!(take(), Some(Failure { phase: 2, origin: 4, kind: expected_kind, raw_os_error: Some(54) }));
        }
        #[test]
        fn each_read_site_and_origin_remain_distinct() {
            for phase in [Phase::ServerProof, Phase::ResponseHeader, Phase::ResponseBody] {
                for origin in [Origin::PreReadDeadline, Origin::TimeoutSetter, Origin::TimeoutRecovery, Origin::UnderlyingRead, Origin::PostReadDeadline] {
                    with_phase(phase, || {
                        begin_read();
                        let result: io::Result<()> = observe_origin(origin, Err(io::ErrorKind::TimedOut.into()));
                        observe_exact_result(&result);
                    });
                    let f = take().unwrap(); assert_eq!((f.phase,f.origin,f.kind), (phase as u8,origin as u8,14));
                }
            }
        }
        #[test]
        fn interrupted_read_does_not_contaminate_later_eof() {
            with_phase(Phase::ResponseBody, || {
                begin_read();
                let _: io::Result<()> = observe_origin(Origin::UnderlyingRead, Err(io::ErrorKind::Interrupted.into()));
                begin_read();
                observe_read_result(&Ok(0));
                observe_exact_result(&Err(io::ErrorKind::UnexpectedEof.into()));
            });
            assert_eq!(take(),Some(Failure { phase:3,origin:6,kind:16,raw_os_error:None }));
        }
        #[test]
        fn successful_timeout_recovery_eof_does_not_keep_setter_error() {
            with_phase(Phase::ResponseBody, || {
                begin_read();
                let _: io::Result<()> = observe_origin(Origin::TimeoutSetter, Err(io::ErrorKind::InvalidInput.into()));
                let result = observe_origin(Origin::TimeoutRecovery, Ok(0));
                observe_read_result(&result);
                observe_exact_result(&Err(io::ErrorKind::UnexpectedEof.into()));
            });
            assert_eq!(take().unwrap().origin,8);
        }

        #[test]
        fn post_read_deadline_replacement_is_original_final_origin() {
            with_phase(Phase::ResponseBody, || {
                begin_read();
                let _: io::Result<()> = observe_origin(Origin::UnderlyingRead, Err(io::ErrorKind::ConnectionReset.into()));
                let result: io::Result<()> = observe_origin(Origin::PostReadDeadline, Err(io::ErrorKind::TimedOut.into()));
                observe_exact_result(&result);
            });
            assert_eq!(take().unwrap().origin,5);
        }
        #[test]
        fn success_and_unscoped_errors_do_not_create_a_record() {
            let _ = take();
            let value = with_phase(Phase::ServerProof, || { observe_exact_result(&Ok(())); 17 });
            assert_eq!(value,17);
            observe_exact_result(&Err(io::ErrorKind::UnexpectedEof.into()));
            assert!(take().is_none());
        }
        #[test]
        fn phase_restores_on_panic_and_threads_do_not_share_failures() {
            let _ = std::panic::catch_unwind(|| with_phase(Phase::ServerProof, || panic!("fixture")));
            observe_exact_result(&Err(io::ErrorKind::UnexpectedEof.into()));
            assert!(take().is_none());
            let thread = std::thread::spawn(|| {
                with_phase(Phase::ResponseHeader, || observe_exact_result(&Err(io::ErrorKind::UnexpectedEof.into())));
                take().unwrap()
            });
            assert_eq!(thread.join().unwrap().phase,2);
            assert!(take().is_none());
        }
    }
}

#[cfg(any(test, all(feature = "diagnostic-phases", target_os = "macos")))]
pub(crate) use enabled::*;


#[cfg(all(test, not(all(feature = "diagnostic-phases", target_os = "macos"))))]
mod macro_tests {
    #[test]
    fn default_read_macros_forward_once_and_erase_diagnostic_expressions() {
        let calls = std::cell::Cell::new(0);
        let result: std::io::Result<usize> = crate::observe_native_read_phase!(AbsentPhase, {
            calls.set(calls.get() + 1);
            Ok(7)
        });
        let result = crate::observe_native_read_origin!(AbsentOrigin, {
            calls.set(calls.get() + 1);
            result
        });
        crate::observe_native_read_value!(absent_diagnostic_action, absent_diagnostic_expression());
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.get(), 2);
    }
}

#[cfg(all(test, feature = "diagnostic-phases", target_os = "macos"))]
mod feature_macro_tests {
    #[test]
    fn feature_read_macros_forward_each_operation_once() {
        let calls = std::cell::Cell::new(0);
        let result: std::io::Result<usize> = crate::observe_native_read_phase!(ServerProof, {
            calls.set(calls.get() + 1);
            Ok(7)
        });
        let result = crate::observe_native_read_origin!(UnderlyingRead, {
            calls.set(calls.get() + 1);
            result
        });
        assert_eq!(result.unwrap(), 7);
        assert_eq!(calls.get(), 2);
    }
}
