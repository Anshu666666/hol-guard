//! Diagnostic-only observations of the parent Windows startup request.
//! Disabled macros preserve original expressions and erase diagnostic inputs.

#[cfg(not(all(feature = "diagnostic-phases", windows)))]
#[macro_export]
macro_rules! windows_startup_begin { ($($unused:tt)*) => {}; }
#[cfg(all(feature = "diagnostic-phases", windows))]
#[macro_export]
macro_rules! windows_startup_begin {
    ($started:expr, $deadline:expr) => {
        $crate::native_windows_startup_observation::enabled::begin($started, $deadline)
    };
}

#[cfg(not(all(feature = "diagnostic-phases", windows)))]
#[macro_export]
macro_rules! windows_startup_call { ($stage:ident, $call:expr) => { $call }; }
#[cfg(all(feature = "diagnostic-phases", windows))]
#[macro_export]
macro_rules! windows_startup_call {
    ($stage:ident, $call:expr) => {{
        use $crate::native_windows_startup_observation::enabled as observation;
        observation::start(observation::Stage::$stage);
        let result = $call;
        observation::end(observation::Stage::$stage, result.as_ref().err().map(|error| error.as_str()));
        result
    }};
}

#[cfg(not(all(feature = "diagnostic-phases", windows)))]
#[macro_export]
macro_rules! windows_startup_exchange { ($call:expr) => { $call }; }
#[cfg(all(feature = "diagnostic-phases", windows))]
#[macro_export]
macro_rules! windows_startup_exchange {
    ($call:expr) => {{
        use $crate::native_windows_startup_observation::enabled as observation;
        observation::start(observation::Stage::Exchange);
        let result = $call;
        observation::end(observation::Stage::Exchange, result.as_ref().err().map(|error| error.code.as_str()));
        result
    }};
}

#[cfg(not(all(feature = "diagnostic-phases", windows)))]
#[macro_export]
macro_rules! windows_startup_event { ($($unused:tt)*) => {}; }
#[cfg(all(feature = "diagnostic-phases", windows))]
#[macro_export]
macro_rules! windows_startup_event {
    ($event:ident, $count:expr) => {
        $crate::native_windows_startup_observation::enabled::event(
            $crate::native_windows_startup_observation::enabled::Event::$event, $count)
    };
}

#[cfg(not(all(feature = "diagnostic-phases", windows)))]
#[macro_export]
macro_rules! windows_startup_retry { ($($unused:tt)*) => {}; }
#[cfg(all(feature = "diagnostic-phases", windows))]
#[macro_export]
macro_rules! windows_startup_retry {
    ($error:expr) => {
        $crate::native_windows_startup_observation::enabled::retry(&$error.code, $error.retryable_teardown)
    };
}

#[cfg(not(all(feature = "diagnostic-phases", windows)))]
#[macro_export]
macro_rules! windows_startup_emit { ($($unused:tt)*) => {}; }
#[cfg(all(feature = "diagnostic-phases", windows))]
#[macro_export]
macro_rules! windows_startup_emit {
    ($error:expr) => {
        $crate::native_windows_startup_observation::enabled::emit($error)
    };
}

#[cfg(all(feature = "diagnostic-phases", windows))]
#[path = "native_windows_startup_observation_enabled.rs"]
pub(crate) mod enabled;

#[cfg(test)]
mod tests {
    #[test]
    fn original_success_and_error_calls_are_forwarded_once() {
        let calls = std::cell::Cell::new(0);
        let ok = crate::windows_startup_call!(Lease, {
            calls.set(calls.get() + 1);
            Ok::<_, String>(vec![1, 2, 3])
        });
        assert_eq!(ok, Ok(vec![1, 2, 3]));
        let error = crate::windows_startup_call!(Lease, {
            calls.set(calls.get() + 1);
            Err::<(), _>("original fatal error".to_owned())
        });
        assert_eq!(error, Err("original fatal error".to_owned()));
        assert_eq!(calls.get(), 2);
    }

    #[test]
    fn exact_duplicate_key_payload_keeps_the_original_default_budget() {
        let bytes = br#"{"schema":"guard-hook-envelope.v2","schema":"other"}"#;
        assert_eq!(bytes.len(), 52);
        assert_eq!(crate::managed_resident::client_timeout(bytes), std::time::Duration::from_millis(750));
    }

    #[cfg(not(all(feature = "diagnostic-phases", windows)))]
    #[test]
    fn disabled_diagnostic_arguments_are_not_evaluated() {
        crate::windows_startup_begin!(an_undefined_start, an_undefined_deadline);
        crate::windows_startup_event!(Undefined, an_undefined_count);
        crate::windows_startup_retry!(an_undefined_error);
        crate::windows_startup_emit!(an_undefined_error);
        let result = crate::windows_startup_call!(Undefined, Ok::<_, String>(7));
        assert_eq!(result, Ok(7));
    }
}
