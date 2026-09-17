//! Opt-in fixed-schema client diagnostics. Default builds have no timers/state.
#[derive(Clone, Copy)]
pub(crate) enum Phase {
    RuntimeIdentity,
    Discovery,
    PeerValidation,
    Connect,
    Authentication,
    RequestWrite,
    ResponseRead,
}

#[inline(always)]
pub(crate) fn measure<T, E>(phase: Phase, call: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    #[cfg(feature = "diagnostic-native-client")]
    let started = enabled::start();
    #[cfg(not(feature = "diagnostic-native-client"))]
    let _ = phase;
    let result = call();
    #[cfg(feature = "diagnostic-native-client")]
    enabled::finish(phase, started, result.is_ok());
    result
}

#[inline(always)]
pub(crate) fn socket_opened() {
    #[cfg(feature = "diagnostic-native-client")]
    enabled::update(|state| {
        state.opened = state.opened.checked_add(1).unwrap_or_else(|| {
            state.overflow = true;
            u64::MAX
        });
    });
}

#[inline(always)]
pub(crate) fn socket_count_unknown() {
    #[cfg(feature = "diagnostic-native-client")]
    enabled::update(|state| state.socket_count_complete = false);
}

#[inline(always)]
pub(crate) fn request_digest(digest: &[u8]) {
    #[cfg(feature = "diagnostic-native-client")]
    enabled::update(|state| state.digest = digest.try_into().ok());
    #[cfg(not(feature = "diagnostic-native-client"))]
    let _ = digest;
}

#[inline(always)]
pub(crate) fn request<T>(call: impl FnOnce() -> T) -> T {
    #[cfg(feature = "diagnostic-native-client")]
    let scope = enabled::Request::begin();
    let result = call();
    #[cfg(feature = "diagnostic-native-client")]
    scope.finish();
    result
}

#[cfg(feature = "diagnostic-native-client")]
pub(crate) use enabled::enable;

#[cfg(feature = "diagnostic-native-client")]
mod enabled {
    use super::Phase;
    use serde_json::{json, Value};
    use std::cell::{Cell, RefCell};
    use std::io::Write;
    use std::time::Instant;

    const MAX_RECORDS: u64 = 1024;
    const PHASES: [&str; 7] = [
        "runtime_identity",
        "discovery",
        "peer_validation",
        "connect",
        "authentication",
        "request_write",
        "response_read",
    ];
    thread_local! {
        static ENABLED: Cell<bool> = const { Cell::new(false) };
        static SEQUENCE: Cell<u64> = const { Cell::new(0) };
        static STATE: RefCell<Option<State>> = const { RefCell::new(None) };
    }

    #[derive(Clone, Copy, Default)]
    struct Span {
        calls: u64,
        succeeded: u64,
        nanoseconds: u64,
    }

    pub(super) struct State {
        spans: [Span; 7],
        pub(super) opened: u64,
        pub(super) socket_count_complete: bool,
        pub(super) digest: Option<[u8; 32]>,
        pub(super) overflow: bool,
    }

    impl Default for State {
        fn default() -> Self {
            Self {
                spans: [Span::default(); 7],
                opened: 0,
                socket_count_complete: true,
                digest: None,
                overflow: false,
            }
        }
    }

    pub(crate) fn enable() {
        ENABLED.set(true);
    }

    pub(super) fn update(update: impl FnOnce(&mut State)) {
        STATE.with_borrow_mut(|state| {
            if let Some(state) = state {
                update(state);
            }
        });
    }

    pub(super) fn start() -> Option<Instant> {
        STATE.with_borrow(|state| state.as_ref().map(|_| Instant::now()))
    }

    pub(super) fn finish(phase: Phase, started: Option<Instant>, succeeded: bool) {
        let Some(started) = started else {
            return;
        };
        let nanos = u64::try_from(started.elapsed().as_nanos());
        update(|state| {
            let span = &mut state.spans[phase as usize];
            let next = nanos.ok().and_then(|n| span.nanoseconds.checked_add(n));
            if let Some(next) = next {
                span.nanoseconds = next;
            } else {
                state.overflow = true;
            }
            span.calls = span.calls.checked_add(1).unwrap_or_else(|| {
                state.overflow = true;
                u64::MAX
            });
            span.succeeded = span
                .succeeded
                .checked_add(u64::from(succeeded))
                .unwrap_or_else(|| {
                    state.overflow = true;
                    u64::MAX
                });
            if matches!(phase, Phase::Connect) && !succeeded {
                state.socket_count_complete = false;
            }
        });
    }

    pub(super) struct Request(Option<(u64, Instant)>);

    impl Request {
        pub(super) fn begin() -> Self {
            if !ENABLED.get() {
                return Self(None);
            }
            let sequence = SEQUENCE.get().saturating_add(1);
            SEQUENCE.set(sequence);
            if sequence > MAX_RECORDS {
                return Self(None);
            }
            STATE.set(Some(State::default()));
            Self(Some((sequence, Instant::now())))
        }

        pub(super) fn finish(mut self) {
            let Some((sequence, started)) = self.0.take() else {
                return;
            };
            let state = STATE.take().expect("diagnostic request state");
            let value = record(sequence, started.elapsed().as_nanos(), state);
            // Only this explicit diagnostic command emits these fixed records.
            // A lost record is incomplete evidence, never a transport retry.
            if let Ok(mut encoded) = serde_json::to_vec(&value) {
                if encoded.len() < 4096 {
                    encoded.push(b'\n');
                    let _ = std::io::stderr().lock().write_all(&encoded);
                }
            }
        }
    }

    impl Drop for Request {
        fn drop(&mut self) {
            if self.0.is_some() {
                STATE.set(None);
            }
        }
    }

    fn record(sequence: u64, total: u128, state: State) -> Value {
        let spans: serde_json::Map<String, Value> = PHASES
            .into_iter()
            .zip(state.spans)
            .map(|(name, span)| {
                (
                    name.to_owned(),
                    json!({
                        "calls": span.calls, "succeeded": span.succeeded,
                        "nanoseconds": if span.calls == 0 { None } else { Some(span.nanoseconds) },
                    }),
                )
            })
            .collect();
        let total = u64::try_from(total).ok();
        json!({
            "schema": "hol-guard.native-client-profile.v1",
            "sequence": sequence, "request_sha256": state.digest.map(hex::encode),
            "helper_request_nanoseconds": total, "phases": spans,
            "socket_opened": state.opened, "socket_count_complete": state.socket_count_complete,
            "overflow": state.overflow || total.is_none(),
            "span_semantics": "inclusive_do_not_sum", "headline_timing_eligible": false,
        })
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn fixed_record_preserves_missing_phases_and_accounting_uncertainty() {
            let mut state = State {
                socket_count_complete: false,
                opened: 2,
                ..State::default()
            };
            state.spans[3] = Span {
                calls: 3,
                succeeded: 2,
                nanoseconds: 17,
            };
            let record = record(1, 19, state);
            assert_eq!(record["socket_opened"], 2);
            assert_eq!(record["socket_count_complete"], false);
            assert_eq!(record["phases"]["connect"]["calls"], 3);
            assert_eq!(record["phases"]["discovery"]["nanoseconds"], Value::Null);
            assert_eq!(record["request_sha256"], Value::Null);
            assert!(serde_json::to_vec(&record).unwrap().len() < 4096);
        }

        #[test]
        fn disabled_measurement_and_original_errors_are_unchanged() {
            ENABLED.set(false);
            STATE.set(None);
            let error = Box::new(41);
            let address = &*error as *const i32;
            let result: Result<(), Box<i32>> = super::super::measure(Phase::Connect, || Err(error));
            assert_eq!(&*result.unwrap_err() as *const i32, address);
            assert!(STATE.with_borrow(|state| state.is_none()));
        }

        #[test]
        fn failed_connect_and_counter_overflow_remain_incomplete() {
            STATE.set(Some(State {
                opened: u64::MAX,
                ..State::default()
            }));
            super::super::socket_opened();
            let result = super::super::measure(Phase::Connect, || Err::<(), _>(7));
            assert_eq!(result, Err(7));
            let state = STATE.take().unwrap();
            assert!(state.overflow);
            assert!(!state.socket_count_complete);
        }

        #[test]
        fn request_cap_and_unwinding_clear_state() {
            ENABLED.set(true);
            SEQUENCE.set(MAX_RECORDS);
            let capped = Request::begin();
            assert!(capped.0.is_none());
            assert!(STATE.with_borrow(|state| state.is_none()));
            SEQUENCE.set(0);
            let result = std::panic::catch_unwind(|| {
                let _request = Request::begin();
                panic!("synthetic");
            });
            assert!(result.is_err());
            assert!(STATE.with_borrow(|state| state.is_none()));
            ENABLED.set(false);
        }

        #[test]
        fn active_measurement_counts_calls_errors_and_existing_digest() {
            STATE.set(Some(State::default()));
            assert_eq!(
                super::super::measure(Phase::Authentication, || Err::<(), _>(7)),
                Err(7)
            );
            super::super::socket_opened();
            super::super::request_digest(&[3; 32]);
            let state = STATE.take().unwrap();
            assert_eq!(state.spans[4].calls, 1);
            assert_eq!(state.spans[4].succeeded, 0);
            assert_eq!(state.opened, 1);
            assert_eq!(state.digest, Some([3; 32]));
        }
    }
}
