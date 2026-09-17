//! Separately emitted resident spans; never part of a semantic response.

#[cfg(feature = "diagnostic-native-client")]
#[path = "native_client_profile_relay.rs"]
mod relay;
#[cfg(feature = "diagnostic-native-client")]
pub(crate) use relay::{drain, start_relay};

#[inline(always)]
pub(crate) fn command(normal: &'static str) -> &'static str {
    #[cfg(feature = "diagnostic-native-client")]
    if enabled::forwarding() {
        return match normal {
            "supervise-managed" => "supervise-managed-profile",
            "serve-managed" => "serve-managed-profile",
            _ => normal,
        };
    }
    normal
}

#[inline(always)]
pub(crate) fn accepts(command: &str, normal: &str) -> bool {
    if command == normal {
        return true;
    }
    #[cfg(feature = "diagnostic-native-client")]
    return matches!(
        (command, normal),
        ("supervise-managed-profile", "supervise-managed")
            | ("serve-managed-profile", "serve-managed")
    );
    #[cfg(not(feature = "diagnostic-native-client"))]
    false
}

#[inline(always)]
pub(crate) fn configure(command: &str, generation: u64) {
    #[cfg(feature = "diagnostic-native-client")]
    match command {
        "resident-client-stream-profile" | "supervise-managed-profile" => enabled::enable(0),
        "serve-managed-profile" => enabled::enable(generation),
        _ => (),
    }
    #[cfg(not(feature = "diagnostic-native-client"))]
    let _ = (command, generation);
}

#[inline(always)]
#[cfg(not(windows))]
pub(crate) fn stderr() -> std::process::Stdio {
    #[cfg(feature = "diagnostic-native-client")]
    if enabled::forwarding() {
        return std::process::Stdio::piped();
    }
    std::process::Stdio::null()
}

#[inline(always)]
pub(crate) fn edge<T, E>(call: impl FnOnce() -> Result<T, E>) -> Result<T, E> {
    #[cfg(feature = "diagnostic-native-client")]
    let started = enabled::edge_start();
    let result = call();
    #[cfg(feature = "diagnostic-native-client")]
    enabled::edge_finish(started, result.is_ok());
    result
}

#[cfg(all(windows, feature = "diagnostic-native-client"))]
pub(crate) use enabled::forwarding;
#[cfg(feature = "diagnostic-native-client")]
pub(crate) use enabled::{Outcome, Request};

#[cfg(feature = "diagnostic-native-client")]
mod enabled {
    use serde_json::{json, Value};
    use std::cell::RefCell;
    use std::io::Write;
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::time::Instant;

    static FORWARD: AtomicBool = AtomicBool::new(false);
    static GENERATION: AtomicU64 = AtomicU64::new(0);
    static SEQUENCE: AtomicU64 = AtomicU64::new(0);
    const MAX_RECORDS: u64 = 1024;
    thread_local! { static EDGE: RefCell<Option<Edge>> = const { RefCell::new(None) }; }

    #[derive(Default)]
    struct Edge {
        calls: u64,
        succeeded: u64,
        nanos: u64,
        overflow: bool,
    }

    pub(super) fn enable(generation: u64) {
        GENERATION.store(generation, Ordering::Release);
        FORWARD.store(true, Ordering::Release);
    }

    pub(crate) fn forwarding() -> bool {
        FORWARD.load(Ordering::Acquire)
    }

    pub(super) fn edge_start() -> Option<Instant> {
        EDGE.with_borrow(|state| state.as_ref().map(|_| Instant::now()))
    }

    pub(super) fn edge_finish(started: Option<Instant>, succeeded: bool) {
        let Some(started) = started else {
            return;
        };
        EDGE.with_borrow_mut(|state| {
            let Some(state) = state else {
                return;
            };
            let elapsed = u64::try_from(started.elapsed().as_nanos()).ok();
            let next = elapsed.and_then(|n| state.nanos.checked_add(n));
            match next {
                Some(n) => state.nanos = n,
                None => state.overflow = true,
            };
            match state.calls.checked_add(1) {
                Some(n) => state.calls = n,
                None => state.overflow = true,
            };
            match state.succeeded.checked_add(u64::from(succeeded)) {
                Some(n) => state.succeeded = n,
                None => state.overflow = true,
            };
        });
    }

    pub(crate) enum Outcome {
        Success,
        Rejected,
        Panicked,
    }
    pub(crate) struct Request(Option<(u64, u64, [u8; 32], Instant)>);
    pub(crate) struct Record(Option<Value>);

    impl Request {
        pub(crate) fn begin(digest: &[u8]) -> Self {
            let generation = GENERATION.load(Ordering::Acquire);
            if generation == 0 {
                return Self(None);
            }
            let Ok(digest) = digest.try_into() else {
                return Self(None);
            };
            let sequence = SEQUENCE
                .fetch_update(Ordering::AcqRel, Ordering::Acquire, |n| {
                    (n < MAX_RECORDS).then_some(n + 1)
                })
                .ok()
                .map(|n| n + 1);
            let Some(sequence) = sequence else {
                return Self(None);
            };
            EDGE.set(Some(Edge::default()));
            Self(Some((sequence, generation, digest, Instant::now())))
        }

        pub(crate) fn finish(mut self, outcome: Outcome) -> Record {
            let Some((sequence, generation, digest, started)) = self.0.take() else {
                return Record(None);
            };
            let elapsed = u64::try_from(started.elapsed().as_nanos()).ok();
            let edge = EDGE.take().unwrap_or(Edge {
                overflow: true,
                ..Edge::default()
            });
            Record(Some(json!({
                "schema": "hol-guard.native-resident-profile.v1",
                "sequence": sequence, "generation": generation,
                "process_id": std::process::id(), "request_sha256": hex::encode(digest),
                "dispatch_encode_nanoseconds": elapsed,
                "edge_evaluation": {"calls": edge.calls, "succeeded": edge.succeeded,
                    "nanoseconds": (edge.calls > 0).then_some(edge.nanos)},
                "outcome": match outcome { Outcome::Success => "success", Outcome::Rejected => "rejected", Outcome::Panicked => "panicked" },
                "overflow": edge.overflow || elapsed.is_none(),
                "span_semantics": "inclusive_do_not_sum", "headline_timing_eligible": false,
            })))
        }
    }

    impl Drop for Request {
        fn drop(&mut self) {
            if self.0.is_some() {
                EDGE.set(None);
            }
        }
    }

    impl Record {
        // Called only after the unchanged response-write attempt. Failure loses
        // evidence and must never change the response or trigger a retry.
        pub(crate) fn emit(self) {
            let Some(value) = self.0 else {
                return;
            };
            if let Ok(mut bytes) = serde_json::to_vec(&value) {
                if bytes.len() < 1024 {
                    bytes.push(b'\n');
                    let _ = std::io::stderr().lock().write_all(&bytes);
                }
            }
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        // One test owns all process-global profile configuration. Keeping the
        // matrix together prevents Cargo's parallel test runner racing enable,
        // normal-command, cap or reset assertions against one another.
        #[test]
        fn native_client_profile_resident_contract() {
            struct Reset;
            impl Drop for Reset {
                fn drop(&mut self) {
                    FORWARD.store(false, Ordering::Release);
                    GENERATION.store(0, Ordering::Release);
                    SEQUENCE.store(0, Ordering::Release);
                    EDGE.set(None);
                }
            }
            let _reset = Reset;
            assert!(!forwarding());
            assert_eq!(super::super::command("serve-managed"), "serve-managed");
            assert!(Request::begin(&[1; 32])
                .finish(Outcome::Success)
                .0
                .is_none());
            super::super::configure("serve-managed-profile", 7);
            assert_eq!(
                super::super::command("serve-managed"),
                "serve-managed-profile"
            );
            assert!(Request::begin(&[1; 31])
                .finish(Outcome::Success)
                .0
                .is_none());
            let profile = Request::begin(&[0xab; 32]);
            let mut calls = 0;
            let result: Result<&str, &str> = super::super::edge(|| {
                calls += 1;
                Ok("unchanged")
            });
            assert_eq!(result, Ok("unchanged"));
            assert_eq!(calls, 1);
            let record = profile.finish(Outcome::Success).0.unwrap();
            assert_eq!(record["request_sha256"], "ab".repeat(32));
            assert_eq!(record["generation"], 7);
            assert_eq!(record["edge_evaluation"]["calls"], 1);
            assert_eq!(record["edge_evaluation"]["succeeded"], 1);
            assert!(
                record["edge_evaluation"]["nanoseconds"].as_u64().unwrap()
                    <= record["dispatch_encode_nanoseconds"].as_u64().unwrap()
            );
            assert!(serde_json::to_vec(&record).unwrap().len() < 1024);

            let profile = Request::begin(&[2; 32]);
            let result: Result<(), &str> = super::super::edge(|| Err("same-error"));
            assert_eq!(result, Err("same-error"));
            let rejected = profile.finish(Outcome::Rejected).0.unwrap();
            assert_eq!(rejected["outcome"], "rejected");
            assert_eq!(rejected["edge_evaluation"]["succeeded"], 0);

            let profile = Request::begin(&[3; 32]);
            let failure = std::panic::catch_unwind(|| {
                super::super::edge(|| -> Result<(), ()> { panic!("fixture") })
            });
            assert!(failure.is_err());
            assert_eq!(
                profile.finish(Outcome::Panicked).0.unwrap()["outcome"],
                "panicked"
            );
            drop(Request::begin(&[4; 32]));
            assert!(EDGE.with_borrow(Option::is_none));
            let profile = Request::begin(&[5; 32]);
            EDGE.with_borrow_mut(|state| {
                state.as_mut().unwrap().calls = u64::MAX;
            });
            let _: Result<(), ()> = super::super::edge(|| Ok(()));
            assert_eq!(
                profile.finish(Outcome::Success).0.unwrap()["overflow"],
                true
            );

            let parent = Request::begin(&[6; 32]);
            let child = std::thread::spawn(|| {
                let profile = Request::begin(&[7; 32]);
                let _: Result<(), ()> = super::super::edge(|| Ok(()));
                profile.finish(Outcome::Success).0.unwrap()
            })
            .join()
            .unwrap();
            assert_eq!(child["edge_evaluation"]["calls"], 1);
            let untouched = parent.finish(Outcome::Success).0.unwrap();
            assert_eq!(untouched["edge_evaluation"]["calls"], 0);
            assert!(untouched["edge_evaluation"]["nanoseconds"].is_null());
            SEQUENCE.store(MAX_RECORDS, Ordering::Release);
            assert!(Request::begin(&[8; 32])
                .finish(Outcome::Success)
                .0
                .is_none());
        }
    }
}
