//! Preserve the caller's absolute deadline through managed return boundaries.
use std::path::Path;
use std::time::Instant;

use super::lease;

fn finish(result: Result<Vec<u8>, String>, deadline: Instant) -> Result<Vec<u8>, String> {
    if result.is_ok() && Instant::now() >= deadline {
        // The request may already be committed. A late success is fatal,
        // and an earlier error must retain its original classification.
        return Err("native_client_deadline_exceeded".to_owned());
    }
    result
}

pub(crate) fn client_request_at_deadline(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let client_lease = lease::acquire(state_base)?;
    let result = client_request_with_lease(state_base, payload, deadline, &client_lease);
    drop(client_lease);
    #[cfg(test)]
    super::deadline_tests::checkpoint(super::deadline_tests::Stage::LeaseCleanup);
    finish(result, deadline)
}

pub(super) fn client_request_with_lease(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
    client_lease: &lease::ClientLease,
) -> Result<Vec<u8>, String> {
    let result =
        super::client_request_with_lease_inner(state_base, payload, deadline, client_lease);
    #[cfg(test)]
    super::deadline_tests::checkpoint(super::deadline_tests::Stage::Returned);
    finish(result, deadline)
}
