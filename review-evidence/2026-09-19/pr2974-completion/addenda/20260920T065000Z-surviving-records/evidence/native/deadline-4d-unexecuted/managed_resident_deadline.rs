//! Preserve a managed request's deadline across lease and return boundaries.
use std::path::Path;
use std::time::Instant;

use super::lease;

pub(crate) fn client_request_at_deadline(
    state_base: &Path,
    payload: &[u8],
    deadline: Instant,
) -> Result<Vec<u8>, String> {
    let client_lease = lease::acquire(state_base)?;
    let result = client_request_with_lease(state_base, payload, deadline, &client_lease);
    #[cfg(test)]
    super::deadline_tests::checkpoint(super::deadline_tests::Stage::LeaseCleanup);
    drop(client_lease);
    result
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
    result
}
