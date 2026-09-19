//! Preserve the authenticated command floor when persisting a raw snapshot.

use super::persist_authority_with_control_floor;
use crate::policy_store::{
    policy_store_command_floor, AuthenticatedPolicySnapshot, VERIFIER_KEY_BYTES,
};
use std::path::Path;

pub(in crate::policy_store) fn persist_authority(
    path: &Path,
    generation_floor: u64,
    policy_digest: &str,
    snapshot: Option<&AuthenticatedPolicySnapshot>,
    verifier_key: &[u8; VERIFIER_KEY_BYTES],
) -> Result<(), String> {
    let floor = policy_store_command_floor::floor_for_binding(
        snapshot.and_then(|value| value.command_extensions().as_ref()),
    );
    persist_authority_with_control_floor(
        path,
        generation_floor,
        policy_digest,
        snapshot,
        verifier_key,
        floor.as_ref(),
    )
}

