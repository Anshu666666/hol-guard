use super::{
    canonical,
    response::{Event, Failure},
};
use ring::hmac;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct PeerIdentity {
    pub(super) compatibility_version: u64,
    pub(super) package_version: String,
    pub(super) source_root: String,
    pub(super) runtime_fingerprint: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct State {
    pub(super) host: String,
    pub(super) port: u16,
    pub(super) pid: u64,
    pub(super) state_id: String,
    pub(super) started_at: String,
    pub(super) guard_home: String,
    pub(super) auth_token_id: String,
}

pub(super) fn key(encoded: &[u8]) -> Result<[u8; 32], Failure> {
    let text = std::str::from_utf8(encoded)
        .map_err(|_| Failure::Integrity("daemon discovery key is malformed"))?
        .trim();
    let mut key = [0; 32];
    hex::decode_to_slice(text, &mut key)
        .map_err(|_| Failure::Integrity("daemon discovery key is malformed"))?;
    Ok(key)
}

fn verify(value: &Value, key: &[u8; 32], field: &str) -> Result<(), Failure> {
    let signature = text(value, field)?;
    if signature.len() != 64
        || !signature
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(Failure::Integrity("daemon signature is malformed"));
    }
    let signature =
        hex::decode(signature).map_err(|_| Failure::Integrity("daemon signature is malformed"))?;
    let bytes = canonical::signing_bytes(value, field)?;
    hmac::verify(&hmac::Key::new(hmac::HMAC_SHA256, key), &bytes, &signature)
        .map_err(|_| Failure::Integrity("daemon authentication failed"))
}

/// Caller must admit bounded strict JSON before any signature verification.
pub(super) fn state(
    value: &Value,
    key: &[u8; 32],
    guard_home: &str,
    peer: &PeerIdentity,
) -> Result<State, Failure> {
    verify(value, key, "state_signature")?;
    if integer(value, "discovery_protocol_version")? != 1
        || text(value, "discovery_key_id")? != hex::encode(Sha256::digest(key))
        || integer(value, "compatibility_version")? != peer.compatibility_version
        || text(value, "package_version")? != peer.package_version
        || text(value, "source_root")? != peer.source_root
        || text(value, "runtime_fingerprint")? != peer.runtime_fingerprint
        || text(value, "guard_home")? != guard_home
    {
        return Err(Failure::Integrity(
            "daemon package or Guard home identity changed",
        ));
    }
    let host = text(value, "host")?;
    if !matches!(host, "127.0.0.1" | "::1") {
        return Err(Failure::Integrity(
            "daemon host is outside the pilot profile",
        ));
    }
    let port = u16::try_from(integer(value, "port")?)
        .map_err(|_| Failure::Integrity("daemon port is invalid"))?;
    let pid = integer(value, "pid")?;
    if port == 0 || pid == 0 {
        return Err(Failure::Integrity("daemon process identity is invalid"));
    }
    Ok(State {
        host: host.to_owned(),
        port,
        pid,
        state_id: text(value, "state_id")?.to_owned(),
        started_at: text(value, "started_at")?.to_owned(),
        guard_home: guard_home.to_owned(),
        auth_token_id: text(value, "auth_token_id")?.to_owned(),
    })
}

pub(super) fn challenge(
    value: &Value,
    key: &[u8; 32],
    state: &State,
    nonce: &str,
    event: Event,
    now_ms: u64,
) -> Result<String, Failure> {
    verify(value, key, "proof")?;
    let same = integer(value, "protocol_version")? == 1
        && text(value, "nonce")? == nonce
        && text(value, "hook_event")? == event.name()
        && text(value, "state_id")? == state.state_id
        && text(value, "host")? == state.host
        && integer(value, "port")? == u64::from(state.port)
        && integer(value, "pid")? == state.pid
        && text(value, "started_at")? == state.started_at
        && text(value, "guard_home")? == state.guard_home;
    let issued = integer(value, "issued_at_ms")?;
    let expires = integer(value, "expires_at_ms")?;
    if !same
        || issued > now_ms.saturating_add(1000)
        || expires < now_ms
        || expires.checked_sub(issued).is_none_or(|ttl| ttl > 5000)
    {
        return Err(Failure::Integrity(
            "daemon challenge identity or lifetime is invalid",
        ));
    }
    Ok(text(value, "proof")?.to_owned())
}

fn text<'a>(value: &'a Value, field: &str) -> Result<&'a str, Failure> {
    value
        .get(field)
        .and_then(Value::as_str)
        .filter(|text| !text.is_empty())
        .ok_or(Failure::Integrity("daemon identity field is malformed"))
}

fn integer(value: &Value, field: &str) -> Result<u64, Failure> {
    value
        .get(field)
        .and_then(Value::as_u64)
        .ok_or(Failure::Integrity("daemon identity number is malformed"))
}
