//! Feature-gated transport experiment; never selected by ordinary registration.
mod canonical;
mod config;
mod discovery;
mod files;
mod http;
mod response;
mod response_json;
mod target;

use response::{Event, Failure};
use serde_json::json;
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

const MAX_WIRE_BYTES: usize = 1_000_000;
const LAUNCHER_BUDGET: Duration = Duration::from_secs(8);
const DAEMON_BUDGET: Duration = Duration::from_secs(2);

pub(crate) fn run(args: &[String]) -> Result<(), String> {
    let [flag, path, digest_flag, digest, event_flag, event] = args else {
        return Err("native_claude_launcher_arguments_invalid".into());
    };
    if flag != "--config" || digest_flag != "--config-sha256" || event_flag != "--event" {
        return Err("native_claude_launcher_arguments_invalid".into());
    }
    let event = Event::parse(event).ok_or("native_claude_launcher_event_unsupported")?;
    // This is a separate one-shot process. A caught failure emits only the
    // fixed harness response, never a panic diagnostic containing input.
    std::panic::set_hook(Box::new(|_| {}));
    let path = PathBuf::from(path);
    let digest = digest.clone();
    let deadline = Instant::now() + LAUNCHER_BUDGET;
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guard-claude-launcher".into())
        .spawn(move || {
            let result = std::panic::catch_unwind(|| attempt(&path, &digest, event, deadline))
                .unwrap_or(Err(Failure::Integrity("launcher worker failed")));
            let _ = sender.send(result);
        })
        .map_err(|_| "native_claude_launcher_worker_failed")?;
    let work_budget = deadline
        .saturating_duration_since(Instant::now())
        .saturating_sub(Duration::from_millis(25));
    let result = receiver
        .recv_timeout(work_budget)
        .unwrap_or(Err(Failure::Availability(
            "Guard daemon hook request exceeded its absolute deadline",
        )));
    let mut bytes = match result {
        Ok(bytes) => bytes,
        Err(failure) => serde_json::to_vec(&response::final_response(event, &failure))
            .map_err(|_| "native_claude_launcher_response_failed")?,
    };
    bytes.push(b'\n');
    let (sender, receiver) = std::sync::mpsc::sync_channel(1);
    std::thread::Builder::new()
        .name("guard-claude-output".into())
        .spawn(move || {
            let _ = sender.send(std::io::stdout().lock().write_all(&bytes));
        })
        .map_err(|_| "native_claude_launcher_output_failed")?;
    receiver
        .recv_timeout(deadline.saturating_duration_since(Instant::now()))
        .map_err(|_| "native_claude_launcher_output_deadline")?
        .map_err(|_| "native_claude_launcher_output_failed".into())
}

fn attempt(path: &Path, digest: &str, event: Event, deadline: Instant) -> Result<Vec<u8>, Failure> {
    let config = config::load(path, digest)?;
    let mut bytes = Vec::new();
    std::io::stdin()
        .take(MAX_WIRE_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| Failure::Availability("hook input is unavailable"))?;
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Failure::Limit("hook input"));
    }
    let value = crate::strict_json_value(&bytes)
        .map_err(|_| Failure::Integrity("hook input is outside the canonical pilot profile"))?;
    if !value.is_object()
        || value
            .get("hook_event_name")
            .and_then(serde_json::Value::as_str)
            != Some(event.name())
    {
        return Err(Failure::Integrity(
            "hook event does not match the registered pilot event",
        ));
    }
    let guard_home = config
        .guard_home
        .to_str()
        .ok_or(Failure::Integrity("Guard home is not Unicode"))?;
    let read_identity = || {
        let key = discovery::key(&files::read(
            &config.guard_home.join("daemon-discovery-key"),
            256,
            true,
        )?)?;
        let raw = files::read(
            &config.guard_home.join("daemon-state.json"),
            64 * 1024,
            true,
        )?;
        let value = crate::strict_json_value(&raw)
            .map_err(|_| Failure::Integrity("daemon state is malformed"))?;
        let state = discovery::state(&value, &key, guard_home, &config.daemon)?;
        Ok::<_, Failure>((state, key))
    };
    // Initial discovery failures are recoverable availability in the existing
    // Python bridge. A contacted proof or subsequent reread failure is not.
    let (state, key) =
        read_identity().map_err(|_| Failure::Availability("daemon discovery is unavailable"))?;
    let request_deadline = deadline.min(Instant::now() + DAEMON_BUDGET);
    let mut connection = http::Connection::connect(&state.host, state.port, request_deadline)?;
    let mut nonce = [0; 32];
    getrandom::fill(&mut nonce)
        .map_err(|_| Failure::Integrity("daemon nonce generation failed"))?;
    let nonce = hex::encode(nonce);
    let challenge_request = serde_json::to_vec(&json!({"protocol_version":1,
        "nonce":nonce,"state_id":state.state_id,"hook_event":event.name()}))
    .map_err(|_| Failure::Integrity("daemon challenge encoding failed"))?;
    let challenge =
        connection.request("/v1/daemon/identity-challenge", &challenge_request, None)?;
    let challenge = crate::strict_json_value(&challenge)
        .map_err(|_| Failure::Integrity("daemon identity challenge is malformed"))?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| Failure::Integrity("daemon challenge clock is invalid"))?;
    let now = u64::try_from(now.as_millis())
        .map_err(|_| Failure::Integrity("daemon challenge clock is invalid"))?;
    let proof = discovery::challenge(&challenge, &key, &state, &nonce, event, now)?;
    let (current, current_key) = read_identity()
        .map_err(|_| Failure::Integrity("daemon state changed during identity verification"))?;
    if current != state || !crate::constant_time_eq(&key, &current_key) {
        return Err(Failure::Integrity(
            "daemon state changed during identity verification",
        ));
    }
    let response = connection.request(
        &format!("/v1/hooks/claude-code?{}", config.query),
        &bytes,
        Some((&nonce, &proof)),
    )?;
    response_json::admit(response)
}

#[cfg(test)]
mod tests;
