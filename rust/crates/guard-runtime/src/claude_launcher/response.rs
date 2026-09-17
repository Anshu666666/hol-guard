use serde_json::{json, Value};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Event {
    Pre,
    Post,
}

impl Event {
    pub(super) fn parse(value: &str) -> Option<Self> {
        match value {
            "PreToolUse" => Some(Self::Pre),
            "PostToolUse" => Some(Self::Post),
            _ => None,
        }
    }

    pub(super) fn name(self) -> &'static str {
        match self {
            Self::Pre => "PreToolUse",
            Self::Post => "PostToolUse",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) enum Failure {
    Availability(&'static str),
    Integrity(&'static str),
    Limit(&'static str),
    UnsupportedResponse,
}

pub(super) fn final_response(event: Event, failure: &Failure) -> Value {
    match failure {
        Failure::Availability(reason) => {
            if event == Event::Post {
                return json!({});
            }
            let message = format!("HOL Guard could not reach the local daemon ({reason}) and continued this action without native review.");
            json!({"continue": true, "hookSpecificOutput": {
                "hookEventName": event.name(), "permissionDecision": "allow",
                "permissionDecisionReason": message
            }})
        }
        Failure::Integrity(reason) => {
            let message = format!(
                "HOL Guard denied the action because daemon authentication failed: {reason}"
            );
            if event == Event::Post {
                json!({"continue": true, "stopReason": message})
            } else {
                deny(event, message)
            }
        }
        Failure::Limit(kind) => deny(
            event,
            format!("HOL Guard blocked this action because {kind} exceeded the safe size limit."),
        ),
        Failure::UnsupportedResponse => deny(
            event,
            "HOL Guard blocked this action because the daemon response is outside the native launcher pilot profile.".into(),
        ),
    }
}

fn deny(event: Event, message: String) -> Value {
    if event == Event::Post {
        json!({"decision": "block", "reason": message,
            "hookSpecificOutput": {"hookEventName": event.name()}})
    } else {
        json!({"systemMessage": message, "hookSpecificOutput": {
            "hookEventName": event.name(), "permissionDecision": "deny",
            "permissionDecisionReason": message
        }})
    }
}

/// Preserve bridge classification: overload precedes HTTP authentication codes.
/// Error-body text affects classification only; it is never returned or logged.
pub(super) fn http_failure(status: u16, body: &[u8]) -> Failure {
    let detail = String::from_utf8_lossy(body).to_ascii_lowercase();
    let overload = status == 429
        || ["capacity", "overload", "too_many", "too many", "busy"]
            .iter()
            .any(|needle| detail.contains(needle));
    if overload {
        Failure::Availability("daemon overload")
    } else if status == 401 || status == 403 {
        Failure::Integrity("daemon authorization failed")
    } else {
        Failure::Availability("daemon HTTP failure")
    }
}
