//! Hook responses are opaque delivered decisions, not native request envelopes.
//! A valid denial outside the admitted parser profile must never become an allow.
use super::{response::Failure, MAX_WIRE_BYTES};
use serde_json::Value;

pub(super) fn admit(bytes: Vec<u8>) -> Result<Vec<u8>, Failure> {
    // The existing Python transport decodes HTTP bytes with replacement before
    // its object check. Preserve that byte-to-text behavior for admitted output.
    if bytes.len() > MAX_WIRE_BYTES {
        return Err(Failure::UnsupportedResponse);
    }
    let decoded = String::from_utf8_lossy(&bytes);
    let text =
        decoded.trim_matches(|c: char| c.is_whitespace() || ('\u{1c}'..='\u{1f}').contains(&c));
    if text.len() > MAX_WIRE_BYTES {
        return Err(Failure::UnsupportedResponse);
    }
    match serde_json::from_str::<Value>(text) {
        Ok(Value::Object(_)) => Ok(text.as_bytes().to_vec()),
        Ok(_) => Err(Failure::Availability("daemon returned malformed hook JSON")),
        Err(error) => {
            // These finite errors identify Python JSON domains that serde_json
            // cannot preserve. Its pinned error names are frozen by paired
            // fixtures; unknown malformed syntax retains legacy availability.
            let reason = error.to_string();
            let unsupported = [
                "recursion limit exceeded",
                "number out of range",
                "invalid unicode code point",
                "lone leading surrogate in hex escape",
            ]
            .iter()
            .any(|prefix| reason.starts_with(prefix))
                || contains_nonfinite_literal(text.as_bytes())
                || contains_surrogate_escape(text.as_bytes());
            if unsupported {
                Err(Failure::UnsupportedResponse)
            } else {
                Err(Failure::Availability("daemon returned malformed hook JSON"))
            }
        }
    }
}

fn contains_surrogate_escape(bytes: &[u8]) -> bool {
    let mut quoted = false;
    let mut index = 0;
    while let Some(&byte) = bytes.get(index) {
        if byte == b'"' {
            quoted = !quoted;
        } else if quoted && byte == b'\\' {
            if bytes.get(index + 1) == Some(&b'u') {
                if let Some(hex) = bytes.get(index + 2..index + 6) {
                    let codepoint = hex.iter().try_fold(0_u16, |value, digit| {
                        char::from(*digit)
                            .to_digit(16)
                            .map(|digit| value * 16 + digit as u16)
                    });
                    if codepoint.is_some_and(|value| (0xd800..=0xdfff).contains(&value)) {
                        return true;
                    }
                }
            }
            index += 1;
        }
        index += 1;
    }
    false
}

fn contains_nonfinite_literal(bytes: &[u8]) -> bool {
    let mut quoted = false;
    let mut escaped = false;
    for (index, byte) in bytes.iter().copied().enumerate() {
        if quoted {
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                quoted = false;
            }
        } else if byte == b'"' {
            quoted = true;
        } else if (index == 0 || b" \t\r\n[:,".contains(&bytes[index - 1]))
            && [b"NaN".as_slice(), b"Infinity", b"-Infinity"]
                .into_iter()
                .any(|literal| {
                    bytes[index..].starts_with(literal)
                        && bytes
                            .get(index + literal.len())
                            .is_none_or(|after| b" \t\r\n]},".contains(after))
                })
        {
            return true;
        }
    }
    false
}
