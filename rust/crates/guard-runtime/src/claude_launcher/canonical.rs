//! Exact Python ensure_ascii=True canonical bytes for a declared finite domain.
//! Float and non-Unicode-scalar input are unsupported, never reinterpreted.
use super::response::Failure;
use serde_json::Value;

const MAX_CANONICAL_BYTES: usize = 512 * 1024;

pub(super) fn signing_bytes(value: &Value, omitted: &str) -> Result<Vec<u8>, Failure> {
    let object = value
        .as_object()
        .ok_or(Failure::Integrity("signed object is malformed"))?;
    let mut output = Vec::new();
    output.push(b'{');
    let mut keys: Vec<_> = object
        .keys()
        .filter(|key| key.as_str() != omitted)
        .collect();
    keys.sort();
    for (index, key) in keys.into_iter().enumerate() {
        if index != 0 {
            output.push(b',');
        }
        string(key, &mut output);
        output.push(b':');
        write(&object[key], &mut output, 1)?;
    }
    output.push(b'}');
    check_size(&output)?;
    Ok(output)
}

fn write(value: &Value, output: &mut Vec<u8>, depth: usize) -> Result<(), Failure> {
    if depth > 32 {
        return Err(Failure::Integrity("signed JSON depth is unsupported"));
    }
    match value {
        Value::Null => output.extend_from_slice(b"null"),
        Value::Bool(value) => output.extend_from_slice(if *value { b"true" } else { b"false" }),
        Value::Number(value) if value.is_i64() || value.is_u64() => {
            output.extend_from_slice(value.to_string().as_bytes())
        }
        Value::Number(_) => {
            return Err(Failure::Integrity(
                "signed JSON number domain is unsupported",
            ))
        }
        Value::String(value) => string(value, output),
        Value::Array(values) => {
            output.push(b'[');
            for (index, value) in values.iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                write(value, output, depth + 1)?;
            }
            output.push(b']');
        }
        Value::Object(values) => {
            output.push(b'{');
            let mut keys: Vec<_> = values.keys().collect();
            keys.sort();
            for (index, key) in keys.into_iter().enumerate() {
                if index != 0 {
                    output.push(b',');
                }
                string(key, output);
                output.push(b':');
                write(&values[key], output, depth + 1)?;
            }
            output.push(b'}');
        }
    }
    check_size(output)
}

fn check_size(output: &[u8]) -> Result<(), Failure> {
    if output.len() > MAX_CANONICAL_BYTES {
        Err(Failure::Integrity("signed JSON canonical bound exceeded"))
    } else {
        Ok(())
    }
}

fn escape(unit: u16, output: &mut Vec<u8>) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    output.extend_from_slice(b"\\u");
    for shift in [12, 8, 4, 0] {
        output.push(HEX[((unit >> shift) & 15) as usize]);
    }
}

fn string(value: &str, output: &mut Vec<u8>) {
    output.push(b'"');
    for character in value.chars() {
        match character {
            '"' => output.extend_from_slice(b"\\\""),
            '\\' => output.extend_from_slice(b"\\\\"),
            '\u{8}' => output.extend_from_slice(b"\\b"),
            '\u{c}' => output.extend_from_slice(b"\\f"),
            '\n' => output.extend_from_slice(b"\\n"),
            '\r' => output.extend_from_slice(b"\\r"),
            '\t' => output.extend_from_slice(b"\\t"),
            ' '..='~' => output.push(character as u8),
            _ => {
                for unit in character.encode_utf16(&mut [0; 2]) {
                    escape(*unit, output);
                }
            }
        }
    }
    output.push(b'"');
}
