//! Narrow daemon HTTP framing, one connection and one hook write per invocation.
use super::{
    response::{http_failure, Failure},
    MAX_WIRE_BYTES,
};
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{IpAddr, SocketAddr, TcpStream};
use std::time::{Duration, Instant};

const MAX_HEADERS: usize = 16 * 1024;
const MAX_LINE: usize = 4096;

pub(super) struct Connection {
    reader: BufReader<TcpStream>,
    deadline: Instant,
    host: String,
    port: u16,
}

impl Connection {
    pub(super) fn connect(host: &str, port: u16, deadline: Instant) -> Result<Self, Failure> {
        let ip: IpAddr = host
            .parse()
            .map_err(|_| Failure::Integrity("daemon host is invalid"))?;
        if !ip.is_loopback() {
            return Err(Failure::Integrity("daemon host is not loopback"));
        }
        let stream = TcpStream::connect_timeout(&SocketAddr::new(ip, port), remaining(deadline)?)
            .map_err(|_| Failure::Availability("daemon connection is unavailable"))?;
        Ok(Self {
            reader: BufReader::new(stream),
            deadline,
            host: host.to_owned(),
            port,
        })
    }

    pub(super) fn request(
        &mut self,
        path: &str,
        body: &[u8],
        proof: Option<(&str, &str)>,
    ) -> Result<Vec<u8>, Failure> {
        if !path.starts_with('/')
            || path.bytes().any(|byte| byte <= 32 || byte >= 127)
            || body.len() > MAX_WIRE_BYTES
        {
            return Err(Failure::Integrity("daemon request framing is invalid"));
        }
        let host = if self.host.contains(':') {
            format!("[{}]", self.host)
        } else {
            self.host.clone()
        };
        let connection = if proof.is_some() {
            "close"
        } else {
            "keep-alive"
        };
        let mut headers = format!("POST {path} HTTP/1.1\r\nHost: {host}:{}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: {connection}\r\n", self.port, body.len());
        if let Some((nonce, signature)) = proof {
            if ![nonce, signature]
                .into_iter()
                .all(|value| value.len() == 64 && value.bytes().all(|b| b.is_ascii_hexdigit()))
            {
                return Err(Failure::Integrity("daemon proof header is malformed"));
            }
            headers.push_str(&format!(
                "X-Guard-Daemon-Nonce: {nonce}\r\nX-Guard-Daemon-Proof: {signature}\r\n"
            ));
        }
        headers.push_str("\r\n");
        self.write(headers.as_bytes())?;
        self.write(body)?;
        self.response()
    }

    fn write(&mut self, mut bytes: &[u8]) -> Result<(), Failure> {
        while !bytes.is_empty() {
            self.reader
                .get_ref()
                .set_write_timeout(Some(remaining(self.deadline)?))
                .map_err(|_| Failure::Availability("daemon write deadline is unavailable"))?;
            let count = self
                .reader
                .get_mut()
                .write(bytes)
                .map_err(|_| Failure::Availability("daemon write failed"))?;
            if count == 0 {
                return Err(Failure::Availability("daemon write was incomplete"));
            }
            bytes = &bytes[count..];
        }
        Ok(())
    }

    fn response(&mut self) -> Result<Vec<u8>, Failure> {
        let timer = self
            .reader
            .get_ref()
            .try_clone()
            .map_err(|_| Failure::Availability("daemon deadline handle is unavailable"))?;
        let deadline = self.deadline;
        read_response(&mut self.reader, || {
            timer
                .set_read_timeout(Some(remaining(deadline)?))
                .map_err(|_| Failure::Availability("daemon read deadline is unavailable"))
        })
    }
}

fn line<R: Read>(
    reader: &mut BufReader<R>,
    before_read: &mut impl FnMut() -> Result<(), Failure>,
) -> Result<Vec<u8>, Failure> {
    // Actual transport read errors are ordinary availability. A stricter pilot
    // framing bound is a separate unsupported outcome: Python may accept it
    // and deliver a denial, which cannot safely become an availability allow.
    let mut output = Vec::new();
    loop {
        before_read()?;
        let available = reader
            .fill_buf()
            .map_err(|_| Failure::Availability("daemon read failed"))?;
        if available.is_empty() {
            return Err(if output.is_empty() {
                Failure::Availability("daemon response was incomplete")
            } else {
                Failure::UnsupportedResponse
            });
        }
        let amount = available
            .iter()
            .position(|byte| *byte == b'\n')
            .map_or(available.len(), |n| n + 1);
        if output.len().saturating_add(amount) > MAX_LINE {
            return Err(Failure::UnsupportedResponse);
        }
        output.extend_from_slice(&available[..amount]);
        reader.consume(amount);
        if output.last() == Some(&b'\n') {
            if !output.ends_with(b"\r\n") {
                return Err(Failure::UnsupportedResponse);
            }
            output.truncate(output.len() - 2);
            return Ok(output);
        }
    }
}

fn read_response<R: Read>(
    reader: &mut BufReader<R>,
    mut before_read: impl FnMut() -> Result<(), Failure>,
) -> Result<Vec<u8>, Failure> {
    let status_line = line(reader, &mut before_read)?;
    let status_line =
        std::str::from_utf8(&status_line).map_err(|_| Failure::UnsupportedResponse)?;
    let parts: Vec<_> = status_line.splitn(3, ' ').collect();
    if !status_line.starts_with("HTTP/") {
        return Err(Failure::Availability("daemon HTTP status is malformed"));
    }
    if parts.len() < 2
        || !matches!(parts[0], "HTTP/1.0" | "HTTP/1.1")
        || parts[1].len() != 3
        || !parts[1].bytes().all(|b| b.is_ascii_digit())
    {
        return Err(Failure::UnsupportedResponse);
    }
    let status: u16 = parts[1].parse().map_err(|_| Failure::UnsupportedResponse)?;
    // Python follows informational responses to a later final response. The
    // narrow daemon profile emits a final status directly; do not turn a
    // possible later denial into ordinary HTTP-error availability.
    if status < 200 {
        return Err(Failure::UnsupportedResponse);
    }
    let mut consumed = status_line.len() + 2;
    let mut length = None;
    let mut count = 0;
    loop {
        let line = line(reader, &mut before_read).map_err(|error| match error {
            Failure::Availability("daemon response was incomplete")
                if matches!(status, 401 | 403) =>
            {
                http_failure(status, &[])
            }
            other => other,
        })?;
        consumed += line.len() + 2;
        count += 1;
        if consumed > MAX_HEADERS || count > 64 {
            return Err(Failure::UnsupportedResponse);
        }
        if line.is_empty() {
            break;
        }
        let line = std::str::from_utf8(&line).map_err(|_| Failure::UnsupportedResponse)?;
        let (name, value) = line.split_once(':').ok_or(Failure::UnsupportedResponse)?;
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.bytes().any(|byte| byte < 32 && byte != b'\t')
        {
            return Err(Failure::UnsupportedResponse);
        }
        if name.eq_ignore_ascii_case("transfer-encoding") {
            return Err(Failure::UnsupportedResponse);
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                return Err(Failure::UnsupportedResponse);
            }
            let value = value.trim_start_matches('0');
            let next = if value.is_empty() {
                0
            } else {
                value
                    .parse::<usize>()
                    .map_err(|_| Failure::UnsupportedResponse)?
            };
            if next > MAX_WIRE_BYTES || length.is_some_and(|current| current != next) {
                return Err(Failure::UnsupportedResponse);
            }
            length = Some(next);
        }
    }
    let length = length.ok_or(Failure::UnsupportedResponse)?;
    let mut body = vec![0; length];
    let mut filled = 0;
    while filled < length {
        before_read()?;
        let count = reader
            .read(&mut body[filled..])
            .map_err(|_| Failure::Availability("daemon read failed"))?;
        if count == 0 {
            return Err(if filled == 0 && matches!(status, 401 | 403) {
                http_failure(status, &[])
            } else if filled == 0 {
                Failure::Availability("daemon response was incomplete")
            } else {
                Failure::UnsupportedResponse
            });
        }
        filled += count;
    }
    if !reader.buffer().is_empty() {
        return Err(Failure::UnsupportedResponse);
    }
    if status != 200 {
        return Err(http_failure(status, &body));
    }
    Ok(body)
}

fn remaining(deadline: Instant) -> Result<Duration, Failure> {
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining < Duration::from_millis(10) {
        Err(Failure::Availability(
            "Guard daemon hook request exhausted its absolute deadline",
        ))
    } else {
        Ok(remaining)
    }
}

#[cfg(test)]
#[path = "http_tests.rs"]
mod tests;
