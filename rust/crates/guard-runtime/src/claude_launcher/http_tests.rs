use super::*;
use std::io::{self, Cursor};
use std::net::TcpListener;

fn parse(bytes: &[u8]) -> Result<Vec<u8>, Failure> {
    read_response(&mut BufReader::new(Cursor::new(bytes)), || Ok(()))
}

#[test]
fn connected_socket_disables_nagle_and_preserves_two_request_wire_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let deadline = Instant::now() + Duration::from_secs(5);
    let mut connection = Connection::connect("127.0.0.1", port, deadline).unwrap();
    assert!(connection.reader.get_ref().nodelay().unwrap());
    assert_eq!(connection.deadline, deadline);
    let (stream, _) = listener.accept().unwrap();
    stream
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    stream
        .set_write_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    let peer = std::thread::spawn(move || {
        let mut reader = BufReader::new(stream);
        let mut requests = Vec::new();
        for body in [b"challenge".as_slice(), b"{\"command\":\"printf guard\"}"] {
            let mut request = Vec::new();
            loop {
                let start = request.len();
                assert!(reader.read_until(b'\n', &mut request).unwrap() > 0);
                if &request[start..] == b"\r\n" {
                    break;
                }
                assert!(request.len() <= MAX_HEADERS);
            }
            let mut actual_body = vec![0; body.len()];
            reader.read_exact(&mut actual_body).unwrap();
            assert_eq!(actual_body, body);
            request.extend_from_slice(&actual_body);
            requests.push(request);
            reader
                .get_mut()
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}")
                .unwrap();
        }
        let mut extra = [0];
        assert_eq!(reader.read(&mut extra).unwrap(), 0);
        requests
    });
    let nonce = "a".repeat(64);
    let signature = "b".repeat(64);
    assert_eq!(
        connection
            .request("/challenge", b"challenge", None)
            .unwrap(),
        b"{}"
    );
    assert_eq!(
        connection
            .request(
                "/hook",
                b"{\"command\":\"printf guard\"}",
                Some((&nonce, &signature))
            )
            .unwrap(),
        b"{}"
    );
    drop(connection);
    let requests = peer.join().unwrap();
    assert_eq!(requests[0], format!("POST /challenge HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 9\r\nConnection: keep-alive\r\n\r\nchallenge").as_bytes());
    assert_eq!(requests[1], format!("POST /hook HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\nContent-Type: application/json\r\nContent-Length: 26\r\nConnection: close\r\nX-Guard-Daemon-Nonce: {nonce}\r\nX-Guard-Daemon-Proof: {signature}\r\n\r\n{{\"command\":\"printf guard\"}}").as_bytes());
}

#[test]
fn actual_python_wire_parser_vectors_preserve_supported_denials_and_explicit_limits() {
    for case in super::super::tests::reference()["http_wire_cases"]
        .as_array()
        .unwrap()
    {
        let wire = hex::decode(case["wire_hex"].as_str().unwrap()).unwrap();
        let result = parse(&wire);
        match case["native_profile"].as_str().unwrap() {
            "pass" => assert_eq!(hex::encode(result.unwrap()), case["python_hex"], "{case}"),
            "unsupported" => assert_eq!(result, Err(Failure::UnsupportedResponse), "{case}"),
            "availability" => {
                assert!(matches!(result, Err(Failure::Availability(_))));
                assert_eq!(case["python_failure"], "transport-failure");
            }
            "integrity" => {
                assert!(matches!(result, Err(Failure::Integrity(_))), "{case}");
                assert_eq!(
                    case["python_failure"],
                    "authenticated-control-plane-failure"
                );
            }
            _ => unreachable!(),
        }
    }
}

#[test]
fn exact_server_framing_and_body_bound() {
    assert_eq!(
        parse(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nCache-Control: no-store\r\n\r\n{}")
            .unwrap(),
        b"{}"
    );
    let mut maximum =
        format!("HTTP/1.0 200 OK\r\nContent-Length: {MAX_WIRE_BYTES}\r\n\r\n").into_bytes();
    maximum.resize(maximum.len() + MAX_WIRE_BYTES, b'x');
    assert_eq!(parse(&maximum).unwrap().len(), MAX_WIRE_BYTES);
    assert!(matches!(
        parse(
            format!(
                "HTTP/1.0 200 OK\r\nContent-Length: {}\r\n\r\n",
                MAX_WIRE_BYTES + 1
            )
            .as_bytes()
        ),
        Err(Failure::UnsupportedResponse)
    ));
}

#[test]
fn ambiguous_or_unbounded_framing_is_never_hook_success() {
    for raw in [
        b"HTTP/1.1 200 OK\r\n\r\n{}".as_slice(),
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nContent-Length: 3\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: +2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: -2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 99999999999999999999999999999999\r\n\r\n",
        b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\r\n Content-Length: 2\r\n\r\n{}",
        b"HTTP/1.1 200 OK\nContent-Length: 2\n\n{}",
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}{}",
    ] {
        assert!(
            matches!(parse(raw), Err(Failure::UnsupportedResponse)),
            "{raw:?}"
        );
    }
    assert!(matches!(
        parse(b"HTTP/1.1 200 OK\r\nContent-Length: 3\r\n\r\n{}"),
        Err(Failure::UnsupportedResponse)
    ));
    let many = format!(
        "HTTP/1.1 200 OK\r\n{}Content-Length: 2\r\n\r\n{{}}",
        "X-A: 1\r\n".repeat(65)
    );
    assert!(matches!(
        parse(many.as_bytes()),
        Err(Failure::UnsupportedResponse)
    ));
    let huge = format!(
        "HTTP/1.1 200 OK\r\nX-A: {}\r\nContent-Length: 2\r\n\r\n{{}}",
        "x".repeat(MAX_LINE)
    );
    assert!(matches!(
        parse(huge.as_bytes()),
        Err(Failure::UnsupportedResponse)
    ));
}

#[test]
fn deadline_is_checked_between_buffered_fragments_and_before_body() {
    let mut checks = 0;
    let result = read_response(
        &mut BufReader::new(Cursor::new(
            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}",
        )),
        || {
            checks += 1;
            if checks == 4 {
                Err(Failure::Availability("expired"))
            } else {
                Ok(())
            }
        },
    );
    assert_eq!(result, Err(Failure::Availability("expired")));
    assert_eq!(checks, 4);
    assert!(remaining(Instant::now() - Duration::from_secs(1)).is_err());
}

struct SingleByte(Cursor<Vec<u8>>);
impl Read for SingleByte {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let length = bytes.len().min(1);
        self.0.read(&mut bytes[..length])
    }
}

#[test]
fn short_reads_preserve_status_body_and_authentication_classification() {
    let mut reader = BufReader::new(SingleByte(Cursor::new(
        b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\n{}".to_vec(),
    )));
    assert_eq!(read_response(&mut reader, || Ok(())).unwrap(), b"{}");
    assert!(matches!(
        parse(b"HTTP/1.1 401 Unauthorized\r\nContent-Length: 0\r\n\r\n"),
        Err(Failure::Integrity(_))
    ));
    assert!(matches!(
        parse(b"HTTP/1.1 503 Busy\r\nContent-Length: 4\r\n\r\nbusy"),
        Err(Failure::Availability(_))
    ));
}
