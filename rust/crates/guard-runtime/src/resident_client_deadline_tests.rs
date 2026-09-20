use super::*;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener};
use std::thread;

const TOKEN: [u8; crate::AUTH_TOKEN_BYTES] = [0x5a; crate::AUTH_TOKEN_BYTES];

fn socket_pair() -> (TcpStream, TcpStream) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).unwrap();
    let client = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let (server, _) = listener.accept().unwrap();
    for stream in [&client, &server] {
        stream.set_nodelay(true).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(2)))
            .unwrap();
    }
    (client, server)
}

fn accept_authentication(stream: &mut TcpStream, slow_proof: bool) -> io::Result<()> {
    let mut nonce = [0u8; AUTH_NONCE_BYTES];
    stream.read_exact(&mut nonce)?;
    let proof = hmac_sha256(&TOKEN, SERVER_PROOF_LABEL, &nonce);
    if slow_proof {
        // Every fragment arrives within the old socket inactivity timeout;
        // their aggregate duration exceeds the authentication phase budget.
        for chunk in proof.chunks(4) {
            thread::sleep(Duration::from_millis(40));
            stream.write_all(chunk)?;
        }
    } else {
        stream.write_all(&proof)?;
    }
    let mut client_proof = [0u8; AUTH_PROOF_BYTES];
    stream.read_exact(&mut client_proof)?;
    assert_eq!(
        client_proof,
        hmac_sha256(&TOKEN, CLIENT_PROOF_LABEL, &nonce)
    );
    Ok(())
}

fn accept_request(stream: &mut TcpStream) -> io::Result<[u8; FRAME_REQUEST_ID_BYTES]> {
    let mut header = [0u8; FRAME_HEADER_BYTES];
    stream.read_exact(&mut header)?;
    assert_eq!(&header[..4], REQUEST_MAGIC);
    let request_id = header[4..4 + FRAME_REQUEST_ID_BYTES].try_into().unwrap();
    let length = u32::from_be_bytes(header[FRAME_HEADER_BYTES - 4..].try_into().unwrap()) as usize;
    let mut payload = vec![0u8; length];
    stream.read_exact(&mut payload)?;
    assert_eq!(payload, b"{}");
    assert_eq!(
        &header[4 + FRAME_REQUEST_ID_BYTES..FRAME_HEADER_BYTES - 4],
        Sha256::digest(&payload).as_slice(),
    );
    Ok(request_id)
}

fn response_header(request_id: &[u8; FRAME_REQUEST_ID_BYTES], response: &[u8]) -> Vec<u8> {
    let mut header = Vec::new();
    header.extend_from_slice(RESPONSE_MAGIC);
    header.extend_from_slice(request_id);
    header.extend_from_slice(&Sha256::digest(response));
    header.extend_from_slice(&(response.len() as u32).to_be_bytes());
    header
}

#[test]
fn timely_authenticated_socket_response_is_unchanged() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let request_id = accept_request(&mut server)?;
        server.write_all(&response_header(&request_id, b"{}"))?;
        server.write_all(b"{}")
    });
    let result = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap();
    assert_eq!(result, b"{}");
    peer.join().unwrap().unwrap();
}

#[test]
fn fragmented_server_proof_cannot_renew_authentication_budget() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, true)?;
        let request_id = accept_request(&mut server)?;
        server.write_all(&response_header(&request_id, b"{}"))?;
        server.write_all(b"{}")
    });
    let started = Instant::now();
    let result = exchange_request(&mut client, &TOKEN, b"{}", started + Duration::from_secs(2));
    let elapsed = started.elapsed();
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_frame_read_failed");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[test]
fn fragmented_response_header_cannot_renew_request_budget() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let request_id = accept_request(&mut server)?;
        for chunk in response_header(&request_id, b"{}").chunks(8) {
            thread::sleep(Duration::from_millis(40));
            server.write_all(chunk)?;
        }
        server.write_all(b"{}")
    });
    let started = Instant::now();
    let result = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        started + Duration::from_millis(180),
    );
    let elapsed = started.elapsed();
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[test]
fn response_body_uses_time_left_after_header_and_partial_reads() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let request_id = accept_request(&mut server)?;
        thread::sleep(Duration::from_millis(70));
        server.write_all(&response_header(&request_id, b"{}"))?;
        for byte in b"{}" {
            thread::sleep(Duration::from_millis(70));
            server.write_all(&[*byte])?;
        }
        Ok(())
    });
    let started = Instant::now();
    let result = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        started + Duration::from_millis(180),
    );
    let elapsed = started.elapsed();
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[cfg(unix)]
#[test]
fn progressing_backpressured_request_write_remains_bounded_and_nonretryable() {
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    let (mut client, mut server) = socket_pair();
    nix::sys::socket::setsockopt(&client, nix::sys::socket::sockopt::SndBuf, &4096).unwrap();
    let stopped = Arc::new(AtomicBool::new(false));
    let peer_stopped = Arc::clone(&stopped);
    let peer = thread::spawn(move || -> io::Result<()> {
        accept_authentication(&mut server, false)?;
        let mut buffer = [0u8; 1024];
        while !peer_stopped.load(Ordering::Acquire) {
            if server.read(&mut buffer)? == 0 {
                break;
            }
            thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    });
    let payload = vec![b'x'; 2 * 1024 * 1024];
    let started = Instant::now();
    let result = exchange_request(
        &mut client,
        &TOKEN,
        &payload,
        started + Duration::from_millis(180),
    );
    let elapsed = started.elapsed();
    stopped.store(true, Ordering::Release);
    let _ = client.shutdown(Shutdown::Both);
    let _ = peer.join().unwrap();
    let error = result.unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
    assert!(elapsed < Duration::from_millis(800));
}

#[test]
fn timely_authentication_rejection_keeps_its_fatal_error() {
    let (mut client, mut server) = socket_pair();
    let peer = thread::spawn(move || -> io::Result<()> {
        let mut nonce = [0u8; AUTH_NONCE_BYTES];
        server.read_exact(&mut nonce)?;
        server.write_all(&[0u8; AUTH_PROOF_BYTES])
    });
    let error = exchange_request(
        &mut client,
        &TOKEN,
        b"{}",
        Instant::now() + Duration::from_secs(2),
    )
    .unwrap_err();
    assert_eq!(error.code, "native_client_auth_rejected");
    assert!(!error.retryable_teardown);
    peer.join().unwrap().unwrap();
}

#[test]
fn zero_budget_is_rejected_before_endpoint_or_process_access() {
    let error = send_request_for_digest_detailed(
        "loopback",
        "invalid",
        &TOKEN,
        b"{}",
        Duration::ZERO,
        &ExpectedProcessIdentity {
            process_id: 0,
            start_marker: "",
            digest: None,
        },
    )
    .unwrap_err();
    assert_eq!(error.code, "native_client_deadline_exceeded");
    assert!(!error.retryable_teardown);
}
