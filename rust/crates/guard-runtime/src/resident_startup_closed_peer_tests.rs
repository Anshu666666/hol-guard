//! Mac platform control, separate from the real first-policy-push probe.
//!
//! The peer closes only after writing a complete, correctly bound response.
//! This demonstrates the existing timeout-setter failure without repairing or
//! suppressing it, then proves the response was still buffered and readable.

use super::deadline::DeadlineStream;
use super::read_committed_response;
use sha2::{Digest, Sha256};
use std::io::{self, Read, Write};
use std::os::unix::net::UnixStream;
use std::time::{Duration, Instant};

#[test]
fn closed_unix_peer_rejects_timeout_reset_but_retains_complete_bound_response() {
    let (mut client, mut peer) = UnixStream::pair().expect("real Unix socket pair");
    let timeout = Some(Duration::from_millis(250));
    client
        .set_read_timeout(timeout)
        .expect("timeout is valid while peer is connected");
    peer.set_write_timeout(timeout)
        .expect("bounded fixture write");

    let request_id = [0x7a; crate::FRAME_REQUEST_ID_BYTES];
    let response = b"closed-peer-buffered-response";
    let mut frame = Vec::with_capacity(crate::FRAME_HEADER_BYTES + response.len());
    frame.extend_from_slice(crate::RESPONSE_MAGIC);
    frame.extend_from_slice(&request_id);
    frame.extend_from_slice(&Sha256::digest(response));
    frame.extend_from_slice(&(response.len() as u32).to_be_bytes());
    frame.extend_from_slice(response);
    assert_eq!(frame.len(), crate::FRAME_HEADER_BYTES + response.len());
    peer.write_all(&frame)
        .expect("complete bound fixture frame");
    peer.flush().expect("fixture flush");
    drop(peer);

    // The identical, previously accepted timeout now fails at setsockopt.
    // The error is captured directly, before any receive on the client.
    let setter_error = client
        .set_read_timeout(timeout)
        .expect_err("Darwin rejects timeout reconfiguration after peer close");
    assert_eq!(setter_error.kind(), io::ErrorKind::InvalidInput);
    assert_eq!(setter_error.raw_os_error(), Some(22));

    // Exercise the original production deadline wrapper on the same socket.
    // Its pre-read timeout reconfiguration fails before consuming the header.
    {
        let mut bounded = DeadlineStream::new(&mut client, Instant::now() + Duration::from_secs(2));
        let mut header = [0u8; crate::FRAME_HEADER_BYTES];
        let wrapper_error = bounded
            .read(&mut header)
            .expect_err("original deadline wrapper preserves the setter failure");
        assert_eq!(wrapper_error.kind(), io::ErrorKind::InvalidInput);
        assert_eq!(wrapper_error.raw_os_error(), setter_error.raw_os_error());
        assert_eq!(header, [0; crate::FRAME_HEADER_BYTES]);
    }

    // This diagnostic-only read cannot block. The actual committed-response
    // decoder verifies magic, request binding, bounded length, and body digest.
    // Successful decoding also proves the failed wrapper consumed no bytes.
    client
        .set_nonblocking(true)
        .expect("nonblocking buffered-read control");
    let decoded = read_committed_response(&mut client, &request_id)
        .expect("complete bound response remains readable after peer close");
    assert_eq!(decoded, response);
    let mut trailing = [0u8; 1];
    assert_eq!(client.read(&mut trailing).expect("closed peer EOF"), 0);
}
