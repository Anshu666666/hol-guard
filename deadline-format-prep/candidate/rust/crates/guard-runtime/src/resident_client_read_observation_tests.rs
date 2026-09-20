//! Exercise the actual client read sites and deadline adapter with owned streams.
use super::*;
use crate::native_client_read_observation as observation;
use std::cell::Cell;
use std::io::{Cursor, Read, Write};

#[derive(Clone, Copy)]
enum Recovery { Absent, Error, Eof }
struct Probe {
    bytes: Cursor<Vec<u8>>,
    read_error: Option<i32>,
    setter_error: bool,
    recovery: Recovery,
    delay_until: Option<Instant>,
    reads: usize,
    writes: usize,
    setters: Cell<usize>,
    recoveries: usize,
}
impl Probe {
    fn new(bytes: Vec<u8>) -> Self {
        Self { bytes: Cursor::new(bytes), read_error: None, setter_error: false,
            recovery: Recovery::Absent, delay_until: None, reads: 0, writes: 0,
            setters: Cell::new(0), recoveries: 0 }
    }
}
impl Read for Probe {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.reads += 1;
        if let Some(deadline) = self.delay_until {
            std::thread::sleep(deadline.saturating_duration_since(Instant::now()) + Duration::from_millis(1));
        }
        if let Some(code) = self.read_error { return Err(io::Error::from_raw_os_error(code)); }
        self.bytes.read(output)
    }
}
impl Write for Probe {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> { self.writes += 1; Ok(input.len()) }
    fn flush(&mut self) -> io::Result<()> { Ok(()) }
}
impl ResidentStream for Probe {
    fn set_resident_read_timeout(&self, _: Option<Duration>) -> io::Result<()> {
        self.setters.set(self.setters.get()+1);
        if self.setter_error { Err(io::Error::from_raw_os_error(22)) } else { Ok(()) }
    }
    fn set_resident_write_timeout(&self, _: Option<Duration>) -> io::Result<()> { Ok(()) }
    fn set_resident_nonblocking(&self, _: bool) -> io::Result<()> { panic!("unexpected mode mutation") }
    fn read_buffered_after_timeout_error(&mut self, _: &mut [u8], _: &io::Error, _: Instant) -> Option<io::Result<usize>> {
        self.recoveries += 1;
        match self.recovery { Recovery::Absent => None, Recovery::Error => Some(Err(io::Error::from_raw_os_error(54))), Recovery::Eof => Some(Ok(0)) }
    }
}
fn header() -> Vec<u8> {
    let mut header = RESPONSE_MAGIC.to_vec();
    header.extend_from_slice(&[3u8; FRAME_REQUEST_ID_BYTES]);
    header.extend_from_slice(&Sha256::digest(b"{}"));
    header.extend_from_slice(&2u32.to_be_bytes());
    header
}
fn assert_failure(error: ResidentClientError, phase: u8, origin: u8, raw: Option<i32>) {
    assert_eq!(error.code,"native_client_frame_read_failed");
    assert!(!error.retryable_teardown);
    let observed = observation::take().expect("actual read failure must be recorded");
    assert_eq!((observed.phase,observed.origin,observed.raw_os_error),(phase,origin,raw));
}
#[test]
fn actual_authentication_proof_read_preserves_native_error() {
    let mut probe = Probe::new(vec![]); probe.read_error = Some(54);
    let mut stream = DeadlineStream::new(&mut probe, Instant::now()+Duration::from_secs(5));
    let error = authenticate(&mut stream,&[7u8;32],Duration::from_secs(5)).unwrap_err();
    assert_failure(error,1,4,Some(54));
    assert_eq!((probe.reads,probe.writes,probe.recoveries),(1,1,0));
}
#[test]
fn actual_response_header_eof_is_not_body_or_authentication() {
    let mut probe = Probe::new(vec![]);
    let error = read_committed_response(&mut DeadlineStream::new(&mut probe,Instant::now()+Duration::from_secs(5)),&[3;FRAME_REQUEST_ID_BYTES]).unwrap_err();
    assert_failure(error,2,6,None); assert_eq!(probe.reads,1);
}
#[test]
fn actual_bound_response_body_eof_is_distinct() {
    let mut probe = Probe::new(header());
    let error = read_committed_response(&mut DeadlineStream::new(&mut probe,Instant::now()+Duration::from_secs(5)),&[3;FRAME_REQUEST_ID_BYTES]).unwrap_err();
    assert_failure(error,3,6,None); assert_eq!(probe.reads,2);
}
#[test]
fn actual_pre_read_deadline_makes_no_setter_or_read_call() {
    let mut probe = Probe::new(vec![]);
    let error = read_committed_response(&mut DeadlineStream::new(&mut probe,Instant::now()),&[3;FRAME_REQUEST_ID_BYTES]).unwrap_err();
    assert_failure(error,2,1,None); assert_eq!((probe.reads,probe.setters.get()),(0,0));
}
#[test]
fn actual_setter_failure_and_recovery_have_separate_origins() {
    for (recovery,origin,raw) in [(Recovery::Absent,2,Some(22)),(Recovery::Error,3,Some(54)),(Recovery::Eof,8,None)] {
        let mut probe = Probe::new(vec![]); probe.setter_error=true; probe.recovery=recovery;
        let error = read_committed_response(&mut DeadlineStream::new(&mut probe,Instant::now()+Duration::from_secs(5)),&[3;FRAME_REQUEST_ID_BYTES]).unwrap_err();
        assert_failure(error,2,origin,raw); assert_eq!((probe.reads,probe.setters.get(),probe.recoveries),(0,1,1));
    }
}
#[test]
fn actual_post_read_deadline_keeps_original_rejection() {
    // Fixture-only admission window: expiry happens inside the one owned read.
    // This is not a production or original-selector deadline change.
    let deadline=Instant::now()+Duration::from_secs(5);
    let mut probe=Probe::new(header()); probe.delay_until=Some(deadline);
    let error=read_committed_response(&mut DeadlineStream::new(&mut probe,deadline),&[3;FRAME_REQUEST_ID_BYTES]).unwrap_err();
    assert_failure(error,2,5,None); assert_eq!(probe.reads,1);
}
#[test]
fn actual_successful_bound_response_keeps_bytes_without_failure() {
    let _=observation::take();
    let mut bytes=header();bytes.extend_from_slice(b"{}");
    let mut probe=Probe::new(bytes);
    let response=read_committed_response(&mut DeadlineStream::new(&mut probe,Instant::now()+Duration::from_secs(5)),&[3;FRAME_REQUEST_ID_BYTES]).unwrap();
    assert_eq!(response,b"{}");assert_eq!(probe.reads,2);assert!(observation::take().is_none());
}
