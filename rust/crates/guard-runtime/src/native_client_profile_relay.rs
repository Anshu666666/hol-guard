//! A separate pipe at each process hop; one process writes each captured pipe.
use std::io::{BufRead, BufReader, Read, Write};
use std::sync::{mpsc, Mutex};
use std::time::{Duration, Instant};

static RELAYS: Mutex<Vec<mpsc::Receiver<()>>> = Mutex::new(Vec::new());
const MAX_RELAYS: usize = 32;
const MAX_RECORDS: usize = 2048;
const MAX_LINE: usize = 4096;

fn terminal(child: u32, records: usize, complete: bool) {
    let value = serde_json::json!({
        "schema": "hol-guard.native-resident-profile-relay.v1",
        "parent_process_id": std::process::id(), "child_process_id": child,
        "records": records, "complete": complete,
    });
    if let Ok(mut bytes) = serde_json::to_vec(&value) {
        bytes.push(b'\n');
        let _ = std::io::stderr().lock().write_all(&bytes);
    }
}

fn forward(reader: impl Read, child: u32) {
    let (count, complete) = forward_lines(reader, |line| std::io::stderr().lock().write_all(line));
    terminal(child, count, complete);
}

fn forward_lines(
    reader: impl Read,
    mut write: impl FnMut(&[u8]) -> std::io::Result<()>,
) -> (usize, bool) {
    let mut reader = BufReader::new(reader);
    let mut count = 0;
    let complete = loop {
        let mut line = Vec::with_capacity(1024);
        let read = reader
            .by_ref()
            .take((MAX_LINE + 1) as u64)
            .read_until(b'\n', &mut line);
        match read {
            Ok(0) => break true,
            Ok(_) if line.len() <= MAX_LINE && line.ends_with(b"\n") && count < MAX_RECORDS => {
                // The local emitter takes this same process-wide lock. No
                // child shares this write handle; its stderr has another pipe.
                if write(&line).is_err() {
                    break false;
                }
                count += 1;
            }
            _ => break false,
        }
    };
    (count, complete)
}

pub(crate) fn start_relay(reader: impl Read + Send + 'static, child: u32) {
    let (send, receive) = mpsc::channel();
    let Ok(mut relays) = RELAYS.lock() else {
        terminal(child, 0, false);
        return;
    };
    if relays.len() >= MAX_RELAYS {
        terminal(child, 0, false);
        return;
    }
    match std::thread::Builder::new()
        .name("native-profile-relay".into())
        .spawn(move || {
            forward(reader, child);
            let _ = send.send(());
        }) {
        Ok(_) => relays.push(receive),
        Err(_) => terminal(child, 0, false),
    }
}

pub(crate) fn drain() {
    let deadline = Instant::now() + Duration::from_secs(2);
    let Ok(mut relays) = RELAYS.lock() else {
        terminal(0, 0, false);
        return;
    };
    for relay in relays.drain(..) {
        if relay
            .recv_timeout(deadline.saturating_duration_since(Instant::now()))
            .is_err()
        {
            terminal(0, 0, false);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{self, Cursor};

    #[test]
    fn forwards_complete_large_lines_without_cross_process_writers() {
        let mut bytes = vec![b'a'; 4095];
        bytes.push(b'\n');
        bytes.extend(b"second\n");
        let mut captured = Vec::new();
        let result = forward_lines(Cursor::new(&bytes), |line| {
            captured.push(line.to_vec());
            Ok(())
        });
        assert_eq!(result, (2, true));
        assert_eq!(captured.concat(), bytes);
        assert_eq!(captured[0].len(), 4096);
    }

    #[test]
    fn partial_overlong_io_and_record_cap_remain_incomplete() {
        for bytes in [
            b"partial".to_vec(),
            vec![b'x'; 4097],
            b"x\n".repeat(MAX_RECORDS + 1),
        ] {
            let result = forward_lines(Cursor::new(bytes), |_| Ok(()));
            assert!(!result.1);
        }
        assert_eq!(
            forward_lines(Cursor::new(b"line\n"), |_| Err(
                io::ErrorKind::BrokenPipe.into()
            )),
            (0, false)
        );
        struct Failed;
        impl Read for Failed {
            fn read(&mut self, _: &mut [u8]) -> io::Result<usize> {
                Err(io::ErrorKind::BrokenPipe.into())
            }
        }
        assert_eq!(forward_lines(Failed, |_| Ok(())), (0, false));
    }

    #[test]
    fn drain_waits_for_eof_terminal_before_command_exit() {
        let (send, receive) = mpsc::channel();
        RELAYS.lock().unwrap().push(receive);
        let emitted = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let produced = emitted.clone();
        let thread = std::thread::spawn(move || {
            produced.store(true, std::sync::atomic::Ordering::Release);
            send.send(()).unwrap();
        });
        drain();
        assert!(emitted.load(std::sync::atomic::Ordering::Acquire));
        thread.join().unwrap();
    }
}
