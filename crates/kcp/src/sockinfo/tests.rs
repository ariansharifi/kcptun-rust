//! Tests of [`send_queue_len`] against real sockets: a reader that stops reading makes the count
//! grow, and the count falls as soon as the reader takes data again. That fall is the signal the
//! proxy pipe relies on (D35), so it is what these pin.

use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::os::fd::AsFd;
use std::time::{Duration, Instant};

use super::*;

/// Writes into `w` until the kernel refuses more, returning how much it took.
fn fill<W: Write>(w: &mut W) -> usize {
    let chunk = [0x5au8; 16 * 1024];
    let mut total = 0;
    loop {
        match w.write(&chunk) {
            Ok(0) => return total,
            Ok(n) => total += n,
            Err(e) if e.kind() == ErrorKind::WouldBlock => return total,
            Err(e) => panic!("write: {e}"),
        }
    }
}

/// Polls `f` until it holds or `limit` passes; loopback delivery is fast but not synchronous.
fn eventually(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    f()
}

fn tcp_pair() -> (TcpStream, TcpStream) {
    let _guard = kcptun_testkit::socket_creation_guard();
    let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
    let writer = TcpStream::connect(listener.local_addr().expect("addr")).expect("connect");
    let (reader, _) = listener.accept().expect("accept");
    (writer, reader)
}

#[test]
fn an_idle_tcp_socket_has_nothing_queued() {
    let (writer, _reader) = tcp_pair();
    assert_eq!(send_queue_len(writer.as_fd()).expect("ask"), Some(0));
}

#[test]
fn a_reader_that_stops_reading_leaves_bytes_queued_and_reading_drains_them() {
    let (mut writer, mut reader) = tcp_pair();
    writer.set_nonblocking(true).expect("nonblocking");
    let written = fill(&mut writer);
    assert!(written > 0, "the kernel took nothing at all");

    // The reader's window is shut, so the tail of what was written is still ours.
    let queued = send_queue_len(writer.as_fd())
        .expect("ask")
        .expect("this platform answers");
    assert!(
        queued > 0,
        "nothing queued after {written} bytes into a full socket"
    );
    assert!(queued <= written, "{queued} queued of {written} written");

    // Reading everything the reader has opens its window again, the queue moves, and the count
    // falls. Going all the way to zero takes reading every byte.
    let mut buf = vec![0u8; 64 * 1024];
    let mut read = 0;
    let fell = eventually(Duration::from_secs(10), || {
        reader.set_nonblocking(true).expect("nonblocking");
        loop {
            match reader.read(&mut buf) {
                Ok(0) => break,
                Ok(n) => read += n,
                Err(e) if e.kind() == ErrorKind::WouldBlock => break,
                Err(e) => panic!("read: {e}"),
            }
        }
        send_queue_len(writer.as_fd()).expect("ask") == Some(0)
    });
    assert!(fell, "the queue never drained; read {read} of {written}");
    assert_eq!(read, written, "every byte arrived");
}

/// Linux counts what a unix-socket reader has not consumed; macOS keeps that data on the reader's
/// side and always says 0, which the pipe treats as "no signal".
#[test]
fn a_unix_stream_socket_answers() {
    let (mut writer, mut reader) = {
        let _guard = kcptun_testkit::socket_creation_guard();
        std::os::unix::net::UnixStream::pair().expect("pair")
    };
    writer.set_nonblocking(true).expect("nonblocking");
    let written = fill(&mut writer);
    assert!(written > 0);
    let queued = send_queue_len(writer.as_fd()).expect("ask");
    if cfg!(any(target_os = "linux", target_os = "android")) {
        let queued = queued.expect("linux answers");
        assert!(queued > 0, "nothing counted after {written} unread bytes");
        let mut buf = vec![0u8; written];
        reader.read_exact(&mut buf).expect("read");
        assert_eq!(send_queue_len(writer.as_fd()).expect("ask"), Some(0));
    } else if cfg!(target_os = "macos") {
        assert_eq!(
            queued,
            Some(0),
            "macOS keeps unix data on the reader's side"
        );
    }
}
