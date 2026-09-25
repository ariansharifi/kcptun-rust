//! Per-packet UDP I/O, the path every platform without `recvmmsg`/`sendmmsg` takes.
//!
//! Go: `readloop.go:defaultReadLoop` reads one datagram per `ReadFrom` and `tx.go:defaultTx`
//! writes one per `WriteTo`, stopping at the first error. The only difference here is that a
//! receive keeps draining datagrams that are **already queued** into the rest of the caller's
//! batch instead of returning after the first one; that is the same sequence of datagrams in the
//! same order, just handed over in fewer hops.
#![forbid(unsafe_code)]

use std::io;

use tokio::net::UdpSocket;

use crate::addr;
use crate::packet_conn::{RecvBatch, TxMsg};

/// Waits for one datagram, then fills the rest of `batch` with whatever else is already queued.
// Go: kcp-go/v5@v5.6.66 readloop.go:(*UDPSession).defaultReadLoop()
pub(crate) async fn recv_batch(socket: &UdpSocket, batch: &mut RecvBatch) -> io::Result<usize> {
    debug_assert!(!batch.is_empty());
    let mut slots = batch.iter_mut();
    let Some(mut first) = slots.next() else {
        return Ok(0);
    };
    let (n, from) = loop {
        socket.readable().await?;
        match socket.try_recv_from(first.buf_mut()) {
            Ok(result) => break result,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => continue,
            Err(err) => return Err(err),
        }
    };
    first.set_received(n, Some(from));

    let mut count = 1;
    for mut slot in slots {
        // Anything but `Ok` ends the batch: a `WouldBlock` means the queue is empty, and a real
        // error is reported by the next call, which is where Go would have seen it too.
        let Ok((n, from)) = socket.try_recv_from(slot.buf_mut()) else {
            break;
        };
        slot.set_received(n, Some(from));
        count += 1;
    }
    Ok(count)
}

/// Sends the messages one by one, returning how many went out.
// Go: kcp-go/v5@v5.6.66 tx.go:(*UDPSession).defaultTx()
pub(crate) async fn send_batch(
    socket: &UdpSocket,
    msgs: &[TxMsg<'_>],
    v6: bool,
) -> io::Result<usize> {
    let mut sent = 0;
    while sent < msgs.len() {
        let msg = &msgs[sent];
        let result = match addr::to_family(msg.addr, v6) {
            Ok(target) => socket.try_send_to(msg.data, target),
            Err(err) => Err(err),
        };
        match result {
            Ok(_) => sent += 1,
            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                if sent > 0 {
                    // A partial batch: the caller loops, as Go's `tx` does.
                    break;
                }
                socket.writable().await?;
            }
            Err(err) => {
                if sent > 0 {
                    break;
                }
                return Err(err);
            }
        }
    }
    Ok(sent)
}
