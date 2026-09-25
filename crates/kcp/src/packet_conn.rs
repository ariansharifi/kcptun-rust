//! The packet connection a KCP session or listener runs on.
//!
//! Go passes a `net.PacketConn` around (`sess.go`), and on Linux additionally asks it for the
//! batch interface `batchConn` (`platform_linux.go`), which is `x/net/ipv4.PacketConn`'s
//! `ReadBatch`/`WriteBatch`: `recvmmsg`/`sendmmsg` under the hood. Everything that is not a UDP
//! socket (notably `tcpraw`) goes through the per-packet path instead.
//!
//! [`PacketConn`] merges the two into a single batch interface, so that the session and the
//! listener have one code path: the UDP implementation ([`crate::io::UdpPacketConn`]) uses
//! `recvmmsg`/`sendmmsg` where they exist and loops over `recvfrom`/`sendto` elsewhere, and
//! `tcpraw` (Step 10) implements the same trait over its raw sockets.
//!
//! The trait is dyn-compatible (sessions accepted by a listener share the listener's socket as an
//! `Arc<dyn PacketConn>`), which is why the two I/O methods return boxed futures. One box per
//! batch of up to [`BATCH_SIZE`] datagrams is not measurable next to the syscall it wraps.
//!
//! Go reference: kcp-go/v5@v5.6.66 `readloop.go`, `readloop_linux.go`, `tx.go`, `tx_linux.go`.
#![forbid(unsafe_code)]

use std::fmt;
use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::pin::Pin;

use crate::crypt::MTU_LIMIT;

/// Datagrams per batched receive, the size of Go's `msgs` array.
// Go: kcp-go/v5@v5.6.66 readloop_linux.go:batchSize
pub const BATCH_SIZE: usize = 256;

/// The 12.3c fix depends on a full batch being a *large* allocation: glibc's default `mmap`
/// threshold is 128 kB, and only above it does `calloc` hand back a fresh anonymous mapping it
/// already knows to be zero, instead of a binned block it has to memset, which faults every page
/// of an idle session's batch. Shrinking [`BATCH_SIZE`] below that line would silently undo the
/// 435 kB → 55 kB result with the whole test suite still green, so it fails the build instead.
/// See `docs/benchmarks/memory.md` §7.
const _: () = assert!(
    BATCH_SIZE * MTU_LIMIT >= 128 * 1024,
    "the batch must stay above glibc's default mmap threshold or calloc memsets it again: docs/benchmarks/memory.md §7"
);

/// A boxed future, as returned by the I/O methods of [`PacketConn`].
pub type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// The result of the last datagram read into one slot of a [`RecvBatch`].
#[derive(Clone, Copy, Debug, Default)]
struct SlotMeta {
    /// How much of the slot's [`MTU_LIMIT`] bytes the datagram filled.
    n: usize,
    /// Who sent it, where the transport reports a sender.
    addr: Option<SocketAddr>,
}

/// A batch of receive slots: Go's `msgs := make([]ipv4.Message, batchSize)`, each message
/// carrying one `mtuLimit`-byte buffer.
///
/// Allocated once per read loop and reused for every receive, as in `readloop_linux.go`.
///
/// # Why the buffers are one allocation (plan 12.3c)
///
/// The obvious port of Go's loop is one `vec![0u8; MTU_LIMIT]` per slot, and that is what this
/// type replaced. It cost **384 kB of resident memory per client session, on a session that had
/// never received a single datagram**, and it was the largest single item in the 698 kB per-idle-
/// session slope that `docs/benchmarks/memory.md` §3 measured against Go's 243 kB.
///
/// Go allocates exactly the same 256 × 1500 bytes and pays almost none of it, because its
/// allocator knows a freshly mapped span is already zero and skips the clear (`runtime.mallocgc`,
/// `needzero`): the pages stay untouched until a datagram lands in one, and RSS counts resident,
/// not allocated. A 1500-byte `vec![0u8; _]` gets no such treatment: `calloc` of a small block
/// is served from the allocator's bins and memset, which faults every page of all 256 buffers
/// immediately.
///
/// One contiguous `MTU_LIMIT * slots` allocation restores Go's behaviour without changing the
/// batch size: at `BATCH_SIZE` the region is 384 kB, which is above the default `mmap` threshold
/// of glibc (128 kB) and above macOS's large-allocation threshold, so on those two it is served
/// by a fresh anonymous mapping that `calloc` already knows to be zero and does not touch. The
/// pages become resident as datagrams arrive in them and no sooner, so a batch costs what it
/// uses. The slots are laid out back to back in that one region, which the
/// `slots_are_one_contiguous_allocation` test below pins down.
///
/// That is a *measured* property of those two allocators, not something the size guarantees.
/// **Static musl (mallocng) and mimalloc are measured counterexamples**: mallocng memsets every
/// `calloc` at every size, and mimalloc commits the segment a large object lands in, which makes
/// the single big allocation worse than the 256 small ones. glibc's threshold is dynamic as well
/// (freeing a large mapped chunk raises it), so a batch that is freed and re-allocated: session
/// churn: need not be treated like the first one.
///
/// The measurement, and the allocators this does *not* fix, are in
/// `docs/benchmarks/memory.md` §7: 435 kB → 55 kB of RSS per idle client session on glibc (Go
/// pays 243 kB), 476 → 63 kB on macOS, 595 → 455 kB on static musl and 517 → 645 kB on
/// musl + mimalloc.
// Go: kcp-go/v5@v5.6.66 readloop_linux.go (`msgs := make([]ipv4.Message, batchSize)`,
//     `msgs[k].Buffers = [][]byte{make([]byte, mtuLimit)}`)
pub struct RecvBatch {
    /// `meta.len() * MTU_LIMIT` bytes: every slot's buffer, back to back.
    data: Box<[u8]>,
    /// One result per slot.
    meta: Box<[SlotMeta]>,
}

impl RecvBatch {
    /// A batch of `slots` empty slots, each with a [`MTU_LIMIT`]-byte buffer.
    ///
    /// # Panics
    ///
    /// If `slots * MTU_LIMIT` does not fit in a `usize`. The product is checked rather than
    /// wrapped (`docs/porting-guide.md` §4 wraps *protocol* arithmetic, not allocation sizes):
    /// a wrapped length would leave `data` shorter than `meta.len()` whole slots and break the
    /// invariant on [`iter_mut`](Self::iter_mut) that
    /// [`RecvScratch::recvmmsg`](crate::io) depends on.
    pub fn new(slots: usize) -> RecvBatch {
        let bytes = slots
            .checked_mul(MTU_LIMIT)
            .expect("batch byte length overflows usize");
        RecvBatch {
            // `into_boxed_slice` on a `Vec` whose length is its capacity does not reallocate, so
            // this is the single zeroed allocation the type documentation describes.
            data: vec![0u8; bytes].into_boxed_slice(),
            meta: vec![SlotMeta::default(); slots].into_boxed_slice(),
        }
    }

    /// How many slots the batch has.
    ///
    /// This is exactly the number of slots [`iter_mut`](Self::iter_mut) yields, see there.
    pub fn len(&self) -> usize {
        self.meta.len()
    }

    /// Whether the batch has no slots at all.
    pub fn is_empty(&self) -> bool {
        self.meta.is_empty()
    }

    /// Every slot in order, borrowed for writing.
    ///
    /// **Invariant:** this yields exactly [`len`](Self::len) slots, because `new` allocates
    /// `meta.len()` whole `MTU_LIMIT` chunks. The Linux batch path relies on it: `recvmmsg`
    /// takes `vlen = batch.len()` and fills one `iovec` per slot this iterator yields, so a
    /// shorter iterator would hand the kernel message headers pointing at stale `iovec`s.
    pub fn iter_mut(&mut self) -> impl ExactSizeIterator<Item = RecvSlot<'_>> {
        // `data` is exactly `meta.len()` whole chunks long, so the remainder is always empty.
        let (chunks, _) = self.data.as_chunks_mut::<MTU_LIMIT>();
        chunks
            .iter_mut()
            .zip(self.meta.iter_mut())
            .map(|(buf, meta)| RecvSlot {
                buf: buf.as_mut_slice(),
                meta,
            })
    }

    /// One slot by index, or `None` past the end.
    pub fn slot_mut(&mut self, index: usize) -> Option<RecvSlot<'_>> {
        // The bound check comes first: `index * MTU_LIMIT` would otherwise panic in a debug
        // build (and wrap in a release one) for an index this returns `None` for.
        let meta = self.meta.get_mut(index)?;
        let start = index * MTU_LIMIT;
        let buf = self
            .data
            .get_mut(start..start + MTU_LIMIT)
            .expect("`data` holds `meta.len()` whole slots");
        Some(RecvSlot { buf, meta })
    }
}

impl fmt::Debug for RecvBatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvBatch")
            .field("slots", &self.meta.len())
            .field("slot_cap", &MTU_LIMIT)
            .finish()
    }
}

/// One slot of a [`RecvBatch`], borrowed: a [`MTU_LIMIT`]-byte buffer plus the result of the
/// datagram that was read into it.
// Go: kcp-go/v5@v5.6.66 readloop_linux.go (`msgs[k].Buffers[0]`, `msg.N`, `msg.Addr`)
pub struct RecvSlot<'a> {
    buf: &'a mut [u8],
    meta: &'a mut SlotMeta,
}

impl RecvSlot<'_> {
    /// The datagram most recently read into this slot (empty before the first one).
    pub fn data(&self) -> &[u8] {
        &self.buf[..self.meta.n]
    }

    /// The datagram most recently read into this slot, mutably.
    ///
    /// The input pipeline decrypts in place (Go's `packetInput` decrypts into the same buffer
    /// and re-slices it), so the read loop hands it this rather than [`data`](Self::data).
    pub fn data_mut(&mut self) -> &mut [u8] {
        &mut self.buf[..self.meta.n]
    }

    /// The sender of the datagram in [`data`](Self::data), if the transport reports one.
    pub fn addr(&self) -> Option<SocketAddr> {
        self.meta.addr
    }

    /// The writable buffer, [`MTU_LIMIT`] bytes long.
    ///
    /// For [`PacketConn`] implementors: the buffer a datagram is read into, before
    /// [`set_received`](Self::set_received) records how much of it was filled.
    pub fn buf_mut(&mut self) -> &mut [u8] {
        self.buf
    }

    /// Records the result of a receive: `n` bytes (clamped to the buffer, as a truncated datagram
    /// only fills it) from `addr`.
    ///
    /// For [`PacketConn`] implementors: the other half of
    /// [`buf_mut`](Self::buf_mut), called once the datagram is in the buffer.
    pub fn set_received(&mut self, n: usize, addr: Option<SocketAddr>) {
        self.meta.n = n.min(self.buf.len());
        self.meta.addr = addr;
    }
}

impl fmt::Debug for RecvSlot<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RecvSlot")
            .field("len", &self.meta.n)
            .field("cap", &self.buf.len())
            .field("addr", &self.meta.addr)
            .finish()
    }
}

/// One datagram to transmit: Go's `ipv4.Message` with a single buffer.
// Go: kcp-go/v5@v5.6.66 sess.go:txqueue (`ipv4.Message{Buffers: [][]byte{...}, Addr: ...}`)
#[derive(Clone, Copy, Debug)]
pub struct TxMsg<'a> {
    /// The payload.
    pub data: &'a [u8],
    /// The destination.
    pub addr: SocketAddr,
}

impl<'a> TxMsg<'a> {
    /// A message carrying `data` to `addr`.
    pub fn new(data: &'a [u8], addr: SocketAddr) -> Self {
        TxMsg { data, addr }
    }
}

/// The packet transport of a session or listener.
///
/// All methods take `&self`: a session reads and writes concurrently, and every accepted session
/// of a listener shares one socket.
///
/// **Contract**
///
/// - [`recv_batch`](PacketConn::recv_batch) waits for at least one datagram, fills the batch's
///   first `n` slots in arrival order and returns `n ≥ 1` (`0` only for an empty batch). An error
///   is final for the caller's read loop, as it is for Go's `ReadFrom`/`ReadBatch`.
/// - [`send_batch`](PacketConn::send_batch) returns how many **messages** it sent, which may be
///   fewer than `msgs.len()`. The caller must resend the remainder, exactly as Go's
///   `tx` does (`for len(txqueue) > 0 { n, err := WriteBatch(txqueue, 0); …; txqueue = txqueue[n:] }`).
///   It returns an error only when nothing was sent; a failure after a partial batch surfaces on
///   the next call.
/// - The setters return Go's `invalid operation` error when the transport does not support them.
/// - [`close`](PacketConn::close) is idempotent in effect but reports the second call, like Go's
///   `net.UDPConn.Close` (`use of closed network connection`); afterwards the I/O methods fail.
// Go: kcp-go/v5@v5.6.66 sess.go (net.PacketConn), platform_linux.go (batchConn)
pub trait PacketConn: Send + Sync + 'static {
    /// Receives datagrams into `batch`, returning how many slots were filled.
    fn recv_batch<'a>(&'a self, batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>>;

    /// Sends a batch of datagrams, returning how many messages were sent (see the contract).
    fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>>;

    /// The local address of the transport.
    fn local_addr(&self) -> io::Result<SocketAddr>;

    /// Sets the receive buffer size (`SO_RCVBUF`).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetReadBuffer()
    fn set_read_buffer(&self, bytes: usize) -> io::Result<()>;

    /// Sets the send buffer size (`SO_SNDBUF`).
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetWriteBuffer()
    fn set_write_buffer(&self, bytes: usize) -> io::Result<()>;

    /// Sets the DSCP code point of outgoing packets.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetDSCP()
    fn set_dscp(&self, dscp: i32) -> io::Result<()>;

    /// Closes the transport.
    fn close(&self) -> io::Result<()>;
}

/// Go's `errInvalidOperation`, returned by transports that do not support an option.
// Go: kcp-go/v5@v5.6.66 sess.go:errInvalidOperation
pub fn invalid_operation() -> io::Error {
    io::Error::new(io::ErrorKind::Unsupported, "invalid operation")
}

#[cfg(test)]
mod tests {
    //! The trait has to be implementable from *outside* this crate (`kcptun-tcpraw`, Step 10),
    //! so this dummy transport deliberately uses nothing but the public API of this module.
    use std::sync::Mutex;

    use super::*;

    /// A loopback transport: `send_batch` queues the datagrams, `recv_batch` hands them back.
    struct Loopback {
        queue: Mutex<Vec<(Vec<u8>, SocketAddr)>>,
    }

    impl PacketConn for Loopback {
        fn recv_batch<'a>(&'a self, batch: &'a mut RecvBatch) -> BoxFuture<'a, io::Result<usize>> {
            Box::pin(async move {
                let mut queue = self.queue.lock().expect("queue");
                let n = queue.len().min(batch.len());
                for (mut slot, (data, addr)) in batch.iter_mut().zip(queue.drain(..n)) {
                    let len = data.len().min(slot.buf_mut().len());
                    slot.buf_mut()[..len].copy_from_slice(&data[..len]);
                    slot.set_received(len, Some(addr));
                }
                Ok(n)
            })
        }

        fn send_batch<'a>(&'a self, msgs: &'a [TxMsg<'a>]) -> BoxFuture<'a, io::Result<usize>> {
            Box::pin(async move {
                let mut queue = self.queue.lock().expect("queue");
                for msg in msgs {
                    queue.push((msg.data.to_vec(), msg.addr));
                }
                Ok(msgs.len())
            })
        }

        fn local_addr(&self) -> io::Result<SocketAddr> {
            Ok("127.0.0.1:0".parse().expect("literal"))
        }

        fn set_read_buffer(&self, _bytes: usize) -> io::Result<()> {
            Err(invalid_operation())
        }

        fn set_write_buffer(&self, _bytes: usize) -> io::Result<()> {
            Err(invalid_operation())
        }

        fn set_dscp(&self, _dscp: i32) -> io::Result<()> {
            Err(invalid_operation())
        }

        fn close(&self) -> io::Result<()> {
            Ok(())
        }
    }

    /// Guards the API surface Step 10's `kcptun-tcpraw` needs: a foreign implementor must be able
    /// to fill a [`RecvSlot`], and the trait must stay dyn-compatible.
    #[test]
    fn foreign_implementor_can_fill_slots() {
        let conn: Box<dyn PacketConn> = Box::new(Loopback {
            queue: Mutex::new(Vec::new()),
        });
        let peer: SocketAddr = "10.0.0.1:29900".parse().expect("literal");
        let rt = tokio::runtime::Builder::new_current_thread()
            .build()
            .expect("runtime");
        rt.block_on(async {
            let sent = conn
                .send_batch(&[TxMsg::new(b"hello", peer), TxMsg::new(b"world", peer)])
                .await
                .expect("send");
            assert_eq!(sent, 2);

            let mut batch = RecvBatch::new(4);
            let n = conn.recv_batch(&mut batch).await.expect("recv");
            assert_eq!(n, 2);
            let filled: Vec<(Vec<u8>, Option<SocketAddr>)> = batch
                .iter_mut()
                .take(n)
                .map(|slot| (slot.data().to_vec(), slot.addr()))
                .collect();
            assert_eq!(filled[0].0, b"hello");
            assert_eq!(filled[1].0, b"world");
            assert_eq!(filled[0].1, Some(peer));
        });
        assert!(conn.set_dscp(46).is_err());
        conn.close().expect("close");
    }

    /// A fresh batch has `slots` empty slots of [`MTU_LIMIT`] bytes each, and no slot beyond.
    #[test]
    fn a_new_batch_is_empty_slots_of_one_mtu() {
        let mut batch = RecvBatch::new(BATCH_SIZE);
        assert_eq!(batch.len(), BATCH_SIZE);
        assert!(!batch.is_empty());
        assert_eq!(batch.iter_mut().len(), BATCH_SIZE);
        for mut slot in batch.iter_mut() {
            assert_eq!(slot.data(), b"");
            assert_eq!(slot.addr(), None);
            assert_eq!(slot.buf_mut().len(), MTU_LIMIT);
        }
        assert!(batch.slot_mut(BATCH_SIZE).is_none());

        let empty = RecvBatch::new(0);
        assert_eq!(empty.len(), 0);
        assert!(empty.is_empty());
    }

    /// An index far past the end is `None`, not an overflowed range: `slot_mut` bound-checks
    /// before it multiplies, so `index * MTU_LIMIT` can neither panic in a debug build nor wrap
    /// in a release one.
    #[test]
    fn a_far_out_of_range_slot_index_is_none() {
        let mut batch = RecvBatch::new(4);
        assert!(batch.slot_mut(4).is_none());
        assert!(batch.slot_mut(usize::MAX / MTU_LIMIT + 1).is_none());
        assert!(batch.slot_mut(usize::MAX).is_none());
    }

    /// **The 12.3c fix.** Every slot's buffer is a window into one allocation, laid out back to
    /// back with no gap, which is what makes the batch a single `MTU_LIMIT * slots` `calloc`
    /// that the allocator serves from a fresh anonymous mapping and never touches (see
    /// [`RecvBatch`]). Per-slot `vec![0u8; MTU_LIMIT]`s would be 256 separate small blocks,
    /// memset one by one, and would fault 384 kB per session before a single datagram arrived.
    #[test]
    fn slots_are_one_contiguous_allocation() {
        let mut batch = RecvBatch::new(BATCH_SIZE);
        let starts: Vec<usize> = batch
            .iter_mut()
            .map(|mut slot| slot.buf_mut().as_ptr().addr())
            .collect();
        assert_eq!(starts.len(), BATCH_SIZE);
        for (i, window) in starts.windows(2).enumerate() {
            assert_eq!(
                window[1] - window[0],
                MTU_LIMIT,
                "slot {} does not sit one MTU after slot {i}",
                i + 1
            );
        }
    }

    /// Slots do not overlap: what one receive writes stays in its own slot.
    #[test]
    fn slots_do_not_overlap() {
        let mut batch = RecvBatch::new(4);
        for (i, mut slot) in batch.iter_mut().enumerate() {
            let byte = b'a' + u8::try_from(i).expect("small");
            slot.buf_mut().fill(byte);
            slot.set_received(3, None);
        }
        let seen: Vec<Vec<u8>> = batch.iter_mut().map(|slot| slot.data().to_vec()).collect();
        assert_eq!(
            seen,
            vec![
                b"aaa".to_vec(),
                b"bbb".to_vec(),
                b"ccc".to_vec(),
                b"ddd".to_vec()
            ]
        );
    }

    /// `set_received` clamps to the buffer, as a truncated datagram can only have filled it, and
    /// `data`/`data_mut` then agree on that length.
    #[test]
    fn set_received_clamps_to_the_buffer() {
        let peer: SocketAddr = "10.0.0.2:29900".parse().expect("literal");
        let mut batch = RecvBatch::new(1);
        let mut slot = batch.slot_mut(0).expect("slot 0");
        slot.buf_mut().fill(0xAB);
        slot.set_received(MTU_LIMIT + 4096, Some(peer));
        assert_eq!(slot.data().len(), MTU_LIMIT);
        assert_eq!(slot.data_mut().len(), MTU_LIMIT);
        assert_eq!(slot.addr(), Some(peer));

        // And a later, shorter datagram re-slices the same buffer rather than growing it.
        slot.set_received(7, None);
        assert_eq!(slot.data(), &[0xAB; 7]);
        assert_eq!(slot.addr(), None);
    }
}
