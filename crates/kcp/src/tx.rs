//! The outgoing packet pipeline of a session (port of kcp-go `sess.go:postProcess` and
//! `tx.go`/`tx_linux.go`).
//!
//! ```text
//! KCP output ─▶ FEC encoding ─▶ CRC32 integrity ─▶ encryption ─▶ TxQueue ─▶ rate limit ─▶ socket
//! ```
//!
//! kcp-go keeps this whole pipeline out of the session mutex by handing packets to a goroutine
//! over a buffered channel (`chPostProcessing`, 2048 deep). The KCP output callback, which runs
//! **under** the lock, only copies the segment into a pooled buffer and does a non-blocking send;
//! if the channel is full the packet is dropped and KCP retransmits it. This module is the same
//! design (DECISIONS D04): [`TxHandle::send`] is the non-blocking producer the session calls from
//! the output callback, [`TxPipeline::run`] is the consumer task.
//!
//! **Deviation V18.** The one thing the port does not copy is *what happens when the channel is
//! full*. Dropping there is invisible to KCP: the segment has already been counted as
//! transmitted, so every dropped packet of a burst costs a retransmission timeout. Instead
//! [`TxHandle::capacity`] reports the free slots, `Kcp::flush` stops emitting before it touches a
//! segment that would not fit, and the rest goes out on the next flush. [`SendOutcome::Dropped`]
//! is still possible (an OOB packet, or a race with another producer), just no longer the way a
//! large send window behaves.
//!
//! Batching follows `postProcess` exactly: packets accumulate in a queue until the channel is
//! empty or the queue holds [`MAX_BATCH_SIZE`] messages, at which point the whole batch is paced
//! through the rate limiter (bytes, not packets) and written with one
//! [`PacketConn::send_batch`] (`sendmmsg` on Linux). The buffers then go back to the pool, which
//! for Go is a loop of `defaultBufferPool.Put` and here is `Drop` (see [`crate::bufpool`]).
//!
//! `postProcess` itself already drains on close: its `die` case does `chDie = nil; continue`
//! while `chPostProcessing` is non-empty and only returns once the channel is empty
//! (sess.go:752-758). [`TxPipeline::run`] reproduces that with a `biased` select, tokio's
//! `select!` being random by default.
//!
//! **Deviation V05.** What Go does lose on close is the packet that is still being *handed over*:
//! its output callback and `SendOOB` select `<-s.die` against the channel send, so once `die` is
//! closed each queued packet has about an even chance of being dropped instead. [`TxHandle::send`]
//! has no such race, so the final flush is queued deterministically. The other half of the
//! deviation (queueing that flush before signalling `die`) belongs to the session (05.4).
//!
//! Not ported: Go's `s.kcp.debugLog(IKCP_LOG_OUTPUT, …)` after each batch. The trace logger lives
//! in the `Kcp`, which is behind the session mutex here (Go reads it from this goroutine without
//! the lock); the session wires it up in 05.4 if the `trace` feature needs it.
#![forbid(unsafe_code)]

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

use crate::bufpool::{BufferPool, PacketBuf};
use crate::clock::{Clock, MonotonicMs, SystemClock};
use crate::crypt::{CRYPT_HEADER_SIZE, NONCE_SIZE, PacketCrypt};
use crate::entropy;
use crate::error_slot::ErrorSlot;
use crate::fec::{FecEncoder, MAX_FEC_ENCODE_LATENCY};
use crate::packet_conn::{PacketConn, TxMsg};
use crate::rate::Limiter;
use crate::snmp::DEFAULT_SNMP;

/// Packets written to the socket in one batch.
// Go: kcp-go/v5@v5.6.66 sess.go:maxBatchSize
pub const MAX_BATCH_SIZE: usize = 64;

/// Depth of a session's packet channel: Go's value.
///
/// One `flush()` can emit up to a full send window of packets, so with kcptun's production
/// profile (`-sndwnd 8192`) a burst is four times this bound. Go drops the surplus in its output
/// callback, which costs a retransmission timeout per lost packet; **Deviation V18** stops
/// `Kcp::flush` before it touches a segment it cannot hand over instead (see
/// [`TxHandle::capacity`] and `Output::capacity`), so the burst is spread over the next flushes
/// and the bound can stay where Go has it. Step 05.10 had raised it to 8192 as a stopgap
/// (Deviation V13, now superseded): the 05.9 echo baseline went from 12.9 MiB/s to 90.9-95.2
/// (8 MiB, `-crypt xor`, no FEC, windows 8192, macOS arm64), and backpressure holds that without
/// the extra depth.
///
/// Nothing is preallocated: `tokio::sync::mpsc` grows its block list on demand and the capacity is
/// only a bound. What the bound does buy is burst memory: at most this many pooled 1500-byte
/// buffers (about 3 MB) can be queued at once, a quarter of what a window-sized channel allowed.
// Go: kcp-go/v5@v5.6.66 sess.go:devBacklog
pub const DEV_BACKLOG: usize = 2048;

/// A packet on its way from KCP (or [`SendOOB`](TxHandle::send)) to the wire.
///
/// The buffer holds the finished packet with `header_size` bytes of room in front of it for the
/// crypto and FEC headers, exactly as Go's `defaultBufferPool.Get()[:size+sess.headerSize]`.
// Go: kcp-go/v5@v5.6.66 sess.go:sendRequest
#[derive(Debug)]
pub struct SendRequest {
    buffer: PacketBuf,
    oob: bool,
}

impl SendRequest {
    /// A normal packet: FEC-encoded as a data shard, and it may produce parity.
    pub fn data(buffer: PacketBuf) -> SendRequest {
        SendRequest { buffer, oob: false }
    }

    /// An out-of-band packet: sealed with the OOB FEC header, never FEC-protected.
    ///
    /// The caller must have FEC enabled: Go's `SendOOB` refuses with `OOB requires FEC to be
    /// enabled` (sess.go:856) when `fecEncoder == nil`, and without an encoder this packet would
    /// go out with no OOB header at all.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SendOOB() (`sendRequest{buf, true}`)
    pub fn oob(buffer: PacketBuf) -> SendRequest {
        SendRequest { buffer, oob: true }
    }
}

/// What [`TxHandle::send`] did with a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SendOutcome {
    /// Queued for the tx task.
    Queued,
    /// The channel was full: the packet was dropped and its buffer recycled. KCP retransmits it;
    /// an OOB packet is lost (Go returns `nil` for that, OOB being best-effort).
    Dropped,
    /// The tx task is gone, so the session is closed (Go's `case <-s.die`, which makes `SendOOB`
    /// return `io.ErrClosedPipe`).
    Closed,
}

/// The state a session shares with its tx task.
// Go: the `dup`, `rateLimiter` and `socketWriteError` fields of `UDPSession`
#[derive(Debug, Default)]
pub struct TxShared {
    /// Go's `dup`: how many extra copies of every packet to send (testing only).
    dup: AtomicUsize,
    /// Go's `rateLimiter`; unlimited until `-ratelimit` sets a rate.
    limiter: Limiter,
    /// Go's `socketWriteError` + `chSocketWriteError`.
    write_error: ErrorSlot,
}

impl TxShared {
    /// Number of duplicate copies sent after every packet.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetDUP()
    pub fn dup(&self) -> usize {
        self.dup.load(Ordering::Relaxed)
    }

    /// Sets the number of duplicate copies (testing only; Go's `SetDUP`).
    pub fn set_dup(&self, dup: usize) {
        self.dup.store(dup, Ordering::Relaxed);
    }

    /// The rate limiter the tx task paces batches with.
    pub fn limiter(&self) -> &Limiter {
        &self.limiter
    }

    /// Sets the rate limit in bytes per second; `0` disables pacing.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).SetRateLimit()
    pub fn set_rate_limit(&self, bytes_per_second: u32) {
        self.limiter.set_rate(bytes_per_second);
    }

    /// The first error the socket reported while writing, if any.
    pub fn write_error(&self) -> &ErrorSlot {
        &self.write_error
    }
}

/// Everything [`channel`] needs to build a session's tx pipeline.
pub struct TxConfig<C = SystemClock> {
    /// The socket the packets go out on (shared with the listener for accepted sessions).
    pub conn: Arc<dyn PacketConn>,
    /// The peer (Go's `s.remote`), the destination of every packet.
    pub remote: SocketAddr,
    /// The packet cipher, or `None` for `-crypt null`.
    pub block: Option<PacketCrypt>,
    /// The FEC encoder, or `None` when FEC is disabled.
    pub fec_encoder: Option<FecEncoder>,
    /// Where packet buffers come from and go back to.
    pub pool: Arc<BufferPool>,
    /// Millisecond clock, the session's (so that a simulation drives both this and the KCP
    /// state machine). Only the FEC encoder's continuity check reads it, through
    /// [`MonotonicMs`].
    pub clock: C,
    /// Go's `die`: closed when the session closes.
    pub die: CancellationToken,
}

/// Creates a session's tx channel and the task that drains it.
///
/// The caller spawns [`TxPipeline::run`] and keeps the [`TxHandle`].
// Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (`make(chan sendRequest, devBacklog)` and
//     `go sess.postProcess()`)
pub fn channel<C: Clock>(config: TxConfig<C>) -> (TxHandle, TxPipeline<C>) {
    let (tx, rx) = mpsc::channel(DEV_BACKLOG);
    let shared = Arc::new(TxShared::default());
    let handle = TxHandle {
        tx,
        shared: Arc::clone(&shared),
        pool: Arc::clone(&config.pool),
    };
    let pipeline = TxPipeline {
        rx,
        shared,
        conn: config.conn,
        remote: config.remote,
        block: config.block,
        fec_encoder: config.fec_encoder,
        pool: config.pool,
        clock: MonotonicMs::new(config.clock),
        die: config.die,
        txqueue: Vec::with_capacity(MAX_BATCH_SIZE),
        parity: Vec::new(),
        bytes_to_send: 0,
    };
    (handle, pipeline)
}

/// The session's end of the tx pipeline.
#[derive(Clone, Debug)]
pub struct TxHandle {
    tx: mpsc::Sender<SendRequest>,
    shared: Arc<TxShared>,
    pool: Arc<BufferPool>,
}

impl TxHandle {
    /// Queues a packet without ever blocking, because the KCP output callback runs under the
    /// session mutex.
    ///
    /// Go's output callback drops the packet when the channel is full and recycles its buffer;
    /// so does this, by dropping `request`, but `Kcp::flush` stops before it gets that far
    /// (Deviation V18, module docs), so a full channel no longer costs a retransmission timeout.
    /// Go additionally races `die` against the send, which loses the final flush about half the
    /// time, see Deviation V05 in the module docs.
    // Go: kcp-go/v5@v5.6.66 sess.go:newUDPSession() (the `NewKCP` output closure)
    pub fn send(&self, request: SendRequest) -> SendOutcome {
        match self.tx.try_send(request) {
            Ok(()) => SendOutcome::Queued,
            // The buffer goes back to the pool with the returned request.
            Err(mpsc::error::TrySendError::Full(_)) => SendOutcome::Dropped,
            Err(mpsc::error::TrySendError::Closed(_)) => SendOutcome::Closed,
        }
    }

    /// The pool the session takes packet buffers from.
    pub fn pool(&self) -> &Arc<BufferPool> {
        &self.pool
    }

    /// The state shared with the tx task (`dup`, rate limiter, write error).
    pub fn shared(&self) -> &Arc<TxShared> {
        &self.shared
    }

    /// Number of packets currently queued (Go's `len(s.chPostProcessing)`).
    pub fn queued(&self) -> usize {
        self.tx.max_capacity() - self.tx.capacity()
    }

    /// Free slots in the channel: how many more packets [`send`](Self::send) takes before it
    /// starts dropping them. This is what `Kcp::flush` stops on (**Deviation V18**).
    ///
    /// A closed channel reports [`usize::MAX`]: its permits are never released again, so a
    /// session whose tx task has gone would otherwise stop flushing for good. Every packet is
    /// dropped there anyway ([`SendOutcome::Closed`]), exactly as in Go.
    pub fn capacity(&self) -> usize {
        if self.tx.is_closed() {
            return usize::MAX;
        }
        self.tx.capacity()
    }
}

/// The task that turns queued packets into datagrams.
///
/// Owns the FEC encoder and the cipher: both are only ever touched here, so neither needs a lock.
// Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).postProcess()
pub struct TxPipeline<C = SystemClock> {
    rx: mpsc::Receiver<SendRequest>,
    shared: Arc<TxShared>,
    conn: Arc<dyn PacketConn>,
    remote: SocketAddr,
    block: Option<PacketCrypt>,
    fec_encoder: Option<FecEncoder>,
    pool: Arc<BufferPool>,
    clock: MonotonicMs<C>,
    die: CancellationToken,

    /// Go's `txqueue`: the packets of the batch being assembled.
    txqueue: Vec<PacketBuf>,
    /// Scratch for the parity shards of one FEC group, reused across packets.
    parity: Vec<PacketBuf>,
    /// Go's `bytesToSend`: the size of the batch, what the rate limiter is charged for.
    bytes_to_send: usize,
}

impl<C: Clock> TxPipeline<C> {
    /// Runs until the session dies and the queue is empty, or until the last [`TxHandle`] is
    /// dropped.
    // Go: kcp-go/v5@v5.6.66 sess.go:(*UDPSession).postProcess()
    pub async fn run(mut self) {
        loop {
            let request = tokio::select! {
                // Faithful to Go's `postProcess`, which blocks `die` while `chPostProcessing` is
                // non-empty (sess.go:752-758); `biased` gives the same drain-then-exit order
                // under tokio's otherwise-random select.
                biased;
                request = self.rx.recv() => request,
                () = self.die.cancelled() => None,
            };
            let Some(request) = request else { break };

            self.process(request);

            // Transmit when the channel is empty or we've reached max batch size.
            if self.rx.is_empty() || self.txqueue.len() >= MAX_BATCH_SIZE {
                self.transmit().await;
            }
        }
        // Unreachable in practice (the queue is flushed whenever the channel runs empty), but
        // no packet may be left behind on the way out.
        if !self.txqueue.is_empty() {
            self.transmit().await;
        }
    }

    /// FEC-encodes, encrypts and queues one packet, with its duplicates and parity shards.
    // Go: kcp-go/v5@v5.6.66 sess.go:postProcess(), steps 1-3
    fn process(&mut self, request: SendRequest) {
        let SendRequest { mut buffer, oob } = request;
        debug_assert!(
            self.parity.is_empty(),
            "the previous packet's parity shards must have been queued or dropped"
        );
        debug_assert!(
            !oob || self.fec_encoder.is_some(),
            "an OOB request needs a FEC encoder; Go's SendOOB refuses without one (sess.go:856)"
        );

        // 1. FEC encoding. The parity shards are views into the encoder's shard cache, so they
        //    are copied into their own buffers here and encrypted below; Go encrypts the cache
        //    in place and copies afterwards, which puts the same bytes on the wire.
        if let Some(encoder) = self.fec_encoder.as_mut() {
            if oob {
                if encoder.encode_oob(buffer.as_mut_slice()).is_err() {
                    // Shorter than the FEC header. Unreachable: SendOOB reserves headerSize
                    // bytes. Go would panic on the slice bounds.
                    return;
                }
            } else {
                let now_ms = self.clock.now_ms();
                match encoder.encode(buffer.as_mut_slice(), MAX_FEC_ENCODE_LATENCY, now_ms) {
                    Ok(shards) => {
                        for shard in shards.iter() {
                            let mut parity = self.pool.get(shard.len());
                            parity.as_mut_slice().copy_from_slice(shard);
                            self.parity.push(parity);
                        }
                    }
                    // Shorter than the FEC header or longer than the MTU limit; both are
                    // unreachable for a KCP segment and both panic in Go.
                    Err(_) => return,
                }
            }
        }

        // 2. Encryption (of the packet and of every parity shard).
        let mut sealed = seal(self.block.as_ref(), &mut buffer);
        if sealed {
            for parity in &mut self.parity {
                if !seal(self.block.as_ref(), parity) {
                    sealed = false;
                    break;
                }
            }
        }
        if !sealed {
            self.parity.clear();
            return;
        }

        // 3. TxQueue: the original, then the `dup` copies, then the parity shards, which is the
        //    order Go appends them in.
        let len = buffer.len();
        self.bytes_to_send += len;
        self.txqueue.push(buffer);

        let original = self.txqueue.len() - 1;
        for _ in 0..self.shared.dup() {
            let mut copy = self.pool.get(len);
            copy.as_mut_slice()
                .copy_from_slice(self.txqueue[original].as_slice());
            self.bytes_to_send += copy.len();
            self.txqueue.push(copy);
        }

        for parity in self.parity.drain(..) {
            self.bytes_to_send += parity.len();
            self.txqueue.push(parity);
        }
    }

    /// Paces and writes the queued batch, then recycles its buffers.
    // Go: kcp-go/v5@v5.6.66 sess.go:postProcess() (the transmit branch) and tx_linux.go:tx()
    async fn transmit(&mut self) {
        if self.txqueue.is_empty() {
            self.bytes_to_send = 0;
            return;
        }

        // Deviation V02: a batch larger than the burst is paced rather than refused; Go's
        // `WaitN` returns an error there, which kcp-go v5.6.66 turns into a panic.
        self.shared.limiter.wait_n(self.bytes_to_send).await;

        let msgs: Vec<TxMsg<'_>> = self
            .txqueue
            .iter()
            .map(|buf| TxMsg::new(buf.as_slice(), self.remote))
            .collect();

        // Partial batches are resent, exactly as Go loops over `txqueue = txqueue[n:]`.
        let mut sent = 0;
        let mut nbytes = 0u64;
        let mut npkts = 0u64;
        while sent < msgs.len() {
            match self.conn.send_batch(&msgs[sent..]).await {
                Ok(0) => break, // no progress: stop instead of spinning
                Ok(n) => {
                    let n = n.min(msgs.len() - sent);
                    for msg in &msgs[sent..sent + n] {
                        nbytes += msg.data.len() as u64;
                    }
                    npkts += n as u64;
                    sent += n;
                }
                Err(err) => {
                    self.shared.write_error.set(err);
                    break;
                }
            }
        }
        drop(msgs);

        // `OutBytes` counts the payload of every message the socket accepted, like Go's Linux
        // `tx` (`nbytes += len(txqueue[k].Buffers[0])`). Go's per-packet `defaultTx` adds the
        // byte count `WriteTo` returned instead, which is the same number for a UDP datagram.
        DEFAULT_SNMP.out_pkts.fetch_add(npkts, Ordering::Relaxed);
        DEFAULT_SNMP.out_bytes.fetch_add(nbytes, Ordering::Relaxed);

        // Recycle: `Drop` is Go's `defaultBufferPool.Put(txqueue[k].Buffers[0])`.
        self.txqueue.clear();
        self.bytes_to_send = 0;
    }
}

/// Encrypts one packet in place, following `docs/WIRE-FORMAT.md` §2.
///
/// Returns `false` when the packet is too short for its crypto header (unreachable for packets
/// the session builds, where Go would panic); the caller then drops it.
// Go: kcp-go/v5@v5.6.66 sess.go:postProcess(), step 2
fn seal(block: Option<&PacketCrypt>, buffer: &mut PacketBuf) -> bool {
    match block {
        // -crypt null: no crypto layer at all.
        None => true,
        Some(PacketCrypt::Aead(aead)) => {
            let len = buffer.len();
            let nonce_size = aead.nonce_size();
            if len < nonce_size {
                return false;
            }
            entropy::fill_nonce(&mut buffer.as_mut_slice()[..nonce_size]);
            match aead.seal_in_place(buffer.full_mut(), len) {
                Ok(sealed) => {
                    buffer.set_len(sealed);
                    true
                }
                // The tag does not fit; Go panics ("please increase MTU size"). Unreachable:
                // SetMtu subtracts the AEAD overhead from the KCP MTU.
                Err(_) => false,
            }
        }
        Some(PacketCrypt::Block(block)) => {
            if buffer.len() < CRYPT_HEADER_SIZE {
                return false;
            }
            let packet = buffer.as_mut_slice();
            entropy::fill_nonce(&mut packet[..NONCE_SIZE]);
            let checksum = crc32fast::hash(&packet[CRYPT_HEADER_SIZE..]);
            packet[NONCE_SIZE..CRYPT_HEADER_SIZE].copy_from_slice(&checksum.to_le_bytes());
            block.encrypt(packet);
            true
        }
    }
}

#[cfg(test)]
mod tests;
