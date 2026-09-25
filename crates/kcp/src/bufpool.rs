//! Pooled packet buffers (port of kcp-go `bufferpool.go`, DECISIONS D06).
//!
//! Every packet that leaves a session travels in one fixed [`MTU_LIMIT`]-byte buffer: the KCP
//! output callback fills it under the session lock, the tx task encrypts it in place and hands it
//! to the socket, and it then goes back to the pool. Go does exactly the same with a `sync.Pool`
//! of `mtuLimit`-byte slices (`defaultBufferPool`), and recycles each buffer **explicitly**:
//!
//! ```go
//! bts := defaultBufferPool.Get()[:size+sess.headerSize]   // acquire
//! ...
//! defaultBufferPool.Put(txqueue[k].Buffers[0])            // release, by hand
//! ```
//!
//! Every path that abandons a buffer has to remember that `Put` (kcp-go's output callback does it
//! on a full queue, `SendOOB` does it twice, `postProcess` does it after `tx`), and nothing stops
//! it from putting the same slice back twice. Here [`BufferPool::get`] returns a [`PacketBuf`]
//! RAII handle that returns its buffer in `Drop`, so a buffer can be neither leaked nor recycled
//! twice however the packet path ends — dropped on a full channel, dropped on a closing session,
//! or consumed by the tx task.
//!
//! The pool itself is a bounded lock-free [`ArrayQueue`] (D06) instead of Go's per-P `sync.Pool`
//! caches: the queue is `capacity` buffers deep, a `get` on an empty pool allocates a fresh
//! buffer, and a `Drop` into a full pool frees it. Memory is therefore capped at
//! `capacity × 1500` bytes of *parked* buffers, where Go's pool is bounded only by the garbage
//! collector.
//!
//! Buffers are recycled **as they are**, never zeroed (Go does not zero them either), so a fresh
//! [`PacketBuf`] holds whatever the previous packet left behind. Everything that is put on the
//! wire has to be written first; the tx path writes the crypto header, the FEC header and the
//! payload over the whole buffer.
#![forbid(unsafe_code)]

use std::fmt;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};

use crossbeam_queue::ArrayQueue;

use crate::crypt::MTU_LIMIT;

/// Number of buffers a [`BufferPool`] parks before it starts freeing them: 2048, the depth of one
/// session's tx channel (Go's `devBacklog`), which is the largest number of buffers a single
/// session can have in flight.
pub const DEFAULT_CAPACITY: usize = 2048;

/// One packet buffer, always [`MTU_LIMIT`] bytes of capacity.
type Buffer = Box<[u8; MTU_LIMIT]>;

/// The process-wide packet pool, Go's `defaultBufferPool`.
///
/// kcp-go shares one pool between every session ("a system-wide packet buffer shared among
/// sending, receiving and FEC"), and so does this. A session may equally be given a pool of its
/// own ([`BufferPool::new`]), which trades memory for less cross-session traffic on the queue;
/// which of the two is better under many sessions is a Step 12 measurement.
// Go: kcp-go/v5@v5.6.66 bufferpool.go:defaultBufferPool
pub fn default_pool() -> &'static Arc<BufferPool> {
    static POOL: LazyLock<Arc<BufferPool>> = LazyLock::new(BufferPool::with_default_capacity);
    &POOL
}

/// Counters of a [`BufferPool`], for tests and diagnostics (Go's `sync.Pool` has none).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct PoolStats {
    /// Buffers handed out by [`BufferPool::get`].
    pub gets: u64,
    /// Of those, buffers that had to be allocated because the pool was empty.
    pub allocated: u64,
    /// Buffers returned to the pool by [`PacketBuf`]'s `Drop`.
    pub recycled: u64,
    /// Buffers freed by `Drop` because the pool was full.
    pub discarded: u64,
}

/// A bounded pool of [`MTU_LIMIT`]-byte packet buffers.
///
/// Cloneable and shareable: the pool is always used through an `Arc`, because every
/// [`PacketBuf`] keeps a handle to the pool it came from.
// Go: kcp-go/v5@v5.6.66 bufferpool.go:bufferPool
pub struct BufferPool {
    free: ArrayQueue<Buffer>,
    gets: AtomicU64,
    allocated: AtomicU64,
    recycled: AtomicU64,
    discarded: AtomicU64,
}

impl BufferPool {
    /// Creates an empty pool that parks up to `capacity` buffers (at least one).
    // Go: kcp-go/v5@v5.6.66 bufferpool.go:newBufferPool()
    pub fn new(capacity: usize) -> Arc<BufferPool> {
        Arc::new(BufferPool {
            free: ArrayQueue::new(capacity.max(1)),
            gets: AtomicU64::new(0),
            allocated: AtomicU64::new(0),
            recycled: AtomicU64::new(0),
            discarded: AtomicU64::new(0),
        })
    }

    /// Creates a pool of [`DEFAULT_CAPACITY`] buffers.
    pub fn with_default_capacity() -> Arc<BufferPool> {
        BufferPool::new(DEFAULT_CAPACITY)
    }

    /// Takes a buffer of `len` bytes out of the pool, allocating one if the pool is empty.
    ///
    /// The contents are **unspecified** (whatever the previous user left, like Go's
    /// `sync.Pool`); `len` is clamped to [`MTU_LIMIT`], where Go's `Get()[:n]` would panic.
    // Go: kcp-go/v5@v5.6.66 bufferpool.go:bufferPool.Get(), used as `Get()[:size+headerSize]`
    pub fn get(self: &Arc<Self>, len: usize) -> PacketBuf {
        self.gets.fetch_add(1, Ordering::Relaxed);
        let buf = self.free.pop().unwrap_or_else(|| {
            self.allocated.fetch_add(1, Ordering::Relaxed);
            // Box::new([0u8; MTU_LIMIT]) would build the array on the stack first; this builds
            // it straight on the heap.
            vec![0u8; MTU_LIMIT]
                .into_boxed_slice()
                .try_into()
                .expect("vec![0; MTU_LIMIT] is exactly MTU_LIMIT bytes long")
        });
        PacketBuf {
            buf: Some(buf),
            len: len.min(MTU_LIMIT),
            pool: Arc::clone(self),
        }
    }

    /// Returns a buffer to the pool, or frees it when the pool is full.
    // Go: kcp-go/v5@v5.6.66 bufferpool.go:bufferPool.Put() (called by hand; here: PacketBuf::drop)
    fn put(&self, buf: Buffer) {
        if self.free.push(buf).is_err() {
            self.discarded.fetch_add(1, Ordering::Relaxed);
        } else {
            self.recycled.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// The counters of this pool.
    pub fn stats(&self) -> PoolStats {
        PoolStats {
            gets: self.gets.load(Ordering::Relaxed),
            allocated: self.allocated.load(Ordering::Relaxed),
            recycled: self.recycled.load(Ordering::Relaxed),
            discarded: self.discarded.load(Ordering::Relaxed),
        }
    }

    /// Number of buffers currently parked in the pool.
    pub fn parked(&self) -> usize {
        self.free.len()
    }

    /// Maximum number of buffers the pool parks.
    pub fn capacity(&self) -> usize {
        self.free.capacity()
    }

    /// Frees parked buffers until at most `keep` are left, and returns how many were freed.
    ///
    /// The pool's bound caps how much a burst can *park* ([`DEFAULT_CAPACITY`] × [`MTU_LIMIT`] =
    /// 3 MB) but nothing brings it back down again, so a process that has once been busy keeps
    /// that 3 MB for good. Go has no such problem: every GC cycle empties a `sync.Pool`
    /// (`poolCleanup`), which is why an idle Go kcptun holds no pooled buffers at all. This is
    /// that clearing, driven by [`crate::memory::trim_when_idle`] instead of by a collector.
    ///
    /// Concurrent `get`s are safe: only currently parked buffers are popped, and a `get` that
    /// finds the pool empty allocates as usual.
    // Go: runtime/mgc.go:poolCleanup() — the GC's own emptying of every sync.Pool.
    pub fn trim(&self, keep: usize) -> usize {
        let mut freed = 0;
        while self.free.len() > keep && self.free.pop().is_some() {
            freed += 1;
        }
        freed
    }
}

impl fmt::Debug for BufferPool {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("BufferPool")
            .field("parked", &self.parked())
            .field("capacity", &self.capacity())
            .field("stats", &self.stats())
            .finish()
    }
}

/// A packet buffer borrowed from a [`BufferPool`]: [`MTU_LIMIT`] bytes of capacity, of which the
/// first [`len`](Self::len) are the packet.
///
/// Derefs to the packet bytes (`self[..len]`). The buffer goes back to its pool on `Drop`, which
/// is where Go calls `defaultBufferPool.Put`.
pub struct PacketBuf {
    /// Always `Some` except inside `Drop`, which moves the buffer back to the pool.
    buf: Option<Buffer>,
    len: usize,
    pool: Arc<BufferPool>,
}

impl PacketBuf {
    /// Length of the packet.
    pub fn len(&self) -> usize {
        self.len
    }

    /// Whether the packet is empty.
    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Capacity of the buffer: always [`MTU_LIMIT`].
    pub fn capacity(&self) -> usize {
        MTU_LIMIT
    }

    /// Sets the packet length, clamped to [`MTU_LIMIT`] (Go's re-slicing would panic).
    ///
    /// Bytes between the old and the new length keep whatever they held; the AEAD path uses this
    /// to take in the 16-byte tag `Seal` appended.
    pub fn set_len(&mut self, len: usize) {
        self.len = len.min(MTU_LIMIT);
    }

    /// The packet bytes.
    pub fn as_slice(&self) -> &[u8] {
        &self.raw()[..self.len]
    }

    /// The packet bytes, mutably.
    pub fn as_mut_slice(&mut self) -> &mut [u8] {
        let len = self.len;
        &mut self.raw_mut()[..len]
    }

    /// The whole [`MTU_LIMIT`]-byte buffer, including the bytes past [`len`](Self::len).
    ///
    /// Needed by `AeadCrypt::seal_in_place`, which writes its tag after the packet and then
    /// reports the new length.
    pub fn full_mut(&mut self) -> &mut [u8] {
        self.raw_mut()
    }

    fn raw(&self) -> &[u8; MTU_LIMIT] {
        self.buf
            .as_deref()
            .expect("PacketBuf holds its buffer until Drop takes it")
    }

    fn raw_mut(&mut self) -> &mut [u8; MTU_LIMIT] {
        self.buf
            .as_deref_mut()
            .expect("PacketBuf holds its buffer until Drop takes it")
    }
}

impl Deref for PacketBuf {
    type Target = [u8];

    fn deref(&self) -> &[u8] {
        self.as_slice()
    }
}

impl DerefMut for PacketBuf {
    fn deref_mut(&mut self) -> &mut [u8] {
        self.as_mut_slice()
    }
}

impl Drop for PacketBuf {
    // Go: kcp-go/v5@v5.6.66 sess.go — the explicit `defaultBufferPool.Put(...)` calls.
    fn drop(&mut self) {
        if let Some(buf) = self.buf.take() {
            self.pool.put(buf);
        }
    }
}

impl fmt::Debug for PacketBuf {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PacketBuf")
            .field("len", &self.len)
            .field("capacity", &MTU_LIMIT)
            .finish()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn get_allocates_and_drop_recycles() {
        let pool = BufferPool::new(4);
        assert_eq!(pool.parked(), 0);

        let buf = pool.get(100);
        assert_eq!(buf.len(), 100);
        assert_eq!(buf.capacity(), MTU_LIMIT);
        assert_eq!(
            pool.stats(),
            PoolStats {
                gets: 1,
                allocated: 1,
                recycled: 0,
                discarded: 0
            }
        );

        drop(buf);
        assert_eq!(pool.parked(), 1);
        assert_eq!(pool.stats().recycled, 1);

        // The second get reuses the parked buffer instead of allocating.
        let buf = pool.get(1);
        assert_eq!(pool.stats().gets, 2);
        assert_eq!(pool.stats().allocated, 1);
        assert_eq!(pool.parked(), 0);
        drop(buf);
    }

    /// The buffer really is the same allocation, i.e. the pool recycles rather than reallocates.
    #[test]
    fn recycled_buffer_keeps_its_contents() {
        let pool = BufferPool::new(2);
        let mut buf = pool.get(MTU_LIMIT);
        buf.as_mut_slice().fill(0xab);
        drop(buf);

        let buf = pool.get(8);
        assert_eq!(buf.as_slice(), [0xab; 8]);
    }

    /// Over the bound the pool falls back to allocation, and drops past the bound free the
    /// buffer instead of growing the pool.
    #[test]
    fn pool_is_bounded_with_allocation_fallback() {
        let pool = BufferPool::new(2);
        let bufs: Vec<PacketBuf> = (0..5).map(|_| pool.get(10)).collect();
        assert_eq!(pool.stats().allocated, 5, "empty pool must allocate");

        drop(bufs);
        assert_eq!(pool.parked(), 2, "pool must not grow past its capacity");
        assert_eq!(pool.stats().recycled, 2);
        assert_eq!(pool.stats().discarded, 3);

        // Capacity is available again for the next round.
        let a = pool.get(1);
        let b = pool.get(1);
        assert_eq!(pool.stats().allocated, 5);
        let c = pool.get(1);
        assert_eq!(pool.stats().allocated, 6);
        drop((a, b, c));
    }

    #[test]
    fn set_len_and_slices_are_clamped_to_mtu_limit() {
        let pool = BufferPool::new(1);
        let mut buf = pool.get(MTU_LIMIT + 100);
        assert_eq!(buf.len(), MTU_LIMIT);
        buf.set_len(0);
        assert!(buf.is_empty());
        assert_eq!(buf.as_slice(), b"");
        buf.set_len(usize::MAX);
        assert_eq!(buf.len(), MTU_LIMIT);
        assert_eq!(buf.full_mut().len(), MTU_LIMIT);
    }

    /// Deref/DerefMut cover the packet, `full_mut` the whole buffer: what the AEAD seal needs.
    #[test]
    fn deref_covers_the_packet_and_full_mut_the_buffer() {
        let pool = BufferPool::new(1);
        let mut buf = pool.get(4);
        buf.copy_from_slice(b"kcp!");
        assert_eq!(&buf[..], b"kcp!");
        buf.full_mut()[4..8].copy_from_slice(b"tail");
        buf.set_len(8);
        assert_eq!(&buf[..], b"kcp!tail");
    }

    /// The pool outlives its handles: a `PacketBuf` keeps the pool alive and recycles into it.
    #[test]
    fn handle_keeps_the_pool_alive() {
        let buf = {
            let pool = BufferPool::new(1);
            pool.get(7)
        };
        assert_eq!(buf.len(), 7);
        drop(buf);
    }

    /// `trim` frees down to the requested level, never below it, and leaves the pool usable.
    #[test]
    fn trim_frees_parked_buffers_down_to_keep() {
        let pool = BufferPool::new(64);
        let bufs: Vec<PacketBuf> = (0..64).map(|_| pool.get(10)).collect();
        drop(bufs);
        // 64 slots hold 63 buffers; the 64th is freed on drop.
        let parked = pool.parked();
        assert!(parked >= 63, "parked {parked}");

        assert_eq!(pool.trim(16), parked - 16);
        assert_eq!(pool.parked(), 16);

        // Already at or below `keep`: nothing to do.
        assert_eq!(pool.trim(16), 0);
        assert_eq!(pool.trim(100), 0);
        assert_eq!(pool.parked(), 16);

        assert_eq!(pool.trim(0), 16);
        assert_eq!(pool.parked(), 0);

        // The pool still works, it just has to allocate again.
        let before = pool.stats().allocated;
        let buf = pool.get(4);
        assert_eq!(buf.len(), 4);
        assert_eq!(pool.stats().allocated, before + 1);
    }

    /// The shared pool is one instance with Go's capacity, and hands out usable buffers.
    #[test]
    fn default_pool_is_shared_and_usable() {
        let pool = default_pool();
        assert!(Arc::ptr_eq(pool, default_pool()));
        assert_eq!(pool.capacity(), DEFAULT_CAPACITY);
        let mut buf = pool.get(16);
        buf.fill(1);
        assert_eq!(buf.len(), 16);
    }

    #[test]
    fn get_and_drop_are_thread_safe() {
        let pool = BufferPool::new(16);
        std::thread::scope(|s| {
            for _ in 0..4 {
                let pool = Arc::clone(&pool);
                s.spawn(move || {
                    for i in 0..1000 {
                        let mut buf = pool.get(64);
                        buf.as_mut_slice().fill(i as u8);
                        assert_eq!(buf.as_slice()[0], i as u8);
                    }
                });
            }
        });
        let stats = pool.stats();
        assert_eq!(stats.gets, 4000);
        assert_eq!(stats.recycled + stats.discarded, 4000);
        assert!(pool.parked() <= 16);
    }
}
