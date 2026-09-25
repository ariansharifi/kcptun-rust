//! Forward error correction for KCP packets: the Reed-Solomon FEC encoder and decoder (port of
//! kcp-go `fec.go`).
//!
//! FEC packet layout (see `docs/WIRE-FORMAT.md` §4), starting at `header_offset` (the room left
//! in front for the crypto header, `nonce + crc32` or the AEAD nonce):
//!
//! ```text
//! data   : seqid u32 | type u16 = 0x00F1 | size u16 = 2 + len(KCP bytes) | KCP bytes
//! parity : seqid u32 | type u16 = 0x00F2 | parity bytes
//! oob    : seqid u32 = 0xFFFFFFFF | type u16 = 0x00F3 | size u16 | payload
//! ```
//!
//! An RS shard is the region from the `size` field (`payload_offset = header_offset + 6`) to the
//! end of the packet, zero-padded to the longest packet of its group. All integers are little
//! endian.
#![forbid(unsafe_code)]

use std::collections::hash_map::Entry;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::Ordering;

use crate::autotune::AutoTune;
use crate::crypt::MTU_LIMIT;
use crate::kcp::_itimediff;
use crate::rs::{self, Codec, ShardBuf};
use crate::snmp::DEFAULT_SNMP;

/// Size of the FEC header: seqid (4 bytes) and type (2 bytes).
// Go: kcp-go/v5@v5.6.66 fec.go:fecHeaderSize
pub const FEC_HEADER_SIZE: usize = 6;

/// FEC header plus the 2-byte size field of data and OOB packets.
// Go: kcp-go/v5@v5.6.66 fec.go:fecHeaderSizePlus2
pub const FEC_HEADER_SIZE_PLUS2: usize = FEC_HEADER_SIZE + 2;

/// FEC packet type of a data shard.
// Go: kcp-go/v5@v5.6.66 fec.go:typeData
pub const TYPE_DATA: u16 = 0xf1;

/// FEC packet type of a parity shard.
// Go: kcp-go/v5@v5.6.66 fec.go:typeParity
pub const TYPE_PARITY: u16 = 0xf2;

/// FEC packet type of an out-of-band packet (not FEC-protected).
// Go: kcp-go/v5@v5.6.66 fec.go:typeOOB
pub const TYPE_OOB: u16 = 0xf3;

/// Shard sets (groups) a decoder keeps before discarding older ones.
// Go: kcp-go/v5@v5.6.66 fec.go:maxShardSets
pub const MAX_SHARD_SETS: usize = 3;

/// The seqid of every out-of-band packet (max `u32`).
// Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.sealOOB() (uint32(0xffffffff))
pub const OOB_SEQID: u32 = 0xffff_ffff;

/// Longest gap (milliseconds) between two consecutive data packets for which the encoder still
/// emits the group's parity; the session passes it as `rto` to [`FecEncoder::encode`].
// Go: kcp-go/v5@v5.6.66 sess.go:maxFECEncodeLatency
pub const MAX_FEC_ENCODE_LATENCY: u32 = 500;

/// Errors of the FEC encoder.
///
/// Go has no counterpart for the packet length errors: `fecEncoder.encode` would panic with a
/// slice bounds error, which the session code never triggers (its packet buffers are at most
/// `mtuLimit` bytes and always hold the FEC header). They are reported instead of panicking and
/// leave the encoder untouched.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum Error {
    /// The Reed-Solomon codec cannot be built for the shard counts. With `ds + ps > 256` this
    /// is [`rs::Error::MaxShardNum`] (Deviation V07: Go silently switches to Leopard GF16, which
    /// no peer can decode).
    #[error(transparent)]
    Codec(#[from] rs::Error),
    /// The packet is too short to hold the FEC header and the size field.
    #[error("FEC packet too short: {len} bytes, need at least {min}")]
    PacketTooShort {
        /// Length of the packet.
        len: usize,
        /// `payload_offset + 2`.
        min: usize,
    },
    /// The packet does not fit into a shard cache slot (`MTU_LIMIT` bytes).
    #[error("FEC packet too large: {len} bytes, at most {max}")]
    PacketTooLarge {
        /// Length of the packet.
        len: usize,
        /// [`MTU_LIMIT`].
        max: usize,
    },
}

/// The FEC encoder of one session: seals outgoing packets as FEC data shards and emits the
/// parity shards of every complete group.
// Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder
#[derive(Debug)]
pub struct FecEncoder {
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
    /// Protect Against Wrapped Sequence numbers: the largest multiple of `shard_size` that fits
    /// into a `u32`; seqids run modulo it so that groups never straddle the wrap.
    paws: u32,
    /// Next seqid.
    next: u32,

    /// Number of data shards collected in the current group.
    shard_count: usize,
    /// Maximum packet length in the current group (including the headers).
    max_size: usize,

    /// FEC header offset.
    header_offset: usize,
    /// FEC payload offset (`header_offset + 6`, the size field).
    payload_offset: usize,

    /// `shard_size` slots of [`MTU_LIMIT`] bytes: data shards first, then parity shards.
    shard_cache: Vec<Vec<u8>>,
    /// Current length of each slot, Go's `len(shardCache[k])`.
    shard_len: Vec<usize>,
    /// Time (ms) of the previous `encode` call.
    ts_latest_packet: i64,

    /// RS encoder.
    codec: Codec,
}

/// The parity shards of one group returned by [`FecEncoder::encode`]: views into the encoder's
/// shard cache, like the `[][]byte` Go returns (`shardCache[ds:][k][:maxSize]`).
///
/// Each shard is `max_size` bytes, the length of the group's longest data packet:
/// `[0, header_offset)` is room for the crypto header (its contents are unspecified, the crypto
/// layer overwrites it), then seqid, type [`TYPE_PARITY`] and the parity bytes. The borrow ends
/// before the next `encode` call, which overwrites the cache; the session's tx path copies each
/// shard into its own packet buffer and encrypts it there (Go encrypts the cache slot in place
/// and then copies it; the bytes sent are the same).
///
/// Empty when the call did not complete a group, or when the group's parity was skipped.
#[derive(Clone, Copy, Debug)]
pub struct ParityShards<'a> {
    shards: &'a [Vec<u8>],
    size: usize,
}

impl<'a> ParityShards<'a> {
    const NONE: ParityShards<'static> = ParityShards {
        shards: &[],
        size: 0,
    };

    /// Number of parity shards (0 or the encoder's parity shard count).
    pub fn len(&self) -> usize {
        self.shards.len()
    }

    /// Whether no parity shard was produced.
    pub fn is_empty(&self) -> bool {
        self.shards.is_empty()
    }

    /// The length of every shard (0 when empty).
    pub fn shard_len(&self) -> usize {
        self.size
    }

    /// Parity shard `k`, if any.
    pub fn get(&self, k: usize) -> Option<&'a [u8]> {
        self.shards.get(k).map(|s| &s[..self.size])
    }

    /// The parity shards in seqid order.
    pub fn iter(&self) -> ParityIter<'a> {
        self.into_iter()
    }
}

impl<'a> IntoIterator for ParityShards<'a> {
    type Item = &'a [u8];
    type IntoIter = ParityIter<'a>;

    fn into_iter(self) -> ParityIter<'a> {
        ParityIter {
            shards: self.shards.iter(),
            size: self.size,
        }
    }
}

/// Iterator over the shards of a [`ParityShards`], in seqid order.
#[derive(Clone, Debug)]
pub struct ParityIter<'a> {
    shards: std::slice::Iter<'a, Vec<u8>>,
    size: usize,
}

impl<'a> Iterator for ParityIter<'a> {
    type Item = &'a [u8];

    fn next(&mut self) -> Option<&'a [u8]> {
        self.shards.next().map(|s| &s[..self.size])
    }

    fn size_hint(&self) -> (usize, Option<usize>) {
        self.shards.size_hint()
    }
}

impl ExactSizeIterator for ParityIter<'_> {}

impl FecEncoder {
    /// Creates an encoder for groups of `data_shards` data and `parity_shards` parity shards,
    /// with the FEC header at `offset` of every packet (the session's crypto header size).
    ///
    /// Returns `Ok(None)` unless `data_shards > 0 && parity_shards > 0`: FEC is disabled, like
    /// Go's `nil` encoder.
    ///
    /// Errors: [`Error::Codec`] when the RS codec cannot be built, in particular
    /// [`rs::Error::MaxShardNum`] for `data_shards + parity_shards > 256`. Go has no such check
    /// in the encoder (klauspost then silently builds a Leopard GF16 code that no kcp-go peer
    /// can decode); Deviation V07: the error is reported instead, and kcptun rejects the flags
    /// at startup. It is never mapped to "no FEC".
    // Go: kcp-go/v5@v5.6.66 fec.go:newFECEncoder()
    pub fn new(
        data_shards: isize,
        parity_shards: isize,
        offset: usize,
    ) -> Result<Option<FecEncoder>, Error> {
        if data_shards <= 0 || parity_shards <= 0 {
            return Ok(None);
        }
        let data_shards = data_shards.unsigned_abs();
        let parity_shards = parity_shards.unsigned_abs();
        // Deviation V07: ds + ps > 256 fails here (Go: Leopard GF16 codec).
        let codec = Codec::new(data_shards, parity_shards)?;
        // Codec::new guarantees 2 <= shard_size <= 256.
        let shard_size = data_shards + parity_shards;
        let paws = paws(shard_size);
        let header_offset = offset;
        let payload_offset = header_offset.saturating_add(FEC_HEADER_SIZE);

        Ok(Some(FecEncoder {
            data_shards,
            parity_shards,
            shard_size,
            paws,
            next: 0,
            shard_count: 0,
            max_size: 0,
            header_offset,
            payload_offset,
            shard_cache: vec![vec![0u8; MTU_LIMIT]; shard_size],
            shard_len: vec![MTU_LIMIT; shard_size],
            // Go starts tsLatestPacket at 0 and compares wall-clock UnixMilli() against it, so
            // the very first group always counts as non-continuous (with ds == 1, the first
            // packet's parity is skipped). The session passes a monotonic clock that may start
            // near 0, so the start value is "infinitely long ago" instead, which keeps that
            // quirk without depending on the wall clock (see the porting guide).
            ts_latest_packet: i64::MIN / 2,
            codec,
        }))
    }

    /// Number of data shards per group.
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Number of parity shards per group.
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// Offset of the FEC header in every packet.
    pub fn header_offset(&self) -> usize {
        self.header_offset
    }

    /// Offset of the size field (the start of the RS shard) in every packet.
    pub fn payload_offset(&self) -> usize {
        self.payload_offset
    }

    /// Seals `b` as the next data shard and, when it completes a group of `data_shards`, returns
    /// the group's parity shards (see [`ParityShards`]).
    ///
    /// `b` is the whole outgoing packet: `header_offset` bytes of room for the crypto header,
    /// the 6-byte FEC header and 2-byte size field (both written here), then the KCP bytes. It
    /// must be at least `payload_offset + 2` and at most [`MTU_LIMIT`] bytes long.
    ///
    /// The parity of a group is skipped (its seqids are still consumed) unless
    /// `now_ms - (time of the previous call) < rto`: the session passes
    /// [`MAX_FEC_ENCODE_LATENCY`] as `rto`, like Go. `now_ms` is a monotonic, non-wrapping
    /// millisecond clock (Go reads `time.Now().UnixMilli()` here); the caller must extend the
    /// wrapping `u32` [`crate::clock::Clock`] to i64 (e.g. by accumulating `wrapping_sub`
    /// deltas), otherwise one group per u32 wrap is treated as continuous. The time of every
    /// call is recorded, whether or
    /// not it completes a group. Before the first call that time is `i64::MIN / 2`, so any
    /// `now_ms` above `i64::MIN / 2 + rto` (every real clock) makes the first group skip its
    /// parity when it completes on the first call (`data_shards == 1`), like Go.
    ///
    /// Allocation: none per packet; one `Vec` of shard slices per group with parity (plus the
    /// codec's own per-call vectors). Measured in 04.7: amortised over 10 packets these do not
    /// show above the memcpy, and the encoder is faster than Go on both NEON machines; removing
    /// them is a Step 12 follow-up (`docs/benchmarks/fec.md`).
    ///
    /// Errors: [`Error::PacketTooShort`], [`Error::PacketTooLarge`]; the encoder and `b` are
    /// then unchanged.
    // Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.encode()
    pub fn encode(
        &mut self,
        b: &mut [u8],
        rto: u32,
        now_ms: i64,
    ) -> Result<ParityShards<'_>, Error> {
        // Go would panic on these (slice bounds); nothing is modified before the checks.
        let min = self.payload_offset.saturating_add(2);
        if b.len() < min {
            return Err(Error::PacketTooShort { len: b.len(), min });
        }
        if b.len() > MTU_LIMIT {
            return Err(Error::PacketTooLarge {
                len: b.len(),
                max: MTU_LIMIT,
            });
        }

        // The header format:
        // | FEC SEQID(4B) | FEC TYPE(2B) | SIZE (2B) | PAYLOAD(SIZE-2) |
        // |<-headerOffset                |<-payloadOffset
        Self::seal_data(&mut self.next, self.paws, &mut b[self.header_offset..]);
        let size = (b.len() - self.payload_offset) as u16;
        b[self.payload_offset..self.payload_offset + 2].copy_from_slice(&size.to_le_bytes());

        // copy data from payloadOffset to fec shard cache
        let sz = b.len();
        let slot = self.shard_count;
        self.shard_len[slot] = sz;
        self.shard_cache[slot][self.payload_offset..sz].copy_from_slice(&b[self.payload_offset..]);
        self.shard_count += 1;

        // track max datashard length
        if sz > self.max_size {
            self.max_size = sz;
        }

        // Generation of Reed-Solomon Erasure Code when we have enough datashards
        let now = now_ms;
        // Some(length) of the parity shards to return (Go: ps != nil).
        let mut ps = None;
        if self.shard_count == self.data_shards {
            // Generate the parity shards if we collect enough datashards; the continuity is
            // determined by the time interval between the latest 2 data packets. If the
            // interval is not below rto, the data is considered non-continuous and the parity
            // is skipped, but the seqids are still consumed (see skip_parity), which the
            // receiver needs to keep its groups aligned.
            //
            // Go: `now-enc.tsLatestPacket < int64(rto)` (wrapping int64). Saturating here so
            // the i64::MIN / 2 start value can never wrap; identical for any real clock.
            if now.saturating_sub(self.ts_latest_packet) < i64::from(rto) {
                let max_size = self.max_size;
                let payload_offset = self.payload_offset;

                // clear the tail of each datashard to make them equal-sized
                for i in 0..self.data_shards {
                    let slen = self.shard_len[i];
                    if slen < max_size {
                        self.shard_cache[i][slen..max_size].fill(0);
                    }
                }

                // construct equal-sized slices with stripped header
                let mut cache: Vec<&mut [u8]> = self
                    .shard_cache
                    .iter_mut()
                    .map(|shard| &mut shard[payload_offset..max_size])
                    .collect();

                // Reed-Solomon Erasure Code Encoding
                if self.codec.encode(&mut cache).is_ok() {
                    for k in self.data_shards..self.shard_size {
                        // NOTE(x): seal parity will increase the seqid by 1
                        Self::seal_parity(
                            &mut self.next,
                            self.paws,
                            &mut self.shard_cache[k][self.header_offset..],
                        );
                        self.shard_len[k] = max_size;
                    }
                    ps = Some(max_size);
                } else {
                    // encoding failed, record the error but keep the seqid monotonic increasing
                    // (unreachable: every shard is max_size - payload_offset >= 2 bytes long)
                    DEFAULT_SNMP.fec_errs.fetch_add(1, Ordering::Relaxed);
                    self.skip_parity();
                }
            } else {
                // Non-continuous data detected, skip this parity generation. Though we do not
                // send non-continuous parity shards, we still need to increase the seqid.
                self.skip_parity();
            }

            // reset shard count and max size
            self.shard_count = 0;
            self.max_size = 0;
        }

        // record the time of the latest data packet
        self.ts_latest_packet = now;

        Ok(match ps {
            Some(size) => ParityShards {
                shards: &self.shard_cache[self.data_shards..],
                size,
            },
            None => ParityShards::NONE,
        })
    }

    /// Writes seqid `*next` and [`TYPE_DATA`] into the FEC header at the start of `data` and
    /// advances `*next` modulo `paws`. (Go's methods take the encoder; `next` and `paws` are
    /// passed explicitly so a shard cache slot can be sealed while borrowed.)
    // Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.sealData()
    fn seal_data(next: &mut u32, paws: u32, data: &mut [u8]) {
        data[0..4].copy_from_slice(&next.to_le_bytes());
        data[4..6].copy_from_slice(&TYPE_DATA.to_le_bytes());
        *next = next.wrapping_add(1) % paws;
    }

    /// Writes seqid `*next` and [`TYPE_PARITY`] into the FEC header at the start of `data` and
    /// advances `*next` modulo `paws`.
    // Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.sealParity()
    fn seal_parity(next: &mut u32, paws: u32, data: &mut [u8]) {
        data[0..4].copy_from_slice(&next.to_le_bytes());
        data[4..6].copy_from_slice(&TYPE_PARITY.to_le_bytes());
        *next = next.wrapping_add(1) % paws;
    }

    /// Seals `b` as an out-of-band packet: seqid [`OOB_SEQID`], type [`TYPE_OOB`] and the size
    /// field `len(b) - payload_offset`. Does not consume a seqid and is not FEC-protected.
    ///
    /// Errors: [`Error::PacketTooShort`] if `b` is shorter than `payload_offset + 2` (Go would
    /// panic); `b` is then unchanged.
    // Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.encodeOOB()
    pub fn encode_oob(&self, b: &mut [u8]) -> Result<(), Error> {
        let min = self.payload_offset.saturating_add(2);
        if b.len() < min {
            return Err(Error::PacketTooShort { len: b.len(), min });
        }
        Self::seal_oob(&mut b[self.header_offset..]);
        // Go: uint16(len(b[enc.payloadOffset:])), truncating like Go.
        let size = (b.len() - self.payload_offset) as u16;
        b[self.payload_offset..self.payload_offset + 2].copy_from_slice(&size.to_le_bytes());
        Ok(())
    }

    /// Writes [`OOB_SEQID`] and [`TYPE_OOB`] into the FEC header at the start of `data`.
    // Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.sealOOB()
    fn seal_oob(data: &mut [u8]) {
        // use max uint32 as OOB seqid
        data[0..4].copy_from_slice(&OOB_SEQID.to_le_bytes());
        data[4..6].copy_from_slice(&TYPE_OOB.to_le_bytes());
    }

    /// Skips the whole parity block by advancing the seqid.
    // Go: kcp-go/v5@v5.6.66 fec.go:fecEncoder.skipParity()
    fn skip_parity(&mut self) {
        self.next = self.next.wrapping_add(self.parity_shards as u32) % self.paws;
    }
}

// ---------------------------------------------------------------------------------------------
// Decoder
// ---------------------------------------------------------------------------------------------

/// The seqid of a FEC packet (`b` starts at the FEC header and is at least 6 bytes long).
// Go: kcp-go/v5@v5.6.66 fec.go:fecPacket.seqid()
fn fec_seqid(b: &[u8]) -> u32 {
    u32::from_le_bytes([b[0], b[1], b[2], b[3]])
}

/// The type of a FEC packet (`b` starts at the FEC header and is at least 6 bytes long).
// Go: kcp-go/v5@v5.6.66 fec.go:fecPacket.flag()
fn fec_flag(b: &[u8]) -> u16 {
    u16::from_le_bytes([b[4], b[5]])
}

/// The packets received for one group (shard set), with a set of their seqids to reject
/// duplicates.
///
/// Go declares `Less`/`Swap` so that `shardHeap` satisfies `container/heap`, but `fec.go`
/// only calls `heap.Init` on the empty heap (a no-op) and then the `Push`/`Pop` **methods**
/// directly, never `heap.Push`/`heap.Pop`: `Push` appends and `Pop` removes the last element.
/// The "heap" is therefore a stack, ported as such (the pop order does not matter anyway: every
/// popped packet goes to the decode cache slot of its seqid).
// Go: kcp-go/v5@v5.6.66 fec.go:shardHeap
#[derive(Debug, Default)]
struct ShardHeap {
    /// Copies of the received packets, each starting at the FEC header.
    elements: Vec<Vec<u8>>,
    /// Seqids of `elements` (Go: `marks map[uint32]struct{}`).
    marks: HashSet<u32>,
}

impl ShardHeap {
    // Go: kcp-go/v5@v5.6.66 fec.go:shardHeap.Len()
    fn len(&self) -> usize {
        self.elements.len()
    }

    /// Appends `pkt` (at least [`FEC_HEADER_SIZE`] bytes) and marks its seqid.
    // Go: kcp-go/v5@v5.6.66 fec.go:shardHeap.Push()
    fn push(&mut self, pkt: Vec<u8>) {
        self.marks.insert(fec_seqid(&pkt));
        self.elements.push(pkt);
    }

    /// Removes the last packet and unmarks its seqid (`None` when empty; Go panics, but only
    /// pops while `Len() > 0`).
    // Go: kcp-go/v5@v5.6.66 fec.go:shardHeap.Pop()
    fn pop(&mut self) -> Option<Vec<u8>> {
        let x = self.elements.pop()?;
        self.marks.remove(&fec_seqid(&x));
        Some(x)
    }

    // Go: kcp-go/v5@v5.6.66 fec.go:shardHeap.Has()
    fn has(&self, sn: u32) -> bool {
        self.marks.contains(&sn)
    }
}

/// One slot of the decoder's decode cache: the RS shard is `buf[start..]`. A received packet is
/// stored whole with `start = FEC_HEADER_SIZE` (Go: `pkt.data()`, a subslice of the packet
/// buffer); a missing data shard is an empty buffer with `start = 0`, which `reconstruct_data`
/// grows and fills (Go: `defaultBufferPool.Get()[:0]`). Empty = missing (Go: `nil`).
#[derive(Debug, Default)]
struct DecodeShard {
    buf: Vec<u8>,
    start: usize,
}

impl ShardBuf for DecodeShard {
    fn shard(&self) -> &[u8] {
        self.buf.get(self.start..).unwrap_or_default()
    }

    fn shard_mut(&mut self) -> &mut [u8] {
        self.buf.get_mut(self.start..).unwrap_or_default()
    }

    fn set_shard_len(&mut self, n: usize) {
        self.buf.resize(self.start.saturating_add(n), 0);
    }
}

/// The FEC decoder of one session: collects the data and parity shards of each group and
/// rebuilds lost data shards once enough shards of the group have arrived. It follows the
/// peer's `(data_shards, parity_shards)` automatically (auto-tuning) when the packet types stop
/// matching the configured ones.
// Go: kcp-go/v5@v5.6.66 fec.go:fecDecoder
#[derive(Debug)]
pub struct FecDecoder {
    data_shards: usize,
    parity_shards: usize,
    shard_size: usize,
    /// `shard_set[initial shard id] = shards received for that group`
    shard_set: HashMap<u32, ShardHeap>,
    /// Protect Against Wrapped Sequence numbers (see [`FecEncoder`]).
    paws: u32,

    /// The latest recovered shard id; shard sets more than [`MAX_SHARD_SETS`] groups older are
    /// discarded.
    newest_shard_id: u32,

    /// `shard_size` slots, indexed by `seqid % shard_size`.
    decode_cache: Vec<DecodeShard>,
    /// Whether each decode cache slot holds a received packet.
    flag_cache: Vec<bool>,

    /// RS decoder.
    codec: Codec,

    /// Auto-tuning of the FEC parameters.
    auto_tune: AutoTune,
    should_tune: bool,
}

impl FecDecoder {
    /// Creates a decoder for groups of `data_shards` data and `parity_shards` parity shards.
    ///
    /// Returns `None` unless `data_shards > 0 && parity_shards > 0` and
    /// `data_shards + parity_shards <= 256`, like Go's `nil` decoder.
    // Go: kcp-go/v5@v5.6.66 fec.go:newFECDecoder()
    pub fn new(data_shards: isize, parity_shards: isize) -> Option<FecDecoder> {
        if data_shards <= 0 || parity_shards <= 0 {
            return None;
        }

        if data_shards.saturating_add(parity_shards) > 256 {
            return None;
        }

        let data_shards = data_shards.unsigned_abs();
        let parity_shards = parity_shards.unsigned_abs();
        let shard_size = data_shards + parity_shards;
        let codec = Codec::new(data_shards, parity_shards).ok()?;
        Some(FecDecoder {
            data_shards,
            parity_shards,
            shard_size,
            shard_set: HashMap::new(),
            paws: paws(shard_size),
            newest_shard_id: 0,
            decode_cache: Self::new_decode_cache(shard_size),
            flag_cache: vec![false; shard_size],
            codec,
            auto_tune: AutoTune::new(),
            should_tune: false,
        })
    }

    fn new_decode_cache(shard_size: usize) -> Vec<DecodeShard> {
        (0..shard_size).map(|_| DecodeShard::default()).collect()
    }

    /// Current number of data shards per group (changes when auto-tuning applies new
    /// parameters).
    pub fn data_shards(&self) -> usize {
        self.data_shards
    }

    /// Current number of parity shards per group.
    pub fn parity_shards(&self) -> usize {
        self.parity_shards
    }

    /// Decodes one FEC data or parity packet and returns the data shards it made recoverable.
    ///
    /// `pkt` starts at the FEC header (seqid, type), i.e. after the crypto header. The session
    /// feeds data packets to KCP itself before calling this; the returned buffers are the
    /// *recovered* data shards only, each starting at the size field (Go: `pkt.data()`, the
    /// RS shard) and zero-padded to the longest shard of the group. Consumer contract (Go
    /// `sess.go:kcpInput`): `sz = LE16(r[0..2])`; if `2 <= sz <= r.len()`, `r[2..sz]` is fed
    /// to KCP as an FEC packet, otherwise the shard is ignored.
    ///
    /// Updates the `FECShardSet`, `FECParityShards`, `FECFullShardSet`, `FECRecovered`,
    /// `FECErrs` and `FECShardMin` counters of [`DEFAULT_SNMP`] like Go.
    ///
    /// Packets shorter than [`FEC_HEADER_SIZE`] are ignored without touching the decoder (Go
    /// would panic; the session only passes packets of at least `FEC_HEADER_SIZE_PLUS2`
    /// bytes). Longer than [`MTU_LIMIT`] (Go would panic copying into a pool buffer; the
    /// session's receive buffers are `MTU_LIMIT` bytes) is processed normally.
    ///
    /// Allocation: one copy of every stored packet and one buffer per recovered shard (Go uses
    /// its buffer pool for both).
    // Go: kcp-go/v5@v5.6.66 fec.go:fecDecoder.decode()
    pub fn decode(&mut self, pkt: &[u8]) -> Vec<Vec<u8>> {
        let mut recovered = Vec::new();
        if pkt.len() < FEC_HEADER_SIZE {
            return recovered;
        }
        let in_seqid = fec_seqid(pkt);
        let in_flag = fec_flag(pkt);

        // Sample the packet type for auto-tuning
        if in_flag == TYPE_DATA {
            self.auto_tune.sample(true, in_seqid);
        } else {
            self.auto_tune.sample(false, in_seqid);
        }

        // check seqid < paws to avoid invalid packets
        if in_seqid >= self.paws {
            return recovered;
        }

        // check if the packet type matches the current FEC parameters
        // (shard_size <= 256, so the conversions are exact)
        let shard_size = self.shard_size as u32;
        if in_seqid % shard_size < self.data_shards as u32 {
            if in_flag != TYPE_DATA {
                // expect TYPE_DATA
                self.should_tune = true;
            }
        } else if in_flag != TYPE_PARITY {
            self.should_tune = true;
        }

        // perform auto-tuning if the decoder is out of sync.
        if self.should_tune {
            let auto_ds = self.auto_tune.find_period(true);
            let auto_ps = self.auto_tune.find_period(false);

            // validate the auto-tuned parameters
            if auto_ds > 0 && auto_ps > 0 && auto_ds + auto_ps < 256 {
                let auto_ds = auto_ds.unsigned_abs() as usize;
                let auto_ps = auto_ps.unsigned_abs() as usize;
                if auto_ds != self.data_shards || auto_ps != self.parity_shards {
                    // Go assigns the new shard counts and empties the shard set before
                    // reedsolomon.New and returns on its error, leaving the rest stale. The
                    // codec is built first here so the decoder always stays consistent; the
                    // error is unreachable (0 < ds, 0 < ps, ds + ps < 256).
                    let Ok(codec) = Codec::new(auto_ds, auto_ps) else {
                        return recovered;
                    };
                    // apply the new FEC parameters
                    self.data_shards = auto_ds;
                    self.parity_shards = auto_ps;
                    self.shard_size = auto_ds + auto_ps;
                    // recycle old shards before creating new shard_set (dropped here)
                    self.shard_set = HashMap::new(); // empty the shard set
                    self.codec = codec;
                    self.decode_cache = Self::new_decode_cache(self.shard_size);
                    self.flag_cache = vec![false; self.shard_size];
                    self.paws = paws(self.shard_size);
                }
                // reset should_tune regardless of whether parameters changed to avoid
                // permanent blocking when detected parameters match current ones
                self.should_tune = false;
            }
            return recovered;
        }

        // get the shard heap for this shard id
        let shard_id = self.get_shard_id(in_seqid);
        let shard = match self.shard_set.entry(shard_id) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                DEFAULT_SNMP.fec_shard_set.fetch_add(1, Ordering::Relaxed);
                e.insert(ShardHeap::default())
            }
        };

        // ignore duplicate packets
        if shard.has(in_seqid) {
            return recovered;
        }

        // update statistics for parity shards
        if in_flag == TYPE_PARITY {
            DEFAULT_SNMP
                .fec_parity_shards
                .fetch_add(1, Ordering::Relaxed);
        }

        // push a copy of the packet into the shard heap (Go: a 1500-byte pool buffer; the
        // capacity lets the zero-extension below happen in place)
        let mut copy = Vec::with_capacity(pkt.len().max(MTU_LIMIT));
        copy.extend_from_slice(pkt);
        shard.push(copy);

        // try to recover data if we have enough shards
        if shard.len() >= self.data_shards {
            let mut num_data_shard = 0usize;
            let mut maxlen = 0usize;

            // prepare the decode cache
            for (s, f) in self.decode_cache.iter_mut().zip(self.flag_cache.iter_mut()) {
                *s = DecodeShard::default();
                *f = false;
            }

            // pop all shards from the heap and fill into the decode cache
            while let Some(pkt) = shard.pop() {
                let seqid = fec_seqid(&pkt);
                let is_data = fec_flag(&pkt) == TYPE_DATA;
                let dlen = pkt.len() - FEC_HEADER_SIZE;
                let idx = (seqid % shard_size) as usize;
                self.decode_cache[idx] = DecodeShard {
                    buf: pkt,
                    start: FEC_HEADER_SIZE,
                };
                self.flag_cache[idx] = true;
                if is_data {
                    num_data_shard += 1;
                }
                if dlen > maxlen {
                    maxlen = dlen;
                }
            }

            if num_data_shard == self.data_shards {
                // case 1: all data shards are present
                DEFAULT_SNMP
                    .fec_full_shard_set
                    .fetch_add(1, Ordering::Relaxed);
            } else {
                // case 2: some data shards are missing, try to recover
                // fill '0' into the tail of each shard to make them equal-sized
                for (k, (s, &present)) in self
                    .decode_cache
                    .iter_mut()
                    .zip(self.flag_cache.iter())
                    .enumerate()
                {
                    if present {
                        s.buf.resize(s.start + maxlen, 0);
                    } else if k < self.data_shards {
                        // prepare memory for the data recovery
                        *s = DecodeShard {
                            buf: Vec::with_capacity(MTU_LIMIT),
                            start: 0,
                        };
                    }
                }

                // Reed-Solomon Erasure Code Decoding
                if self.codec.reconstruct_data(&mut self.decode_cache).is_ok() {
                    for (s, &present) in self
                        .decode_cache
                        .iter_mut()
                        .zip(self.flag_cache.iter())
                        .take(self.data_shards)
                    {
                        if !present {
                            recovered.push(std::mem::take(&mut s.buf));
                        }
                    }
                } else {
                    // recovery failed, record the error (the new buffers are dropped below)
                    DEFAULT_SNMP.fec_errs.fetch_add(1, Ordering::Relaxed);
                }

                // record the number of recovered packets
                DEFAULT_SNMP
                    .fec_recovered
                    .fetch_add(recovered.len() as u64, Ordering::Relaxed);
            }

            // recycle the packets
            for s in &mut self.decode_cache {
                *s = DecodeShard::default();
            }
        }

        // update the newest shard id
        if _itimediff(
            shard_id.wrapping_mul(shard_size),
            self.newest_shard_id.wrapping_mul(shard_size),
        ) > 0
        {
            self.newest_shard_id = shard_id;
            DEFAULT_SNMP
                .fec_shard_min
                .store(u64::from(self.newest_shard_id), Ordering::Relaxed);
        }

        // try to discard shard sets that are too old
        self.discard_shards();

        recovered
    }

    /// The shard (group) id of a seqid.
    // Go: kcp-go/v5@v5.6.66 fec.go:fecDecoder.getShardId()
    fn get_shard_id(&self, seqid: u32) -> u32 {
        seqid / self.shard_size as u32
    }

    /// Removes the shard sets more than [`MAX_SHARD_SETS`] groups older than the newest one and
    /// stores the number of remaining sets in the `FECShardSet` gauge.
    // Go: kcp-go/v5@v5.6.66 fec.go:fecDecoder.discardShards()
    fn discard_shards(&mut self) {
        let shard_size = self.shard_size as u32;
        let newest = self.newest_shard_id.wrapping_mul(shard_size);
        // shard_size <= 256, so the product fits an i32 (Go: maxShardSets*int32(shardSize)).
        let limit = MAX_SHARD_SETS as i32 * shard_size as i32;
        // discard shards that are too old
        self.shard_set
            .retain(|&shard_id, _| _itimediff(newest, shard_id.wrapping_mul(shard_size)) <= limit);

        DEFAULT_SNMP
            .fec_shard_set
            .store(self.shard_set.len() as u64, Ordering::Relaxed);
    }
}

/// The largest multiple of `shard_size` (1..=256) that fits into a `u32`.
// Go: kcp-go/v5@v5.6.66 fec.go (newFECDecoder/newFECEncoder):
// `0xffffffff / uint32(shardSize) * uint32(shardSize)`
fn paws(shard_size: usize) -> u32 {
    let shard_size = shard_size as u32;
    0xffff_ffff / shard_size * shard_size
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod decoder_tests;

#[cfg(test)]
mod vector_tests;

#[cfg(test)]
mod go_tests;
