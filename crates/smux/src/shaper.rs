//! The write shaper: one priority heap per stream id, served round-robin.
//!
//! Port of `shaper.go`. Every frame a session sends goes through here, so this file decides the
//! order of the bytes on the wire (`docs/WIRE-FORMAT.md` §7):
//!
//! - inside one stream: [`ClassId::Ctrl`] (`cmdSYN`, `cmdUPD`) before [`ClassId::Data`]
//!   (`cmdPSH`, `cmdFIN`), then by request sequence number with a wrapping compare, so a `cmdFIN`
//!   never overtakes the stream's data;
//! - across streams: round-robin over the stream ids that have pending frames, in the order the
//!   ids first queued a frame. The keepalive `cmdNOP` uses stream id 0, so it is one more
//!   round-robin member and has no global priority.
//!
//! **Structure of the port (DECISIONS D15).** Go runs a `shaperLoop` goroutine that moves
//! requests from a channel into a `shaperQueue` guarded by the queue's own `sync.Mutex`, with an
//! atomic counter so `Len`/`IsEmpty` can be read without that mutex. The port merges the
//! goroutine away: writers push into the queue directly and the send task pops from it, so the
//! session owns one `Mutex<ShaperQueue<_>>` (never held across an `.await`) and this type needs
//! no interior locking and no atomics: `len` and `is_empty` are plain field reads under the
//! session's lock. Admission is bounded at [`MAX_SHAPER_SIZE`](crate::MAX_SHAPER_SIZE) requests
//! by the session (06.3), the same bound Go's `shaperLoop` enforces by detaching the channel.
//! The ordering rules, and therefore the frame order, are unchanged; that is what the tests
//! ported from `shaper_test.go` below pin down.

use std::collections::HashMap;
use std::collections::hash_map::Entry;

use crate::session::ClassId;

// Go: smux@v1.5.55 shaper.go:_itimediff()
/// `later - earlier` as a signed difference (porting guide §3): sequence numbers wrap.
fn itimediff(later: u32, earlier: u32) -> i32 {
    later.wrapping_sub(earlier) as i32
}

/// One queued frame: the ordering keys plus the caller's `body`.
///
/// Go's `writeRequest` is `{class, frame Frame, seq uint32, result chan writeResult}`. The port
/// keeps `class`, the frame's `sid` and `seq` (everything the shaper orders by) and leaves the
/// rest to the session, which picks `T`: Go's `Frame` borrows the writer's buffer, while a
/// request that crosses to the send task has to own its payload (an `Arc<[u8]>`, say) and carry
/// the channel that reports the result back. The shaper never looks inside `body`.
// Go: smux@v1.5.55 session.go:writeRequest
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct WriteRequest<T> {
    /// Priority class: control frames of a stream go before its data frames.
    pub class: ClassId,
    /// Stream id of the frame (Go reads `req.frame.sid`).
    pub sid: u32,
    /// Session-wide request sequence number (Go: `atomic.AddUint32(&s.requestID, 1)`).
    pub seq: u32,
    /// Whatever the session needs to send the frame and report the result.
    pub body: T,
}

/// A min-heap of [`WriteRequest`]s, ordered by class and then by sequence number.
///
/// A verbatim port of Go's `shaperHeap` *and* of the `container/heap` sift algorithm it is
/// driven by (`up`/`down` from `go1.27.1 src/container/heap/heap.go`), so that even requests
/// that compare equal come out in Go's order.
// Go: smux@v1.5.55 shaper.go:shaperHeap
#[derive(Debug)]
pub(crate) struct ShaperHeap<T> {
    items: Vec<WriteRequest<T>>,
}

impl<T> ShaperHeap<T> {
    /// Creates an empty heap.
    pub const fn new() -> Self {
        ShaperHeap { items: Vec::new() }
    }

    /// Creates an empty heap with room for `capacity` requests.
    ///
    /// Go takes heaps from a `sync.Pool` whose `New` pre-allocates 16 entries; the port has no
    /// pool (`Drop` frees the storage), but keeps the initial capacity.
    // Go: smux@v1.5.55 shaper.go:shaperHeapPool
    pub fn with_capacity(capacity: usize) -> Self {
        ShaperHeap {
            items: Vec::with_capacity(capacity),
        }
    }

    /// Number of queued requests.
    // Go: smux@v1.5.55 shaper.go:shaperHeap.Len()
    // Part of the ported heap interface; only the ported tests read it.
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.items.len()
    }

    /// Whether the heap is empty.
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    /// Whether `items[i]` sorts before `items[j]`: class first, then the wrapping sequence
    /// compare. Panics never happen: both indices come from the heap algorithm.
    // Go: smux@v1.5.55 shaper.go:shaperHeap.Less()
    fn less(&self, i: usize, j: usize) -> bool {
        let a = &self.items[i];
        let b = &self.items[j];
        if a.class != b.class {
            return a.class < b.class;
        }
        itimediff(b.seq, a.seq) > 0
    }

    /// Queues a request (`heap.Push`: append, then sift up).
    // Go: go1.27.1 src/container/heap/heap.go:Push() with shaper.go:shaperHeap.Push()
    pub fn push(&mut self, req: WriteRequest<T>) {
        self.items.push(req);
        self.up(self.items.len() - 1);
    }

    /// Removes and returns the smallest request, or `None` if the heap is empty (`heap.Pop`
    /// panics there; no caller in this crate can reach it).
    ///
    /// Pinned smux v1.5.55 already clears the vacated slot (`old[n-1] = writeRequest{}`) so the
    /// popped frame's payload is not kept alive by the heap's backing array. `Vec::pop` moves the
    /// request out of the array, which has the same effect.
    // Go: go1.27.1 src/container/heap/heap.go:Pop() with shaper.go:shaperHeap.Pop()
    pub fn pop(&mut self) -> Option<WriteRequest<T>> {
        let n = self.items.len().checked_sub(1)?;
        self.items.swap(0, n);
        self.down(0, n);
        self.items.pop()
    }

    // Go: go1.27.1 src/container/heap/heap.go:up()
    fn up(&mut self, j: usize) {
        let mut j = j;
        loop {
            // Go: `i := (j - 1) / 2; if i == j`, integer division makes the root its own
            // parent, which is the loop's exit condition.
            if j == 0 {
                break;
            }
            let i = (j - 1) / 2;
            if !self.less(j, i) {
                break;
            }
            self.items.swap(i, j);
            j = i;
        }
    }

    /// Sifts `i0` down through the first `n` items. The return value says whether anything
    /// moved; Go needs it for `heap.Fix`, which smux never calls, and so does nobody here.
    // Go: go1.27.1 src/container/heap/heap.go:down()
    fn down(&mut self, i0: usize, n: usize) -> bool {
        let mut i = i0;
        // Go guards `j1 < 0` against int overflow; `checked_*` is the same guard.
        while let Some(j1) = i.checked_mul(2).and_then(|v| v.checked_add(1)) {
            if j1 >= n {
                break;
            }
            let mut j = j1;
            let j2 = j1 + 1;
            if j2 < n && self.less(j2, j1) {
                j = j2;
            }
            if !self.less(j, i) {
                break;
            }
            self.items.swap(i, j);
            i = j;
        }
        i > i0
    }
}

impl<T> Default for ShaperHeap<T> {
    fn default() -> Self {
        ShaperHeap::new()
    }
}

/// Index of a node in [`RrList`]'s slab.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct NodeId(usize);

/// One round-robin list entry: a stream id and its neighbours.
#[derive(Debug)]
struct RrNode {
    sid: u32,
    prev: Option<NodeId>,
    next: Option<NodeId>,
}

/// The round-robin list of stream ids with pending frames.
///
/// Go uses `container/list`, a doubly linked list of pointers, and holds one element pointer
/// (`sq.next`) across calls. The port is the same doubly linked list over a slab of slots, with
/// [`NodeId`] indices instead of pointers and a free list so removed slots are reused; the safe
/// equivalent of Go's `*list.Element`. Insertion order matters: `Push` appends new ids at the
/// back while the cursor keeps walking the existing ones, which is why the list cannot be
/// replaced by a rotating queue (a `VecDeque` that re-appends the id it just served would put a
/// newly queued id *before* the ids the cursor has not reached yet).
// Go: container/list, used as smux@v1.5.55 shaper.go:shaperQueue.rrList
#[derive(Debug, Default)]
struct RrList {
    slots: Vec<Option<RrNode>>,
    free: Vec<usize>,
    front: Option<NodeId>,
    back: Option<NodeId>,
    len: usize,
}

impl RrList {
    fn new() -> Self {
        RrList::default()
    }

    /// Number of ids in the list (`rrList.Len()`).
    fn len(&self) -> usize {
        self.len
    }

    fn node(&self, id: NodeId) -> &RrNode {
        self.slots[id.0]
            .as_ref()
            .expect("shaper RR list: a node id is used only while its node is in the list")
    }

    fn node_mut(&mut self, id: NodeId) -> &mut RrNode {
        self.slots[id.0]
            .as_mut()
            .expect("shaper RR list: a node id is used only while its node is in the list")
    }

    /// The stream id stored in `id`.
    fn sid(&self, id: NodeId) -> u32 {
        self.node(id).sid
    }

    /// The element after `id`, or `None` at the back (`elem.Next()`).
    fn next(&self, id: NodeId) -> Option<NodeId> {
        self.node(id).next
    }

    /// The first element (`rrList.Front()`).
    fn front(&self) -> Option<NodeId> {
        self.front
    }

    /// Appends `sid` and returns its element (`rrList.PushBack(sid)`).
    fn push_back(&mut self, sid: u32) -> NodeId {
        let node = RrNode {
            sid,
            prev: self.back,
            next: None,
        };
        let id = match self.free.pop() {
            Some(slot) => {
                self.slots[slot] = Some(node);
                NodeId(slot)
            }
            None => {
                self.slots.push(Some(node));
                NodeId(self.slots.len() - 1)
            }
        };
        match self.back {
            Some(back) => self.node_mut(back).next = Some(id),
            None => self.front = Some(id),
        }
        self.back = Some(id);
        self.len += 1;
        id
    }

    /// Unlinks `id` and frees its slot (`rrList.Remove(elem)`).
    fn remove(&mut self, id: NodeId) {
        let (prev, next) = {
            let node = self.node(id);
            (node.prev, node.next)
        };
        match prev {
            Some(p) => self.node_mut(p).next = next,
            None => self.front = next,
        }
        match next {
            Some(n) => self.node_mut(n).prev = prev,
            None => self.back = prev,
        }
        self.slots[id.0] = None;
        self.free.push(id.0);
        self.len -= 1;
    }
}

/// The session's write queue: one [`ShaperHeap`] per stream id, served round-robin.
///
/// `T` is the request body the session attaches to each frame; see [`WriteRequest`].
// Go: smux@v1.5.55 shaper.go:shaperQueue
#[derive(Debug)]
pub struct ShaperQueue<T> {
    /// Total number of queued requests (Go: `atomic.AddInt64(&sq.count, ±1)`; the port is
    /// always called under the session's mutex, so a plain counter is enough).
    count: usize,
    streams: HashMap<u32, ShaperHeap<T>>,
    rr_list: RrList,
    /// The element to start the next [`pop`](Self::pop) from (Go: `sq.next`).
    next: Option<NodeId>,
}

impl<T> ShaperQueue<T> {
    /// Creates an empty queue.
    // Go: smux@v1.5.55 shaper.go:NewShaperQueue()
    pub fn new() -> Self {
        ShaperQueue {
            count: 0,
            streams: HashMap::new(),
            rr_list: RrList::new(),
            next: None,
        }
    }

    /// Queues `req` in its stream's heap, appending the stream to the round-robin list the
    /// first time it has a pending frame.
    // Go: smux@v1.5.55 shaper.go:shaperQueue.Push()
    pub fn push(&mut self, req: WriteRequest<T>) {
        // create heap for the stream if not exists.
        let sid = req.sid;
        let heap = match self.streams.entry(sid) {
            Entry::Occupied(e) => e.into_mut(),
            Entry::Vacant(e) => {
                let elem = self.rr_list.push_back(sid);
                if self.next.is_none() {
                    self.next = Some(elem);
                }
                // Go takes a heap with capacity 16 from shaperHeapPool.
                e.insert(ShaperHeap::with_capacity(16))
            }
        };

        // push the request into the corresponding stream heap.
        heap.push(req);
        self.count += 1;
    }

    /// Returns the next frame to write, round-robin over the streams that have one.
    ///
    /// The cursor advances to the element *after* the one served, wrapping at the back, and a
    /// stream whose heap runs empty leaves the list at once, so every element in the list has
    /// pending frames and the scan below always succeeds on its first step. The scan is Go's
    /// and is kept for the same reason Go keeps it: it is what makes the cursor safe.
    // Go: smux@v1.5.55 shaper.go:shaperQueue.Pop()
    pub fn pop(&mut self) -> Option<WriteRequest<T>> {
        // if there are no streams, return false
        let start = self.next?;
        if self.count == 0 {
            return None;
        }

        // get the starting index for round-robin.
        let mut current = start;

        // loop through all streams in a round-robin manner
        loop {
            let sid = self.rr_list.sid(current);
            let popped = match self.streams.get_mut(&sid) {
                Some(h) if !h.is_empty() => h.pop().map(|req| (req, h.is_empty())),
                _ => None,
            };

            if let Some((req, now_empty)) = popped {
                self.count -= 1;

                // update next pointer for round-robin
                let next = self.rr_list.next(current).or_else(|| self.rr_list.front());
                self.next = next;

                // If the heap is empty after popping, delete it.
                if now_empty {
                    self.streams.remove(&sid);
                    self.rr_list.remove(current);
                    // if a list has only one element, then current->next will point to itself,
                    // so after removing current, we need to set next to nil.
                    if self.rr_list.len() == 0 {
                        self.next = None;
                    }
                }
                return Some(req);
            }

            // move to next
            current = match self.rr_list.next(current).or_else(|| self.rr_list.front()) {
                Some(id) => id,
                None => break,
            };
            if current == start {
                // full loop: no packets
                break;
            }
        }

        // no requests found in any stream
        None
    }

    /// Whether nothing is queued.
    // Go: smux@v1.5.55 shaper.go:shaperQueue.IsEmpty()
    pub fn is_empty(&self) -> bool {
        self.count == 0
    }

    /// Total number of queued requests.
    // Go: smux@v1.5.55 shaper.go:shaperQueue.Len()
    pub fn len(&self) -> usize {
        self.count
    }

    /// Number of stream ids with at least one queued request (Go: `len(sq.streams)`).
    pub fn num_streams(&self) -> usize {
        self.streams.len()
    }
}

impl<T> Default for ShaperQueue<T> {
    fn default() -> Self {
        ShaperQueue::new()
    }
}

#[cfg(test)]
mod tests;
