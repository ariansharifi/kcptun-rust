//! Growable ring (circular) buffer used for KCP's `snd_queue`, `rcv_queue` and `snd_buf`
//! (port of kcp-go `ringbuffer.go`).
//!
//! The capacity semantics are Go's: the backing array keeps one slot empty to tell "full" from
//! "empty", so a ring with `len(elements) == n` holds at most [`max_len`](RingBuffer::max_len)
//! `= n - 1` elements, and pushing into a full ring grows it (< 8 → 8, < 1024 → ×2, else
//! +10 % rounded up). Vacated slots are reset to `T::default()` (Go's zero value), which drops
//! the old element immediately, as Go does to avoid retaining references.
#![forbid(unsafe_code)]

use std::iter::Chain;
use std::slice;

/// Minimum capacity (length of the backing array).
// Go: kcp-go/v5@v5.6.66 ringbuffer.go:RINGBUFFER_MIN
pub const RINGBUFFER_MIN: usize = 8;
/// Below this capacity the ring doubles when it grows; above it, it grows by 10 %.
// Go: kcp-go/v5@v5.6.66 ringbuffer.go:RINGBUFFER_EXP
pub const RINGBUFFER_EXP: usize = 1024;

/// A FIFO ring buffer that grows when full.
// Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer
#[derive(Clone, Debug)]
pub struct RingBuffer<T> {
    /// Index of the next element to be popped.
    head: usize,
    /// Index of the next empty slot to push into.
    tail: usize,
    /// Underlying storage, used circularly; always at least `RINGBUFFER_MIN` long.
    elements: Vec<T>,
}

/// Iterator over the elements of a [`RingBuffer`] from head to tail (reversible).
pub type Iter<'a, T> = Chain<slice::Iter<'a, T>, slice::Iter<'a, T>>;
/// Mutable iterator over the elements of a [`RingBuffer`] from head to tail (reversible).
pub type IterMut<'a, T> = Chain<slice::IterMut<'a, T>, slice::IterMut<'a, T>>;

impl<T: Default> Default for RingBuffer<T> {
    fn default() -> Self {
        Self::new(RINGBUFFER_MIN)
    }
}

impl<T: Default> RingBuffer<T> {
    /// Creates a ring whose backing array has `size` slots (at least [`RINGBUFFER_MIN`]), so it
    /// holds `size - 1` elements before growing.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:NewRingBuffer()
    pub fn new(size: usize) -> Self {
        let size = size.max(RINGBUFFER_MIN);
        let mut elements = Vec::with_capacity(size);
        elements.resize_with(size, T::default);
        RingBuffer {
            head: 0,
            tail: 0,
            elements,
        }
    }

    /// Appends `v` at the tail, growing the ring first if it is full.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.Push()
    pub fn push(&mut self, v: T) {
        if self.is_full() {
            self.grow();
        }
        self.elements[self.tail] = v;
        self.tail = (self.tail + 1) % self.elements.len();
    }

    /// Removes and returns the element at the head, or `None` if the ring is empty. The slot is
    /// reset to `T::default()`.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.Pop()
    pub fn pop(&mut self) -> Option<T> {
        if self.is_empty() {
            return None;
        }
        let value = std::mem::take(&mut self.elements[self.head]);
        self.head = (self.head + 1) % self.elements.len();
        Some(value)
    }

    /// The element at the head, or `None` if the ring is empty.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.Peek()
    pub fn peek(&self) -> Option<&T> {
        if self.is_empty() {
            return None;
        }
        Some(&self.elements[self.head])
    }

    /// Mutable access to the element at the head (Go's `Peek` returns a pointer).
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.Peek()
    pub fn peek_mut(&mut self) -> Option<&mut T> {
        if self.is_empty() {
            return None;
        }
        Some(&mut self.elements[self.head])
    }

    /// Discards up to `n` elements from the head and returns how many were discarded.
    // Go (post-pin fix, V01): kcp-go@v5.6.72 ringbuffer.go:RingBuffer.Discard()
    // The pinned v5.6.66 loop (clear one slot, advance head modulo len) gives the same result;
    // the upstream rewrite clears whole ranges and handles `head + n == len` (the case
    // TestRingBufferDiscardBoundary covers) by wrapping head to 0.
    pub fn discard(&mut self, n: usize) -> usize {
        let current_len = self.len();
        let n = n.min(current_len);
        if n == current_len {
            self.clear();
            return n;
        }
        let cap = self.elements.len();
        let end = self.head + n;
        if end < cap {
            // No wrap: clear the contiguous range.
            self.elements[self.head..end].fill_with(T::default);
            self.head = end;
        } else {
            // Wraps around.
            self.elements[self.head..cap].fill_with(T::default);
            self.elements[..end - cap].fill_with(T::default);
            self.head = end - cap;
        }
        n
    }

    /// Calls `f` on each element from head to tail until it returns `false`.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.ForEach()
    pub fn for_each<F: FnMut(&mut T) -> bool>(&mut self, mut f: F) {
        for v in self.iter_mut() {
            if !f(v) {
                return;
            }
        }
    }

    /// Calls `f` on each element from tail to head until it returns `false`.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.ForEachReverse()
    pub fn for_each_reverse<F: FnMut(&mut T) -> bool>(&mut self, mut f: F) {
        for v in self.iter_mut().rev() {
            if !f(v) {
                return;
            }
        }
    }

    /// Removes every element (resetting their slots) and rewinds head and tail to 0. The
    /// capacity is kept.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.Clear()
    pub fn clear(&mut self) {
        if self.head <= self.tail {
            self.elements[self.head..self.tail].fill_with(T::default);
        } else {
            self.elements[self.head..].fill_with(T::default);
            self.elements[..self.tail].fill_with(T::default);
        }
        self.head = 0;
        self.tail = 0;
    }

    /// Shrinks the backing array back to `size` slots, keeping whatever the ring still holds,
    /// and reports whether anything was given up.
    ///
    /// This is the counterpart of [`grow`](Self::grow) that Go does not have: `RingBuffer` never
    /// shrinks there either, but a Go process pays for the old array only until the collector and
    /// the scavenger take it back, while here the largest array the ring ever needed is held for
    /// the life of the session. With the production window (`-sndwnd 8192`) one burst takes
    /// `snd_buf` to 8192 slots × 64 B = 512 kB and `rcv_queue` to the same, so an otherwise idle
    /// session keeps about 1 MB it will not use again (plan 12.3, `docs/benchmarks/memory.md` §4).
    ///
    /// The ring is never shrunk below [`RINGBUFFER_MIN`], nor below what it currently holds plus
    /// the always-empty slot, so this is safe to call at any moment. [`crate::memory`] explains
    /// when it is worth calling.
    pub fn shrink_to(&mut self, size: usize) -> bool {
        let new_size = size.max(RINGBUFFER_MIN).max(self.len() + 1);
        if self.elements.len() <= new_size {
            return false;
        }
        let current_length = self.len();
        let mut new_elements: Vec<T> = Vec::with_capacity(new_size);
        // Move the elements in logical order, exactly as `grow` does.
        let (a, b) = self.as_mut_slices();
        new_elements.extend(a.iter_mut().map(std::mem::take));
        new_elements.extend(b.iter_mut().map(std::mem::take));
        new_elements.resize_with(new_size, T::default);

        self.head = 0;
        self.tail = current_length;
        self.elements = new_elements;
        true
    }

    /// Grows the backing array when the ring is full, preserving the element order and moving
    /// the head to index 0.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.grow()
    fn grow(&mut self) {
        let current_length = self.len();
        let current_size = self.elements.len();
        let new_size = if current_size < RINGBUFFER_MIN {
            RINGBUFFER_MIN
        } else if current_size < RINGBUFFER_EXP {
            current_size * 2
        } else {
            current_size + current_size.div_ceil(10) // +10 %, rounded up: (n + 9) / 10
        };

        let mut new_elements: Vec<T> = Vec::with_capacity(new_size);
        // Move the elements in logical order: [head..tail) or [head..end) + [0..tail).
        let (a, b) = self.as_mut_slices();
        new_elements.extend(a.iter_mut().map(std::mem::take));
        new_elements.extend(b.iter_mut().map(std::mem::take));
        new_elements.resize_with(new_size, T::default);

        self.head = 0;
        self.tail = current_length;
        self.elements = new_elements;
    }
}

impl<T> RingBuffer<T> {
    /// Number of elements in the ring.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.Len()
    pub fn len(&self) -> usize {
        if self.head <= self.tail {
            self.tail - self.head
        } else {
            // Wrapped: elements from head to the end, plus from the start to tail.
            self.elements.len() - self.head + self.tail
        }
    }

    /// `true` if the ring holds no elements.
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.IsEmpty()
    pub fn is_empty(&self) -> bool {
        self.head == self.tail
    }

    /// Maximum number of elements before the ring grows (`len(elements) - 1`).
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.MaxLen()
    pub fn max_len(&self) -> usize {
        self.elements.len() - 1
    }

    /// `true` if the next push grows the ring (`(tail + 1) % len(elements) == head`).
    // Go: kcp-go/v5@v5.6.66 ringbuffer.go:RingBuffer.IsFull()
    pub fn is_full(&self) -> bool {
        (self.tail + 1) % self.elements.len() == self.head
    }

    /// The elements as two slices, head to tail: `[head..tail)` and an empty slice, or
    /// `[head..end)` and `[0..tail)` when the ring wraps (the two loops of Go's `ForEach`).
    pub fn as_slices(&self) -> (&[T], &[T]) {
        if self.head <= self.tail {
            (&self.elements[self.head..self.tail], &[])
        } else {
            let (front, back) = self.elements.split_at(self.head);
            (back, &front[..self.tail])
        }
    }

    /// Mutable version of [`as_slices`](Self::as_slices).
    pub fn as_mut_slices(&mut self) -> (&mut [T], &mut [T]) {
        if self.head <= self.tail {
            (&mut self.elements[self.head..self.tail], &mut [])
        } else {
            let (front, back) = self.elements.split_at_mut(self.head);
            (back, &mut front[..self.tail])
        }
    }

    /// The element `index` places after the head, or `None` if the ring holds fewer than
    /// `index + 1` elements.
    ///
    /// Not in Go, which only ever walks the ring. [`Kcp::parse_ack`](crate::kcp::Kcp) uses it
    /// to go straight to the segment an ACK names instead of searching for it (Decision D31);
    /// the index it passes is a sequence-number difference, so it can be arbitrarily large and
    /// is bounded here rather than by the caller.
    pub fn get(&self, index: usize) -> Option<&T> {
        if index >= self.len() {
            return None;
        }
        // `head < elements.len()` and `index < len() <= elements.len()`, so one subtraction
        // brings the sum back into the array: cheaper than a `%` on a runtime divisor.
        let mut i = self.head + index;
        if i >= self.elements.len() {
            i -= self.elements.len();
        }
        Some(&self.elements[i])
    }

    /// Mutable version of [`get`](Self::get).
    pub fn get_mut(&mut self, index: usize) -> Option<&mut T> {
        if index >= self.len() {
            return None;
        }
        let mut i = self.head + index;
        if i >= self.elements.len() {
            i -= self.elements.len();
        }
        Some(&mut self.elements[i])
    }

    /// Mutable iteration over the first `n` elements from the head, in O(1):
    /// [`iter_mut`](Self::iter_mut) stopped after `n` elements (`n` at or above
    /// [`len`](Self::len) yields all of them).
    ///
    /// Not in Go, whose `ForEach` stops by returning `false` from the callback: a test the
    /// loop then runs on every element. `Kcp::parse_fastack` knows from the sequence number
    /// how many segments it has to touch (Decision D31), so it takes that test out of the
    /// loop body. The counterpart of [`iter_mut_from`](Self::iter_mut_from).
    pub fn iter_mut_to(&mut self, n: usize) -> IterMut<'_, T> {
        let n = n.min(self.len());
        let (a, b) = self.as_mut_slices();
        if n <= a.len() {
            let (a, _) = a.split_at_mut(n);
            // The second half is not reached: an empty slice of the same type keeps `IterMut`
            // the same either way.
            let (b, _) = b.split_at_mut(0);
            a.iter_mut().chain(b.iter_mut())
        } else {
            let (b, _) = b.split_at_mut(n - a.len());
            a.iter_mut().chain(b.iter_mut())
        }
    }

    /// Iterates from head to tail; `.rev()` iterates like Go's `ForEachReverse`.
    pub fn iter(&self) -> Iter<'_, T> {
        let (a, b) = self.as_slices();
        a.iter().chain(b.iter())
    }

    /// Mutable iteration from head to tail; `.rev()` iterates from tail to head.
    pub fn iter_mut(&mut self) -> IterMut<'_, T> {
        let (a, b) = self.as_mut_slices();
        a.iter_mut().chain(b.iter_mut())
    }

    /// Mutable iteration from the element `skip` places after the head to the tail, in O(1):
    /// [`iter_mut`](Self::iter_mut) with the first `skip` elements left out (`skip` at or above
    /// [`len`](Self::len) yields nothing).
    ///
    /// Not in Go, which has no `ForEach` from an offset. `Kcp::flush` uses it to leave the part
    /// of `snd_buf` it has proved to be a no-op untouched (Decision D29), and the point is
    /// precisely that the skipped elements are never *read*: `iter_mut().skip(n)` would yield
    /// the same elements, but only because `Chain::nth` happens to forward to the slices'
    /// `nth`, which is not a promise the standard library makes.
    pub fn iter_mut_from(&mut self, skip: usize) -> IterMut<'_, T> {
        let (a, b) = self.as_mut_slices();
        if skip <= a.len() {
            let (_, a) = a.split_at_mut(skip);
            a.iter_mut().chain(b.iter_mut())
        } else {
            let (_, b) = b.split_at_mut((skip - a.len()).min(b.len()));
            // The first half is spent: an empty slice of the same type keeps `IterMut` the
            // same either way.
            let (a, _) = a.split_at_mut(0);
            a.iter_mut().chain(b.iter_mut())
        }
    }
}

impl<'a, T> IntoIterator for &'a RingBuffer<T> {
    type Item = &'a T;
    type IntoIter = Iter<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

impl<'a, T> IntoIterator for &'a mut RingBuffer<T> {
    type Item = &'a mut T;
    type IntoIter = IterMut<'a, T>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter_mut()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::rng::Pcg;

    // Go: kcp-go@v5.6.72 ringbuffer_test.go:TestRingSize
    #[test]
    fn test_ring_size() {
        let mut r = RingBuffer::<i32>::new(1);
        assert_eq!(r.len(), 0);

        // re-zero
        for i in 0..64 {
            r.push(i);
            r.pop();
            assert_eq!(r.len(), 0, "after pushing and popping");
        }

        let mut left: usize = 1024 * 1024;
        for i in 0..left {
            r.push(i as i32);
        }

        // Go uses math/rand; any sequence exercises the same paths.
        let mut rng = Pcg::new(1, 2);
        loop {
            let used = rng.below(left as u64 + 1) as usize;
            left -= used;
            for _ in 0..used {
                assert!(r.pop().is_some(), "expected to pop a value");
            }
            assert_eq!(r.len(), left, "after popping");
            if left == 0 {
                break;
            }
        }
        assert_eq!(r.len(), 0);
    }

    // Go: kcp-go@v5.6.72 ringbuffer_test.go:TestRingSize2
    #[test]
    fn test_ring_size2() {
        // Emulate head = 32, tail = 31 and Len() = 63.
        let mut r = RingBuffer::<i32>::new(64);
        for i in 0..63 {
            r.push(i);
        }
        for _ in 0..32 {
            assert!(r.pop().is_some());
        }
        for i in 0..32 {
            r.push(i + 63);
            assert_eq!(r.len(), i as usize + (63 - 32 + 1));
        }
        assert_eq!(r.head, 32);
        assert_eq!(r.tail, 31);
        assert_eq!(r.len(), 63);

        // One more push grows the ring.
        r.push(95);
        assert_eq!(r.max_len(), 127);
        assert_eq!(r.len(), 64);
        assert_eq!(r.head, 0);
        assert_eq!(r.tail, 64);
        let want: Vec<i32> = (32..96).collect();
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), want);
    }

    // Go: kcp-go@v5.6.72 ringbuffer_test.go:TestRingBuffer
    #[test]
    fn test_ring_buffer() {
        let mut r = RingBuffer::<i32>::new(1);
        assert_eq!(r.len(), 0);
        for i in 0..64 {
            r.push(i);
            assert_eq!(r.len(), i as usize + 1);
        }
        for i in 0..32 {
            assert_eq!(r.pop(), Some(i));
        }
        assert_eq!(r.len(), 32);

        // Push more elements to test the ring's behaviour.
        let size = r.len();
        for i in 0..32 {
            r.push(i);
            assert_eq!(r.len(), i as usize + 1 + size);
        }
        assert_eq!(r.len(), 64);

        // The ring is [32 ... 63, 0 ... 31].
        let mut evicted = 0;
        let expected_head = [62, 28];
        let mut round = 0;
        while !r.is_empty() {
            evicted += r.discard(30);
            if round < expected_head.len() {
                assert_eq!(r.peek(), Some(&expected_head[round]), "round {round}");
            } else {
                assert_eq!(r.peek(), None, "round {round}");
            }
            assert_eq!(r.len() + evicted, 64);
            round += 1;
        }
        assert_eq!(round, 3);
    }

    // Go: kcp-go@v5.6.72 ringbuffer_test.go:TestRingBufferGrow
    #[test]
    fn test_ring_buffer_grow() {
        let mut r = RingBuffer::<usize>::new(4);
        let expected_capacities = [8, 16, 32, 64, 128];
        let push_count = 100;
        for i in 0..push_count {
            r.push(i);
            let capacity = r.max_len();
            let valid = expected_capacities.iter().any(|ec| capacity == ec - 1);
            assert!(
                valid || capacity > RINGBUFFER_EXP,
                "unexpected capacity during growth: {capacity}"
            );
        }
        // Push to 1024.
        for i in push_count..1024 {
            r.push(i);
        }
        // Past RINGBUFFER_EXP the ring grows by 10 %: 1024 + 103 = 1127 slots.
        r.push(1);
        assert_eq!(r.max_len(), 1126);

        // Values are preserved in order.
        for i in 0..push_count {
            assert_eq!(r.pop(), Some(i), "index {i}");
        }
    }

    // Go: kcp-go@v5.6.72 ringbuffer_test.go:TestRingForEach
    #[test]
    fn test_ring_for_each() {
        let mut r = RingBuffer::<i32>::new(10);
        for i in 0..10 {
            r.push(i);
        }
        let mut sum = 0;
        let mut i = 0;
        r.for_each(|v| {
            assert_eq!(*v, i);
            i += 1;
            sum += *v;
            true
        });
        assert_eq!(sum, 45);

        let mut count = 0;
        r.for_each(|_| {
            count += 1;
            true
        });
        assert_eq!(count, 10);
    }

    // Go: kcp-go@v5.6.72 ringbuffer_test.go:TestRingBufferDiscardBoundary
    #[test]
    fn test_ring_buffer_discard_boundary() {
        // Backing array of 64 (MaxLen 63), filled to capacity: head = 0, tail = 63.
        let mut r = RingBuffer::<i32>::new(64);
        for i in 0..63 {
            r.push(i);
        }
        // Pop one and push one so tail wraps to 0: head = 1, tail = 0, len = 63.
        r.pop();
        r.push(63);
        assert_eq!((r.head, r.tail, r.len()), (1, 0, 63));

        // head + 63 == len(elements): head must wrap to 0.
        r.discard(63);
        assert_eq!(r.len(), 0);
        r.push(99);
        assert_eq!(r.peek(), Some(&99));
    }

    // Go: kcp-go@v5.6.72 ringbuffer_test.go:TestRingForEachReverse
    #[test]
    fn test_ring_for_each_reverse() {
        let mut r = RingBuffer::<i32>::new(10);
        for i in 0..10 {
            r.push(i);
        }
        let mut sum = 0;
        let mut i = 9;
        r.for_each_reverse(|v| {
            assert_eq!(*v, i);
            i -= 1;
            sum += *v;
            true
        });
        assert_eq!(sum, 45);

        let mut count = 0;
        r.for_each_reverse(|_| {
            count += 1;
            true
        });
        assert_eq!(count, 10);
    }

    /// Builds a wrapped ring holding `0..n` (head > tail).
    fn wrapped(n: i32) -> RingBuffer<i32> {
        let mut r = RingBuffer::new(16);
        for i in 0..10 {
            r.push(-1 - i);
        }
        for _ in 0..10 {
            r.pop();
        }
        for i in 0..n {
            r.push(i);
        }
        assert!(r.head > r.tail, "ring should wrap");
        r
    }

    #[test]
    fn for_each_stops_early_and_handles_wrap() {
        let mut r = wrapped(12);
        let mut seen = Vec::new();
        r.for_each(|v| {
            seen.push(*v);
            *v != 7
        });
        assert_eq!(seen, (0..=7).collect::<Vec<_>>());

        let mut seen = Vec::new();
        r.for_each_reverse(|v| {
            seen.push(*v);
            *v != 3
        });
        assert_eq!(seen, (3..12).rev().collect::<Vec<_>>());

        // Mutation through for_each is visible.
        r.for_each(|v| {
            *v *= 2;
            true
        });
        assert_eq!(
            r.iter().copied().collect::<Vec<_>>(),
            (0..12).map(|v| v * 2).collect::<Vec<_>>()
        );
        assert_eq!(
            r.iter().rev().copied().collect::<Vec<_>>(),
            (0..12).rev().map(|v| v * 2).collect::<Vec<_>>()
        );
    }

    #[test]
    fn empty_ring_operations() {
        let mut r = RingBuffer::<i32>::default();
        assert!(r.is_empty());
        assert_eq!(r.max_len(), RINGBUFFER_MIN - 1);
        assert_eq!(r.pop(), None);
        assert_eq!(r.peek(), None);
        assert_eq!(r.peek_mut(), None);
        assert_eq!(r.discard(5), 0);
        assert_eq!(r.iter().count(), 0);
        r.for_each(|_| panic!("called on an empty ring"));
        r.for_each_reverse(|_| panic!("called on an empty ring"));
    }

    #[test]
    fn discard_wrapped_partial_and_clear() {
        let mut r = wrapped(12); // head = 10, 16 slots
        assert_eq!(r.discard(8), 8); // crosses the end of the array
        assert_eq!(r.head, 2);
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![8, 9, 10, 11]);
        assert_eq!(r.discard(100), 4);
        assert!(r.is_empty());
        assert_eq!((r.head, r.tail), (0, 0));

        let mut r = wrapped(12);
        r.clear();
        assert!(r.is_empty());
        assert_eq!((r.head, r.tail), (0, 0));
        assert!(r.elements.iter().all(|&v| v == 0), "slots reset to zero");
    }

    #[test]
    fn vacated_slots_drop_their_values() {
        use std::rc::Rc;
        let tracker = Rc::new(());
        let mut r = RingBuffer::<Option<Rc<()>>>::new(8);
        for _ in 0..5 {
            r.push(Some(tracker.clone()));
        }
        assert_eq!(Rc::strong_count(&tracker), 6);
        drop(r.pop());
        assert_eq!(Rc::strong_count(&tracker), 5);
        r.discard(2);
        assert_eq!(Rc::strong_count(&tracker), 3);
        r.clear();
        assert_eq!(Rc::strong_count(&tracker), 1);
    }

    #[test]
    fn grow_policy() {
        // Go: size + (size + 9) / 10 above RINGBUFFER_EXP.
        let mut r = RingBuffer::<u8>::new(RINGBUFFER_EXP);
        for _ in 0..RINGBUFFER_EXP - 1 {
            r.push(0);
        }
        assert!(r.is_full());
        r.push(0);
        assert_eq!(r.elements.len(), 1024 + 103);
        let mut r = RingBuffer::<u8>::new(2000);
        for _ in 0..2000 {
            r.push(0);
        }
        assert_eq!(r.elements.len(), 2000 + 200);
        let mut r = RingBuffer::<u8>::new(2001);
        for _ in 0..2001 {
            r.push(0);
        }
        assert_eq!(r.elements.len(), 2001 + 201);
    }

    /// `shrink_to` gives the backing array back without losing or reordering elements, and
    /// refuses to go below what the ring holds or below `RINGBUFFER_MIN`.
    #[test]
    fn shrink_to_returns_capacity_and_keeps_the_elements() {
        // Grow a ring well past its start size, then drain it.
        let mut r: RingBuffer<i32> = RingBuffer::new(8);
        for i in 0..5000 {
            r.push(i);
        }
        let grown = r.max_len();
        assert!(grown >= 5000, "grown {grown}");
        for i in 0..5000 {
            assert_eq!(r.pop(), Some(i));
        }
        assert!(r.is_empty());
        assert_eq!(r.max_len(), grown, "draining must not shrink by itself");

        assert!(r.shrink_to(64));
        assert_eq!(r.max_len(), 63);
        assert!(!r.shrink_to(64), "already at the target");

        // Usable afterwards, and it grows again exactly as a fresh ring would.
        for i in 0..100 {
            r.push(i);
        }
        assert_eq!(r.len(), 100);
        assert_eq!(r.pop(), Some(0));
    }

    /// Shrinking a ring that still holds data keeps every element, in order, even when the
    /// elements wrap around the end of the array.
    #[test]
    fn shrink_to_keeps_wrapped_elements_in_order() {
        let mut r: RingBuffer<i32> = RingBuffer::new(8);
        for i in 0..2000 {
            r.push(i);
        }
        for _ in 0..1995 {
            r.pop();
        }
        // Push a few more so head is far from 0 and the contents wrap.
        for i in 2000..2003 {
            r.push(i);
        }
        let before: Vec<i32> = r.iter().copied().collect();
        assert_eq!(before, vec![1995, 1996, 1997, 1998, 1999, 2000, 2001, 2002]);

        assert!(r.shrink_to(0));
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), before);
        // Never below RINGBUFFER_MIN, and never below what it holds plus the empty slot.
        assert!(r.max_len() >= before.len());
        assert!(r.max_len() >= RINGBUFFER_MIN - 1);
    }

    /// A ring at or below the target is left alone, allocation included.
    #[test]
    fn shrink_to_is_a_no_op_at_or_below_the_target() {
        let mut r: RingBuffer<i32> = RingBuffer::new(64);
        assert!(!r.shrink_to(64));
        assert!(!r.shrink_to(1024));
        assert_eq!(r.max_len(), 63);
        r.push(1);
        assert!(!r.shrink_to(64));
        assert_eq!(r.peek(), Some(&1));
    }

    /// Shrinking drops the elements the ring no longer has room for: there are none, so
    /// nothing is dropped, but the vacated slots really do release their values.
    #[test]
    fn shrink_to_drops_the_vacated_slots() {
        use std::rc::Rc;
        let mut r: RingBuffer<Option<Rc<u8>>> = RingBuffer::new(8);
        let tracked = Rc::new(7u8);
        for _ in 0..2000 {
            r.push(Some(Rc::clone(&tracked)));
        }
        while r.pop().is_some() {}
        assert_eq!(Rc::strong_count(&tracked), 1, "popping must release");
        assert!(r.shrink_to(8));
        assert_eq!(Rc::strong_count(&tracked), 1);
    }

    /// Model check against VecDeque with random operations.
    #[test]
    fn model_ring_matches_vecdeque() {
        use std::collections::VecDeque;
        let mut rng = Pcg::new(7, 11);
        for _ in 0..50 {
            let mut r = RingBuffer::<u32>::new(rng.below(20) as usize);
            let mut m = VecDeque::new();
            for step in 0..2000u32 {
                match rng.below(6) {
                    0..=2 => {
                        r.push(step);
                        m.push_back(step);
                    }
                    3 => assert_eq!(r.pop(), m.pop_front()),
                    4 => {
                        let n = rng.below(10) as usize;
                        let k = n.min(m.len());
                        assert_eq!(r.discard(n), k);
                        m.drain(..k);
                    }
                    _ => {
                        if let Some(v) = r.peek_mut() {
                            *v = v.wrapping_add(1);
                            *m.front_mut().expect("same length") += 1;
                        }
                    }
                }
                assert_eq!(r.len(), m.len());
                assert_eq!(r.is_empty(), m.is_empty());
                assert!(r.len() <= r.max_len());
                assert_eq!(r.peek(), m.front());
                assert!(r.iter().eq(m.iter()));
                assert!(r.iter().rev().eq(m.iter().rev()));
            }
        }
    }

    /// `iter_mut_from` yields exactly what `iter_mut().skip(n)` would, for every offset and on
    /// both sides of the wrap, including the two degenerate ends, an offset of 0 and one past
    /// the last element.
    #[test]
    fn iter_mut_from_skips_exactly_n_elements() {
        // `head` from 0 to past the end of the backing array, so the ring wraps at every
        // possible place.
        for head in 0..12usize {
            for len in 0..8usize {
                let mut r = RingBuffer::<i32>::new(9);
                for i in 0..head {
                    r.push(i as i32);
                    r.pop();
                }
                for i in 0..len {
                    r.push(1000 + i as i32);
                }
                assert_eq!(r.len(), len);
                for skip in 0..len + 3 {
                    let want: Vec<i32> = r.iter().skip(skip).copied().collect();
                    let got: Vec<i32> = r.iter_mut_from(skip).map(|v| *v).collect();
                    assert_eq!(got, want, "head {head}, len {len}, skip {skip}");
                }
            }
        }
    }

    /// `get`/`get_mut` address exactly what `iter().nth(i)` yields, for every ring layout,
    /// including every place the ring can wrap, and answer `None` past the end.
    #[test]
    fn get_addresses_the_same_element_as_walking_to_it() {
        for head in 0..12usize {
            for len in 0..8usize {
                let mut r = RingBuffer::<i32>::new(9);
                for i in 0..head {
                    r.push(i as i32);
                    r.pop();
                }
                for i in 0..len {
                    r.push(1000 + i as i32);
                }
                for i in 0..len + 3 {
                    let want = r.iter().nth(i).copied();
                    assert_eq!(r.get(i).copied(), want, "head {head}, len {len}, index {i}");
                    assert_eq!(r.get_mut(i).map(|v| *v), want, "head {head}, len {len}");
                }
                // Writing through `get_mut` is visible to everyone else.
                if len > 0 {
                    *r.get_mut(len - 1).expect("last element") = -1;
                    assert_eq!(r.iter().next_back(), Some(&-1));
                }
            }
        }
    }

    /// `iter_mut_to` yields exactly what `iter_mut().take(n)` would, for every bound and on
    /// both sides of the wrap, and touches nothing past the bound.
    #[test]
    fn iter_mut_to_stops_after_n_elements() {
        for head in 0..12usize {
            for len in 0..8usize {
                let mut r = RingBuffer::<i32>::new(9);
                for i in 0..head {
                    r.push(i as i32);
                    r.pop();
                }
                for i in 0..len {
                    r.push(1000 + i as i32);
                }
                for n in 0..len + 3 {
                    let want: Vec<i32> = r.iter().take(n).copied().collect();
                    let got: Vec<i32> = r.iter_mut_to(n).map(|v| *v).collect();
                    assert_eq!(got, want, "head {head}, len {len}, n {n}");
                }
            }
        }

        let mut r = RingBuffer::<i32>::new(6);
        for i in 0..8 {
            r.push(i);
            if i < 3 {
                r.pop();
            }
        }
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![3, 4, 5, 6, 7]);
        for v in r.iter_mut_to(2) {
            *v = -*v;
        }
        assert_eq!(r.iter().copied().collect::<Vec<_>>(), vec![-3, -4, 5, 6, 7]);
    }

    /// The elements it skips are not touched: only those from `skip` on are written through.
    #[test]
    fn iter_mut_from_writes_only_past_the_offset() {
        let mut r = RingBuffer::<i32>::new(6);
        for i in 0..8 {
            r.push(i);
            if i < 3 {
                r.pop();
            }
        }
        let before: Vec<i32> = r.iter().copied().collect();
        assert_eq!(before, vec![3, 4, 5, 6, 7]);
        for v in r.iter_mut_from(2) {
            *v = -*v;
        }
        assert_eq!(
            r.iter().copied().collect::<Vec<_>>(),
            vec![3, 4, -5, -6, -7]
        );
    }
}
