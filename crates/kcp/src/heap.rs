//! Min-heap of received out-of-order segments (`rcv_buf`), ordered by sequence number with
//! wrapping comparison, plus a set of the sequence numbers it holds (port of kcp-go's
//! `segmentHeap` in `kcp.go`, driven through Go's `container/heap`).
//!
//! The sift-up/sift-down code mirrors `container/heap` (`Push` = append + up, `Pop` = swap the
//! root with the last element + down + remove the last). KCP never inserts two segments with the
//! same `sn` (`parse_data` checks [`has`](SegmentHeap::has) first), so the pop order is fully
//! determined by the keys; mirroring `container/heap` exactly additionally keeps the internal
//! layout identical to Go's.
#![forbid(unsafe_code)]

use std::collections::HashSet;

use crate::kcp::_itimediff;
use crate::segment::Segment;

/// Receive-side segment heap with duplicate detection.
// Go: kcp-go/v5@v5.6.66 kcp.go:segmentHeap
#[derive(Clone, Debug, Default)]
pub struct SegmentHeap {
    segments: Vec<Segment>,
    /// Sequence numbers currently in the heap (Go: `marks map[uint32]struct{}`).
    marks: HashSet<u32>,
}

impl SegmentHeap {
    /// Creates an empty heap.
    // Go: kcp-go/v5@v5.6.66 kcp.go:newSegmentHeap()
    pub fn new() -> Self {
        Self::default()
    }

    /// Number of segments in the heap.
    // Go: kcp-go/v5@v5.6.66 kcp.go:segmentHeap.Len()
    pub fn len(&self) -> usize {
        self.segments.len()
    }

    /// `true` if the heap is empty.
    pub fn is_empty(&self) -> bool {
        self.segments.is_empty()
    }

    /// `segments[i]` sorts before `segments[j]`: `_itimediff(sn_j, sn_i) > 0`.
    // Go: kcp-go/v5@v5.6.66 kcp.go:segmentHeap.Less()
    fn less(&self, i: usize, j: usize) -> bool {
        _itimediff(self.segments[j].sn, self.segments[i].sn) > 0
    }

    /// Inserts `seg` and marks its `sn`.
    // Go: container/heap.Push(h, seg) with kcp-go/v5@v5.6.66 kcp.go:segmentHeap.Push()
    pub fn push(&mut self, seg: Segment) {
        self.marks.insert(seg.sn);
        self.segments.push(seg);
        self.up(self.segments.len() - 1);
    }

    /// Removes and returns the segment with the smallest `sn` (wrapping order) and unmarks it,
    /// or `None` if the heap is empty (Go's `heap.Pop` panics on an empty heap; KCP only pops
    /// after checking `Len() > 0`).
    // Go: container/heap.Pop(h) with kcp-go/v5@v5.6.66 kcp.go:segmentHeap.Pop()
    // Go (post-pin fix, V01): kcp-go@v5.6.72 kcp.go:segmentHeap.Pop() clears the vacated
    // slot (`h.segments[n-1] = segment{}`); Vec::pop moves the segment out, so nothing is retained here either.
    pub fn pop(&mut self) -> Option<Segment> {
        let n = self.segments.len().checked_sub(1)?;
        self.segments.swap(0, n);
        self.down(0, n);
        let x = self.segments.pop()?;
        self.marks.remove(&x.sn);
        Some(x)
    }

    /// The segment with the smallest `sn` (Go reads `rcv_buf.segments[0]`).
    pub fn peek(&self) -> Option<&Segment> {
        self.segments.first()
    }

    /// `true` if a segment with this `sn` is in the heap.
    // Go: kcp-go/v5@v5.6.66 kcp.go:segmentHeap.Has()
    pub fn has(&self, sn: u32) -> bool {
        self.marks.contains(&sn)
    }

    /// The segments in heap (array) order, e.g. for iteration in `recv`/`peek_size`.
    pub fn segments(&self) -> &[Segment] {
        &self.segments
    }

    /// Slots the backing array can hold without reallocating.
    pub fn capacity(&self) -> usize {
        self.segments.capacity()
    }

    /// Releases the capacity a burst of out-of-order segments left behind, and reports whether
    /// anything was given up. The contents and the heap order are untouched.
    ///
    /// `rcv_buf` grows to hold the whole receive window while a burst is being reassembled: up
    /// to `-rcvwnd` 8192 entries, 512 kB of `Segment` plus the `marks` set, and neither `Vec`
    /// nor `HashSet` gives that back on its own. Go's do not either, but there the replaced
    /// arrays become garbage that the collector and the scavenger return (plan 12.3,
    /// `docs/benchmarks/memory.md` §4).
    pub fn shrink(&mut self) -> bool {
        let before = self.segments.capacity() + self.marks.capacity();
        self.segments.shrink_to_fit();
        self.marks.shrink_to_fit();
        self.segments.capacity() + self.marks.capacity() < before
    }

    // Go: container/heap up()
    fn up(&mut self, mut j: usize) {
        while j > 0 {
            let i = (j - 1) / 2; // parent
            if !self.less(j, i) {
                break;
            }
            self.segments.swap(i, j);
            j = i;
        }
    }

    // Go: container/heap down()
    fn down(&mut self, i0: usize, n: usize) -> bool {
        let mut i = i0;
        loop {
            let j1 = 2 * i + 1;
            if j1 >= n {
                break;
            }
            let mut j = j1; // left child
            let j2 = j1 + 1;
            if j2 < n && self.less(j2, j1) {
                j = j2; // right child
            }
            if !self.less(j, i) {
                break;
            }
            self.segments.swap(i, j);
            i = j;
        }
        i > i0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kcptun_testkit::rng::Pcg;

    fn seg(sn: u32) -> Segment {
        Segment {
            sn,
            ..Segment::default()
        }
    }

    // Go: kcp-go@v5.6.72 kcp_test.go:TestSegmentHeap
    #[test]
    fn test_segment_heap() {
        let mut h = SegmentHeap::new();
        let segments = [seg(1), seg(2), seg(3)];
        for s in &segments {
            h.push(s.clone());
        }
        assert_eq!(h.len(), segments.len());
        for s in &segments {
            assert_eq!(h.pop().map(|x| x.sn), Some(s.sn));
        }
    }

    #[test]
    fn marks_follow_push_and_pop() {
        let mut h = SegmentHeap::new();
        assert!(h.is_empty());
        assert_eq!(h.pop(), None);
        assert_eq!(h.peek(), None);
        for sn in [5, 3, 9] {
            h.push(seg(sn));
        }
        assert!(h.has(3) && h.has(5) && h.has(9) && !h.has(4));
        assert_eq!(h.peek().map(|s| s.sn), Some(3));
        assert_eq!(h.pop().map(|s| s.sn), Some(3));
        assert!(!h.has(3));
        assert!(h.has(5));
        assert_eq!(h.segments().len(), 2);
    }

    #[test]
    fn wrapping_order_across_u32_max() {
        let mut h = SegmentHeap::new();
        for sn in [2, u32::MAX, 0, u32::MAX - 1, 1] {
            h.push(seg(sn));
        }
        let order: Vec<u32> = std::iter::from_fn(|| h.pop().map(|s| s.sn)).collect();
        assert_eq!(order, vec![u32::MAX - 1, u32::MAX, 0, 1, 2]);
    }

    /// Random unique sns within a window pop in wrapping-sorted order, and the heap invariant
    /// holds after every operation.
    #[test]
    fn heap_pops_in_wrapping_order_random() {
        let mut rng = Pcg::new(3, 5);
        for _ in 0..200 {
            let base = rng.next_u32();
            let n = rng.below(64) as usize;
            let mut offsets: Vec<u32> = (0..256).collect();
            // Fisher-Yates with the deterministic generator.
            for i in (1..offsets.len()).rev() {
                offsets.swap(i, rng.below(i as u64 + 1) as usize);
            }
            offsets.truncate(n);
            let mut h = SegmentHeap::new();
            for &o in &offsets {
                h.push(seg(base.wrapping_add(o)));
                check_invariant(&h);
            }
            let mut sorted = offsets.clone();
            sorted.sort_unstable();
            for o in sorted {
                assert!(h.has(base.wrapping_add(o)));
                assert_eq!(h.pop().map(|s| s.sn), Some(base.wrapping_add(o)));
                assert!(!h.has(base.wrapping_add(o)));
                check_invariant(&h);
            }
            assert!(h.is_empty() && h.marks.is_empty());
        }
    }

    fn check_invariant(h: &SegmentHeap) {
        for j in 1..h.len() {
            assert!(!h.less(j, (j - 1) / 2), "heap order violated at {j}");
        }
        assert_eq!(h.marks.len(), h.len());
    }
}
