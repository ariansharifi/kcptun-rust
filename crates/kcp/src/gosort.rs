//! Go's `sort.Slice` (pattern-defeating quicksort), ported from the Go 1.27.1 standard library
//! (`sort/slice.go` and the generated `sort/zsortfunc.go`), for [`autotune`](crate::autotune).
//!
//! kcp-go's `autoTune.FindPeriod` sorts its samples with `sort.Slice` and the comparison
//! `_itimediff(a.seq, b.seq) < 0`. That comparison is only a strict weak order while all seqids
//! lie within 2^31 of each other, and samples may have equal seqids (duplicate packets). Both
//! happen with packets from the network, so the Rust standard library sorts cannot be used:
//! they may **panic** when the comparison is not a total order (Rust ≥ 1.81), and even when they
//! do not, the order they leave for equal or cyclic elements differs from Go's, which can change
//! the period `FindPeriod` finds. This module reproduces Go's algorithm step by step (same
//! pivots, same swaps, same `xorshift` pattern breaking seeded by the length), so the resulting
//! order is identical to Go's for **every** input, including inconsistent comparisons, and like
//! Go it never indexes outside the slice. `sort.Slice` is not stable; this port is exactly as
//! unstable. The `autotune` golden vectors (`testdata/vectors/autotune.json`) compare the full
//! sorted order with Go's.
//!
//! Go's `int` indices become `usize`; every subtraction is guarded exactly where Go's loop
//! conditions keep the index non-negative. Go's `uint` in `breakPatterns` is `usize` (both are
//! the pointer width).
#![forbid(unsafe_code)]

/// Counters of the rarely taken paths, so the tests can prove the golden vectors reach them.
#[cfg(test)]
pub(crate) mod coverage {
    use std::cell::Cell;

    thread_local! {
        pub(crate) static HEAP_SORT: Cell<u64> = const { Cell::new(0) };
        pub(crate) static BREAK_PATTERNS: Cell<u64> = const { Cell::new(0) };
        pub(crate) static DECREASING_HINT: Cell<u64> = const { Cell::new(0) };
        pub(crate) static PARTITION_EQUAL: Cell<u64> = const { Cell::new(0) };
        pub(crate) static PARTIAL_INSERTION_SORTED: Cell<u64> = const { Cell::new(0) };
        pub(crate) static PARTIAL_INSERTION_SHIFT: Cell<u64> = const { Cell::new(0) };
    }

    /// Resets every counter of this thread.
    pub(crate) fn reset() {
        for c in [
            &HEAP_SORT,
            &BREAK_PATTERNS,
            &DECREASING_HINT,
            &PARTITION_EQUAL,
            &PARTIAL_INSERTION_SORTED,
            &PARTIAL_INSERTION_SHIFT,
        ] {
            c.with(|c| c.set(0));
        }
    }
}

/// Counts a rarely taken path (tests only).
macro_rules! hit {
    ($name:ident) => {
        #[cfg(test)]
        coverage::$name.with(|c| c.set(c.get() + 1));
    };
}

/// Go's `lessSwap`: the slice and the `less` function, addressed by index.
struct LessSwap<'a, T, F> {
    data: &'a mut [T],
    less: F,
}

impl<T, F: FnMut(&T, &T) -> bool> LessSwap<'_, T, F> {
    #[inline]
    fn less(&mut self, i: usize, j: usize) -> bool {
        (self.less)(&self.data[i], &self.data[j])
    }

    #[inline]
    fn swap(&mut self, i: usize, j: usize) {
        self.data.swap(i, j);
    }
}

/// Go's `sortedHint`.
// Go: go1.27.1 sort/sort.go:sortedHint
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum SortedHint {
    Unknown,
    Increasing,
    Decreasing,
}

/// Go's `xorshift` generator of `breakPatterns`.
// Go: go1.27.1 sort/sort.go:xorshift
struct Xorshift(u64);

impl Xorshift {
    // Go: go1.27.1 sort/sort.go:xorshift.Next()
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
}

/// `bits.Len(uint(x))`: the number of bits needed to represent `x` (0 for 0).
fn bits_len(x: usize) -> u32 {
    usize::BITS - x.leading_zeros()
}

// Go: go1.27.1 sort/sort.go:nextPowerOfTwo()
fn next_power_of_two(length: usize) -> usize {
    // length >= 8 here (breakPatterns), so the shift is below usize::BITS.
    1usize << bits_len(length)
}

/// Sorts `data` in place like Go's `sort.Slice(data, less)`, where `less(a, b)` reports whether
/// `a` must sort before `b`. Produces exactly Go's order, also for comparisons that are not a
/// strict weak order, and never panics unless `less` does.
// Go: go1.27.1 sort/slice.go:Slice()
pub fn slice<T, F: FnMut(&T, &T) -> bool>(data: &mut [T], less: F) {
    let length = data.len();
    let limit = bits_len(length) as usize;
    let mut ls = LessSwap { data, less };
    pdqsort_func(&mut ls, 0, length, limit);
}

/// Sorts `data[a..b]` by insertion sort.
// Go: go1.27.1 sort/zsortfunc.go:insertionSort_func()
fn insertion_sort_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
) {
    for i in a + 1..b {
        let mut j = i;
        while j > a && data.less(j, j - 1) {
            data.swap(j, j - 1);
            j -= 1;
        }
    }
}

/// Restores the heap property on `data[lo..hi]`; `first` is the offset of the heap's root.
// Go: go1.27.1 sort/zsortfunc.go:siftDown_func()
fn sift_down_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    lo: usize,
    hi: usize,
    first: usize,
) {
    let mut root = lo;
    loop {
        let mut child = 2 * root + 1;
        if child >= hi {
            break;
        }
        if child + 1 < hi && data.less(first + child, first + child + 1) {
            child += 1;
        }
        if !data.less(first + root, first + child) {
            return;
        }
        data.swap(first + root, first + child);
        root = child;
    }
}

// Go: go1.27.1 sort/zsortfunc.go:heapSort_func()
fn heap_sort_func<T, F: FnMut(&T, &T) -> bool>(data: &mut LessSwap<'_, T, F>, a: usize, b: usize) {
    hit!(HEAP_SORT);
    let first = a;
    let lo = 0;
    let hi = b - a;

    // Build heap with greatest element at top.
    // Go: for i := (hi - 1) / 2; i >= 0; i-- (hi > 12 here, see pdqsort_func)
    for i in (0..=(hi - 1) / 2).rev() {
        sift_down_func(data, i, hi, first);
    }

    // Pop elements, largest first, into end of data.
    for i in (0..hi).rev() {
        data.swap(first, first + i);
        sift_down_func(data, lo, i, first);
    }
}

/// Sorts `data[a..b]`; `limit` is the number of bad (very unbalanced) pivots allowed before
/// falling back to heapsort.
// Go: go1.27.1 sort/zsortfunc.go:pdqsort_func()
fn pdqsort_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    mut a: usize,
    mut b: usize,
    mut limit: usize,
) {
    const MAX_INSERTION: usize = 12;

    let mut was_balanced = true; // whether the last partitioning was reasonably balanced
    let mut was_partitioned = true; // whether the slice was already partitioned

    loop {
        let length = b - a;

        if length <= MAX_INSERTION {
            insertion_sort_func(data, a, b);
            return;
        }

        // Fall back to heapsort if too many bad choices were made.
        if limit == 0 {
            heap_sort_func(data, a, b);
            return;
        }

        // If the last partitioning was imbalanced, we need to breaking patterns.
        if !was_balanced {
            break_patterns_func(data, a, b);
            limit -= 1;
        }

        let (mut pivot, mut hint) = choose_pivot_func(data, a, b);
        if hint == SortedHint::Decreasing {
            hit!(DECREASING_HINT);
            reverse_range_func(data, a, b);
            // The chosen pivot was pivot-a elements after the start of the array.
            // After reversing it is pivot-a elements before the end of the array.
            pivot = (b - 1) - (pivot - a);
            hint = SortedHint::Increasing;
        }

        // The slice is likely already sorted.
        if was_balanced
            && was_partitioned
            && hint == SortedHint::Increasing
            && partial_insertion_sort_func(data, a, b)
        {
            hit!(PARTIAL_INSERTION_SORTED);
            return;
        }

        // Probably the slice contains many duplicate elements, partition the slice into
        // elements equal to and elements greater than the pivot.
        if a > 0 && !data.less(a - 1, pivot) {
            hit!(PARTITION_EQUAL);
            let mid = partition_equal_func(data, a, b, pivot);
            a = mid;
            continue;
        }

        let (mid, already_partitioned) = partition_func(data, a, b, pivot);
        was_partitioned = already_partitioned;

        let (left_len, right_len) = (mid - a, b - mid);
        let balance_threshold = length / 8;
        if left_len < right_len {
            was_balanced = left_len >= balance_threshold;
            pdqsort_func(data, a, mid, limit);
            a = mid + 1;
        } else {
            was_balanced = right_len >= balance_threshold;
            pdqsort_func(data, mid + 1, b, limit);
            b = mid;
        }
    }
}

/// One quicksort partition of `data[a..b]` around `data[pivot]`: returns the pivot's new index
/// and whether the range was already partitioned.
// Go: go1.27.1 sort/zsortfunc.go:partition_func()
fn partition_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
    pivot: usize,
) -> (usize, bool) {
    data.swap(a, pivot);
    // i and j are inclusive of the elements remaining to be partitioned. j never drops below
    // i - 1 >= a, so it cannot underflow.
    let (mut i, mut j) = (a + 1, b - 1);

    while i <= j && data.less(i, a) {
        i += 1;
    }
    while i <= j && !data.less(j, a) {
        j -= 1;
    }
    if i > j {
        data.swap(j, a);
        return (j, true);
    }
    data.swap(i, j);
    i += 1;
    j -= 1;

    loop {
        while i <= j && data.less(i, a) {
            i += 1;
        }
        while i <= j && !data.less(j, a) {
            j -= 1;
        }
        if i > j {
            break;
        }
        data.swap(i, j);
        i += 1;
        j -= 1;
    }
    data.swap(j, a);
    (j, false)
}

/// Partitions `data[a..b]` into elements equal to `data[pivot]` followed by greater ones
/// (assumes none is smaller); returns the start of the greater ones.
// Go: go1.27.1 sort/zsortfunc.go:partitionEqual_func()
fn partition_equal_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
    pivot: usize,
) -> usize {
    data.swap(a, pivot);
    let (mut i, mut j) = (a + 1, b - 1); // inclusive, as in partition_func

    loop {
        while i <= j && !data.less(a, i) {
            i += 1;
        }
        while i <= j && data.less(a, j) {
            j -= 1;
        }
        if i > j {
            break;
        }
        data.swap(i, j);
        i += 1;
        j -= 1;
    }
    i
}

/// Partially sorts `data[a..b]`; returns `true` if it is sorted at the end.
// Go: go1.27.1 sort/zsortfunc.go:partialInsertionSort_func()
fn partial_insertion_sort_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
) -> bool {
    const MAX_STEPS: usize = 5; // maximum number of adjacent out-of-order pairs that will get shifted
    const SHORTEST_SHIFTING: usize = 50; // don't shift any elements on short arrays

    let mut i = a + 1;
    for _ in 0..MAX_STEPS {
        while i < b && !data.less(i, i - 1) {
            i += 1;
        }

        if i == b {
            return true;
        }

        if b - a < SHORTEST_SHIFTING {
            return false;
        }

        hit!(PARTIAL_INSERTION_SHIFT);
        data.swap(i, i - 1);

        // Shift the smaller one to the left. (Go bounds this loop by j >= 1, not j > a.)
        if i - a >= 2 {
            let mut j = i - 1;
            while j >= 1 {
                if !data.less(j, j - 1) {
                    break;
                }
                data.swap(j, j - 1);
                j -= 1;
            }
        }
        // Shift the greater one to the right.
        if b - i >= 2 {
            for j in i + 1..b {
                if !data.less(j, j - 1) {
                    break;
                }
                data.swap(j, j - 1);
            }
        }
    }
    false
}

/// Scatters some elements around to break patterns that cause imbalanced partitions.
// Go: go1.27.1 sort/zsortfunc.go:breakPatterns_func()
fn break_patterns_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
) {
    let length = b - a;
    if length >= 8 {
        hit!(BREAK_PATTERNS);
        let mut random = Xorshift(length as u64);
        let modulus = next_power_of_two(length);

        let mid = a + (length / 4) * 2;
        for idx in mid - 1..=mid + 1 {
            // Go: int(uint(random.Next()) & (modulus - 1)); uint is the pointer width.
            let mut other = (random.next() as usize) & (modulus - 1);
            if other >= length {
                other -= length;
            }
            data.swap(idx, a + other);
        }
    }
}

/// Chooses a pivot in `data[a..b]`: static below 8 elements, median of three below 50, Tukey's
/// ninther above. The hint says whether the samples looked increasing or decreasing.
// Go: go1.27.1 sort/zsortfunc.go:choosePivot_func()
fn choose_pivot_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
) -> (usize, SortedHint) {
    const SHORTEST_NINTHER: usize = 50;
    const MAX_SWAPS: usize = 4 * 3;

    let l = b - a;

    let mut swaps = 0usize;
    let mut i = a + l / 4;
    let mut j = a + l / 4 * 2;
    let mut k = a + l / 4 * 3;

    if l >= 8 {
        if l >= SHORTEST_NINTHER {
            // Tukey ninther method.
            i = median_adjacent_func(data, i, &mut swaps);
            j = median_adjacent_func(data, j, &mut swaps);
            k = median_adjacent_func(data, k, &mut swaps);
        }
        // Find the median among i, j, k and stores it into j.
        j = median_func(data, i, j, k, &mut swaps);
    }

    match swaps {
        0 => (j, SortedHint::Increasing),
        MAX_SWAPS => (j, SortedHint::Decreasing),
        _ => (j, SortedHint::Unknown),
    }
}

/// Returns `(x, y)` with `data[x] <= data[y]`, where `(x, y)` is `(a, b)` or `(b, a)`.
// Go: go1.27.1 sort/zsortfunc.go:order2_func()
fn order2_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
    swaps: &mut usize,
) -> (usize, usize) {
    if data.less(b, a) {
        *swaps += 1;
        return (b, a);
    }
    (a, b)
}

/// Returns the index (`a`, `b` or `c`) of the median of the three elements.
// Go: go1.27.1 sort/zsortfunc.go:median_func()
fn median_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
    c: usize,
    swaps: &mut usize,
) -> usize {
    let (a, b) = order2_func(data, a, b, swaps);
    let (b, _c) = order2_func(data, b, c, swaps);
    let (_a, b) = order2_func(data, a, b, swaps);
    b
}

/// The median of `data[a - 1]`, `data[a]`, `data[a + 1]`.
// Go: go1.27.1 sort/zsortfunc.go:medianAdjacent_func()
fn median_adjacent_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    swaps: &mut usize,
) -> usize {
    median_func(data, a - 1, a, a + 1, swaps)
}

// Go: go1.27.1 sort/zsortfunc.go:reverseRange_func()
fn reverse_range_func<T, F: FnMut(&T, &T) -> bool>(
    data: &mut LessSwap<'_, T, F>,
    a: usize,
    b: usize,
) {
    let mut i = a;
    let mut j = b - 1;
    while i < j {
        data.swap(i, j);
        i += 1;
        j -= 1;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    fn is_sorted_by_key(v: &[u32]) -> bool {
        v.windows(2).all(|w| w[0] <= w[1])
    }

    #[test]
    fn slice_sorts_total_orders() {
        let mut v: Vec<u32> = (0..1000).map(|i| (i * 7919 + 13) % 1009).collect();
        slice(&mut v, |a, b| a < b);
        assert!(is_sorted_by_key(&v));
        let mut empty: Vec<u32> = Vec::new();
        slice(&mut empty, |a, b| a < b);
        let mut one = vec![5u32];
        slice(&mut one, |a, b| a < b);
        assert_eq!(one, [5]);
    }

    #[test]
    fn bits_len_and_next_power_of_two_match_go() {
        assert_eq!(bits_len(0), 0);
        assert_eq!(bits_len(1), 1);
        assert_eq!(bits_len(8), 4);
        assert_eq!(bits_len(258), 9);
        assert_eq!(next_power_of_two(8), 16);
        assert_eq!(next_power_of_two(258), 512);
    }

    #[test]
    fn xorshift_matches_go() {
        // Go: r := xorshift(258); r.Next(), r.Next(), r.Next() (the copied sort.go generator).
        let mut r = Xorshift(258);
        assert_eq!(r.next(), 274_930_336_128);
        assert_eq!(r.next(), 2_324_004_776_776_311_171);
        assert_eq!(r.next(), 4_100_725_871_469_920_512);
    }

    proptest! {
        /// A total order: the result is a sorted permutation of the input.
        #[test]
        fn prop_slice_sorts_permutation(mut v in proptest::collection::vec(any::<u16>(), 0..600)) {
            let mut want = v.clone();
            want.sort_unstable();
            slice(&mut v, |a, b| a < b);
            prop_assert_eq!(v, want);
        }

        /// An arbitrary (inconsistent, even non-deterministic) comparison never panics and the
        /// result is still a permutation of the input.
        #[test]
        fn prop_slice_arbitrary_less_never_panics(
            len in 0usize..600,
            answers in proptest::collection::vec(any::<bool>(), 1..512),
        ) {
            let mut v: Vec<usize> = (0..len).collect();
            let mut n = 0usize;
            slice(&mut v, |_, _| {
                n += 1;
                answers[n % answers.len()]
            });
            let mut sorted = v.clone();
            sorted.sort_unstable();
            prop_assert_eq!(sorted, (0..len).collect::<Vec<_>>());
        }

        /// The wrapping seqid comparison of autotune, on seqids spread over the whole u32 range
        /// (cyclic, not a strict weak order), never panics.
        #[test]
        fn prop_slice_wrapping_compare_never_panics(
            mut v in proptest::collection::vec(any::<u32>(), 0..600),
        ) {
            let mut want = v.clone();
            slice(&mut v, |a, b| (a.wrapping_sub(*b) as i32) < 0);
            v.sort_unstable();
            want.sort_unstable();
            prop_assert_eq!(v, want);
        }
    }
}
