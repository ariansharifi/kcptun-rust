package main

// Area "autotune" (plan step 04.3): the FEC decoder's pulse period detector, kcp-go v5.6.66
// autotune.go. autoTune is unexported, so the cases run the verbatim copy in internal/kcpcopy
// (checked byte for byte against the pinned file by TestVerbatimCopy). Each case feeds a
// sample sequence to a fresh autoTune, optionally pops the oldest samples like kcp-go's
// TestAutoTunePop, and records FindPeriod(true), FindPeriod(false) and the order sort.Slice
// left in sortCache. The sample sequences include the inputs where that order depends on the
// sort algorithm itself: equal seqids (duplicate packets, with the same or a flipped bit) and
// seqid sets spanning more than 2^31, for which the _itimediff comparison is not a strict weak
// order. Case groups are documented in README.md.

import (
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"slices"
	"sort"

	kcpcopy "github.com/kcptun-rust/tools/govectors/internal/kcpcopy"
)

// autotuneMaxSamples is kcp-go's maxAutoTuneSamples (the ring size).
const autotuneMaxSamples = 258

// autotuneCasesPerGroup is the number of cases of each group.
const autotuneCasesPerGroup = 8

// autotuneCase is one case of the autotune area.
type autotuneCase struct {
	Name      string `json:"name"`
	Samples   string `json:"samples"`        // Sample calls in order, 5 bytes each: seq (u32 LE), bit (0/1)
	Pops      int    `json:"pops,omitempty"` // oldest samples then discarded (head++, count--)
	Count     int    `json:"count"`          // samples in the ring before FindPeriod
	FindTrue  int    `json:"find_true"`      // FindPeriod(true)
	FindFalse int    `json:"find_false"`     // FindPeriod(false)
	Sorted    string `json:"sorted,omitempty"`
	// Sorted: sortCache[:count] after FindPeriod, same 5-byte layout; absent when count < 3
	// (FindPeriod returns -1 before copying and sorting).
}

func (c autotuneCase) CaseName() string { return c.Name }

// pulseSample is one Sample(bit, seq) call.
type pulseSample struct {
	seq uint32
	bit bool
}

func encodePulses(ps []pulseSample) []byte {
	b := make([]byte, 0, 5*len(ps))
	for _, p := range ps {
		b = binary.LittleEndian.AppendUint32(b, p.seq)
		if p.bit {
			b = append(b, 1)
		} else {
			b = append(b, 0)
		}
	}
	return b
}

// autotuneGroup generates the samples (and the number of pops) of one case from its RNG.
type autotuneGroup struct {
	name string
	gen  func(r *rand.Rand) (samples []pulseSample, pops int)
}

// periodicSeqs returns n seqids of an FEC stream with ds data and ps parity shards, as the
// encoder numbers them: consecutive from a group boundary, wrapping at paws (the largest
// multiple of ds+ps not above 0xffffffff), starting at a random point. The bit of a seqid is
// seq % (ds+ps) < ds, as the decoder expects.
func periodicSeqs(r *rand.Rand, n int) []pulseSample {
	ds := 1 + r.IntN(16)
	ps := 1 + r.IntN(8)
	size := uint32(ds + ps)
	paws := 0xffffffff / size * size
	var start uint32
	switch r.IntN(4) {
	case 0:
		start = uint32(r.IntN(3 * int(size)))
	case 1:
		start = r.Uint32() % paws
	default: // close to the paws wrap
		start = paws - 1 - uint32(r.IntN(2*autotuneMaxSamples))
	}
	out := make([]pulseSample, n)
	seq := start
	for i := range out {
		out[i] = pulseSample{seq: seq, bit: seq%size < uint32(ds)}
		seq = (seq + 1) % paws
	}
	return out
}

var autotuneGroups = []autotuneGroup{
	// An undisturbed stream, from 3 samples to well past the ring size.
	{"periodic", func(r *rand.Rand) ([]pulseSample, int) {
		return periodicSeqs(r, 3+r.IntN(700)), 0
	}},
	// Local reordering: samples swapped with a neighbour up to 8 positions later.
	{"reorder", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 20+r.IntN(380))
		for range 1 + r.IntN(len(s)/4) {
			i := r.IntN(len(s) - 1)
			j := min(len(s)-1, i+1+r.IntN(8))
			s[i], s[j] = s[j], s[i]
		}
		return s, 0
	}},
	// Lost packets (gaps in the seqids).
	{"loss", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 20+r.IntN(380))
		keep := s[:0]
		for _, p := range s {
			if r.IntN(25) != 0 {
				keep = append(keep, p)
			}
		}
		return keep, 0
	}},
	// Duplicated packets: equal seqids with equal bits.
	{"dup", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 20+r.IntN(300))
		for range 1 + r.IntN(20) {
			i := r.IntN(len(s))
			j := min(len(s), i+r.IntN(10))
			s = slices.Insert(s, j, s[i])
		}
		return s, 0
	}},
	// Equal seqids with different bits: the result depends on how the sort orders ties.
	{"dup_flip", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 20+r.IntN(300))
		for range 1 + r.IntN(20) {
			i := r.IntN(len(s))
			j := min(len(s), i+r.IntN(10))
			s = slices.Insert(s, j, pulseSample{seq: s[i].seq, bit: !s[i].bit})
		}
		return s, 0
	}},
	// Uniformly random seqids and bits (garbage input; not a strict weak order).
	{"random", func(r *rand.Rand) ([]pulseSample, int) {
		s := make([]pulseSample, 3+r.IntN(400))
		for i := range s {
			s[i] = pulseSample{seq: r.Uint32(), bit: r.IntN(2) == 0}
		}
		return s, 0
	}},
	// Seqids from a small range: many ties (partitionEqual), random bits.
	{"narrow", func(r *rand.Rand) ([]pulseSample, int) {
		k := []int{1, 2, 3, 8, 32, 128}[r.IntN(6)]
		base := r.Uint32()
		s := make([]pulseSample, 3+r.IntN(400))
		for i := range s {
			s[i] = pulseSample{seq: base + uint32(r.IntN(k)), bit: r.IntN(2) == 0}
		}
		return s, 0
	}},
	// A stream sampled in reverse (the decreasing-hint path of pdqsort).
	{"descending", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 3+r.IntN(400))
		slices.Reverse(s)
		return s, 0
	}},
	// A long stream with a few distant swaps (partialInsertionSort shifting).
	{"nearly_sorted", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 50+r.IntN(350))
		for range 1 + r.IntN(6) {
			i, j := r.IntN(len(s)), r.IntN(len(s))
			s[i], s[j] = s[j], s[i]
		}
		return s, 0
	}},
	// Sawtooth and organ-pipe seqid patterns (unbalanced partitions: breakPatterns and the
	// heapsort fallback).
	{"sawtooth", func(r *rand.Rand) ([]pulseSample, int) {
		m := 2 + r.IntN(60)
		organ := r.IntN(2) == 0
		base := r.Uint32()
		s := make([]pulseSample, 60+r.IntN(340))
		for i := range s {
			v := i % m
			if organ && (i/m)%2 == 1 {
				v = m - 1 - v
			}
			seq := base + uint32(v)
			s[i] = pulseSample{seq: seq, bit: seq%3 != 0}
		}
		return s, 0
	}},
	// A stream with a few seqids about 2^31 away (the comparison becomes cyclic).
	{"wide", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 20+r.IntN(300))
		for range 1 + r.IntN(4) {
			i := r.IntN(len(s))
			s[i].seq += 0x80000000 - 2 + uint32(r.IntN(5))
		}
		return s, 0
	}},
	// Distinct seqids in an order built by McIlroy's adversary ("A Killer Adversary for
	// Quicksort", 1999) against sort.Slice itself: pdqsort degrades and falls back to heapsort.
	{"killer", func(r *rand.Rand) ([]pulseSample, int) {
		vals := sortKiller(100 + r.IntN(autotuneMaxSamples-100+1))
		base := r.Uint32()
		s := make([]pulseSample, len(vals))
		for i, v := range vals {
			seq := base + uint32(v)
			s[i] = pulseSample{seq: seq, bit: seq%4 != 0}
		}
		return s, 0
	}},
	// Pops after sampling, like TestAutoTunePop (may leave fewer than 3 samples).
	{"pop", func(r *rand.Rand) ([]pulseSample, int) {
		s := periodicSeqs(r, 3+r.IntN(300))
		return s, r.IntN(min(len(s), autotuneMaxSamples) + 1)
	}},
}

func genAutotune() ([]any, error) {
	var cases []any
	for g, grp := range autotuneGroups {
		for i := range autotuneCasesPerGroup {
			r := newRNG("autotune", uint64(g)<<16+uint64(i))
			samples, pops := grp.gen(r)
			c, err := runAutotune(fmt.Sprintf("%s/%d", grp.name, i), samples, pops)
			if err != nil {
				return nil, err
			}
			cases = append(cases, c)
		}
	}
	return cases, nil
}

func runAutotune(name string, samples []pulseSample, pops int) (autotuneCase, error) {
	var tune kcpcopy.AutoTune
	for _, s := range samples {
		tune.Sample(s.bit, s.seq)
	}
	for range pops {
		tune.Pop()
	}
	c := autotuneCase{Name: name, Samples: hx(encodePulses(samples)), Pops: pops, Count: tune.Count()}
	c.FindTrue = tune.FindPeriod(true)
	seqsT, bitsT := tune.Sorted()
	c.FindFalse = tune.FindPeriod(false)
	seqsF, bitsF := tune.Sorted()
	// Both calls sort the same ring contents with the same deterministic algorithm.
	if !slices.Equal(seqsT, seqsF) || !slices.Equal(bitsT, bitsF) {
		return c, fmt.Errorf("autotune %s: FindPeriod(true) and FindPeriod(false) sorted differently", name)
	}
	if c.Count >= 3 {
		sorted := make([]pulseSample, len(seqsT))
		for i := range sorted {
			sorted[i] = pulseSample{seq: seqsT[i], bit: bitsT[i]}
		}
		c.Sorted = hx(encodePulses(sorted))
	}
	return c, nil
}

// sortKiller returns a permutation of 0..n-1 on which sort.Slice (ascending ints) makes the
// comparisons McIlroy's adversary chose: values are frozen lazily, and an unfrozen ("gas")
// element always compares greater than frozen ones, which drives the pivots to be extremes.
// Sorting the result replays the same comparisons, so it is a bad input for this exact
// algorithm (the autotune vectors check that the Rust port of pdqsort reaches heapsort).
func sortKiller(n int) []int {
	gas := n
	val := make([]int, n)
	for i := range val {
		val[i] = gas
	}
	ids := make([]int, n)
	for i := range ids {
		ids[i] = i
	}
	nsolid, candidate := 0, 0
	freeze := func(x int) { val[x] = nsolid; nsolid++ }
	sort.Slice(ids, func(i, j int) bool {
		x, y := ids[i], ids[j]
		if val[x] == gas && val[y] == gas {
			if x == candidate {
				freeze(x)
			} else {
				freeze(y)
			}
		}
		if val[x] == gas {
			candidate = x
		} else if val[y] == gas {
			candidate = y
		}
		return val[x] < val[y]
	})
	for i := range val { // elements never frozen get the largest values, in position order
		if val[i] == gas {
			freeze(i)
		}
	}
	return val
}
