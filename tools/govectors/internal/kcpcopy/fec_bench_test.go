package kcp

// FEC encoder/decoder benchmarks (plan step 04.7), the Go side of crates/kcp/benches/fec.rs.
// They run the verbatim copy of the pinned kcp-go v5.6.66 fec.go (fecEncoder, fecDecoder) with
// klauspost/reedsolomon v1.13.0, as pinned. The Reed-Solomon codec alone is BenchmarkRS in
// tools/govectors/bench_test.go. Methodology and results: docs/benchmarks/fec.md.
//
// kcp-go's own BenchmarkFECEncode/BenchmarkFECDecode (fec_test.go) allocate a fresh 1500-byte
// packet per iteration, read the wall clock and (decode) drop packets at random, so their
// ns/op mixes the allocator and math/rand into the FEC cost. These keep kcp-go's shape (one
// packet per iteration, (10, 3), header offset 0, b.SetBytes = packet length) but make it
// deterministic and allocation-free on the caller side:
//
//   - packets are 1370 bytes (the shard length of BenchmarkRS);
//   - the encoder clock (FecClock) is fixed, so every group is "continuous" and generates its
//     parity: one iteration in ten runs the RS encode (steady state);
//   - the decoder is fed one prepared group (10 data + 3 parity packets from the encoder) over and
//     over with its seqids rewritten to advance group by group, either complete ("loss0": the
//     10th data packet completes a full shard set, no RS) or with one data packet lost per group
//     ("loss1": the lost index rotates through 0..9, and the first parity packet triggers
//     ReconstructData of 1 shard). One iteration is one received packet; recovered buffers go
//     back to the buffer pool, as sess.go does.
//
// Run (with GOMODCACHE=<repo>/reference/gomod GOFLAGS=-modcacherw GOTOOLCHAIN=local):
//
//	cd tools/govectors && go test ./internal/kcpcopy -run '^$' -bench FEC -benchtime 2s

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
	"time"
)

const (
	benchFECData   = 10
	benchFECParity = 3
	benchFECLen    = 1370
	// benchFECNowMs is the fixed encoder clock (any value works: only differences matter).
	benchFECNowMs = 1_758_000_000_000
	// maxFECEncodeLatency is the rto sess.go passes to fecEncoder.encode (Go: kcp-go/v5@v5.6.66
	// sess.go:maxFECEncodeLatency; sess.go is not copied).
	maxFECEncodeLatency = 500
)

// withFixedFecClock runs f with the copied fec.go's clock stuck at benchFECNowMs.
func withFixedFecClock(f func()) {
	saved := FecClock
	FecClock = func(func() time.Time) int64 { return benchFECNowMs }
	defer func() { FecClock = saved }()
	f()
}

// benchFECPacket returns a benchFECLen-byte packet whose bytes after the FEC header and size
// field are byte((seq*benchFECLen+i)*131 + 7), the pattern of BenchmarkRS
// (crates/kcp/benches/fec.rs: packet()).
func benchFECPacket(seq int) []byte {
	pkt := make([]byte, benchFECLen)
	for i := fecHeaderSizePlus2; i < len(pkt); i++ {
		pkt[i] = byte((seq*benchFECLen+i)*131 + 7)
	}
	return pkt
}

// benchFECGroup encodes one group with a fresh encoder and returns its benchFECData data and
// benchFECParity parity packets (seqids 0..12), each a private copy.
func benchFECGroup(tb testing.TB) [][]byte {
	tb.Helper()
	var group [][]byte
	withFixedFecClock(func() {
		enc := newFECEncoder(benchFECData, benchFECParity, 0)
		for s := range benchFECData {
			pkt := benchFECPacket(s)
			ps := enc.encode(pkt, maxFECEncodeLatency)
			group = append(group, pkt)
			for _, p := range ps {
				group = append(group, append([]byte(nil), p...))
			}
		}
	})
	if len(group) != benchFECData+benchFECParity {
		tb.Fatalf("group has %d packets", len(group))
	}
	return group
}

func BenchmarkFEC(b *testing.B) {
	shape := fmt.Sprintf("%dx%d/%d", benchFECData, benchFECParity, benchFECLen)

	b.Run("encode/"+shape, func(b *testing.B) {
		withFixedFecClock(func() {
			enc := newFECEncoder(benchFECData, benchFECParity, 0)
			pkt := benchFECPacket(0)
			parity := 0
			b.SetBytes(benchFECLen)
			b.ReportAllocs()
			for b.Loop() {
				parity += len(enc.encode(pkt, maxFECEncodeLatency))
			}
			if b.N >= benchFECData && parity == 0 {
				b.Fatal("no parity generated")
			}
		})
	})

	for _, loss := range []int{0, 1} {
		b.Run(fmt.Sprintf("decode/%s/loss%d", shape, loss), func(b *testing.B) {
			group := benchFECGroup(b)
			dec := newFECDecoder(benchFECData, benchFECParity)
			shardSize := uint32(benchFECData + benchFECParity)
			var base uint32 // seqid of the current group's first packet
			pos, g, recovered := 0, 0, 0
			b.SetBytes(benchFECLen)
			b.ReportAllocs()
			for b.Loop() {
				if loss == 1 && pos == g%benchFECData {
					pos++ // this group's lost data packet
				}
				pkt := group[pos]
				binary.LittleEndian.PutUint32(pkt, base+uint32(pos))
				rec := dec.decode(pkt)
				recovered += len(rec)
				for _, r := range rec {
					defaultBufferPool.Put(r)
				}
				pos++
				if pos == len(group) {
					pos, g = 0, g+1
					base = (base + shardSize) % dec.paws
				}
			}
			if loss == 1 && g > 0 && recovered < g {
				b.Fatalf("recovered %d shards in %d groups", recovered, g)
			}
			if loss == 0 && recovered != 0 {
				b.Fatalf("recovered %d shards without loss", recovered)
			}
		})
	}
}

// TestBenchFECRecovery checks the decode benchmark's input: with one data packet lost per group,
// every group recovers exactly that packet's shard.
func TestBenchFECRecovery(t *testing.T) {
	group := benchFECGroup(t)
	want := make([][]byte, benchFECData)
	for s := range want {
		want[s] = append([]byte(nil), group[s][fecHeaderSize:]...)
	}
	dec := newFECDecoder(benchFECData, benchFECParity)
	var base uint32
	for g := range 25 {
		lost := g % benchFECData
		var got [][]byte
		for pos := range group {
			if pos == lost {
				continue
			}
			binary.LittleEndian.PutUint32(group[pos], base+uint32(pos))
			got = append(got, dec.decode(group[pos])...)
		}
		if len(got) != 1 || !bytes.Equal(got[0], want[lost]) {
			t.Fatalf("group %d: recovered %d shards, want shard %d", g, len(got), lost)
		}
		base += uint32(len(group))
	}
}
