package kcp

// KCP ARQ benchmarks (plan step 03.6), the Go side of crates/kcp/benches/kcp.rs. They run on
// this verbatim copy of the pinned kcp-go v5.6.66 kcp.go, which (unlike the library) lets a
// test reach flush() and snd_buf, exactly as kcp-go's own BenchmarkFlush does from inside the
// package. Methodology and results: docs/benchmarks/kcp.md.
//
// Run (with GOMODCACHE=<repo>/reference/gomod GOFLAGS=-modcacherw GOTOOLCHAIN=local):
//
//	cd tools/govectors && go test ./internal/kcpcopy -run '^$' -bench . -benchtime 2s

import (
	"fmt"
	"sync"
	"testing"
)

// benchWindows are kcp-go's BenchmarkFlush ring (1024) and the production window (8192).
var benchWindows = []int{1024, 8192}

// benchFarFutureMs: BenchmarkFlush's segments are due this far in the future. kcp-go uses
// 10000 (10 s), which long runs outlast (then every flush retransmits the whole window); both
// sides use 10^7 ms.
const benchFarFutureMs = 10_000_000

const (
	benchConv = 1
	benchT0   = 1_000_000 // the fixed clock of the input and send benchmarks
	benchMtu  = IKCP_MTU_DEF
	benchMss  = benchMtu - IKCP_OVERHEAD
	// ACKs per packet from a receiver's flush (makeSpace flushes when 24 more bytes would
	// exceed the MTU).
	benchAcksPerPacket = benchMtu / IKCP_OVERHEAD
)

// withFixedClock runs f with the package clock stuck at benchT0.
func withFixedClock(f func()) {
	saved := Clock
	Clock = func() uint32 { return benchT0 }
	defer func() { Clock = saved }()
	f()
}

// benchSegment encodes one segment (header and payload) like segment.encode, without touching
// DefaultSnmp (Rust: kcptun_kcp::internals::fuzz::encode_segment).
func benchSegment(cmd uint8, wnd uint16, ts, sn, una uint32) []byte {
	buf := make([]byte, IKCP_OVERHEAD)
	p := ikcp_encode32u(buf, benchConv)
	p = ikcp_encode8u(p, cmd)
	p = ikcp_encode8u(p, 0)
	p = ikcp_encode16u(p, wnd)
	p = ikcp_encode32u(p, ts)
	p = ikcp_encode32u(p, sn)
	p = ikcp_encode32u(p, una)
	ikcp_encode32u(p, 0)
	return buf
}

// BenchmarkFlushWindow is kcp-go's BenchmarkFlush (kcp_test.go) at snd_buf rings of 1024 (the
// original) and 8192 slots, with resendts benchFarFutureMs ahead instead of 10 s.
func BenchmarkFlushWindow(b *testing.B) {
	for _, n := range benchWindows {
		b.Run(fmt.Sprintf("snd_buf=%d", n), func(b *testing.B) {
			kcp := NewKCP(1, func(buf []byte, size int) {})
			kcp.snd_buf = NewRingBuffer[segment](n)
			for range kcp.snd_buf.MaxLen() {
				kcp.snd_buf.Push(segment{xmit: 1, resendts: currentMs() + benchFarFutureMs})
			}

			b.ReportAllocs()
			var mu sync.Mutex
			for b.Loop() {
				mu.Lock()
				kcp.flush(IKCP_FLUSH_FULL)
				mu.Unlock()
			}
		})
	}
}

// inFlightSender returns a sender with w full-size segments in flight (sn 0..w, sent at
// benchT0), no congestion window (nc = 1) and a peer window of w. The clock must be fixed.
func inFlightSender(tb testing.TB, w int) *KCP {
	kcp := NewKCP(benchConv, func(buf []byte, size int) {})
	kcp.NoDelay(1, 10, 2, 1)
	kcp.WndSize(w, w)
	// The receiver's window (rmt_wnd) comes from a regular packet.
	if r := kcp.Input(benchSegment(IKCP_CMD_WINS, uint16(w), benchT0, 0, 0), IKCP_PACKET_REGULAR, false); r != 0 {
		tb.Fatalf("WINS input = %d", r)
	}
	data := make([]byte, benchMss)
	for i := range data {
		data[i] = 0x5A
	}
	for range w {
		if r := kcp.Send(data); r != 0 {
			tb.Fatalf("Send = %d", r)
		}
	}
	kcp.flush(IKCP_FLUSH_FULL)
	if kcp.WaitSnd() != w {
		tb.Fatalf("in flight %d, want %d", kcp.WaitSnd(), w)
	}
	return kcp
}

// ackPackets returns the ACK packets for segments first..w, benchAcksPerPacket per packet.
// cumulative: each packet's una is one past its last ACK; otherwise una is 0 (segment 0 lost).
func ackPackets(first, w int, cumulative bool) [][]byte {
	var pkts [][]byte
	for start := first; start < w; start += benchAcksPerPacket {
		end := min(start+benchAcksPerPacket, w)
		var una uint32
		if cumulative {
			una = uint32(end)
		}
		var pkt []byte
		for sn := start; sn < end; sn++ {
			pkt = append(pkt, benchSegment(IKCP_CMD_ACK, uint16(w), benchT0, uint32(sn), una)...)
		}
		pkts = append(pkts, pkt)
	}
	return pkts
}

// BenchmarkInputAck: one op inputs the ACK packets for a whole window of w in-flight segments
// (Rust: kcp/input_ack/{in_order,sack}/<w>). The setup (a fresh sender) is not timed.
func BenchmarkInputAck(b *testing.B) {
	withFixedClock(func() {
		for _, c := range []struct {
			name       string
			first      int
			cumulative bool
		}{{"in_order", 0, true}, {"sack", 1, false}} {
			for _, w := range benchWindows {
				b.Run(fmt.Sprintf("%s/w=%d", c.name, w), func(b *testing.B) {
					pkts := ackPackets(c.first, w, c.cumulative)
					// Check once that the packets do what they should.
					k := inFlightSender(b, w)
					for _, p := range pkts {
						if r := k.Input(p, IKCP_PACKET_REGULAR, false); r != 0 {
							b.Fatalf("Input = %d", r)
						}
					}
					want := w
					if c.cumulative {
						want = 0
					}
					if k.WaitSnd() != want {
						b.Fatalf("WaitSnd = %d, want %d", k.WaitSnd(), want)
					}

					b.ReportAllocs()
					b.ResetTimer()
					for i := 0; i < b.N; i++ {
						b.StopTimer()
						k := inFlightSender(b, w)
						b.StartTimer()
						for _, p := range pkts {
							k.Input(p, IKCP_PACKET_REGULAR, false)
						}
					}
					b.StopTimer()
					b.ReportMetric(float64(w-c.first)*float64(b.N)/b.Elapsed().Seconds(), "acks/s")
				})
			}
		}
	})
}

// benchSink collects output packets in one buffer (no allocation per packet in the steady
// state; Rust: Sink).
type benchSink struct {
	bytes []byte
	ends  []int
}

func (s *benchSink) output(buf []byte, size int) {
	s.bytes = append(s.bytes, buf[:size]...)
	s.ends = append(s.ends, len(s.bytes))
}

func (s *benchSink) each(f func([]byte)) {
	start := 0
	for _, end := range s.ends {
		f(s.bytes[start:end])
		start = end
	}
}

func (s *benchSink) clear() {
	s.bytes = s.bytes[:0]
	s.ends = s.ends[:0]
}

const benchSendBytes = 64 * 1024

type benchPair struct {
	a, b         *KCP
	aOut, bOut   *benchSink
	msg, recvBuf []byte
}

func newBenchPair(tb testing.TB) *benchPair {
	p := &benchPair{aOut: &benchSink{}, bOut: &benchSink{},
		msg: make([]byte, benchSendBytes), recvBuf: make([]byte, benchSendBytes)}
	for i := range p.msg {
		p.msg[i] = 0xA5
	}
	peer := func(out *benchSink) *KCP {
		k := NewKCP(benchConv, out.output)
		k.NoDelay(1, 10, 2, 1)
		k.WndSize(1024, 1024)
		k.stream = 1 // kcptun's setting (UDPSession.SetStreamMode(true))
		return k
	}
	p.a, p.b = peer(p.aOut), peer(p.bOut)
	// Warm up: the first exchange teaches the sender the receiver's window (rmt_wnd starts at
	// 32, so 16 of the 48 segments wait for the second round).
	if got := p.round() + p.round(); got != 2*benchSendBytes {
		tb.Fatalf("warm-up moved %d bytes", got)
	}
	if got := p.round(); got != benchSendBytes || p.a.WaitSnd() != 0 {
		tb.Fatalf("steady round moved %d bytes, %d unacked", got, p.a.WaitSnd())
	}
	return p
}

// round sends 64 KiB from a to b and the ACKs back; returns the bytes b read.
func (p *benchPair) round() int {
	p.a.Send(p.msg)
	p.a.flush(IKCP_FLUSH_FULL)
	p.aOut.each(func(pkt []byte) { p.b.Input(pkt, IKCP_PACKET_REGULAR, false) })
	p.aOut.clear()
	got := 0
	for {
		n := p.b.Recv(p.recvBuf)
		if n < 0 {
			break
		}
		got += n
	}
	p.b.flush(IKCP_FLUSH_FULL)
	p.bOut.each(func(pkt []byte) { p.a.Input(pkt, IKCP_PACKET_REGULAR, false) })
	p.bOut.clear()
	return got
}

// BenchmarkSendFlush: a sender/receiver pair moving 64 KiB per op (Rust: kcp/send_flush/64KiB).
func BenchmarkSendFlush(b *testing.B) {
	withFixedClock(func() {
		b.Run("64KiB", func(b *testing.B) {
			p := newBenchPair(b)
			b.SetBytes(benchSendBytes)
			b.ReportAllocs()
			for b.Loop() {
				p.round()
			}
			b.StopTimer()
			if got := p.round(); got != benchSendBytes || p.a.WaitSnd() != 0 {
				b.Fatalf("after the bench: round moved %d bytes, %d unacked", got, p.a.WaitSnd())
			}
		})
	})
}
