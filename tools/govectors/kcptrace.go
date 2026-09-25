package main

// Group "trace/<config>" of area "kcp" (plan step 03.5): golden API traces of two KCP
// endpoints (internal/kcpcopy, a verbatim copy of the pinned kcp-go KCP core whose clock is
// injected) exchanging data over a deterministic lossy link. For every endpoint the trace is
// the exact sequence of calls (with the clock value at the call and the arguments) and the
// exact results (return value, every packet passed to the output callback, the number of clock
// reads and a digest of the whole KCP state afterwards). The Rust port replays each endpoint
// call by call on an injected clock and must reproduce every result byte for byte. The format
// is documented in README.md ("Group trace").
//
// The driver mirrors how kcp-go's UDPSession uses KCP (sess.go): Write splits into mss-sized
// Send calls, checks WaitSnd against snd_wnd and flushes at once (writeDelay off); the update
// timer calls flush(IKCP_FLUSH_FULL) and re-arms after the returned interval (or Update/Check
// in the configs that say so); every received packet goes through Input(data, type,
// ackNoDelay) followed by the reader (PeekSize, Recv). The link loses, delays, jitters,
// reorders, duplicates, truncates and FEC-marks packets from its own seeded PCG.

import (
	"container/heap"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand/v2"
	"strconv"
	"strings"
	"sync/atomic"

	kcpcopy "github.com/kcptun-rust/tools/govectors/internal/kcpcopy"
)

// RNG streams of the trace group (see newRNG): per config i, the link uses
// streamTraceLink+i, the workload streamTraceWork+i, and endpoint e (0 = a, 1 = b) draws its
// Send payloads from streamTracePayload + 2*i + e.
const (
	streamTraceLink    = 1 << 20
	streamTraceWork    = 2 << 20
	streamTracePayload = 3 << 20
)

// traceLink describes one direction of the simulated link.
type traceLink struct {
	Loss      float64 `json:"loss"`       // per-packet loss probability
	DelayMs   uint32  `json:"delay_ms"`   // one-way delay
	JitterMs  uint32  `json:"jitter_ms"`  // uniform extra delay in [0, jitter]
	Reorder   float64 `json:"reorder"`    // probability of an extra ReorderMs delay
	ReorderMs uint32  `json:"reorder_ms"` // extra delay of reordered copies
	Dup       float64 `json:"dup"`        // probability of a second copy
	Fec       float64 `json:"fec"`        // probability that a copy is input as IKCP_PACKET_FEC
	Cut       float64 `json:"cut"`        // probability that a copy is truncated
	Blackout  uint32  `json:"blackout"`   // from this many ms on everything is lost (0 = never)
}

// traceSide configures one endpoint and its application.
type traceSide struct {
	NoDelay    []int `json:"nodelay,omitempty"` // NoDelay arguments (nil: not called)
	SndWnd     int   `json:"snd_wnd"`           // WndSize arguments (0: not called)
	RcvWnd     int   `json:"rcv_wnd"`
	Mtu        int   `json:"mtu,omitempty"` // SetMtu argument (0: not called)
	Stream     int32 `json:"stream"`        // stream field (as UDPSession.SetStreamMode)
	AckNoDelay bool  `json:"ack_no_delay"`
	WriteBytes int   `json:"write_bytes"` // application bytes to write in total
	MaxWrite   int   `json:"max_write"`   // writes are 1..MaxWrite bytes (workload RNG)
	NoSplit    bool  `json:"no_split"`    // Send whole writes (message mode frg) instead of mss pieces
	ReadBuf    int   `json:"read_buf"`    // reader buffer size
	StallFrom  int   `json:"stall_from"`  // reader stalled in [StallFrom, StallTo) ms
	StallTo    int   `json:"stall_to"`
	ExtraSends []int `json:"extra_sends,omitempty"` // Send lengths issued first, outside the workload
	WriteFrom  int   `json:"write_from,omitempty"`  // application writes start at this many ms
}

type traceConfig struct {
	Name      string    `json:"-"`
	Conv      uint32    `json:"conv"`
	T0        uint32    `json:"t0"`         // clock value at the start
	Step      uint32    `json:"clock_step"` // the clock advances by this much on every read
	UseUpdate bool      `json:"use_update"` // drive with Update/Check instead of flush timers
	PingPong  int       `json:"ping_pong"`  // >0: a writes, b answers, messages of this size
	Garbage   bool      `json:"garbage"`    // inject malformed packets into both endpoints
	ToDead    bool      `json:"to_dead"`    // run until a's state is 0xFFFFFFFF (dead_link)
	LimitMs   uint64    `json:"limit_ms"`   // virtual time limit
	A         traceSide `json:"a"`
	B         traceSide `json:"b"`
	AB        traceLink `json:"a_to_b"`
	BA        traceLink `json:"b_to_a"`
}

// traceConfigs are the traced scenarios. kcptun's modes are normal {0,40,2,1}, fast
// {0,30,2,1}, fast2 {1,20,2,1} and fast3 {1,10,2,1}.
var traceConfigs = []traceConfig{
	{
		Name: "normal_w32_mtu1400", Conv: 0x11223344, T0: 1000, LimitMs: 60000,
		A:  traceSide{NoDelay: []int{0, 40, 2, 1}, SndWnd: 32, RcvWnd: 32, Mtu: 1400, Stream: 1, WriteBytes: 16000, MaxWrite: 4096, ReadBuf: 65536},
		B:  traceSide{NoDelay: []int{0, 40, 2, 1}, SndWnd: 32, RcvWnd: 32, Mtu: 1400, Stream: 1, WriteBytes: 1500, MaxWrite: 700, ReadBuf: 65536},
		AB: traceLink{Loss: 0.05, DelayMs: 20, JitterMs: 5, Reorder: 0.05, ReorderMs: 30, Dup: 0.02},
		BA: traceLink{Loss: 0.05, DelayMs: 20, JitterMs: 5, Reorder: 0.05, ReorderMs: 30, Dup: 0.02},
	},
	{
		Name: "fast_w128_mtu1322_acknodelay", Conv: 0xDEADBEEF, T0: 50, LimitMs: 60000,
		A:  traceSide{NoDelay: []int{0, 30, 2, 1}, SndWnd: 128, RcvWnd: 128, Mtu: 1322, Stream: 1, AckNoDelay: true, WriteBytes: 14000, MaxWrite: 3000, ReadBuf: 65536},
		B:  traceSide{NoDelay: []int{0, 30, 2, 1}, SndWnd: 128, RcvWnd: 128, Mtu: 1322, Stream: 1, AckNoDelay: true, WriteBytes: 2500, MaxWrite: 900, ReadBuf: 1000},
		AB: traceLink{Loss: 0.10, DelayMs: 30, JitterMs: 10, Reorder: 0.10, ReorderMs: 40, Dup: 0.05},
		BA: traceLink{Loss: 0.10, DelayMs: 30, JitterMs: 10, Reorder: 0.10, ReorderMs: 40, Dup: 0.05},
	},
	{
		Name: "fast3_w1024_clockstep", Conv: 7, T0: 0x7FFFFF00, Step: 1, LimitMs: 60000,
		A:  traceSide{NoDelay: []int{1, 10, 2, 1}, SndWnd: 1024, RcvWnd: 1024, Mtu: 1400, Stream: 1, WriteBytes: 16000, MaxWrite: 8192, ReadBuf: 65536},
		B:  traceSide{NoDelay: []int{1, 10, 2, 1}, SndWnd: 1024, RcvWnd: 1024, Mtu: 1400, Stream: 1, WriteBytes: 600, MaxWrite: 300, ReadBuf: 65536},
		AB: traceLink{Loss: 0.03, DelayMs: 40, JitterMs: 20, Dup: 0.02},
		BA: traceLink{Loss: 0.03, DelayMs: 40, JitterMs: 20, Dup: 0.02},
	},
	{
		Name: "fast3_w128_mtu200", Conv: 0x0BADF00D, T0: 3, LimitMs: 60000,
		A:  traceSide{NoDelay: []int{1, 10, 2, 1}, SndWnd: 128, RcvWnd: 128, Mtu: 200, Stream: 1, WriteBytes: 12000, MaxWrite: 2000, ReadBuf: 65536},
		B:  traceSide{NoDelay: []int{1, 10, 2, 1}, SndWnd: 128, RcvWnd: 128, Mtu: 200, Stream: 1, WriteBytes: 400, MaxWrite: 200, ReadBuf: 65536},
		AB: traceLink{Loss: 0.05, DelayMs: 15, JitterMs: 3, Reorder: 0.05, ReorderMs: 20},
		BA: traceLink{Loss: 0.05, DelayMs: 15, JitterMs: 3, Reorder: 0.05, ReorderMs: 20},
	},
	{
		Name: "congestion_fastresend_nc0", Conv: 0x01010101, T0: 0, LimitMs: 120000,
		A:  traceSide{NoDelay: []int{0, 40, 2, 0}, SndWnd: 64, RcvWnd: 64, Mtu: 500, Stream: 1, WriteBytes: 14000, MaxWrite: 4000, ReadBuf: 65536},
		B:  traceSide{NoDelay: []int{0, 40, 2, 0}, SndWnd: 64, RcvWnd: 64, Mtu: 500, Stream: 1, WriteBytes: 300, MaxWrite: 300, ReadBuf: 65536},
		AB: traceLink{Loss: 0.08, DelayMs: 40, JitterMs: 5, Reorder: 0.05, ReorderMs: 25},
		BA: traceLink{Loss: 0.08, DelayMs: 40, JitterMs: 5},
	},
	{
		Name: "congestion_default_nc0", Conv: 0x02020202, T0: 12345, LimitMs: 120000,
		A:  traceSide{NoDelay: []int{0, 40, 0, 0}, SndWnd: 32, RcvWnd: 32, Mtu: 400, Stream: 1, WriteBytes: 8000, MaxWrite: 3000, ReadBuf: 65536},
		B:  traceSide{NoDelay: []int{0, 40, 0, 0}, SndWnd: 32, RcvWnd: 32, Mtu: 400, Stream: 1, WriteBytes: 200, MaxWrite: 200, ReadBuf: 65536},
		AB: traceLink{Loss: 0.10, DelayMs: 50},
		BA: traceLink{Loss: 0.10, DelayMs: 50},
	},
	{
		// Message mode on the Update/Check API, with the clock wrapping mid-trace. Whole
		// writes are sent (fragments, frg > 0), including the edge cases len 0 (-1) and
		// 256*mss (-2); a 1000-byte reader buffer yields Recv -2 for larger messages.
		Name: "message_mode_update_check_wrap", Conv: 0xFFFFFFFF, T0: 0xFFFFFE00, UseUpdate: true, LimitMs: 120000,
		A:  traceSide{SndWnd: 32, RcvWnd: 128, NoSplit: true, WriteBytes: 12000, MaxWrite: 4500, ReadBuf: 1000, ExtraSends: []int{0, 256 * 1376, 1, 1376, 1377}},
		B:  traceSide{SndWnd: 32, RcvWnd: 128, NoSplit: true, WriteBytes: 3000, MaxWrite: 1500, ReadBuf: 1000},
		AB: traceLink{Loss: 0.05, DelayMs: 25, JitterMs: 10, Reorder: 0.05, ReorderMs: 30, Dup: 0.03},
		BA: traceLink{Loss: 0.05, DelayMs: 25, JitterMs: 10, Reorder: 0.05, ReorderMs: 30, Dup: 0.03},
	},
	{
		// fast2 mode. b's reader stalls with an 8-segment receive window: a sees rmt_wnd 0 and probes
		// (WASK/WINS, probe_wait growth), b's fast recover sends WINS when reading resumes.
		Name: "zero_window_probe", Conv: 0x5A5A5A5A, T0: 777, LimitMs: 120000,
		A:  traceSide{NoDelay: []int{1, 20, 2, 1}, SndWnd: 32, RcvWnd: 32, Stream: 1, WriteBytes: 16000, MaxWrite: 4000, ReadBuf: 65536, WriteFrom: 50},
		B:  traceSide{NoDelay: []int{1, 20, 2, 1}, SndWnd: 32, RcvWnd: 8, Stream: 1, WriteBytes: 100, MaxWrite: 100, ReadBuf: 65536, StallFrom: 30, StallTo: 2600},
		AB: traceLink{DelayMs: 10},
		BA: traceLink{DelayMs: 10},
	},
	{
		// Everything a sends is lost after 150 ms, and a only starts writing after 200 ms
		// (its first timer after that): its segments are retransmitted until xmit reaches
		// dead_link (20) and state becomes 0xFFFFFFFF.
		Name: "dead_link", Conv: 0x0D0D0D0D, T0: 100, ToDead: true, LimitMs: 600000,
		A:  traceSide{NoDelay: []int{0, 1000, 2, 1}, SndWnd: 32, RcvWnd: 32, Stream: 1, WriteBytes: 300, MaxWrite: 300, ReadBuf: 65536, WriteFrom: 200},
		B:  traceSide{NoDelay: []int{0, 1000, 2, 1}, SndWnd: 32, RcvWnd: 32, Stream: 1, ReadBuf: 65536},
		AB: traceLink{DelayMs: 20, Blackout: 150},
		BA: traceLink{DelayMs: 20},
	},
	{
		// FEC-typed inputs (no rmt_wnd/RTT update, no RepeatSegs), truncated packets and
		// malformed packets (bad conv, short, bad cmd, len beyond data, empty).
		Name: "fec_truncated_garbage", Conv: 0x31415926, T0: 2000, Garbage: true, LimitMs: 60000,
		A:  traceSide{NoDelay: []int{0, 40, 2, 1}, SndWnd: 32, RcvWnd: 32, Mtu: 500, Stream: 1, WriteBytes: 7000, MaxWrite: 2000, ReadBuf: 65536},
		B:  traceSide{NoDelay: []int{0, 40, 2, 1}, SndWnd: 32, RcvWnd: 32, Mtu: 500, Stream: 1, WriteBytes: 7000, MaxWrite: 2000, ReadBuf: 65536},
		AB: traceLink{Loss: 0.05, DelayMs: 20, JitterMs: 5, Fec: 0.2, Cut: 0.15, Dup: 0.1},
		BA: traceLink{Loss: 0.05, DelayMs: 20, JitterMs: 5, Fec: 0.2, Cut: 0.15, Dup: 0.1},
	},
	{
		// Go TestLossyConn1 at the ARQ level: 16 round trips of 64-byte messages (message
		// mode, the kcp-go session default), 10% loss, RTT 200 ms, {1,10,2,1}.
		Name: "lossy_conn1_echo", Conv: 0x00000001, T0: 1, PingPong: 64, LimitMs: 120000,
		A:  traceSide{NoDelay: []int{1, 10, 2, 1}, WriteBytes: 16 * 64, ReadBuf: 64},
		B:  traceSide{NoDelay: []int{1, 10, 2, 1}, WriteBytes: 16 * 64, ReadBuf: 65536},
		AB: traceLink{Loss: 0.10, DelayMs: 100},
		BA: traceLink{Loss: 0.10, DelayMs: 100},
	},
	{
		// Go TestLossyConn4 at the ARQ level: as above with congestion control ({1,10,2,0}),
		// 8 round trips instead of 16 to keep the file small.
		Name: "lossy_conn4_echo", Conv: 0x00000004, T0: 4, PingPong: 64, LimitMs: 120000,
		A:  traceSide{NoDelay: []int{1, 10, 2, 0}, WriteBytes: 8 * 64, ReadBuf: 64},
		B:  traceSide{NoDelay: []int{1, 10, 2, 0}, WriteBytes: 8 * 64, ReadBuf: 65536},
		AB: traceLink{Loss: 0.10, DelayMs: 100},
		BA: traceLink{Loss: 0.10, DelayMs: 100},
	},
}

// traceCase is one trace/<config> case: the configuration and both endpoints' traces.
type traceCase struct {
	Name   string      `json:"name"`
	Params traceConfig `json:"params"`
	Result traceResult `json:"result"`
	A      traceEP     `json:"a"`
	B      traceEP     `json:"b"`
}

// CaseName implements namedCase.
func (c traceCase) CaseName() string { return c.Name }

type traceResult struct {
	EndMs    uint64 `json:"end_ms"`    // virtual ms from the start to the end of the trace
	BytesAB  int    `json:"bytes_a_b"` // application bytes delivered a -> b
	BytesBA  int    `json:"bytes_b_a"`
	Packets  int    `json:"packets"` // output callback calls, both endpoints
	Dropped  int    `json:"dropped"` // copies lost on the link
	ADeadEnd bool   `json:"a_dead"`  // a's state is 0xFFFFFFFF at the end
}

// traceEP is one endpoint's trace.
type traceEP struct {
	// PayloadStream: Send payloads are drawn in call order with randBytes from
	// newRNG("kcp", PayloadStream) (a zero-length Send draws nothing).
	PayloadStream uint64            `json:"payload_stream"`
	Snmp          map[string]uint64 `json:"snmp"`   // DefaultSnmp counter increments caused by this endpoint
	Gauges        []uint64          `json:"gauges"` // RingBufferSndQueue/RcvQueue/SndBuffer after its last flush
	Final         []uint32          `json:"final"`  // StateWords at the end (names: README)
	Ops           []string          `json:"ops"`
}

// traceSnmpFields are the DefaultSnmp counters the KCP core increments.
var traceSnmpFields = []string{"InSegs", "OutSegs", "RepeatSegs", "LostSegs", "FastRetransSegs", "EarlyRetransSegs", "RetransSegs"}

// gaugeSentinel marks the RingBuffer gauges as not written.
const gaugeSentinel = ^uint64(0)

func gaugePtrs() []*uint64 {
	s := kcpcopy.DefaultSnmp
	return []*uint64{&s.RingBufferSndQueue, &s.RingBufferRcvQueue, &s.RingBufferSndBuffer}
}

func snmpCounters() []uint64 {
	s := kcpcopy.DefaultSnmp.Copy()
	return []uint64{s.InSegs, s.OutSegs, s.RepeatSegs, s.LostSegs, s.FastRetransSegs, s.EarlyRetransSegs, s.RetransSegs}
}

// traceSim is the running simulation of one config.
type traceSim struct {
	cfg     traceConfig
	now     uint64 // virtual ms since the start; the clock reads uint32(T0 + now)
	reads   int
	link    *rand.Rand
	work    *rand.Rand
	queue   deliveryQueue
	seq     uint64
	eps     [2]*traceEndpoint
	packets int
	dropped int
	// pendingRaw counts crafted packets not yet delivered (the trace runs until they are).
	pendingRaw int
}

type traceEndpoint struct {
	idx     int
	side    traceSide
	link    traceLink // outgoing
	k       *kcpcopy.KCP
	payload *rand.Rand
	ops     []string
	outs    [][]byte // packets output during the current call
	snmp    []uint64
	gauges  []uint64
	mss     int

	writes    []int // remaining application writes
	nextTimer uint64
	sent      []byte // payload of successful Sends
	recv      []byte // bytes returned by Recv
	idleReads int
}

type delivery struct {
	at   uint64
	seq  uint64
	to   int
	src  string // "op.out" in the sender's trace
	data []byte // the (possibly truncated) packet
	cut  int    // truncated length, or -1
	fec  bool
	raw  bool // crafted packet: recorded as hex
}

type deliveryQueue []delivery

func (q deliveryQueue) Len() int { return len(q) }
func (q deliveryQueue) Less(i, j int) bool {
	if q[i].at != q[j].at {
		return q[i].at < q[j].at
	}
	return q[i].seq < q[j].seq
}
func (q deliveryQueue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *deliveryQueue) Push(x any)   { *q = append(*q, x.(delivery)) }
func (q *deliveryQueue) Pop() any {
	old := *q
	x := old[len(old)-1]
	*q = old[:len(old)-1]
	return x
}

func (s *traceSim) clock() uint32 { return s.cfg.T0 + uint32(s.now) }

// call records one API call of endpoint e: name and argument tokens, then runs f with the
// clock read counter reset, and appends the result tokens.
func (s *traceSim) call(e *traceEndpoint, head string, f func() (ret string)) {
	t := s.clock()
	s.reads = 0
	e.outs = nil
	before := snmpCounters()
	// flush() stores the three RingBuffer gauges on every path (Flush, Input, Update); a
	// sentinel shows whether it ran during this call.
	for _, g := range gaugePtrs() {
		atomic.StoreUint64(g, gaugeSentinel)
	}
	ret := f()
	after := snmpCounters()
	for i := range after {
		e.snmp[i] += after[i] - before[i]
	}
	if g := gaugePtrs(); atomic.LoadUint64(g[0]) != gaugeSentinel {
		e.gauges = []uint64{atomic.LoadUint64(g[0]), atomic.LoadUint64(g[1]), atomic.LoadUint64(g[2])}
	}
	var b strings.Builder
	name, args, _ := strings.Cut(head, " ")
	fmt.Fprintf(&b, "%s t=%d", name, t)
	if args != "" {
		b.WriteString(" " + args)
	}
	if ret != "" {
		b.WriteString(" " + ret)
	}
	fmt.Fprintf(&b, " rd=%d st=%016x", s.reads, e.k.StateDigest())
	opIdx := len(e.ops)
	for i, p := range e.outs {
		b.WriteString(" o=" + hx(p))
		s.transmit(e, fmt.Sprintf("%d.%d", opIdx, i), p)
	}
	e.ops = append(e.ops, b.String())
}

// transmit puts one output packet on the link towards the other endpoint.
func (s *traceSim) transmit(e *traceEndpoint, src string, p []byte) {
	s.packets++
	l := e.link
	if l.Blackout != 0 && s.now >= uint64(l.Blackout) {
		s.dropped++
		return
	}
	if s.link.Float64() < l.Loss {
		s.dropped++
		return
	}
	copies := 1
	if s.link.Float64() < l.Dup {
		copies = 2
	}
	for range copies {
		d := uint64(l.DelayMs)
		if l.JitterMs > 0 {
			d += uint64(s.link.Uint32N(l.JitterMs + 1))
		}
		if s.link.Float64() < l.Reorder {
			d += uint64(l.ReorderMs)
		}
		dv := delivery{at: s.now + d, seq: s.seq, to: 1 - e.idx, src: src, data: p, cut: -1}
		if s.link.Float64() < l.Cut && len(p) > 1 {
			dv.cut = 1 + s.link.IntN(len(p)-1)
			dv.data = p[:dv.cut]
		}
		dv.fec = s.link.Float64() < l.Fec
		s.seq++
		heap.Push(&s.queue, dv)
	}
}

func itoa(v int) string { return strconv.Itoa(v) }

func (s *traceSim) send(e *traceEndpoint, n int) int {
	data := randBytes(e.payload, n)
	var ret int
	s.call(e, "send n="+itoa(n), func() string {
		ret = e.k.Send(data)
		return "ret=" + itoa(ret)
	})
	if ret == 0 {
		e.sent = append(e.sent, data...)
	}
	return ret
}

func (s *traceSim) flush(e *traceEndpoint) uint32 {
	var ret uint32
	s.call(e, "flush ft=2", func() string {
		ret = e.k.Flush(kcpcopy.IKCP_FLUSH_FULL)
		return "ret=" + strconv.FormatUint(uint64(ret), 10)
	})
	return ret
}

func (s *traceSim) waitSnd(e *traceEndpoint) int {
	var ret int
	s.call(e, "waitsnd", func() string {
		ret = e.k.WaitSnd()
		return "ret=" + itoa(ret)
	})
	return ret
}

func (s *traceSim) peek(e *traceEndpoint) int {
	var ret int
	s.call(e, "peek", func() string {
		ret = e.k.PeekSize()
		return "ret=" + itoa(ret)
	})
	return ret
}

func (s *traceSim) recvOp(e *traceEndpoint, n int) int {
	buf := make([]byte, n)
	var ret int
	s.call(e, "recv n="+itoa(n), func() string {
		ret = e.k.Recv(buf)
		r := "ret=" + itoa(ret)
		if ret > 0 {
			r += " h=" + hash16(buf[:ret])
		}
		return r
	})
	if ret > 0 {
		e.recv = append(e.recv, buf[:ret]...)
	}
	return ret
}

// hash16 is the first 8 bytes of the SHA-256 of b, in hex.
func hash16(b []byte) string {
	h := sha256.Sum256(b)
	return hex.EncodeToString(h[:8])
}

func (s *traceSim) stalled(e *traceEndpoint) bool {
	return e.side.StallTo > e.side.StallFrom && s.now >= uint64(e.side.StallFrom) && s.now < uint64(e.side.StallTo)
}

// read drains the receive queue like UDPSession.Read: PeekSize, then Recv into the reader
// buffer if it is large enough; otherwise Recv into it anyway (-2) and then into a buffer of
// exactly the peeked size. Every 8th idle read also calls Recv (-1).
func (s *traceSim) read(e *traceEndpoint) {
	if s.stalled(e) {
		return
	}
	for {
		n := s.peek(e)
		if n < 0 {
			e.idleReads++
			if e.idleReads%8 == 1 {
				s.recvOp(e, e.side.ReadBuf)
			}
			return
		}
		if n > e.side.ReadBuf {
			s.recvOp(e, e.side.ReadBuf)
			s.recvOp(e, n)
		} else {
			s.recvOp(e, e.side.ReadBuf)
		}
	}
}

// canWrite gates the next application write: in ping-pong configs a sends message i once
// it has received i answers, and b answers message j once it has received it.
func (s *traceSim) canWrite(e *traceEndpoint) bool {
	if len(e.writes) == 0 || s.now < uint64(e.side.WriteFrom) {
		return false
	}
	pp := s.cfg.PingPong
	if pp == 0 {
		return true
	}
	done := len(e.sent) / pp
	if e.idx == 0 {
		return len(e.recv) >= done*pp
	}
	return len(e.recv) >= (done+1)*pp
}

// write performs pending application writes like UDPSession.Write (writeDelay off).
func (s *traceSim) write(e *traceEndpoint) {
	for s.canWrite(e) {
		if s.waitSnd(e) >= int(e.k.StateWords()[11]) { // snd_wnd
			return
		}
		n := e.writes[0]
		e.writes = e.writes[1:]
		if e.side.NoSplit {
			s.send(e, n)
		} else {
			for n > 0 {
				c := min(n, e.mss)
				s.send(e, c)
				n -= c
			}
		}
		s.waitSnd(e)
		s.flush(e)
	}
}

// timer runs the update timer of e and re-arms it.
func (s *traceSim) timer(e *traceEndpoint) {
	if s.cfg.UseUpdate {
		s.call(e, "update", func() string { e.k.Update(); return "" })
		var ret uint32
		s.call(e, "check", func() string {
			ret = e.k.Check()
			return "ret=" + strconv.FormatUint(uint64(ret), 10)
		})
		d := kcpcopy.Itimediff(ret, s.clock())
		e.nextTimer = s.now + uint64(max(d, 1))
	} else {
		e.nextTimer = s.now + uint64(s.flush(e))
	}
	s.write(e)
}

// deliver inputs one packet into its endpoint, then runs the reader and the writer.
func (s *traceSim) deliver(d delivery) {
	e := s.eps[d.to]
	pt := kcpcopy.IKCP_PACKET_REGULAR
	if d.fec {
		pt = kcpcopy.IKCP_PACKET_FEC
	}
	and := 0
	if e.side.AckNoDelay {
		and = 1
	}
	var head string
	if d.raw {
		s.pendingRaw--
		head = "input hex=" + hx(d.data)
	} else {
		head = "input src=" + d.src
		if d.cut >= 0 {
			head += " cut=" + itoa(d.cut)
		}
	}
	head += fmt.Sprintf(" pt=%d and=%d", pt, and)
	data := append([]byte(nil), d.data...)
	s.call(e, head, func() string {
		return "ret=" + itoa(e.k.Input(data, pt, e.side.AckNoDelay))
	})
	s.read(e)
	s.write(e)
}

// garbage returns the malformed packets injected when cfg.Garbage is set.
func garbage(conv uint32) [][]byte {
	good := kcpcopy.Encode(kcpcopy.Segment{Conv: conv, Cmd: kcpcopy.IKCP_CMD_WINS, Wnd: 5})
	badConv := kcpcopy.Encode(kcpcopy.Segment{Conv: conv ^ 1, Cmd: kcpcopy.IKCP_CMD_PUSH})
	badCmd := kcpcopy.Encode(kcpcopy.Segment{Conv: conv, Cmd: 99})
	long := kcpcopy.Encode(kcpcopy.Segment{Conv: conv, Cmd: kcpcopy.IKCP_CMD_PUSH, Data: make([]byte, 10)})
	return [][]byte{
		{},
		good[:23],
		badConv,
		badCmd,
		append(append([]byte{}, long...), 1, 2, 3), // len 10, only 3 bytes follow
		append(append([]byte{}, good...), badCmd...),
	}
}

func (s *traceSim) done() bool {
	a, b := s.eps[0], s.eps[1]
	if s.cfg.ToDead {
		return a.k.ConnState() == 0xFFFFFFFF
	}
	return s.pendingRaw == 0 && len(a.writes) == 0 && len(b.writes) == 0 &&
		len(b.recv) == len(a.sent) && len(a.recv) == len(b.sent) &&
		a.k.WaitSnd() == 0 && b.k.WaitSnd() == 0
}

func runTrace(i int, cfg traceConfig) (traceCase, error) {
	s := &traceSim{
		cfg:  cfg,
		link: newRNG("kcp", streamTraceLink+uint64(i)),
		work: newRNG("kcp", streamTraceWork+uint64(i)),
	}
	saved := kcpcopy.Clock
	defer func() { kcpcopy.Clock = saved }()
	kcpcopy.Clock = func() uint32 {
		v := s.clock()
		s.reads++
		s.now += uint64(s.cfg.Step)
		return v
	}

	for ei, side := range []traceSide{cfg.A, cfg.B} {
		e := &traceEndpoint{
			idx:     ei,
			side:    side,
			link:    []traceLink{cfg.AB, cfg.BA}[ei],
			payload: newRNG("kcp", streamTracePayload+uint64(2*i+ei)),
			snmp:    make([]uint64, len(traceSnmpFields)),
		}
		e.k = kcpcopy.NewKCP(cfg.Conv, func(buf []byte, size int) {
			e.outs = append(e.outs, append([]byte(nil), buf[:size]...))
		})
		s.eps[ei] = e
		for left := side.WriteBytes; left > 0; {
			n := left
			if cfg.PingPong > 0 {
				n = min(left, cfg.PingPong)
			} else if side.MaxWrite > 0 {
				n = min(left, 1+s.work.IntN(side.MaxWrite))
			}
			e.writes = append(e.writes, n)
			left -= n
		}
	}

	// Configuration calls, then the edge-case sends, as the session constructor and setters do.
	for _, e := range s.eps {
		sd := e.side
		if sd.Mtu != 0 {
			s.call(e, "setmtu a="+itoa(sd.Mtu), func() string { return "ret=" + itoa(e.k.SetMtu(sd.Mtu)) })
		}
		if sd.NoDelay != nil {
			a := sd.NoDelay
			s.call(e, fmt.Sprintf("nodelay a=%d,%d,%d,%d", a[0], a[1], a[2], a[3]), func() string {
				return "ret=" + itoa(e.k.NoDelay(a[0], a[1], a[2], a[3]))
			})
		}
		if sd.SndWnd != 0 || sd.RcvWnd != 0 {
			s.call(e, fmt.Sprintf("wndsize a=%d,%d", sd.SndWnd, sd.RcvWnd), func() string {
				return "ret=" + itoa(e.k.WndSize(sd.SndWnd, sd.RcvWnd))
			})
		}
		s.call(e, fmt.Sprintf("stream a=%d", sd.Stream), func() string { e.k.SetStream(sd.Stream); return "" })
		e.mss = int(e.k.StateWords()[1])
		if s.cfg.UseUpdate {
			s.call(e, "check", func() string { return "ret=" + strconv.FormatUint(uint64(e.k.Check()), 10) })
		}
		for _, n := range sd.ExtraSends {
			s.send(e, n)
		}
		e.nextTimer = s.now
	}
	if cfg.Garbage {
		for k, g := range garbage(cfg.Conv) {
			for to := range 2 {
				s.seq++
				s.pendingRaw++
				heap.Push(&s.queue, delivery{at: uint64(5 + 7*k + 3*to), seq: s.seq, to: to, data: g, cut: -1, raw: true})
			}
		}
	}

	for !s.done() {
		// The next event: a delivery, a timer, or the end of a reader stall (ties: deliveries,
		// then a, then b).
		next := min(s.eps[0].nextTimer, s.eps[1].nextTimer)
		if len(s.queue) > 0 {
			next = min(next, s.queue[0].at)
		}
		for _, e := range s.eps {
			if to := uint64(e.side.StallTo); e.side.StallTo > e.side.StallFrom && to > s.now {
				next = min(next, to)
			}
		}
		if next > s.now {
			s.now = next
		}
		if s.now > cfg.LimitMs {
			return traceCase{}, fmt.Errorf("trace/%s: not done after %d ms", cfg.Name, cfg.LimitMs)
		}
		switch {
		case len(s.queue) > 0 && s.queue[0].at <= s.now:
			s.deliver(heap.Pop(&s.queue).(delivery))
		case s.eps[0].nextTimer <= s.now:
			s.timer(s.eps[0])
		case s.eps[1].nextTimer <= s.now:
			s.timer(s.eps[1])
		default: // a stall ended
			for _, e := range s.eps {
				if uint64(e.side.StallTo) == s.now {
					s.read(e)
				}
			}
		}
	}

	a, b := s.eps[0], s.eps[1]
	if !cfg.ToDead {
		if string(a.sent) != string(b.recv) || string(b.sent) != string(a.recv) {
			return traceCase{}, fmt.Errorf("trace/%s: received data differs from sent data", cfg.Name)
		}
	}
	c := traceCase{
		Name:   "trace/" + cfg.Name,
		Params: cfg,
		Result: traceResult{
			EndMs: s.now, BytesAB: len(b.recv), BytesBA: len(a.recv), Packets: s.packets,
			Dropped: s.dropped, ADeadEnd: a.k.ConnState() == 0xFFFFFFFF,
		},
	}
	for ei, e := range s.eps {
		ep := traceEP{
			PayloadStream: streamTracePayload + uint64(2*i+ei),
			Snmp:          map[string]uint64{},
			Gauges:        e.gauges,
			Final:         e.k.StateWords(),
			Ops:           e.ops,
		}
		for j, f := range traceSnmpFields {
			ep.Snmp[f] = e.snmp[j]
		}
		if ei == 0 {
			c.A = ep
		} else {
			c.B = ep
		}
	}
	return c, nil
}

func genTraces() ([]any, error) {
	var cases []any
	for i, cfg := range traceConfigs {
		c, err := runTrace(i, cfg)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, nil
}
