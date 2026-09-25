package main

// Area "fec" (plan step 04.6): golden packet streams of kcp-go v5.6.66's FEC layer (fec.go),
// run through internal/kcpcopy, a verbatim copy of fec.go whose only change is the encoder
// clock (FecClock, so the timestamps are scripted; TestVerbatimCopy checks the copy), with the
// pinned klauspost/reedsolomon v1.13.0.
//
//   - encoder/...  : every packet an fecEncoder writes (data packets after sealing, parity
//                    shards, OOB packets) for scripted packet lengths and timestamps, including
//                    gaps at the rto boundary (499/500 ms), long gaps (skipParity), a clock that
//                    goes backwards, the ds == 1 first-group quirk and the paws wrap.
//   - decoder/...  : those streams fed to an fecDecoder with drop, duplicate and reorder
//                    patterns (and truncated or crafted packets): every recovered shard (hash)
//                    and the SNMP FEC counters.
//   - autotune/... : senders that switch (ds, ps) mid-stream, e.g. (10,3) -> (5,2), fed to a
//                    decoder that must auto-tune.
//
// The format is documented in README.md ("Area fec").

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/klauspost/reedsolomon"

	kcpcopy "github.com/kcptun-rust/tools/govectors/internal/kcpcopy"
)

// RNG streams of the fec area (see newRNG).
const (
	streamFecPayload  = 1 << 16 // + encoder config index: packet bytes
	streamFecScript   = 2 << 16 // + encoder config index: packet lengths and clock deltas
	streamFecFeed     = 3 << 16 // + 64*encoder config + pattern index: drop/dup/reorder decisions
	streamFecPhase    = 4 << 16 // + 16*autotune case + phase: packet bytes and lengths
	streamFecAutoFeed = 5 << 16 // + autotune case index: drop/dup/reorder decisions
)

// fecStart is the first scripted encoder time (UnixMilli). kcp-go starts tsLatestPacket at 0,
// so the first comparison sees a gap of about 55 years.
const fecStart int64 = 1758000000000

// fecRto is the rto every stream is encoded with: sess.go passes maxFECEncodeLatency (500).
const fecRto = 500

// fecMtuLimit is kcp-go's mtuLimit, the longest packet.
const fecMtuLimit = 1500

// ---------------------------------------------------------------------------------------------
// Case types
// ---------------------------------------------------------------------------------------------

// fecEncCase is one encoder sequence.
type fecEncCase struct {
	Name          string         `json:"name"`
	DS            int            `json:"ds"`
	PS            int            `json:"ps"`
	Offset        int            `json:"offset"`
	Rto           uint32         `json:"rto"`
	Next          uint32         `json:"next,omitempty"` // initial seqid (SetNext); 0 = fresh encoder
	Paws          uint32         `json:"paws"`
	PayloadStream uint64         `json:"payload_stream"`
	Packets       []fecEncPacket `json:"packets"`
}

func (c fecEncCase) CaseName() string { return c.Name }

// fecEncPacket is one encode (or encodeOOB) call.
type fecEncPacket struct {
	Len    int      `json:"len"`
	Now    int64    `json:"now,omitempty"` // FecClock value of the call (absent for OOB)
	Oob    bool     `json:"oob,omitempty"` // encodeOOB instead of encode
	Out    string   `json:"out"`           // the whole packet after the call
	Parity []string `json:"parity,omitempty"`
}

// fecPhase is one sender of an autotune case: a fresh encoder (offset 0) whose next seqid is
// set to Next, encoding one packet per entry of Lens at Start, Start+Step, ...
type fecPhase struct {
	DS            int    `json:"ds"`
	PS            int    `json:"ps"`
	Next          uint32 `json:"next"`
	PayloadStream uint64 `json:"payload_stream"`
	Lens          string `json:"lens"` // packet lengths, space-separated
	Start         int64  `json:"start"`
	Step          int64  `json:"step"`
}

// fecCounters are the DefaultSnmp FEC fields after a decoder case (reset before it).
type fecCounters struct {
	ShardSet     uint64 `json:"fec_shard_set"` // gauge
	ParityShards uint64 `json:"fec_parity_shards"`
	FullShardSet uint64 `json:"fec_full_shard_set"`
	Recovered    uint64 `json:"fec_recovered"`
	Errs         uint64 `json:"fec_errs"`
	ShardMin     uint64 `json:"fec_shard_min"` // gauge
}

// fecDecCase is one decoder scenario (groups decoder/ and autotune/).
type fecDecCase struct {
	Name         string      `json:"name"`
	Stream       string      `json:"stream,omitempty"` // encoder case whose packets are fed
	Phases       []fecPhase  `json:"phases,omitempty"` // or: the senders that produce the stream
	StreamSHA256 string      `json:"stream_sha256,omitempty"`
	DS           int         `json:"ds"` // decoder construction
	PS           int         `json:"ps"`
	Crafted      []string    `json:"crafted,omitempty"`
	Feed         string      `json:"feed"`
	Recovered    []string    `json:"recovered,omitempty"`
	Tunes        []string    `json:"tunes,omitempty"`
	Counters     fecCounters `json:"counters"`
	FinalDS      int         `json:"final_ds"`
	FinalPS      int         `json:"final_ps"`
	ShardSets    int         `json:"shard_sets"`
}

func (c fecDecCase) CaseName() string { return c.Name }

// ---------------------------------------------------------------------------------------------
// Streams
// ---------------------------------------------------------------------------------------------

// fecPkt is one packet of a stream, from the FEC header on (the crypto header room removed).
type fecPkt struct {
	b      []byte
	seqid  uint32
	flag   uint16
	oob    bool
	source int // index of the encode call (data packet) or of the call that emitted it (parity)
}

// fecStream is what the sender put on the wire, in order, and its (ds, ps).
type fecStream struct {
	ds, ps int
	pkts   []fecPkt
}

func (s *fecStream) add(b []byte, offset int, oob bool, source int) {
	p := bytes.Clone(b[offset:])
	s.pkts = append(s.pkts, fecPkt{
		b: p, seqid: binary.LittleEndian.Uint32(p), flag: binary.LittleEndian.Uint16(p[4:]),
		oob: oob, source: source,
	})
}

// withClock runs f with FecClock returning *now.
func withClock(now *int64, f func()) {
	saved := kcpcopy.FecClock
	kcpcopy.FecClock = func(func() time.Time) int64 { return *now }
	defer func() { kcpcopy.FecClock = saved }()
	f()
}

// ---------------------------------------------------------------------------------------------
// Encoder sequences
// ---------------------------------------------------------------------------------------------

// fecEncConfig scripts one encoder sequence.
type fecEncConfig struct {
	ds, ps, offset int
	data           int           // number of encode calls
	wrapGroups     int           // > 0: start at paws - wrapGroups*(ds+ps)
	maxLen         int           // longest packet
	gaps           map[int]int64 // data index -> clock delta before that call
	oob            map[int]bool  // call index -> encodeOOB call
	lens           map[int]int   // data index -> exact packet length (-1: offset+8)
	wantParity     map[int]bool  // data index -> must (true) / must not (false) emit parity
	expectSkipped  int           // groups whose parity is skipped
	name           string
}

var fecEncConfigs = []fecEncConfig{
	{ // kcptun's default FEC with an encrypted session (cryptHeaderSize 20).
		name: "ds=10,ps=3,off=20", ds: 10, ps: 3, offset: 20, data: 60, maxLen: fecMtuLimit,
		gaps:       map[int]int64{5: 800, 19: 499, 29: 500, 39: 2500, 49: -40},
		lens:       map[int]int{3: -1, 12: fecMtuLimit},
		wantParity: map[int]bool{9: true, 19: true, 29: false, 39: false, 49: true, 59: true},
		// the 800 ms gap before call 5 is inside a group: the group still gets its parity
		expectSkipped: 2,
	},
	{ // small groups, an odd offset and OOB packets in between.
		name: "ds=3,ps=2,off=12", ds: 3, ps: 2, offset: 12, data: 51, maxLen: fecMtuLimit,
		gaps:          map[int]int64{4: 900, 8: 500, 11: 499, 20: 1000, 26: -30, 35: 501},
		oob:           map[int]bool{7: true, 25: true, 40: true},
		lens:          map[int]int{0: -1, 30: fecMtuLimit},
		wantParity:    map[int]bool{2: true, 5: true, 8: false, 11: true, 20: false, 26: true, 35: false},
		expectSkipped: 3,
	},
	{ // ds == 1: every packet closes a group; the first group's parity is skipped (tsLatestPacket 0).
		name: "ds=1,ps=1,off=0", ds: 1, ps: 1, offset: 0, data: 50, maxLen: fecMtuLimit,
		gaps:          map[int]int64{10: 499, 11: 500, 12: 0, 20: 700, 30: -20, 31: 5000},
		lens:          map[int]int{5: -1, 6: fecMtuLimit},
		wantParity:    map[int]bool{0: false, 1: true, 10: true, 11: false, 12: true, 20: false, 30: true, 31: false},
		expectSkipped: 4,
	},
	{ // seqids across the paws wrap (last three groups before it, then 0...).
		name: "ds=4,ps=2,off=8,wrap", ds: 4, ps: 2, offset: 8, data: 24, maxLen: 300, wrapGroups: 3,
		gaps:          map[int]int64{11: 600},
		wantParity:    map[int]bool{3: true, 7: true, 11: false, 15: true},
		expectSkipped: 1,
	},
}

// fecEncoded is an encoder sequence: its vector case and the stream it put on the wire.
type fecEncoded struct {
	c      fecEncCase
	stream fecStream
}

// kcpLen draws the length of a KCP-sized packet (FEC and crypto headers included): an ACK-only
// packet, an MTU-sized data packet, or anything in between.
func kcpLen(r *rand.Rand, offset, maxLen int) int {
	hdr := offset + 8 // crypto header room, FEC header and size field
	switch k := r.IntN(10); {
	case k < 3: // 1..4 ACK segments
		return min(maxLen, hdr+24*(1+r.IntN(4)))
	case k < 6 && maxLen >= 1350: // full-sized packet
		return 1350 + r.IntN(maxLen-1350+1)
	default:
		return hdr + 24 + r.IntN(maxLen-hdr-24+1)
	}
}

func genFecEncoder(idx int, cfg fecEncConfig) (fecEncoded, error) {
	script := newRNG("fec", streamFecScript+uint64(idx))
	enc := kcpcopy.NewFECEncoder(cfg.ds, cfg.ps, cfg.offset)
	if enc == nil {
		return fecEncoded{}, fmt.Errorf("%s: newFECEncoder returned nil", cfg.name)
	}
	shardSize := uint32(cfg.ds + cfg.ps)
	if cfg.wrapGroups > 0 {
		enc.SetNext(enc.Paws() - uint32(cfg.wrapGroups)*shardSize)
	}
	c := fecEncCase{
		Name: "encoder/" + cfg.name, DS: cfg.ds, PS: cfg.ps, Offset: cfg.offset, Rto: fecRto,
		Next: enc.Next(), Paws: enc.Paws(), PayloadStream: streamFecPayload + uint64(idx),
	}

	// Script: lengths and times of all calls.
	calls := cfg.data + len(cfg.oob)
	lens := make([]int, calls)
	nows := make([]int64, calls)
	now := fecStart
	for call, data := 0, 0; call < calls; call++ {
		if cfg.oob[call] {
			lens[call] = cfg.offset + 8 + 24*(1+script.IntN(3))
			continue
		}
		lens[call] = kcpLen(script, cfg.offset, cfg.maxLen)
		if l, ok := cfg.lens[data]; ok {
			lens[call] = l
			if l < 0 {
				lens[call] = cfg.offset + 8
			}
		}
		delta := int64(script.IntN(41))
		if script.IntN(10) == 0 {
			delta = int64(41 + script.IntN(260))
		}
		if g, ok := cfg.gaps[data]; ok {
			delta = g
		}
		if data > 0 {
			now += delta
		}
		nows[call] = now
		data++
	}

	total := 0
	for _, l := range lens {
		total += l
	}
	payload := randBytes(newRNG("fec", c.PayloadStream), total)

	stream := fecStream{ds: cfg.ds, ps: cfg.ps}
	skipped := 0
	var err error
	withClock(&now, func() {
		for call, data := 0, 0; call < calls; call++ {
			b := bytes.Clone(payload[:lens[call]])
			payload = payload[lens[call]:]
			p := fecEncPacket{Len: lens[call]}
			if cfg.oob[call] {
				before := enc.Next()
				enc.EncodeOOB(b)
				if enc.Next() != before {
					err = fmt.Errorf("%s: encodeOOB changed next", cfg.name)
					return
				}
				p.Oob = true
				p.Out = hx(b)
				stream.add(b, cfg.offset, true, call)
				c.Packets = append(c.Packets, p)
				continue
			}
			now = nows[call]
			p.Now = now
			seq := enc.Next()
			ps := enc.Encode(b, fecRto)
			p.Out = hx(b)
			stream.add(b, cfg.offset, false, call)
			for _, s := range ps {
				p.Parity = append(p.Parity, hx(s))
				stream.add(s, cfg.offset, false, call)
			}
			closes := (seq%shardSize)+1 == uint32(cfg.ds)
			if closes && len(ps) == 0 {
				skipped++
			}
			if !closes && len(ps) != 0 {
				err = fmt.Errorf("%s: call %d emitted parity mid-group", cfg.name, call)
				return
			}
			if want, ok := cfg.wantParity[data]; ok && want != (len(ps) != 0) {
				err = fmt.Errorf("%s: data packet %d: parity %v, want %v", cfg.name, data, len(ps) != 0, want)
				return
			}
			c.Packets = append(c.Packets, p)
			data++
		}
	})
	if err != nil {
		return fecEncoded{}, err
	}
	if skipped != cfg.expectSkipped {
		return fecEncoded{}, fmt.Errorf("%s: %d groups skipped their parity, want %d", cfg.name, skipped, cfg.expectSkipped)
	}
	if err := checkFecParity(&stream); err != nil {
		return fecEncoded{}, fmt.Errorf("%s: %w", cfg.name, err)
	}
	return fecEncoded{c: c, stream: stream}, nil
}

// checkFecParity checks every complete group of s with reedsolomon's Verify: the data shards
// (from the size field on, zero-padded to the longest) and the parity shards form a codeword.
func checkFecParity(s *fecStream) error {
	codec, err := reedsolomon.New(s.ds, s.ps)
	if err != nil {
		return err
	}
	groups := map[uint32][]fecPkt{}
	size := uint32(s.ds + s.ps)
	for _, p := range s.pkts {
		if !p.oob {
			groups[p.seqid/size] = append(groups[p.seqid/size], p)
		}
	}
	checked := 0
	for id, g := range groups {
		if len(g) != s.ds+s.ps {
			continue
		}
		maxlen := len(g[s.ds].b) - 6
		shards := make([][]byte, len(g))
		for i, p := range g {
			shards[i] = make([]byte, maxlen)
			if copy(shards[i], p.b[6:]) != len(p.b)-6 {
				return fmt.Errorf("group %d: shard %d longer than the parity", id, i)
			}
		}
		if ok, err := codec.Verify(shards); !ok || err != nil {
			return fmt.Errorf("group %d: parity does not verify (%v)", id, err)
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("no complete group")
	}
	return nil
}

// ---------------------------------------------------------------------------------------------
// Decoder scenarios
// ---------------------------------------------------------------------------------------------

// feedTok is one decode call: stream packet idx (its first cut bytes when cut > 0), or crafted
// packet crafted when idx < 0.
type feedTok struct {
	idx, cut, crafted int
}

func (t feedTok) String() string {
	switch {
	case t.idx < 0:
		return "c" + strconv.Itoa(t.crafted)
	case t.cut > 0:
		return strconv.Itoa(t.idx) + ":" + strconv.Itoa(t.cut)
	default:
		return strconv.Itoa(t.idx)
	}
}

func tok(i int) feedTok { return feedTok{idx: i} }

// groupsOf lists the indices of the non-OOB packets of s per group (by the sender's shard
// size), in stream order of the groups.
func groupsOf(s *fecStream) [][]int {
	size := uint32(s.ds + s.ps)
	var out [][]int
	pos := map[uint32]int{}
	for i, p := range s.pkts {
		if p.oob {
			continue
		}
		g := p.seqid / size
		k, ok := pos[g]
		if !ok {
			k = len(out)
			pos[g] = k
			out = append(out, nil)
		}
		out[k] = append(out[k], i)
	}
	return out
}

// dropPerGroup removes n packets per group (only data packets when dataOnly), chosen at random.
func dropPerGroup(r *rand.Rand, s *fecStream, n int, dataOnly bool) []feedTok {
	drop := map[int]bool{}
	for _, g := range groupsOf(s) {
		var cand []int
		for _, i := range g {
			if !dataOnly || s.pkts[i].flag == 0xf1 {
				cand = append(cand, i)
			}
		}
		r.Shuffle(len(cand), func(a, b int) { cand[a], cand[b] = cand[b], cand[a] })
		for _, i := range cand[:min(n, len(cand))] {
			drop[i] = true
		}
	}
	var out []feedTok
	for i, p := range s.pkts {
		if !p.oob && !drop[i] {
			out = append(out, tok(i))
		}
	}
	return out
}

func cleanFeed(s *fecStream) []feedTok {
	var out []feedTok
	for i, p := range s.pkts {
		if !p.oob {
			out = append(out, tok(i))
		}
	}
	return out
}

// reorder swaps random packets with one up to window positions later.
func reorder(r *rand.Rand, f []feedTok, swaps, window int) []feedTok {
	for range swaps {
		i := r.IntN(len(f) - 1)
		j := min(len(f)-1, i+1+r.IntN(window))
		f[i], f[j] = f[j], f[i]
	}
	return f
}

// moveLate moves n random packets about `by` positions later (past the decoder's discard
// horizon when by is several groups).
func moveLate(r *rand.Rand, f []feedTok, n, by int) []feedTok {
	for range n {
		if len(f) <= by+1 {
			break
		}
		i := r.IntN(len(f) - by - 1)
		t := f[i]
		f = slices.Delete(f, i, i+1)
		j := i + by + r.IntN(by/2+1)
		f = slices.Insert(f, min(j, len(f)), t)
	}
	return f
}

// duplicate inserts copies of packets (probability 1/den each) a few positions later, and some
// much later (after their group was decoded).
func duplicate(r *rand.Rand, f []feedTok, den, far int) []feedTok {
	var out []feedTok
	var later []struct {
		at int
		t  feedTok
	}
	for i, t := range f {
		out = append(out, t)
		for k := 0; k < len(later); {
			if later[k].at <= i {
				out = append(out, later[k].t)
				later = slices.Delete(later, k, k+1)
			} else {
				k++
			}
		}
		if r.IntN(den) == 0 {
			d := r.IntN(6)
			if r.IntN(4) == 0 {
				d = far + r.IntN(far)
			}
			if d == 0 {
				out = append(out, t)
			} else {
				later = append(later, struct {
					at int
					t  feedTok
				}{i + d, t})
			}
		}
	}
	for _, l := range later {
		out = append(out, l.t)
	}
	return out
}

// loseRandom drops each packet with probability 1/den.
func loseRandom(r *rand.Rand, f []feedTok, den int) []feedTok {
	var out []feedTok
	for _, t := range f {
		if r.IntN(den) != 0 {
			out = append(out, t)
		}
	}
	return out
}

// fecPattern builds the feed of one decoder scenario: the decode calls and the crafted packets
// they refer to.
type fecPattern struct {
	name string
	// check: every recovered shard must be a data shard of the stream and the decoder must not
	// retune (false when truncated packets can make recovery produce other bytes)
	check   bool
	applies func(s *fecStream) bool // nil: every stream
	feed    func(r *rand.Rand, s *fecStream, paws uint32) ([]feedTok, [][]byte)
}

// plain wraps a feed function without crafted packets.
func plain(f func(r *rand.Rand, s *fecStream) []feedTok) func(*rand.Rand, *fecStream, uint32) ([]feedTok, [][]byte) {
	return func(r *rand.Rand, s *fecStream, _ uint32) ([]feedTok, [][]byte) { return f(r, s), nil }
}

var fecPatterns = []fecPattern{
	{name: "clean", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok { return cleanFeed(s) })},
	{name: "drop1", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok { return dropPerGroup(r, s, 1, true) })},
	{name: "drop_ps", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok { return dropPerGroup(r, s, s.ps, false) })},
	{name: "drop_ps_data", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok { return dropPerGroup(r, s, s.ps, true) })},
	// with ds == 1 this would drop every packet
	{name: "drop_ps1", check: true, applies: func(s *fecStream) bool { return s.ds > 1 },
		feed: plain(func(r *rand.Rand, s *fecStream) []feedTok { return dropPerGroup(r, s, s.ps+1, false) })},
	{name: "parity_lost", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok {
		var out []feedTok
		for i, p := range s.pkts {
			if !p.oob && p.flag != 0xf2 {
				out = append(out, tok(i))
			}
		}
		return out
	})},
	{name: "dup", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok {
		return duplicate(r, dropPerGroup(r, s, 1, true), 4, 2*(s.ds+s.ps))
	})},
	{name: "reorder", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok {
		f := dropPerGroup(r, s, 1, false)
		f = reorder(r, f, len(f)/3, 8)
		return moveLate(r, f, 3, 5*(s.ds+s.ps))
	})},
	{name: "mixed", check: true, feed: plain(func(r *rand.Rand, s *fecStream) []feedTok {
		f := loseRandom(r, cleanFeed(s), 8)
		f = duplicate(r, f, 10, 3*(s.ds+s.ps))
		return reorder(r, f, len(f)/4, 6)
	})},
	{name: "mistyped", check: true, feed: mistypedFeed},
	{name: "garbage", applies: func(s *fecStream) bool { return s.ds > 1 }, feed: garbageFeed},
}

// fecPkt builds a crafted packet (from the FEC header on).
func craftPkt(seqid uint32, flag uint16, body ...byte) []byte {
	b := binary.LittleEndian.AppendUint32(nil, seqid)
	b = binary.LittleEndian.AppendUint16(b, flag)
	return append(b, body...)
}

// mistypedFeed is the clean stream with packets whose type does not match their position,
// which makes the decoder call FindPeriod: a data packet of the third group and a parity
// packet of the fifth group are replaced by short packets with the same seqid and the parity
// (resp. an unknown) type; FindPeriod finds the current (ds, ps) and the decoder goes on. The
// first data packet of the last group is then repeated with the parity type: the repeated
// seqid breaks FindPeriod's run of consecutive seqids, so the decoder stays out of sync and
// drops everything after it.
func mistypedFeed(r *rand.Rand, s *fecStream, _ uint32) ([]feedTok, [][]byte) {
	groups := groupsOf(s)
	pick := func(g []int, flag uint16, nth int) int {
		var c []int
		for _, i := range g {
			if s.pkts[i].flag == flag {
				c = append(c, i)
			}
		}
		if len(c) == 0 {
			return -1
		}
		return c[min(nth, len(c)-1)]
	}
	replace := map[int]int{} // stream index -> crafted index
	var crafted [][]byte
	if x := pick(groups[2], 0xf1, 1); x >= 0 {
		replace[x] = len(crafted)
		crafted = append(crafted, craftPkt(s.pkts[x].seqid, 0xf2, s.pkts[x].b[6:10]...))
	}
	if y := pick(groups[4], 0xf2, 0); y >= 0 {
		replace[y] = len(crafted)
		crafted = append(crafted, craftPkt(s.pkts[y].seqid, 0x0000, s.pkts[y].b[6:9]...))
	}
	z := pick(groups[len(groups)-1], 0xf1, 0)
	crafted = append(crafted, craftPkt(s.pkts[z].seqid, 0xf2, 1, 2, 3))
	var out []feedTok
	for _, t := range cleanFeed(s) {
		if k, ok := replace[t.idx]; ok {
			out = append(out, feedTok{idx: -1, crafted: k})
			continue
		}
		out = append(out, t)
		if t.idx == z {
			out = append(out, feedTok{idx: -1, crafted: len(crafted) - 1})
		}
	}
	return out, crafted
}

// garbageFeed is the stream with one data packet lost per group, truncated copies of packets
// (at least the 6-byte FEC header; some replace the packet) and short crafted packets: an OOB
// packet, seqids at and above paws, a data packet whose size field is too large and one whose
// size field is too small, all at random positions; and, at the end, a new group (after the
// last one) of header-only packets, data at positions 0..ds-2 and the first parity: ds empty
// shards whose reconstruction fails (FECErrs).
func garbageFeed(r *rand.Rand, s *fecStream, paws uint32) ([]feedTok, [][]byte) {
	var f []feedTok
	last := uint32(0)
	size := uint32(s.ds + s.ps)
	for _, t := range dropPerGroup(r, s, 1, true) {
		last = s.pkts[t.idx].seqid / size // the stream's groups are in order
		if r.IntN(6) == 0 {
			n := len(s.pkts[t.idx].b)
			if cut := 6 + r.IntN(n-6+1); cut < n {
				f = append(f, feedTok{idx: t.idx, cut: cut})
				if r.IntN(2) == 0 {
					continue
				}
			}
		}
		f = append(f, t)
	}
	ds := uint32(s.ds)
	crafted := [][]byte{
		craftPkt(0xffffffff, 0xf3, 10, 0, 1, 2, 3, 4, 5, 6, 7, 8), // c0 OOB
		craftPkt(paws, 0xf1, 4, 0, 0xaa, 0xbb),                    // c1 seqid == paws
		craftPkt(0xffffffff, 0xf2, 1, 2, 3),                       // c2 the largest seqid (>= paws)
		craftPkt(size+ds-1, 0xf1, 0xff, 0xff, 1, 2, 3, 4, 5, 6),   // c3 size field too large
		craftPkt(2*size, 0xf1, 1, 0, 0x55),                        // c4 size field too small
	}
	for k := range crafted {
		f = slices.Insert(f, r.IntN(len(f)+1), feedTok{idx: -1, crafted: k})
	}
	empty := ((last + 1) % (paws / size)) * size
	for k := range ds - 1 {
		f = append(f, feedTok{idx: -1, crafted: len(crafted)})
		crafted = append(crafted, craftPkt(empty+k, 0xf1))
	}
	f = append(f, feedTok{idx: -1, crafted: len(crafted)})
	crafted = append(crafted, craftPkt(empty+ds, 0xf2))
	return f, crafted
}

// runDecoder feeds the tokens to a fresh decoder and fills in the results of c.
func runDecoder(c *fecDecCase, s *fecStream, crafted [][]byte, feed []feedTok) ([][]byte, error) {
	dec := kcpcopy.NewFECDecoder(c.DS, c.PS)
	if dec == nil {
		return nil, fmt.Errorf("%s: newFECDecoder returned nil", c.Name)
	}
	kcpcopy.DefaultSnmp.Reset()
	toks := make([]string, len(feed))
	var all [][]byte
	ds, ps := dec.Shards()
	for call, t := range feed {
		toks[call] = t.String()
		var in []byte
		switch {
		case t.idx < 0:
			in = crafted[t.crafted]
		case t.cut > 0:
			in = s.pkts[t.idx].b[:t.cut]
		default:
			in = s.pkts[t.idx].b
		}
		for _, r := range dec.Decode(bytes.Clone(in)) {
			c.Recovered = append(c.Recovered, fmt.Sprintf("%d %d %s", call, len(r), sha256Hex(r)))
			all = append(all, bytes.Clone(r))
		}
		if nds, nps := dec.Shards(); nds != ds || nps != ps {
			ds, ps = nds, nps
			c.Tunes = append(c.Tunes, fmt.Sprintf("%d %d %d", call, ds, ps))
		}
	}
	c.Feed = strings.Join(toks, " ")
	sn := kcpcopy.DefaultSnmp.Copy()
	c.Counters = fecCounters{
		ShardSet: sn.FECShardSet, ParityShards: sn.FECParityShards, FullShardSet: sn.FECFullShardSet,
		Recovered: sn.FECRecovered, Errs: sn.FECErrs, ShardMin: sn.FECShardMin,
	}
	c.FinalDS, c.FinalPS = dec.Shards()
	c.ShardSets = dec.ShardSets()
	if uint64(len(all)) != c.Counters.Recovered {
		return nil, fmt.Errorf("%s: %d recovered shards but FECRecovered = %d", c.Name, len(all), c.Counters.Recovered)
	}
	return all, nil
}

// checkRecovered checks that every recovered shard is the zero-padded RS shard (from the size
// field on) of a data packet of the stream.
func checkRecovered(name string, s *fecStream, rec [][]byte) error {
	for k, r := range rec {
		ok := false
		for _, p := range s.pkts {
			d := p.b[6:]
			if p.oob || p.flag != 0xf1 || len(d) > len(r) || !bytes.Equal(r[:len(d)], d) {
				continue
			}
			if !slices.ContainsFunc(r[len(d):], func(b byte) bool { return b != 0 }) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("%s: recovered shard %d is no data shard of the stream", name, k)
		}
	}
	return nil
}

// genFecDecoder runs pattern pat (index patIdx) on the stream of encoder config encIdx.
func genFecDecoder(encIdx, patIdx int, e fecEncoded, pat fecPattern) (fecDecCase, error) {
	s := &e.stream
	r := newRNG("fec", streamFecFeed+uint64(64*encIdx+patIdx))
	c := fecDecCase{Name: "decoder/" + strings.TrimPrefix(e.c.Name, "encoder/") + "/" + pat.name,
		Stream: e.c.Name, DS: s.ds, PS: s.ps}
	feed, crafted := pat.feed(r, s, e.c.Paws)
	for _, b := range crafted {
		c.Crafted = append(c.Crafted, hx(b))
	}
	rec, err := runDecoder(&c, s, crafted, feed)
	if err != nil {
		return c, err
	}
	if pat.check {
		if err := checkRecovered(c.Name, s, rec); err != nil {
			return c, err
		}
		if len(c.Tunes) != 0 {
			return c, fmt.Errorf("%s: decoder retuned on its own stream", c.Name)
		}
	}
	return c, nil
}

// ---------------------------------------------------------------------------------------------
// Auto-tuning
// ---------------------------------------------------------------------------------------------

// fecPhaseSpec scripts one sender of an autotune case.
type fecPhaseSpec struct {
	ds, ps int
	data   int
	next   int64 // start seqid; -1: continue after the previous phase (rounded up to a group)
	// The default feed drops one data packet per group from this data packet of the phase on.
	// FindPeriod only finds a period in a gap-free run of seqids at the start of its sorted
	// ring (258 samples), so a new sender is only detected once about 258 of its packets
	// arrived in a row after the older (or lossy) samples left the ring.
	lossFrom int
}

type fecAutoCase struct {
	name    string
	ds, ps  int // decoder
	phases  []fecPhaseSpec
	pattern func(r *rand.Rand, s *fecStream) []feedTok
	// minimum number of retunes the decoder must perform; strict: the decoder must end at the
	// last sender's (ds, ps) and recover something
	tunes  int
	strict bool
}

// dropPerSenderGroup drops one random data packet per group of the sender that produced it,
// in the groups that start at or after the phase's lossFrom.
func dropPerSenderGroup(r *rand.Rand, s *fecStream, phaseOf []int, phases []fecPhase, specs []fecPhaseSpec) []feedTok {
	type key struct {
		phase int
		group uint32
	}
	groups := map[key][]int{}
	var order []key
	for i, p := range s.pkts {
		ph := phases[phaseOf[i]]
		k := key{phaseOf[i], p.seqid / uint32(ph.DS+ph.PS)}
		if _, ok := groups[k]; !ok {
			order = append(order, k)
			groups[k] = nil
		}
		if p.flag == 0xf1 && p.source-p.source%ph.DS >= specs[phaseOf[i]].lossFrom {
			groups[k] = append(groups[k], i)
		}
	}
	drop := map[int]bool{}
	for _, k := range order {
		if g := groups[k]; len(g) > 0 {
			drop[g[r.IntN(len(g))]] = true
		}
	}
	var out []feedTok
	for i := range s.pkts {
		if !drop[i] {
			out = append(out, tok(i))
		}
	}
	return out
}

var fecAutoCases = []fecAutoCase{
	{name: "switch_continue", ds: 10, ps: 3, tunes: 1, strict: true,
		phases: []fecPhaseSpec{{10, 3, 60, 0, 0}, {5, 2, 230, -1, 190}}},
	{name: "switch_restart", ds: 10, ps: 3, tunes: 1, strict: true,
		phases: []fecPhaseSpec{{10, 3, 60, 0, 0}, {5, 2, 230, 0, 190}}},
	{name: "mismatch_start", ds: 5, ps: 2, tunes: 1, strict: true,
		phases: []fecPhaseSpec{{10, 3, 100, 0, 40}}},
	{name: "switch_back", ds: 10, ps: 3, tunes: 2, strict: true,
		phases: []fecPhaseSpec{{10, 3, 40, 0, 0}, {5, 2, 230, -1, 190}, {10, 3, 360, -1, 250}}},
	// random loss, duplicates and reordering around the switch: FindPeriod rarely sees a
	// gap-free run, so the decoder may stay out of sync (and drop packets) for long.
	{name: "switch_mixed", ds: 10, ps: 3,
		phases: []fecPhaseSpec{{10, 3, 60, 0, 0}, {5, 2, 230, -1, 0}},
		pattern: func(r *rand.Rand, s *fecStream) []feedTok {
			f := loseRandom(r, cleanFeed(s), 40)
			f = duplicate(r, f, 30, 10)
			return reorder(r, f, len(f)/20, 5)
		}},
}

// streamDigest is the SHA-256 over every packet of the stream as u16 LE length || bytes.
func streamDigest(s *fecStream) string {
	h := sha256.New()
	for _, p := range s.pkts {
		h.Write(binary.LittleEndian.AppendUint16(nil, uint16(len(p.b))))
		h.Write(p.b)
	}
	return hx(h.Sum(nil))
}

func genFecAuto(idx int, a fecAutoCase) (fecDecCase, error) {
	c := fecDecCase{Name: "autotune/" + a.name, DS: a.ds, PS: a.ps}
	s := &fecStream{ds: a.phases[0].ds, ps: a.phases[0].ps}
	var phaseOf []int
	now := fecStart
	var next uint32
	for pi, spec := range a.phases {
		stream := streamFecPhase + uint64(16*idx+pi)
		lr := newRNG("fec", stream+(1<<12)) // packet lengths
		ph := fecPhase{DS: spec.ds, PS: spec.ps, PayloadStream: stream, Start: now + 1000, Step: 3}
		size := uint32(spec.ds + spec.ps)
		if spec.next >= 0 {
			ph.Next = uint32(spec.next)
		} else {
			ph.Next = (next + size - 1) / size * size
		}
		lens := make([]int, spec.data)
		ls := make([]string, spec.data)
		total := 0
		for i := range lens {
			lens[i] = kcpLen(lr, 0, fecMtuLimit)
			ls[i] = strconv.Itoa(lens[i])
			total += lens[i]
		}
		ph.Lens = strings.Join(ls, " ")
		payload := randBytes(newRNG("fec", stream), total)
		if spec.data%spec.ds != 0 {
			return c, fmt.Errorf("%s: phase %d is not whole groups", c.Name, pi)
		}
		enc := kcpcopy.NewFECEncoder(spec.ds, spec.ps, 0)
		enc.SetNext(ph.Next)
		withClock(&now, func() {
			for i, l := range lens {
				now = ph.Start + int64(i)*ph.Step
				b := bytes.Clone(payload[:l])
				payload = payload[l:]
				ps := enc.Encode(b, fecRto)
				s.add(b, 0, false, i)
				phaseOf = append(phaseOf, pi)
				for _, p := range ps {
					s.add(p, 0, false, i)
					phaseOf = append(phaseOf, pi)
				}
			}
		})
		next = enc.Next()
		c.Phases = append(c.Phases, ph)
	}
	c.StreamSHA256 = streamDigest(s)
	r := newRNG("fec", streamFecAutoFeed+uint64(idx))
	var feed []feedTok
	if a.pattern != nil {
		feed = a.pattern(r, s)
	} else {
		feed = dropPerSenderGroup(r, s, phaseOf, c.Phases, a.phases)
	}
	if _, err := runDecoder(&c, s, nil, feed); err != nil {
		return c, err
	}
	if len(c.Tunes) < a.tunes {
		return c, fmt.Errorf("%s: %d retunes, want at least %d", c.Name, len(c.Tunes), a.tunes)
	}
	if !a.strict {
		return c, nil
	}
	last := a.phases[len(a.phases)-1]
	if c.FinalDS != last.ds || c.FinalPS != last.ps {
		return c, fmt.Errorf("%s: decoder ends at (%d,%d), want (%d,%d)", c.Name, c.FinalDS, c.FinalPS, last.ds, last.ps)
	}
	if c.Counters.Recovered == 0 {
		return c, fmt.Errorf("%s: nothing recovered", c.Name)
	}
	return c, nil
}

// ---------------------------------------------------------------------------------------------

func genFec() ([]any, error) {
	var cases []any
	var encoded []fecEncoded
	for i, cfg := range fecEncConfigs {
		e, err := genFecEncoder(i, cfg)
		if err != nil {
			return nil, err
		}
		encoded = append(encoded, e)
		cases = append(cases, e.c)
	}
	for ei, e := range encoded {
		for pi, pat := range fecPatterns {
			if pat.applies != nil && !pat.applies(&e.stream) {
				continue
			}
			c, err := genFecDecoder(ei, pi, e, pat)
			if err != nil {
				return nil, err
			}
			cases = append(cases, c)
		}
	}
	for i, a := range fecAutoCases {
		c, err := genFecAuto(i, a)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}
	return cases, nil
}
