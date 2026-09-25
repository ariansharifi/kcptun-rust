package main

// Area "kcp" (plan steps 03.1 and 03.5): constants, the 24-byte segment header codec,
// _itimediff and _ibound_, ACK packets produced by the real kcp-go v5.6.66 state machine, the
// Snmp formatting (Header, ToSlice, "%+v" of Copy), and golden API traces of two KCP endpoints
// (kcptrace.go). The segment codec, flush() and the KCP fields are unexported in kcp-go, so
// they come from internal/kcpcopy (a verbatim copy of the KCP core with an injectable clock,
// checked against the reference); the real_ack group checks that copy against the library
// itself. Case groups are documented in README.md.

import (
	"bytes"
	"fmt"
	"reflect"
	"strconv"
	"sync/atomic"

	kcp "github.com/xtaci/kcp-go/v5"

	kcpcopy "github.com/kcptun-rust/tools/govectors/internal/kcpcopy"
)

// RNG streams of the kcp area (see newRNG).
const (
	streamSegFields  = 1       // field values of the segment/random cases
	streamRealAck    = 2       // payloads of the real_ack pushes
	streamItimediff  = 3       // operands of the itimediff/random cases
	streamSegPayload = 1 << 16 // + case index: the payload of a segment case
)

// segParams are the header fields of one segment, in wire order. Len is the len field
// (equal to the payload length for encoded cases).
type segParams struct {
	Conv uint32 `json:"conv"`
	Cmd  uint8  `json:"cmd"`
	Frg  uint8  `json:"frg"`
	Wnd  uint16 `json:"wnd"`
	Ts   uint32 `json:"ts"`
	Sn   uint32 `json:"sn"`
	Una  uint32 `json:"una"`
	Len  uint32 `json:"len"`
}

func headerParams(h kcpcopy.Header) segParams {
	return segParams{Conv: h.Conv, Cmd: h.Cmd, Frg: h.Frg, Wnd: h.Wnd, Ts: h.Ts, Sn: h.Sn, Una: h.Una, Len: h.Len}
}

// realAckParams describes one real_ack case: the segments of the input packet and of the
// packet(s) the library wrote back, all decoded with the copied ikcp_decode* helpers.
type realAckParams struct {
	Conv     uint32      `json:"conv"`
	Push     []segParams `json:"push"`
	Acks     []segParams `json:"acks"`
	Outputs  []int       `json:"outputs"` // size of each output callback call, in order
	InputRet int         `json:"input_ret"`
}

type itimediffParams struct {
	Later   uint32 `json:"later"`
	Earlier uint32 `json:"earlier"`
	Want    int32  `json:"want"`
}

type iboundParams struct {
	Lower  uint32 `json:"lower"`
	Middle uint32 `json:"middle"`
	Upper  uint32 `json:"upper"`
	Want   uint32 `json:"want"`
}

// snmpCase is one Snmp formatting case: the struct is filled with Values (in struct field
// order, whose names are Fields), then Header(), ToSlice() and fmt.Sprintf("%+v", Copy())
// are recorded.
type snmpCase struct {
	Name    string   `json:"name"`
	Fields  []string `json:"fields"`
	Values  []uint64 `json:"values"`
	Header  []string `json:"header"`
	ToSlice []string `json:"to_slice"`
	Format  string   `json:"format"`
}

// CaseName implements namedCase.
func (c snmpCase) CaseName() string { return c.Name }

func genKcp() ([]any, error) {
	var cases []any
	cases = append(cases, Case{Name: "constants", Params: kcpConstants()})

	segs, err := genSegments()
	if err != nil {
		return nil, err
	}
	cases = append(cases, segs...)

	acks, err := genRealAcks()
	if err != nil {
		return nil, err
	}
	cases = append(cases, acks...)

	cases = append(cases, genTimeMath()...)

	snmp, err := genSnmp()
	if err != nil {
		return nil, err
	}
	cases = append(cases, snmp...)

	traces, err := genTraces()
	if err != nil {
		return nil, err
	}
	return append(cases, traces...), nil
}

// kcpConstants returns every exported constant of kcp.go (map keys are sorted in the file).
func kcpConstants() map[string]int64 {
	return map[string]int64{
		"IKCP_RTO_NDL": kcp.IKCP_RTO_NDL, "IKCP_RTO_MIN": kcp.IKCP_RTO_MIN,
		"IKCP_RTO_DEF": kcp.IKCP_RTO_DEF, "IKCP_RTO_MAX": kcp.IKCP_RTO_MAX,
		"IKCP_CMD_PUSH": kcp.IKCP_CMD_PUSH, "IKCP_CMD_ACK": kcp.IKCP_CMD_ACK,
		"IKCP_CMD_WASK": kcp.IKCP_CMD_WASK, "IKCP_CMD_WINS": kcp.IKCP_CMD_WINS,
		"IKCP_ASK_SEND": kcp.IKCP_ASK_SEND, "IKCP_ASK_TELL": kcp.IKCP_ASK_TELL,
		"IKCP_WND_SND": kcp.IKCP_WND_SND, "IKCP_WND_RCV": kcp.IKCP_WND_RCV,
		"IKCP_MTU_DEF": kcp.IKCP_MTU_DEF, "IKCP_ACK_FAST": kcp.IKCP_ACK_FAST,
		"IKCP_INTERVAL": kcp.IKCP_INTERVAL, "IKCP_OVERHEAD": kcp.IKCP_OVERHEAD,
		"IKCP_DEADLINK": kcp.IKCP_DEADLINK, "IKCP_THRESH_INIT": kcp.IKCP_THRESH_INIT,
		"IKCP_THRESH_MIN": kcp.IKCP_THRESH_MIN, "IKCP_PROBE_INIT": kcp.IKCP_PROBE_INIT,
		"IKCP_PROBE_LIMIT": kcp.IKCP_PROBE_LIMIT, "IKCP_SN_OFFSET": kcp.IKCP_SN_OFFSET,
		"IKCP_PACKET_REGULAR": int64(kcp.IKCP_PACKET_REGULAR), "IKCP_PACKET_FEC": int64(kcp.IKCP_PACKET_FEC),
		"IKCP_FLUSH_ACKONLY": int64(kcp.IKCP_FLUSH_ACKONLY), "IKCP_FLUSH_FULL": int64(kcp.IKCP_FLUSH_FULL),
		"IKCP_LOG_OUTPUT": int64(kcp.IKCP_LOG_OUTPUT), "IKCP_LOG_INPUT": int64(kcp.IKCP_LOG_INPUT),
		"IKCP_LOG_SEND": int64(kcp.IKCP_LOG_SEND), "IKCP_LOG_RECV": int64(kcp.IKCP_LOG_RECV),
		"IKCP_LOG_OUT_ACK": int64(kcp.IKCP_LOG_OUT_ACK), "IKCP_LOG_OUT_PUSH": int64(kcp.IKCP_LOG_OUT_PUSH),
		"IKCP_LOG_OUT_WASK": int64(kcp.IKCP_LOG_OUT_WASK), "IKCP_LOG_OUT_WINS": int64(kcp.IKCP_LOG_OUT_WINS),
		"IKCP_LOG_IN_ACK": int64(kcp.IKCP_LOG_IN_ACK), "IKCP_LOG_IN_PUSH": int64(kcp.IKCP_LOG_IN_PUSH),
		"IKCP_LOG_IN_WASK": int64(kcp.IKCP_LOG_IN_WASK), "IKCP_LOG_IN_WINS": int64(kcp.IKCP_LOG_IN_WINS),
		"IKCP_LOG_OUTPUT_ALL": int64(kcp.IKCP_LOG_OUTPUT_ALL), "IKCP_LOG_INPUT_ALL": int64(kcp.IKCP_LOG_INPUT_ALL),
		"IKCP_LOG_ALL":   int64(kcp.IKCP_LOG_ALL),
		"RINGBUFFER_MIN": kcp.RINGBUFFER_MIN, "RINGBUFFER_EXP": kcp.RINGBUFFER_EXP,
	}
}

// segmentSets are the fixed field sets of the segment group; the payload length is the len
// field (the payload bytes come from streamSegPayload + index).
var segmentSets = []struct {
	label string
	p     segParams
}{
	{"zero", segParams{}},
	{"max", segParams{0xFFFFFFFF, 0xFF, 0xFF, 0xFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 1}},
	{"distinct_bytes", segParams{0x04030201, 0x05, 0x06, 0x0807, 0x0C0B0A09, 0x100F0E0D, 0x14131211, 3}},
	{"push_mss_default", segParams{0x9E3779B9, kcp.IKCP_CMD_PUSH, 0, 1024, 123456, 42, 40, 1298}},
	{"push_mss_production", segParams{0x12345678, kcp.IKCP_CMD_PUSH, 0, 512, 0xFFFFFFF0, 0x7FFFFFFF, 0x80000000, 1346}},
	{"push_msg_frg", segParams{7, kcp.IKCP_CMD_PUSH, 3, 32, 1000, 9, 9, 24}},
	{"ack", segParams{0xCAFEBABE, kcp.IKCP_CMD_ACK, 0, 31, 99999, 17, 18, 0}},
	{"wask", segParams{1, kcp.IKCP_CMD_WASK, 0, 128, 5, 0, 0, 0}},
	{"wins", segParams{1, kcp.IKCP_CMD_WINS, 0, 0, 6, 0, 3, 0}},
}

// segmentRandomCount is the number of segment/random cases (all fields from the RNG).
const segmentRandomCount = 8

func genSegments() ([]any, error) {
	var cases []any
	add := func(name string, idx int, p segParams) error {
		data := randBytes(newRNG("kcp", streamSegPayload+uint64(idx)), int(p.Len))
		s := kcpcopy.Segment{Conv: p.Conv, Cmd: p.Cmd, Frg: p.Frg, Wnd: p.Wnd, Ts: p.Ts, Sn: p.Sn, Una: p.Una, Data: data}
		before := atomic.LoadUint64(&kcpcopy.DefaultSnmp.OutSegs)
		hdr := kcpcopy.Encode(s)
		if atomic.LoadUint64(&kcpcopy.DefaultSnmp.OutSegs) != before+1 {
			return fmt.Errorf("%s: encode did not increment OutSegs by one", name)
		}
		h, rest, ok := kcpcopy.DecodeHeader(append(append([]byte{}, hdr...), data...))
		if !ok || headerParams(h) != p || !bytes.Equal(rest, data) {
			return fmt.Errorf("%s: decode(encode(x)) != x", name)
		}
		cases = append(cases, Case{Name: name, Params: p, In: hx(data), Out: hx(hdr)})
		return nil
	}
	for i, s := range segmentSets {
		if err := add("segment/"+s.label, i, s.p); err != nil {
			return nil, err
		}
	}
	r := newRNG("kcp", streamSegFields)
	for i := range segmentRandomCount {
		p := segParams{
			Conv: r.Uint32(), Cmd: uint8(r.Uint32()), Frg: uint8(r.Uint32()), Wnd: uint16(r.Uint32()),
			Ts: r.Uint32(), Sn: r.Uint32(), Una: r.Uint32(), Len: uint32(r.IntN(65)),
		}
		if err := add(fmt.Sprintf("segment/random/%d", i), len(segmentSets)+i, p); err != nil {
			return nil, err
		}
	}
	return cases, nil
}

// realAckSets are the input packets of the real_ack group. Each push is a PUSH segment
// (frg 0, una 0) with the given sn, ts and payload length.
var realAckSets = []struct {
	label  string
	conv   uint32
	pushes []struct{ sn, ts, n uint32 }
}{
	{"in_order", 0x11223344, []struct{ sn, ts, n uint32 }{{0, 12345, 100}}},
	{"ts_wrap", 0xFFFFFFFF, []struct{ sn, ts, n uint32 }{{0, 0xFFFFFFF0, 1}}},
	{"out_of_order", 42, []struct{ sn, ts, n uint32 }{{3, 777, 16}}},
	{"two_in_order", 0x0BADF00D, []struct{ sn, ts, n uint32 }{{0, 100, 10}, {1, 101, 20}}},
	{"reordered_pair", 5, []struct{ sn, ts, n uint32 }{{1, 200, 8}, {0, 199, 8}}},
}

// genRealAcks feeds PUSH packets encoded with the copied codec into a real kcp-go KCP
// (Input with ackNoDelay, so it flushes the ACKs at once) and records its output. The
// output is decoded with the copied helpers and re-encoded, which must reproduce it.
func genRealAcks() ([]any, error) {
	var cases []any
	r := newRNG("kcp", streamRealAck)
	for _, set := range realAckSets {
		var pkt []byte
		var push []segParams
		for _, p := range set.pushes {
			data := randBytes(r, int(p.n))
			s := kcpcopy.Segment{Conv: set.conv, Cmd: kcp.IKCP_CMD_PUSH, Wnd: kcp.IKCP_WND_RCV, Ts: p.ts, Sn: p.sn, Data: data}
			pkt = append(pkt, kcpcopy.Encode(s)...)
			pkt = append(pkt, data...)
			push = append(push, segParams{Conv: s.Conv, Cmd: s.Cmd, Wnd: s.Wnd, Ts: s.Ts, Sn: s.Sn, Len: p.n})
		}

		var out []byte
		var sizes []int
		k := kcp.NewKCP(set.conv, func(buf []byte, size int) {
			out = append(out, buf[:size]...)
			sizes = append(sizes, size)
		})
		ret := k.Input(append([]byte{}, pkt...), kcp.IKCP_PACKET_REGULAR, true)
		if ret != 0 {
			return nil, fmt.Errorf("real_ack/%s: Input returned %d", set.label, ret)
		}

		var acks []segParams
		var re []byte
		for rest := out; len(rest) > 0; {
			h, next, ok := kcpcopy.DecodeHeader(rest)
			if !ok || h.Len != 0 || h.Cmd != kcp.IKCP_CMD_ACK {
				return nil, fmt.Errorf("real_ack/%s: unexpected output %x", set.label, out)
			}
			acks = append(acks, headerParams(h))
			re = append(re, kcpcopy.Encode(kcpcopy.Segment{Conv: h.Conv, Cmd: h.Cmd, Frg: h.Frg, Wnd: h.Wnd, Ts: h.Ts, Sn: h.Sn, Una: h.Una})...)
			rest = next
		}
		if len(acks) == 0 || !bytes.Equal(re, out) {
			return nil, fmt.Errorf("real_ack/%s: copied codec does not reproduce the library output %x", set.label, out)
		}
		cases = append(cases, Case{
			Name:   "real_ack/" + set.label,
			Params: realAckParams{Conv: set.conv, Push: push, Acks: acks, Outputs: sizes, InputRet: ret},
			In:     hx(pkt),
			Out:    hx(out),
		})
	}
	return cases, nil
}

// itimediffFixed are the fixed (later, earlier) pairs of the itimediff group.
var itimediffFixed = [][2]uint32{
	{0, 0}, {1, 0}, {0, 1}, {5, 0xFFFFFFFB}, {0xFFFFFFFB, 5}, {0x7FFFFFFF, 0}, {0x80000000, 0},
	{0, 0x80000000}, {0xFFFFFFFF, 0}, {0, 0xFFFFFFFF}, {100, 200}, {200, 100},
}

// iboundFixed are the (lower, middle, upper) triples of the ibound group, including
// lower > upper (the result is then upper, as _imin_ is applied last).
var iboundFixed = [][3]uint32{
	{10, 5, 5000}, {10, 20, 5000}, {10, 6000, 5000}, {0, 0, 0}, {0, 0xFFFFFFFF, 0xFFFFFFFF},
	{100, 50, 30}, {100, 200, 30}, {30, 0, 60000}, {30, 60001, 60000},
}

const itimediffRandomCount = 16

func genTimeMath() []any {
	var cases []any
	addDiff := func(name string, later, earlier uint32) {
		cases = append(cases, Case{Name: name, Params: itimediffParams{later, earlier, kcpcopy.Itimediff(later, earlier)}})
	}
	for i, p := range itimediffFixed {
		addDiff(fmt.Sprintf("itimediff/%d", i), p[0], p[1])
	}
	r := newRNG("kcp", streamItimediff)
	for i := range itimediffRandomCount {
		addDiff(fmt.Sprintf("itimediff/random/%d", i), r.Uint32(), r.Uint32())
	}
	for i, p := range iboundFixed {
		cases = append(cases, Case{
			Name:   fmt.Sprintf("ibound/%d", i),
			Params: iboundParams{p[0], p[1], p[2], kcpcopy.Ibound(p[0], p[1], p[2])},
		})
	}
	return cases
}

// genSnmp records the Snmp formatting for a zero struct, distinct values (field i = i+1)
// and large values (field i = MaxUint64 - i).
func genSnmp() ([]any, error) {
	typ := reflect.TypeOf(kcp.Snmp{})
	fields := make([]string, typ.NumField())
	for i := range fields {
		if typ.Field(i).Type.Kind() != reflect.Uint64 {
			return nil, fmt.Errorf("snmp: field %s is not uint64", typ.Field(i).Name)
		}
		fields[i] = typ.Field(i).Name
	}
	var cases []any
	for _, g := range []struct {
		name  string
		value func(i int) uint64
	}{
		{"snmp/zero", func(int) uint64 { return 0 }},
		{"snmp/distinct", func(i int) uint64 { return uint64(i + 1) }},
		{"snmp/large", func(i int) uint64 { return ^uint64(0) - uint64(i) }},
	} {
		s := new(kcp.Snmp)
		v := reflect.ValueOf(s).Elem()
		values := make([]uint64, len(fields))
		for i := range fields {
			values[i] = g.value(i)
			v.Field(i).SetUint(values[i])
		}
		c := snmpCase{
			Name: g.name, Fields: fields, Values: values,
			Header: s.Header(), ToSlice: s.ToSlice(), Format: fmt.Sprintf("%+v", s.Copy()),
		}
		if len(c.Header) != len(fields) || len(c.ToSlice) != len(fields) {
			return nil, fmt.Errorf("%s: Header/ToSlice have %d/%d entries for %d fields", g.name, len(c.Header), len(c.ToSlice), len(fields))
		}
		// Every ToSlice entry is one of the values (ToSlice reorders some FEC fields).
		seen := map[string]bool{}
		for _, x := range values {
			seen[strconv.FormatUint(x, 10)] = true
		}
		for _, x := range c.ToSlice {
			if !seen[x] {
				return nil, fmt.Errorf("%s: ToSlice entry %s is not a field value", g.name, x)
			}
		}
		s.Reset()
		if *s.Copy() != (kcp.Snmp{}) {
			return nil, fmt.Errorf("%s: Reset left non-zero fields", g.name)
		}
		cases = append(cases, c)
	}
	return cases, nil
}
