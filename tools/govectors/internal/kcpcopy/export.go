// Package kcp (directory internal/kcpcopy) is a verbatim copy of the KCP core of kcp-go
// v5.6.66 (kcp.go, ringbuffer.go, bufferpool.go, snmp.go, kcp_trace_off.go, autotune.go,
// fec.go; see the header of each file) plus this file, which is NOT copied: it holds the few declarations the copied
// files need from other kcp-go files, the injectable clock, and exported wrappers the vector
// generator uses. kcp-go does not export its segment codec, flush() or the KCP fields, so the
// generator drives this copy instead of the library (the real_ack group of the kcp area checks
// the copy against the library itself).
//
// The package keeps kcp-go's name (kcp) so the copied files are byte-identical; import it as
// kcpcopy.
//
// Original copyright: The MIT License (MIT), Copyright (c) 2015 xtaci.
package kcp

import (
	"encoding/binary"
	"hash/fnv"
	"time"
)

// Go: kcp-go/v5@v5.6.66 sess.go:mtuLimit (used by the copied bufferpool.go).
const mtuLimit = 1500

// Clock is the time source of the copied kcp.go: its currentMs() returns Clock() (the only
// change to the copied files). The default is the original expression, milliseconds since
// refTime truncated to uint32. The vector generator replaces it with a virtual clock.
var Clock = func() uint32 { return uint32(time.Since(refTime) / time.Millisecond) }

// Segment is the exported view of segment for the vector generator: the header fields that
// encode writes, plus the payload (whose length encode writes as the len field).
type Segment struct {
	Conv uint32
	Cmd  uint8
	Frg  uint8
	Wnd  uint16
	Ts   uint32
	Sn   uint32
	Una  uint32
	Data []byte
}

// Encode returns the 24-byte header that segment.encode writes for s. Like the original it
// increments DefaultSnmp.OutSegs (the copy's own counter).
func Encode(s Segment) []byte {
	seg := segment{conv: s.Conv, cmd: s.Cmd, frg: s.Frg, wnd: s.Wnd, ts: s.Ts, sn: s.Sn, una: s.Una, data: s.Data}
	buf := make([]byte, IKCP_OVERHEAD)
	if rest := seg.encode(buf); len(rest) != 0 {
		panic("kcpcopy: encode did not write exactly IKCP_OVERHEAD bytes")
	}
	return buf
}

// Header is a decoded 24-byte segment header, read field by field in the order of
// KCP.Input with the copied ikcp_decode* helpers.
type Header struct {
	Conv uint32
	Cmd  uint8
	Frg  uint8
	Wnd  uint16
	Ts   uint32
	Sn   uint32
	Una  uint32
	Len  uint32
}

// DecodeHeader decodes the header at the start of p and returns the bytes after it. ok is
// false when p is shorter than IKCP_OVERHEAD.
func DecodeHeader(p []byte) (h Header, rest []byte, ok bool) {
	if len(p) < IKCP_OVERHEAD {
		return h, p, false
	}
	p = ikcp_decode32u(p, &h.Conv)
	p = ikcp_decode8u(p, &h.Cmd)
	p = ikcp_decode8u(p, &h.Frg)
	p = ikcp_decode16u(p, &h.Wnd)
	p = ikcp_decode32u(p, &h.Ts)
	p = ikcp_decode32u(p, &h.Sn)
	p = ikcp_decode32u(p, &h.Una)
	p = ikcp_decode32u(p, &h.Len)
	return h, p, true
}

// Itimediff exports _itimediff.
func Itimediff(later, earlier uint32) int32 { return _itimediff(later, earlier) }

// Ibound exports _ibound_.
func Ibound(lower, middle, upper uint32) uint32 { return _ibound_(lower, middle, upper) }

// Flush calls the unexported flush(flushType), as sess.go does from its update timer and
// after Write.
func (kcp *KCP) Flush(flushType FlushType) uint32 { return kcp.flush(flushType) }

// SetStream sets the stream field, as UDPSession.SetStreamMode does.
func (kcp *KCP) SetStream(stream int32) { kcp.stream = stream }

// ConnState returns the state field (0xFFFFFFFF once dead_link was reached).
func (kcp *KCP) ConnState() uint32 { return kcp.state }

// StateWordNames names the entries of StateWords, in order.
var StateWordNames = []string{
	"mtu", "mss", "state", "snd_una", "snd_nxt", "rcv_nxt", "ssthresh", "rx_rttvar", "rx_srtt",
	"rx_rto", "rx_minrto", "snd_wnd", "rcv_wnd", "rmt_wnd", "cwnd", "probe", "interval",
	"ts_flush", "nodelay", "updated", "ts_probe", "probe_wait", "dead_link", "incr",
	"fastresend", "nocwnd", "stream", "snd_queue_len", "rcv_queue_len", "snd_buf_len",
	"rcv_buf_len", "acklist_len",
}

// StateWords returns the scalar KCP state (fields in struct order, signed fields as their
// two's complement bits, then the lengths of the queues, buffers and ACK list).
func (kcp *KCP) StateWords() []uint32 {
	return []uint32{
		kcp.mtu, kcp.mss, kcp.state, kcp.snd_una, kcp.snd_nxt, kcp.rcv_nxt, kcp.ssthresh,
		uint32(kcp.rx_rttvar), uint32(kcp.rx_srtt), kcp.rx_rto, kcp.rx_minrto, kcp.snd_wnd,
		kcp.rcv_wnd, kcp.rmt_wnd, kcp.cwnd, kcp.probe, kcp.interval, kcp.ts_flush, kcp.nodelay,
		kcp.updated, kcp.ts_probe, kcp.probe_wait, kcp.dead_link, kcp.incr,
		uint32(kcp.fastresend), uint32(kcp.nocwnd), uint32(kcp.stream),
		uint32(kcp.snd_queue.Len()), uint32(kcp.rcv_queue.Len()), uint32(kcp.snd_buf.Len()),
		uint32(kcp.rcv_buf.Len()), uint32(len(kcp.acklist)),
	}
}

// StateDigest is the FNV-1a 64 hash of the little-endian bytes of these uint32 words:
// StateWords(); then per snd_queue segment (front to back) frg, len(data); per snd_buf
// segment sn, frg, ts, wnd, una, rto, xmit, resendts, fastack, acked, len(data); per
// rcv_queue segment sn, frg, len(data); per rcv_buf segment in heap array order sn, frg,
// len(data); per acklist entry sn, ts. The Rust trace replay computes the same digest.
func (kcp *KCP) StateDigest() uint64 {
	words := kcp.StateWords()
	for seg := range kcp.snd_queue.ForEach {
		words = append(words, uint32(seg.frg), uint32(len(seg.data)))
	}
	for seg := range kcp.snd_buf.ForEach {
		words = append(words, seg.sn, uint32(seg.frg), seg.ts, uint32(seg.wnd), seg.una, seg.rto,
			seg.xmit, seg.resendts, seg.fastack, seg.acked, uint32(len(seg.data)))
	}
	for seg := range kcp.rcv_queue.ForEach {
		words = append(words, seg.sn, uint32(seg.frg), uint32(len(seg.data)))
	}
	for _, seg := range kcp.rcv_buf.segments {
		words = append(words, seg.sn, uint32(seg.frg), uint32(len(seg.data)))
	}
	for _, ack := range kcp.acklist {
		words = append(words, ack.sn, ack.ts)
	}
	h := fnv.New64a()
	var b [4]byte
	for _, w := range words {
		binary.LittleEndian.PutUint32(b[:], w)
		h.Write(b[:])
	}
	return h.Sum64()
}

// AutoTune is the exported name of the copied autoTune (autotune.go). Its Sample and FindPeriod
// methods are exported already; the zero value is ready to use, as in kcp-go.
type AutoTune = autoTune

// Pop discards the oldest sample, exactly as kcp-go's TestAutoTunePop simulates a pop (advance
// head, decrement count). The caller must ensure Count() > 0.
func (tune *autoTune) Pop() {
	tune.head = (tune.head + 1) % maxAutoTuneSamples
	tune.count--
}

// Count is the number of samples in the ring.
func (tune *autoTune) Count() int { return tune.count }

// Sorted returns a copy of sortCache[:count]: after FindPeriod with Count() >= 3, the samples in
// the order sort.Slice left them (FindPeriod returns before sorting when Count() < 3).
func (tune *autoTune) Sorted() (seqs []uint32, bits []bool) {
	for _, p := range tune.sortCache[:tune.count] {
		seqs = append(seqs, p.seq)
		bits = append(bits, p.bit)
	}
	return seqs, bits
}

// FecClock is the time source of the copied fec.go: fecEncoder.encode reads
// now := FecClock(time.Now) (the only change to that file). The default is the original
// expression, time.Now().UnixMilli(). The vector generator replaces it with scripted times.
var FecClock = func(now func() time.Time) int64 { return now().UnixMilli() }

// FecEncoder is the exported name of the copied fecEncoder (fec.go).
type FecEncoder = fecEncoder

// NewFECEncoder calls newFECEncoder (nil unless dataShards > 0 && parityShards > 0).
func NewFECEncoder(dataShards, parityShards, offset int) *FecEncoder {
	return newFECEncoder(dataShards, parityShards, offset)
}

// Encode calls encode(b, rto). The returned parity shards alias the encoder's shard cache and
// are overwritten by the next call.
func (enc *fecEncoder) Encode(b []byte, rto uint32) [][]byte { return enc.encode(b, rto) }

// EncodeOOB calls encodeOOB(b).
func (enc *fecEncoder) EncodeOOB(b []byte) { enc.encodeOOB(b) }

// Next is the next seqid the encoder assigns.
func (enc *fecEncoder) Next() uint32 { return enc.next }

// SetNext sets the next seqid, as kcp-go's TestFECPAWS does (encoder.next = ...).
func (enc *fecEncoder) SetNext(next uint32) { enc.next = next }

// Paws is the encoder's paws (seqids run modulo it).
func (enc *fecEncoder) Paws() uint32 { return enc.paws }

// FecDecoder is the exported name of the copied fecDecoder (fec.go).
type FecDecoder = fecDecoder

// NewFECDecoder calls newFECDecoder (nil for invalid shard counts).
func NewFECDecoder(dataShards, parityShards int) *FecDecoder {
	return newFECDecoder(dataShards, parityShards)
}

// Decode calls decode(in). The recovered shards are pool buffers owned by the caller.
func (dec *fecDecoder) Decode(in []byte) [][]byte { return dec.decode(fecPacket(in)) }

// Shards returns the decoder's current (dataShards, parityShards), which auto-tuning changes.
func (dec *fecDecoder) Shards() (int, int) { return dec.dataShards, dec.parityShards }

// ShardSets is the number of shard sets (groups) the decoder currently holds.
func (dec *fecDecoder) ShardSets() int { return len(dec.shardSet) }
