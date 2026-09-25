package main

// Area "snappy" (plan step 07.1): the exact framed bytes kcptun's CompStream puts on the KCP
// stream for a scripted sequence of writes, and what golang/snappy's Reader makes of a set of
// hand-made streams, including the malformed ones.
//
// CompStream (kcptun/std/comp.go) is three lines:
//
//	func (c *CompStream) Write(p []byte) (n int, err error) {
//		if _, err := c.w.Write(p); err != nil { ... }
//		if err := c.w.Flush(); err != nil { ... }
//		return len(p), err
//	}
//
// with c.w = snappy.NewBufferedWriter(conn). The generator cannot import kcptun (it refuses
// `replace` directives, see README), so snappyFrame below repeats those two calls per write
// against the pinned golang/snappy v1.0.0: the same thing tools/gointerop/internal/std does
// with a verbatim copy. Nothing else about the framing is reimplemented: the bytes come from
// the library.
//
// Case groups are documented in README.md.

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"io"

	"github.com/golang/snappy"
)

// Byte strings longer than this are stored as a Blob instead of hex (see README, area rs).
const snappyMaxInlineBytes = 4096

// snappyText is cycled to fill a compressible payload. The Rust test builds the same bytes,
// and the recorded `in`/`in_blob` proves it did.
const snappyText = "the quick brown fox jumps over the lazy dog. "

// snappyPayloadStream is the newRNG stream of a "random" payload of n bytes: one stream per
// length, so adding a case never changes the bytes of another.
func snappyPayloadStream(n int) uint64 { return 1<<16 + uint64(n) }

// snappyCrcTable is the Castagnoli table snappy checksums with (snappy.go:crcTable).
var snappyCrcTable = crc32.MakeTable(crc32.Castagnoli)

// snappyCRC is the masked CRC-32C of section 3 of the framing format. snappy's own crc() is
// unexported; that this copy is right is proved by the reader accepting the chunks built with
// it (the read/* cases) and rejecting the ones whose checksum is flipped.
//
// Go: golang/snappy@v1.0.0 snappy.go:crc()
func snappyCRC(b []byte) uint32 {
	c := crc32.Update(0, snappyCrcTable, b)
	return uint32(c>>15|c<<17) + 0xa282ead8
}

// snappyInput builds a payload of n bytes of the given kind.
func snappyInput(kind string, n int, stream uint64) ([]byte, error) {
	switch kind {
	case "text":
		b := make([]byte, n)
		for i := range b {
			b[i] = snappyText[i%len(snappyText)]
		}
		return b, nil
	case "random":
		return randBytes(newRNG("snappy", stream), n), nil
	case "zeros":
		return make([]byte, n), nil
	default:
		return nil, fmt.Errorf("unknown payload kind %q", kind)
	}
}

// snappyFrame is what a CompStream writes to its connection for these writes, in order.
//
// Go: kcptun/std/comp.go:CompStream.Write() over golang/snappy@v1.0.0 encode.go:Writer
func snappyFrame(writes [][]byte) ([]byte, error) {
	var buf bytes.Buffer
	w := snappy.NewBufferedWriter(&buf)
	for _, p := range writes {
		if _, err := w.Write(p); err != nil {
			return nil, err
		}
		if err := w.Flush(); err != nil {
			return nil, err
		}
	}
	// No Close: CompStream.Close closes the connection, and the framing format has no
	// end-of-stream marker, so a closed writer would add nothing.
	return buf.Bytes(), nil
}

// snappyWriteCase is one scripted sequence of CompStream.Write calls and the bytes it produces.
type snappyWriteCase struct {
	Name string `json:"name"`
	// Kind is how the payload is built: "text", "random" or "zeros".
	Kind string `json:"kind"`
	// Stream is the newRNG("snappy", stream) that produced a "random" payload.
	Stream uint64 `json:"stream,omitempty"`
	// Writes is the length of each Write call, in order; their sum is Len.
	Writes []int `json:"writes"`
	Len    int   `json:"len"`
	// In is the whole payload as hex, or InBlob when it is longer than snappyMaxInlineBytes.
	In     string `json:"in,omitempty"`
	InBlob *Blob  `json:"in_blob,omitempty"`
	// Out is the framed output as hex, or OutBlob when it is longer.
	Out     string `json:"out,omitempty"`
	OutBlob *Blob  `json:"out_blob,omitempty"`
}

// CaseName implements namedCase.
func (c snappyWriteCase) CaseName() string { return c.Name }

// snappyReadCase is one framed stream handed to snappy.NewReader: the bytes it decodes before
// it stops, and the error it stops with ("" for a clean end of stream).
type snappyReadCase struct {
	Name string `json:"name"`
	In   string `json:"in,omitempty"`
	Out  string `json:"out,omitempty"`
	Err  string `json:"err"`
}

// CaseName implements namedCase.
func (c snappyReadCase) CaseName() string { return c.Name }

// snappyWrite builds one write case: a payload of the given kind, split into writes of the
// given sizes.
func snappyWrite(name, kind string, sizes []int) (snappyWriteCase, error) {
	total := 0
	for _, s := range sizes {
		total += s
	}
	stream := uint64(0)
	if kind == "random" {
		stream = snappyPayloadStream(total)
	}
	in, err := snappyInput(kind, total, stream)
	if err != nil {
		return snappyWriteCase{}, err
	}

	writes := make([][]byte, 0, len(sizes))
	off := 0
	for _, s := range sizes {
		writes = append(writes, in[off:off+s])
		off += s
	}
	out, err := snappyFrame(writes)
	if err != nil {
		return snappyWriteCase{}, fmt.Errorf("case %s: %w", name, err)
	}

	// Every case must also read back, so no vector can describe a stream snappy cannot parse.
	back, err := io.ReadAll(snappy.NewReader(bytes.NewReader(out)))
	if err != nil {
		return snappyWriteCase{}, fmt.Errorf("case %s: decode: %w", name, err)
	}
	if !bytes.Equal(back, in) {
		return snappyWriteCase{}, fmt.Errorf("case %s: round trip differs", name)
	}

	c := snappyWriteCase{Name: name, Kind: kind, Stream: stream, Writes: sizes, Len: total}
	if len(in) > snappyMaxInlineBytes {
		b := newBlob(in)
		c.InBlob = &b
	} else {
		c.In = hx(in)
	}
	if len(out) > snappyMaxInlineBytes {
		b := newBlob(out)
		c.OutBlob = &b
	} else {
		c.Out = hx(out)
	}
	return c, nil
}

// snappyRead builds one read case by running the pinned reader over in, exactly as
// CompStream.Read does (io.Copy is what tools/gointerop/cmd/snappycheck uses too).
func snappyRead(name string, in []byte) snappyReadCase {
	var out bytes.Buffer
	_, err := io.Copy(&out, snappy.NewReader(bytes.NewReader(in)))
	c := snappyReadCase{Name: name, In: hx(in), Out: hx(out.Bytes())}
	if err != nil {
		c.Err = err.Error()
	}
	return c
}

// snappyChunk is a framed chunk: type byte, 24-bit little-endian length, body.
func snappyChunk(chunkType byte, body []byte) []byte {
	n := len(body)
	out := []byte{chunkType, byte(n), byte(n >> 8), byte(n >> 16)}
	return append(out, body...)
}

// snappyHeader is a chunk header that announces a length the stream does not contain.
func snappyHeader(chunkType byte, chunkLen int) []byte {
	return []byte{chunkType, byte(chunkLen), byte(chunkLen >> 8), byte(chunkLen >> 16)}
}

// snappyDataChunk is a data chunk of the given type: masked CRC-32C of data, then body.
func snappyDataChunk(chunkType byte, checksummed, body []byte) []byte {
	sum := snappyCRC(checksummed)
	payload := []byte{byte(sum), byte(sum >> 8), byte(sum >> 16), byte(sum >> 24)}
	return snappyChunk(chunkType, append(payload, body...))
}

// snappyIdentifier is the stream identifier chunk (snappy.go:magicChunk).
func snappyIdentifier() []byte { return []byte("\xff\x06\x00\x00sNaPpY") }

// snappyPadVarint rewrites the block's leading length varint as a padded, non-canonical
// encoding of n bytes (the same value, with continuation bits set on the extra bytes). Go's
// binary.Uvarint reads up to binary.MaxVarintLen64 (10) bytes, so the block stays valid.
//
// Go: go1.27.1 src/encoding/binary/varint.go:Uvarint()
func snappyPadVarint(block []byte, n int) []byte {
	v, used := binary.Uvarint(block)
	if used <= 0 || n < used || n > binary.MaxVarintLen64 {
		panic("snappyPadVarint: bad input")
	}
	out := make([]byte, 0, len(block)-used+n)
	for i := 0; i < n-1; i++ {
		out = append(out, byte(v&0x7f)|0x80)
		v >>= 7
	}
	out = append(out, byte(v))
	return append(out, block[used:]...)
}

// snappyJoin concatenates chunks into one stream.
func snappyJoin(parts ...[]byte) []byte {
	var out []byte
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// genSnappy produces the area's cases in file order.
func genSnappy() ([]any, error) {
	var cases []any

	// write/*: what CompStream puts on the wire. 8200 bytes is one smux frame (8192 payload
	// plus the 8-byte header) and 70000 spans two 64 KiB chunks.
	writeCases := []struct {
		name  string
		kind  string
		sizes []int
	}{
		{"write/empty", "text", []int{0}},
		{"write/text/len=1", "text", []int{1}},
		{"write/text/len=45", "text", []int{45}},
		{"write/text/len=8200", "text", []int{8200}},
		{"write/text/len=70000", "text", []int{70000}},
		{"write/random/len=1", "random", []int{1}},
		{"write/random/len=8200", "random", []int{8200}},
		{"write/random/len=65536", "random", []int{65536}},
		{"write/random/len=65537", "random", []int{65537}},
		{"write/random/len=70000", "random", []int{70000}},
		{"write/zeros/len=65536", "zeros", []int{65536}},
		{"write/sequence/text", "text", []int{1, 7, 4096, 8200, 65536, 3}},
		{"write/sequence/random", "random", []int{8200, 8200, 1, 65537}},
		{"write/sequence/empty_between", "text", []int{8, 0, 8}},
	}
	for _, w := range writeCases {
		c, err := snappyWrite(w.name, w.kind, w.sizes)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}

	id := snappyIdentifier()
	payload := []byte("payload")
	good := snappyDataChunk(0x01, payload, payload)
	// A real compressed chunk, from the library, to damage below.
	compressible, err := snappyInput("text", 4096, 0)
	if err != nil {
		return nil, err
	}
	compressed, err := snappyFrame([][]byte{compressible})
	if err != nil {
		return nil, err
	}

	// read/*: streams the reader must accept.
	reads := []struct {
		name string
		in   []byte
	}{
		{"read/empty", nil},
		{"read/identifier_only", id},
		{"read/uncompressed", snappyJoin(id, good)},
		{"read/uncompressed_empty_body", snappyJoin(id, snappyDataChunk(0x01, nil, nil), good)},
		{"read/compressed_empty_body",
			snappyJoin(id, snappyDataChunk(0x00, nil, snappy.Encode(nil, nil)), good)},
		{"read/skippable_0x80", snappyJoin(id, snappyChunk(0x80, []byte("skip me")), good)},
		{"read/skippable_0xfd", snappyJoin(id, snappyChunk(0xfd, nil), good)},
		{"read/padding_0xfe", snappyJoin(id, snappyChunk(0xfe, make([]byte, 100)), good)},
		{"read/repeated_identifier", snappyJoin(id, good, id, good)},
		// A block whose length header is a padded (non-canonical) varint. binary.Uvarint
		// accepts up to ten bytes, so Go decodes these; a decoder that insists on the
		// shortest encoding (as some do) would reject them.
		{"read/block_varint_padded_5",
			snappyJoin(id, snappyDataChunk(0x00, payload, snappyPadVarint(
				snappy.Encode(nil, payload), 5)))},
		{"read/block_varint_padded_6",
			snappyJoin(id, snappyDataChunk(0x00, payload, snappyPadVarint(
				snappy.Encode(nil, payload), 6)))},
	}
	for _, r := range reads {
		cases = append(cases, snappyRead(r.name, r.in))
	}

	// error/*: streams the reader must reject, with the error it reports.
	badChecksum := snappyDataChunk(0x01, []byte("other"), payload)
	damaged := append([]byte(nil), compressed...)
	damaged[len(damaged)-1] ^= 0xff
	errors := []struct {
		name string
		in   []byte
	}{
		// The stream identifier must come first, whatever the chunk that comes instead is.
		{"error/no_identifier", good},
		{"error/skippable_before_identifier", snappyChunk(0x80, []byte("pad"))},
		{"error/truncated_identifier", id[:3]},
		{"error/identifier_wrong_length", snappyChunk(0xff, []byte("sNaPp"))},
		{"error/identifier_wrong_body", snappyChunk(0xff, []byte("snappy"))},
		// Reserved unskippable chunk types (0x02-0x7f).
		{"error/reserved_type_0x02", snappyJoin(id, snappyChunk(0x02, nil))},
		{"error/reserved_type_0x7f", snappyJoin(id, snappyChunk(0x7f, []byte("body")))},
		// A chunk longer than the reader's buffer (maxEncodedLenOfMaxBlockSize + 4).
		{"error/chunk_too_long", snappyJoin(id, snappyHeader(0x00, 76495))},
		{"error/skippable_too_long", snappyJoin(id, snappyHeader(0x80, 76495))},
		// Data chunks too short to hold a checksum.
		{"error/compressed_chunk_too_short", snappyJoin(id, snappyChunk(0x00, []byte("abc")))},
		{"error/uncompressed_chunk_too_short", snappyJoin(id, snappyChunk(0x01, []byte("abc")))},
		// More uncompressed data than a block may decode to.
		{"error/uncompressed_over_max_block", snappyJoin(id, snappyHeader(0x01, 65536+4+1),
			[]byte{0, 0, 0, 0})},
		// Damaged bodies.
		{"error/bad_checksum_uncompressed", snappyJoin(id, badChecksum)},
		{"error/bad_checksum_compressed", damaged},
		{"error/truncated_chunk_header", snappyJoin(id, []byte{0x01, 0x05})},
		{"error/truncated_body", snappyJoin(id, snappyHeader(0x01, 14), []byte("abc"))},
		// Blocks the decoder cannot parse.
		{"error/block_bad_varint", snappyJoin(id, snappyDataChunk(0x00, nil,
			[]byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff}))},
		{"error/block_length_over_max", snappyJoin(id, snappyDataChunk(0x00, nil,
			[]byte{0x81, 0x80, 0x04, 0x00}))},
		{"error/block_literal_too_long", snappyJoin(id, snappyDataChunk(0x00, nil,
			[]byte{0x0a, 0x24, 'a', 'b'}))},
		{"error/block_short_output", snappyJoin(id, snappyDataChunk(0x00, nil,
			[]byte{0x0a, 0x04, 'a', 'b'}))},
		// A valid stream followed by a damaged chunk: the bytes before it are delivered.
		{"error/after_good_chunk", snappyJoin(id, good, snappyChunk(0x02, nil))},
	}
	for _, e := range errors {
		c := snappyRead(e.name, e.in)
		if c.Err == "" {
			return nil, fmt.Errorf("case %s: expected an error, got none", e.name)
		}
		cases = append(cases, c)
	}

	return cases, nil
}
