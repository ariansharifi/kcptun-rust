// Package peer holds helpers shared by the interop peers: the deterministic test stream,
// its verifier, chunk-size lists, JSON reporting and the pinned-version check.
package peer

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"io"
	"math/rand/v2"
)

// Stream is the deterministic test byte stream shared with the Rust testkit
// (crates/testkit/src/servers.rs PrngStream): Go math/rand/v2 rand.NewPCG(seed, 0), eight
// little-endian bytes per Uint64, truncated to the length. The bytes do not depend on how
// the stream is split into Read calls.
type Stream struct {
	pcg       *rand.PCG
	remaining int64
	word      [8]byte
	pos       int
}

// NewStream returns the stream of n bytes for seed.
func NewStream(seed uint64, n int64) *Stream {
	return &Stream{pcg: rand.NewPCG(seed, 0), remaining: n, pos: 8}
}

// Remaining reports how many bytes are left.
func (s *Stream) Remaining() int64 { return s.remaining }

// Read fills p with the next bytes of the stream; io.EOF at the end.
func (s *Stream) Read(p []byte) (int, error) {
	if s.remaining <= 0 {
		return 0, io.EOF
	}
	n := len(p)
	if int64(n) > s.remaining {
		n = int(s.remaining)
	}
	for i := 0; i < n; i++ {
		if s.pos == 8 {
			binary.LittleEndian.PutUint64(s.word[:], s.pcg.Uint64())
			s.pos = 0
		}
		p[i] = s.word[s.pos]
		s.pos++
	}
	s.remaining -= int64(n)
	return n, nil
}

// StreamSHA256 returns the lower-case hex SHA-256 of the (seed, n) stream.
func StreamSHA256(seed uint64, n int64) string {
	h := sha256.New()
	if _, err := io.CopyBuffer(h, NewStream(seed, n), make([]byte, 64*1024)); err != nil {
		panic(err) // Stream.Read and hash.Write never fail
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Verifier checks received bytes against the expected (seed, n) stream as they arrive and
// hashes them. It records the first mismatching offset.
type Verifier struct {
	want     *Stream
	scratch  []byte
	hash     hash.Hash
	received int64
	expected int64
	mismatch int64 // -1 while everything matched
}

// NewVerifier expects the (seed, n) stream.
func NewVerifier(seed uint64, n int64) *Verifier {
	return &Verifier{want: NewStream(seed, n), hash: sha256.New(), expected: n, mismatch: -1}
}

// Write consumes received bytes. It fails on the first byte that differs from the expected
// stream, or when more than n bytes arrive.
func (v *Verifier) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if v.received+int64(len(p)) > v.expected {
		v.hash.Write(p)
		if v.mismatch < 0 {
			v.mismatch = v.expected
		}
		v.received += int64(len(p))
		return 0, fmt.Errorf("received %d bytes, more than the %d expected", v.received, v.expected)
	}
	if cap(v.scratch) < len(p) {
		v.scratch = make([]byte, len(p))
	}
	want := v.scratch[:len(p)]
	if _, err := io.ReadFull(v.want, want); err != nil {
		return 0, err
	}
	v.hash.Write(p)
	for i := range p {
		if p[i] != want[i] {
			off := v.received + int64(i)
			v.received += int64(len(p))
			if v.mismatch < 0 {
				v.mismatch = off
			}
			return 0, fmt.Errorf("data mismatch at offset %d: got 0x%02x, want 0x%02x", off, p[i], want[i])
		}
	}
	v.received += int64(len(p))
	return len(p), nil
}

// Received is the number of bytes consumed so far.
func (v *Verifier) Received() int64 { return v.received }

// Done reports whether exactly n matching bytes were received.
func (v *Verifier) Done() bool { return v.mismatch < 0 && v.received == v.expected }

// Mismatch is the first offset that differed, or -1.
func (v *Verifier) Mismatch() int64 { return v.mismatch }

// SHA256 is the lower-case hex SHA-256 of all bytes received so far.
func (v *Verifier) SHA256() string { return hex.EncodeToString(v.hash.Sum(nil)) }
