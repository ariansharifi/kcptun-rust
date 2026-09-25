package main

// Area "qpp" (plan step 07.2): the Quantum Permutation Pad of xtaci/qpp v1.1.25, the sizes it
// derives from the number of qubits, the seed chunks and permutation matrices a seed produces,
// the state of a freshly created PRNG, and the ciphertext of a 1 MiB stream encrypted in
// several chunkings.
//
// seedToChunks, the pad tables and the PRNG state are unexported, so the cases are produced by
// internal/qppcopy, a verbatim copy of qpp.go and prng.go with an export file beside it.
// internal/qppcopy/copy_test.go checks that copy against the pinned source and its behaviour
// against the linked github.com/xtaci/qpp, so nothing here can drift from the real library.
//
// Case groups are documented in README.md.

import (
	"bytes"
	"fmt"

	qpp "github.com/kcptun-rust/tools/govectors/internal/qppcopy"
)

// Number of quantum bits of the implementation; everything kcptun does uses 8.
const qppQubits = 8

// Length of the stream cases' plaintext.
const qppStreamLen = 1 << 20

// RNG streams of the qpp area (see newRNG), one per independent group of bytes.
const (
	qppSeedStream   = 1 // the generated seeds
	qppStreamStream = 2 // the 1 MiB plaintext
	qppChunkStream  = 3 // the random chunking of stream/random
)

// qppSizeCase is one (qubits -> minimum sizes) pair.
type qppSizeCase struct {
	Name        string `json:"name"`
	Qubits      int    `json:"qubits"`
	SeedLen     int    `json:"seed_len"`
	MinimumPads int    `json:"minimum_pads"`
}

// CaseName implements namedCase.
func (c qppSizeCase) CaseName() string { return c.Name }

// qppChunksCase is the seedToChunks output for one seed.
type qppChunksCase struct {
	Name string `json:"name"`
	// Seed is the seed as hex; SeedStream is set instead when it was generated.
	Seed       string `json:"seed"`
	SeedStream uint64 `json:"seed_stream,omitempty"`
	SeedLen    int    `json:"seed_len"`
	// Expanded is true when the seed is shorter than 32 bytes and was PBKDF2-expanded first.
	Expanded bool `json:"expanded"`
	// Chunks is the chunk count, Out the chunks concatenated, as hex.
	Chunks int    `json:"chunks"`
	Out    string `json:"out"`
}

// CaseName implements namedCase.
func (c qppChunksCase) CaseName() string { return c.Name }

// qppPadsCase is the pad tables one seed and pad count produce.
type qppPadsCase struct {
	Name    string `json:"name"`
	Seed    string `json:"seed"`
	NumPads int    `json:"num_pads"`
	// Pad0 is the first pad in full, so a failure can be read without the generator.
	Pad0  string `json:"pad0"`
	Pads  Blob   `json:"pads"`
	RPads Blob   `json:"rpads"`
}

// CaseName implements namedCase.
func (c qppPadsCase) CaseName() string { return c.Name }

// qppPrngCase is the state of a generator right after it was created.
type qppPrngCase struct {
	Name string `json:"name"`
	// Ctor is "create" (CreatePRNG) or "fast" (FastPRNG).
	Ctor       string    `json:"ctor"`
	Seed       string    `json:"seed"`
	SeedStream uint64    `json:"seed_stream,omitempty"`
	SeedLen    int       `json:"seed_len"`
	Xoshiro    [4]uint64 `json:"xoshiro"`
	Seed64     uint64    `json:"seed64"`
	Count      uint8     `json:"count"`
	// Outputs is the next 16 outputs of the generator (xoshiro256ss of the state).
	Outputs []uint64 `json:"outputs"`
}

// CaseName implements namedCase.
func (c qppPrngCase) CaseName() string { return c.Name }

// qppStreamCase is a 1 MiB plaintext encrypted in pieces of the given size.
type qppStreamCase struct {
	Name    string `json:"name"`
	Seed    string `json:"seed"`
	NumPads int    `json:"num_pads"`
	// Chunk is the piece size: 0 means one whole call, -1 random pieces of 1..4096 bytes
	// drawn from newRNG("qpp", chunk_stream).
	Chunk       int    `json:"chunk"`
	ChunkStream uint64 `json:"chunk_stream,omitempty"`
	// Plain is the plaintext, randBytes(newRNG("qpp", plain_stream), len).
	PlainStream uint64 `json:"plain_stream"`
	Plain       Blob   `json:"plain"`
	// Out is the ciphertext; the Rust test also decrypts it back to Plain.
	Out Blob `json:"out"`
	// RandAfter is the default encryption generator's state when the last piece is done.
	RandAfter qppRandState `json:"rand_after"`
}

// CaseName implements namedCase.
func (c qppStreamCase) CaseName() string { return c.Name }

// qppRandState is a Rand as the vectors record it.
type qppRandState struct {
	Xoshiro [4]uint64 `json:"xoshiro"`
	Seed64  uint64    `json:"seed64"`
	Count   uint8     `json:"count"`
}

// qppSeed describes one seed of the area: a fixed string, or bytes drawn from the area's RNG.
type qppSeed struct {
	name   string
	text   string // fixed seeds
	length int    // generated seeds, when text is empty
	stream uint64
}

// bytes returns the seed's bytes.
func (s qppSeed) bytes() []byte {
	if s.text != "" {
		return []byte(s.text)
	}
	return randBytes(newRNG("qpp", s.stream), s.length)
}

// qppSeeds are the seeds of the chunk and PRNG cases: kcptun's default -key, a one-byte seed
// (both shorter than 32 bytes, so both are PBKDF2-expanded first), a seed of exactly the
// expansion threshold, and one longer than the 224 bytes the seven chunks consume: the case
// where seedIdx wraps mid-chunk.
var qppSeeds = []qppSeed{
	{name: "default_key", text: "it's a secrect"},
	{name: "one_byte", text: "a"},
	{name: "len=32", length: 32, stream: qppSeedStream},
	{name: "len=300", length: 300, stream: qppSeedStream + 1},
}

// genQpp produces the area's cases in file order.
func genQpp() ([]any, error) {
	var cases []any

	// minimum/*: the sizes derived from the number of qubits. qubits=8 is the only one QPP
	// uses (QPPMinimumSeedLength(8) = 211, QPPMinimumPads(8) = 7); the rest pin the formula.
	// The range is Go's own TestQPPMinimumSeedLength; the cost is that of (2^qubits)!, so
	// stopping at 15 keeps the vector cheap to check on both sides.
	for qubits := 1; qubits <= 15; qubits++ {
		cases = append(cases, qppSizeCase{
			Name:        fmt.Sprintf("minimum/qubits=%d", qubits),
			Qubits:      qubits,
			SeedLen:     qpp.QPPMinimumSeedLength(uint8(qubits)),
			MinimumPads: qpp.QPPMinimumPads(uint8(qubits)),
		})
	}

	// chunks/*: seedToChunks, the seven 32-byte chunks the pads are derived from.
	for _, s := range qppSeeds {
		seed := s.bytes()
		chunks := qpp.SeedToChunks(seed, qppQubits)
		c := qppChunksCase{
			Name:     "chunks/" + s.name,
			SeedLen:  len(seed),
			Expanded: len(seed) < 32,
			Chunks:   len(chunks),
			Out:      hx(bytes.Join(chunks, nil)),
		}
		if s.text != "" {
			c.Seed = hx(seed)
		} else {
			c.SeedStream = s.stream
		}
		cases = append(cases, c)
	}

	// pads/*: the permutation matrices. 1 is the degenerate single pad, 7 the minimum for 8
	// qubits (and the number of chunks, so every chunk is used exactly once), 61 kcptun's
	// default -qpp-count and 101 a larger prime: the pad id is formatted in binary, so ids
	// with different bit lengths must be covered.
	padSeed := []byte("it's a secrect")
	for _, numPads := range []uint16{1, 7, 61, 101} {
		q := qpp.NewQPP(padSeed, numPads)
		pads, rpads := q.Pads(), q.RPads()
		if len(pads) != int(numPads)*256 || len(rpads) != len(pads) {
			return nil, fmt.Errorf("numPads %d: pads %d bytes, rpads %d bytes",
				numPads, len(pads), len(rpads))
		}
		for i := range pads { // every pad must be a permutation, and rpads its inverse
			if rpads[i&^255+int(pads[i])] != byte(i&255) {
				return nil, fmt.Errorf("numPads %d: pad %d is not reversible", numPads, i/256)
			}
		}
		cases = append(cases, qppPadsCase{
			Name:    fmt.Sprintf("pads/num_pads=%d", numPads),
			Seed:    hx(padSeed),
			NumPads: int(numPads),
			Pad0:    hx(pads[:256]),
			Pads:    newBlob(pads),
			RPads:   newBlob(rpads),
		})
	}

	// prng/*: the generator each constructor produces, and the outputs it goes on to give.
	for _, s := range qppSeeds {
		seed := s.bytes()
		for _, ctor := range []string{"create", "fast"} {
			rd := qpp.CreatePRNG(seed)
			if ctor == "fast" {
				rd = qpp.FastPRNG(seed)
			}
			xoshiro, seed64, count := rd.State()
			outputs := make([]uint64, 16)
			for i := range outputs {
				outputs[i] = rd.Next()
			}
			c := qppPrngCase{
				Name:    fmt.Sprintf("prng/%s/%s", ctor, s.name),
				Ctor:    ctor,
				SeedLen: len(seed),
				Xoshiro: xoshiro,
				Seed64:  seed64,
				Count:   count,
				Outputs: outputs,
			}
			if s.text != "" {
				c.Seed = hx(seed)
			} else {
				c.SeedStream = s.stream
			}
			cases = append(cases, c)
		}
	}

	// stream/*: 1 MiB encrypted in different chunkings. The transform is position-based, so
	// all four must produce the same ciphertext; that they do is the point of the group.
	plain := randBytes(newRNG("qpp", qppStreamStream), qppStreamLen)
	for _, chunk := range []int{0, 1, 7, -1} {
		name := "stream/whole"
		switch {
		case chunk == -1:
			name = "stream/random"
		case chunk > 0:
			name = fmt.Sprintf("stream/chunk=%d", chunk)
		}
		c, err := qppStream(name, padSeed, 61, chunk, plain)
		if err != nil {
			return nil, err
		}
		cases = append(cases, c)
	}

	return cases, nil
}

// qppStream encrypts plain in pieces of the given size (0: one call, -1: random 1..4096) and
// records the result. The ciphertext is decrypted again before it becomes a vector.
func qppStream(name string, seed []byte, numPads uint16, chunk int, plain []byte) (qppStreamCase, error) {
	q := qpp.NewQPP(seed, numPads)
	out := append([]byte(nil), plain...)

	rng := newRNG("qpp", qppChunkStream)
	for off := 0; off < len(out); {
		n := chunk
		switch {
		case n == 0:
			n = len(out)
		case n == -1:
			n = 1 + int(rng.Uint64()%4096)
		}
		if off+n > len(out) {
			n = len(out) - off
		}
		q.Encrypt(out[off : off+n])
		off += n
	}
	if bytes.Equal(out, plain) {
		return qppStreamCase{}, fmt.Errorf("case %s: not encrypted", name)
	}

	// Every case must decrypt again, so no vector can describe a stream QPP cannot undo.
	back := append([]byte(nil), out...)
	qpp.NewQPP(seed, numPads).Decrypt(back)
	if !bytes.Equal(back, plain) {
		return qppStreamCase{}, fmt.Errorf("case %s: round trip differs", name)
	}

	xoshiro, seed64, count := q.EncRand().State()
	c := qppStreamCase{
		Name:        name,
		Seed:        hx(seed),
		NumPads:     int(numPads),
		Chunk:       chunk,
		PlainStream: qppStreamStream,
		Plain:       newBlob(plain),
		Out:         newBlob(out),
		RandAfter:   qppRandState{Xoshiro: xoshiro, Seed64: seed64, Count: count},
	}
	if chunk == -1 {
		c.ChunkStream = qppChunkStream
	}
	return c, nil
}
