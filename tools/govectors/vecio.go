package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"hash/fnv"
	"math/rand/v2"
	"os"
	"path/filepath"
)

// VectorFile is the top-level object of testdata/vectors/<area>.json. Field order here
// is the key order in the file.
type VectorFile struct {
	Generator string            `json:"generator"` // always "govectors"
	Go        string            `json:"go"`        // Go toolchain, e.g. "go1.27.1"
	Modules   map[string]string `json:"modules"`   // module path -> version (keys sorted)
	Area      string            `json:"area"`
	Cases     []any             `json:"cases"` // never null; "[]" when an area has no cases yet
}

// Case is the common shape of one vector. Areas may use their own struct instead when
// a case needs more than one input or output; field order then defines key order.
type Case struct {
	Name   string `json:"name"`             // unique within the file, e.g. "aes/len=21"
	Params any    `json:"params,omitempty"` // struct or map (map keys are sorted)
	In     string `json:"in,omitempty"`     // lower-case hex
	Out    string `json:"out,omitempty"`    // lower-case hex
}

// namedCase is implemented by every case type; area-specific case structs should
// implement it too so that generate can check names are present and unique.
type namedCase interface{ CaseName() string }

// CaseName implements namedCase.
func (c Case) CaseName() string { return c.Name }

// Blob describes a large byte string (e.g. a QPP pad) without storing all of it.
type Blob struct {
	Len    int    `json:"len"`
	SHA256 string `json:"sha256"` // lower-case hex of the SHA-256 of all bytes
	Head   string `json:"head"`   // hex of the first min(len, 16) bytes
	Tail   string `json:"tail"`   // hex of the last min(len, 16) bytes
}

// blobSampleLen is the number of bytes kept at each end of a Blob.
const blobSampleLen = 16

// newBlob summarises b as a Blob.
func newBlob(b []byte) Blob {
	n := min(len(b), blobSampleLen)
	return Blob{Len: len(b), SHA256: sha256Hex(b), Head: hx(b[:n]), Tail: hx(b[len(b)-n:])}
}

// hx is lower-case hex encoding, the only byte encoding used in vector files.
func hx(b []byte) string { return hex.EncodeToString(b) }

// sha256Hex returns the lower-case hex SHA-256 of b.
func sha256Hex(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// newRNG returns the deterministic generator for (area, stream). It is a math/rand/v2
// PCG whose first seed word is the FNV-1a 64 hash of "govectors/<area>" and whose second
// is stream. Each area therefore has its own sequence, and adding cases to one area never
// changes another area's bytes. Use a new stream number for each independent group of
// cases so that inserting a case does not shift the bytes of every later case.
func newRNG(area string, stream uint64) *rand.Rand {
	h := fnv.New64a()
	h.Write([]byte("govectors/" + area))
	return rand.New(rand.NewPCG(h.Sum64(), stream))
}

// randBytes returns n bytes drawn from r, eight bytes per Uint64 (little-endian).
func randBytes(r *rand.Rand, n int) []byte {
	b := make([]byte, n)
	var v uint64
	for i := range b {
		if i%8 == 0 {
			v = r.Uint64()
		}
		b[i] = byte(v)
		v >>= 8
	}
	return b
}

// encodeVectorFile renders f as JSON: 2-space indent, no HTML escaping, trailing newline.
func encodeVectorFile(f *VectorFile) ([]byte, error) {
	if f.Cases == nil {
		f.Cases = []any{}
	}
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(f); err != nil { // Encode appends the trailing '\n'
		return nil, err
	}
	return buf.Bytes(), nil
}

// writeFileAtomic writes data to path through a temporary file in the same directory,
// so an interrupted run never leaves a truncated vector file behind.
func writeFileAtomic(path string, data []byte) error {
	tmp, err := os.CreateTemp(filepath.Dir(path), ".govectors-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), 0o644); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return fmt.Errorf("rename %s: %w", path, err)
	}
	return nil
}
