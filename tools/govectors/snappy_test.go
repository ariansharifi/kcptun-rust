package main

import (
	"bytes"
	"encoding/hex"
	"io"
	"testing"

	"github.com/golang/snappy"
)

// snappyCases returns the generated cases, keyed by name.
func snappyCases(t *testing.T) (map[string]snappyWriteCase, map[string]snappyReadCase) {
	t.Helper()
	cases, err := genSnappy()
	if err != nil {
		t.Fatalf("genSnappy: %v", err)
	}
	writes := make(map[string]snappyWriteCase)
	reads := make(map[string]snappyReadCase)
	for _, c := range cases {
		switch v := c.(type) {
		case snappyWriteCase:
			writes[v.Name] = v
		case snappyReadCase:
			reads[v.Name] = v
		default:
			t.Fatalf("unexpected case type %T", c)
		}
	}
	return writes, reads
}

// The plan (07.1) asks for these shapes; a missing one would silently weaken the Rust tests.
func TestSnappyCasesCoverThePlan(t *testing.T) {
	writes, reads := snappyCases(t)
	for _, name := range []string{
		"write/empty",
		"write/text/len=8200",
		"write/text/len=70000",
		"write/random/len=8200",
		"write/random/len=70000",
		"write/random/len=65536",
		"write/sequence/text",
		"write/sequence/random",
		"write/sequence/empty_between",
	} {
		if _, ok := writes[name]; !ok {
			t.Errorf("missing write case %q", name)
		}
	}
	for _, name := range []string{
		"read/skippable_0x80",
		"error/no_identifier",
		"error/reserved_type_0x02",
		"error/chunk_too_long",
		"error/bad_checksum_compressed",
		"error/truncated_body",
	} {
		if _, ok := reads[name]; !ok {
			t.Errorf("missing read case %q", name)
		}
	}
}

// The framing format has exactly two error values at this level; anything else in a vector
// would mean the generator built a stream that fails for an unintended reason.
func TestSnappyErrorTextsAreTheTwoKnownOnes(t *testing.T) {
	_, reads := snappyCases(t)
	for name, c := range reads {
		switch c.Err {
		case "":
			if len(name) > 6 && name[:6] == "error/" {
				t.Errorf("%s: expected an error", name)
			}
		case snappy.ErrCorrupt.Error(), snappy.ErrUnsupported.Error():
		default:
			t.Errorf("%s: unexpected error %q", name, c.Err)
		}
	}
}

// An empty write must produce no bytes at all: the stream identifier only goes out with the
// first chunk, and kcptun's Flush returns early on an empty buffer.
func TestSnappyEmptyWriteProducesNothing(t *testing.T) {
	writes, _ := snappyCases(t)
	if got := writes["write/empty"].Out; got != "" {
		t.Fatalf("write/empty produced %q", got)
	}
}

// A write longer than one block becomes two chunks, and the stream identifier appears exactly
// once, at the very start.
func TestSnappyChunking(t *testing.T) {
	writes, _ := snappyCases(t)
	c := writes["write/random/len=70000"]
	out, err := hex.DecodeString(c.Out)
	if err != nil || len(out) == 0 {
		// The case is stored as a blob; rebuild it from the recorded parameters.
		in, err := snappyInput(c.Kind, c.Len, c.Stream)
		if err != nil {
			t.Fatalf("input: %v", err)
		}
		if out, err = snappyFrame([][]byte{in}); err != nil {
			t.Fatalf("frame: %v", err)
		}
	}
	magic := snappyIdentifier()
	if !bytes.HasPrefix(out, magic) {
		t.Fatalf("output does not start with the stream identifier")
	}
	if bytes.Count(out, magic) != 1 {
		t.Fatalf("stream identifier appears %d times", bytes.Count(out, magic))
	}
	// identifier + (4 + 4 + 65536) + (4 + 4 + 4464), both chunks uncompressed.
	if want := len(magic) + 8 + 65536 + 8 + (70000 - 65536); len(out) != want {
		t.Fatalf("len(out) = %d, want %d", len(out), want)
	}
	if out[len(magic)] != 0x01 || out[len(magic)+8+65536] != 0x01 {
		t.Fatalf("expected two uncompressed chunks")
	}
}

// snappyCRC must be the library's masked CRC-32C: a chunk built with it has to decode.
func TestSnappyCRCIsAcceptedByTheLibrary(t *testing.T) {
	payload := []byte("checksum me")
	stream := snappyJoin(snappyIdentifier(), snappyDataChunk(0x01, payload, payload))
	got, err := io.ReadAll(snappy.NewReader(bytes.NewReader(stream)))
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("decoded %q, want %q", got, payload)
	}
}

// The payload kinds are deterministic and the recorded length is respected.
func TestSnappyInputKinds(t *testing.T) {
	for _, kind := range []string{"text", "random", "zeros"} {
		a, err := snappyInput(kind, 100, 7)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		b, err := snappyInput(kind, 100, 7)
		if err != nil {
			t.Fatalf("%s: %v", kind, err)
		}
		if len(a) != 100 || !bytes.Equal(a, b) {
			t.Fatalf("%s: not deterministic or wrong length", kind)
		}
	}
	if _, err := snappyInput("nope", 1, 0); err == nil {
		t.Fatal("unknown kind accepted")
	}
}
