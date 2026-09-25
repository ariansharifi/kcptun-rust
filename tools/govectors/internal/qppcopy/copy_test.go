package qpp

import (
	"bytes"
	"crypto/sha256"
	"math/rand/v2"
	"os"
	"testing"

	realqpp "github.com/xtaci/qpp"
)

const refDir = "../../../../reference/kcptun/vendor/github.com/xtaci/qpp/"

// The files copied from qpp v1.1.25. Nothing in them is changed.
var copied = []string{"qpp.go", "prng.go"}

// Below the marker, each copied file must equal the pinned source byte for byte. Skipped when
// reference/ has not been fetched.
func TestVerbatimCopy(t *testing.T) {
	const marker = "// ---- verbatim below ----\n"
	for _, name := range copied {
		ref, err := os.ReadFile(refDir + name)
		if err != nil {
			t.Skipf("reference not fetched: %v", err)
		}
		own, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(own, []byte(marker))
		if i < 0 {
			t.Fatalf("%s: marker missing", name)
		}
		if !bytes.Equal(own[i+len(marker):], ref) {
			t.Errorf("%s differs from the pinned reference", name)
		}
	}
}

// The copy must behave exactly like the linked module: same minimum sizes, and the same
// ciphertext for a stream cut into pieces at every awkward boundary. Everything the generator
// records (the chunks, the pads, the shuffle and the PRNG) feeds into that ciphertext, so a
// copy that had drifted could not pass this.
func TestCopyMatchesTheLinkedModule(t *testing.T) {
	for qubits := 1; qubits <= 10; qubits++ {
		if got, want := QPPMinimumSeedLength(uint8(qubits)), realqpp.QPPMinimumSeedLength(uint8(qubits)); got != want {
			t.Errorf("QPPMinimumSeedLength(%d) = %d, want %d", qubits, got, want)
		}
		if got, want := QPPMinimumPads(uint8(qubits)), realqpp.QPPMinimumPads(uint8(qubits)); got != want {
			t.Errorf("QPPMinimumPads(%d) = %d, want %d", qubits, got, want)
		}
	}

	rng := rand.New(rand.NewPCG(1, 2))
	plain := make([]byte, 64*1024)
	for i := range plain {
		plain[i] = byte(rng.Uint64())
	}
	for _, seed := range [][]byte{[]byte("a"), []byte("it's a secrect"), plain[:32], plain[:300]} {
		for _, numPads := range []uint16{1, 7, 61, 101, 1024} {
			mine := NewQPP(seed, numPads)
			for _, chunk := range []int{0, 1, 7, 8, 9, 4096} {
				// A fresh pair each time: the default generators carry the stream position
				// from one call to the next.
				enc, theirs := NewQPP(seed, numPads), realqpp.NewQPP(seed, numPads)
				a, b := append([]byte(nil), plain...), append([]byte(nil), plain...)
				encryptChunked(enc.Encrypt, a, chunk, rng)
				encryptChunked(theirs.Encrypt, b, chunk, rng)
				if !bytes.Equal(a, b) {
					t.Fatalf("seed %q numPads %d chunk %d: ciphertext differs (%x vs %x)",
						seed, numPads, chunk, sha256.Sum256(a), sha256.Sum256(b))
				}
				// The copy's own decryption must undo it, with a fresh generator.
				back := append([]byte(nil), a...)
				NewQPP(seed, numPads).Decrypt(back)
				if !bytes.Equal(back, plain) {
					t.Fatalf("seed %q numPads %d chunk %d: round trip differs", seed, numPads, chunk)
				}
			}
			// The pads themselves are unexported in the module, so they are compared through
			// the ciphertext above; the copy's own tables must at least be inverses.
			pads, rpads := mine.Pads(), mine.RPads()
			if len(pads) != int(numPads)*256 || len(pads) != len(rpads) {
				t.Fatalf("seed %q numPads %d: pads %d bytes, rpads %d bytes",
					seed, numPads, len(pads), len(rpads))
			}
			for i := range pads {
				pad, rpad := pads[i&^255:i&^255+256], rpads[i&^255:i&^255+256]
				if rpad[pad[i&255]] != byte(i&255) {
					t.Fatalf("seed %q numPads %d: pad %d is not reversible at %d",
						seed, numPads, i/256, i&255)
				}
			}
		}
	}
}

// encryptChunked encrypts data in place in pieces of the given size; 0 means one whole call and
// a negative size means random pieces of 1..4096 bytes.
func encryptChunked(encrypt func([]byte), data []byte, chunk int, rng *rand.Rand) {
	if chunk == 0 {
		encrypt(data)
		return
	}
	for off := 0; off < len(data); {
		n := chunk
		if n < 0 {
			n = 1 + int(rng.Uint64()%4096)
		}
		if off+n > len(data) {
			n = len(data) - off
		}
		encrypt(data[off : off+n])
		off += n
	}
}

// The PRNG constructors must agree too. CreatePRNG and FastPRNG are exported by both, and the
// state is compared through the stream they drive.
func TestPRNGMatchesTheLinkedModule(t *testing.T) {
	seed := []byte("it's a secrect")
	mine, theirs := NewQPP(seed, 61), realqpp.NewQPP(seed, 61)
	for _, ctor := range []string{"create", "fast"} {
		a, b := make([]byte, 1024), make([]byte, 1024)
		for i := range a {
			a[i], b[i] = byte(i), byte(i)
		}
		var mineRand *Rand
		var theirRand *realqpp.Rand
		if ctor == "create" {
			mineRand, theirRand = CreatePRNG(seed), realqpp.CreatePRNG(seed)
		} else {
			mineRand, theirRand = FastPRNG(seed), realqpp.FastPRNG(seed)
		}
		// Unaligned pieces exercise the head/tail loops and the count bookkeeping.
		for off := 0; off < len(a); off += 3 {
			end := min(off+3, len(a))
			mine.EncryptWithPRNG(a[off:end], mineRand)
			theirs.EncryptWithPRNG(b[off:end], theirRand)
		}
		if !bytes.Equal(a, b) {
			t.Fatalf("%sPRNG: ciphertext differs", ctor)
		}
	}
}
