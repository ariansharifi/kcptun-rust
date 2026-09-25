package peer

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"hash/fnv"
	"io"
	"os"
	"runtime/debug"
	"strings"
	"testing"
)

// The stream must equal govectors' randBytes(rand.NewPCG(seed, 0)) and the Rust testkit's
// PrngStream; crates/testkit/src/rng.rs pins the same hash for govectors_rng("crypt", 0).
func TestStreamMatchesTestkitPinnedHash(t *testing.T) {
	h := fnv.New64a()
	h.Write([]byte("govectors/crypt"))
	if got, want := StreamSHA256(h.Sum64(), 1000), "684ffc976a2ad92c9abb534650cd7fffa6fa51cfe74c276f1318b0793ac203a8"; got != want {
		t.Fatalf("StreamSHA256 = %s, want %s", got, want)
	}
}

func TestStreamIndependentOfSplit(t *testing.T) {
	whole, _ := io.ReadAll(NewStream(42, 10007))
	for _, sizes := range [][]int{{1}, {3, 5}, {7, 8, 4096}} {
		s := NewStream(42, 10007)
		var got []byte
		for i := 0; ; i++ {
			buf := make([]byte, sizes[i%len(sizes)])
			n, err := s.Read(buf)
			got = append(got, buf[:n]...)
			if err == io.EOF {
				break
			}
		}
		if !bytes.Equal(got, whole) {
			t.Fatalf("split %v changes the stream", sizes)
		}
	}
	sum := sha256.Sum256(whole)
	if StreamSHA256(42, 10007) != hex.EncodeToString(sum[:]) {
		t.Fatal("StreamSHA256 disagrees with the stream")
	}
}

func TestVerifier(t *testing.T) {
	data, _ := io.ReadAll(NewStream(7, 5000))
	v := NewVerifier(7, 5000)
	for off := 0; off < len(data); off += 333 {
		end := min(off+333, len(data))
		if _, err := v.Write(data[off:end]); err != nil {
			t.Fatal(err)
		}
	}
	if !v.Done() || v.Mismatch() != -1 || v.SHA256() != StreamSHA256(7, 5000) {
		t.Fatalf("verifier: done %v mismatch %d", v.Done(), v.Mismatch())
	}

	bad := append([]byte(nil), data...)
	bad[1234] ^= 1
	v = NewVerifier(7, 5000)
	_, err := v.Write(bad[:1000])
	if err != nil {
		t.Fatal(err)
	}
	if _, err = v.Write(bad[1000:]); err == nil || v.Mismatch() != 1234 || v.Done() {
		t.Fatalf("mismatch not detected: err %v offset %d", err, v.Mismatch())
	}

	v = NewVerifier(7, 10)
	if _, err := v.Write(data[:11]); err == nil || v.Done() {
		t.Fatal("excess bytes not detected")
	}
}

func TestParseChunks(t *testing.T) {
	got, err := ParseChunks("1, 7,4096")
	if err != nil || len(got) != 3 || got[0] != 1 || got[1] != 7 || got[2] != 4096 {
		t.Fatalf("ParseChunks = %v, %v", got, err)
	}
	for _, s := range []string{"", "0", "-1", "1,,2", "x"} {
		if _, err := ParseChunks(s); err == nil {
			t.Fatalf("ParseChunks(%q) accepted", s)
		}
	}
}

func TestChunkedCopy(t *testing.T) {
	in, _ := io.ReadAll(NewStream(3, 1000))
	var calls []int
	var out bytes.Buffer
	w := writerFunc(func(p []byte) (int, error) { calls = append(calls, len(p)); return out.Write(p) })
	n, err := ChunkedCopy(w, bytes.NewReader(in), []int{1, 7, 400}, func(b []byte) {
		for i := range b {
			b[i] ^= 0xff
		}
	})
	if err != nil || n != 1000 {
		t.Fatalf("ChunkedCopy = %d, %v", n, err)
	}
	want := []int{1, 7, 400, 1, 7, 400, 1, 7, 176}
	if len(calls) != len(want) {
		t.Fatalf("write sizes %v, want %v", calls, want)
	}
	for i := range want {
		if calls[i] != want[i] {
			t.Fatalf("write sizes %v, want %v", calls, want)
		}
	}
	for i := range in {
		if out.Bytes()[i] != in[i]^0xff {
			t.Fatalf("byte %d not transformed", i)
		}
	}
	calls = nil
	if n, err := ChunkedCopy(w, bytes.NewReader(nil), []int{5}, nil); n != 0 || err != nil || len(calls) != 0 {
		t.Fatalf("empty input: %d %v %v", n, err, calls)
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(p []byte) (int, error) { return f(p) }

func TestCheckModules(t *testing.T) {
	ok := []*debug.Module{{Path: "github.com/xtaci/smux", Version: "v1.5.55"}, {Path: "example.com/other", Version: "v9"}}
	if err := checkModules(ok); err != nil {
		t.Fatal(err)
	}
	if err := checkModules([]*debug.Module{{Path: "github.com/xtaci/smux", Version: "v1.5.56"}}); err == nil {
		t.Fatal("wrong version accepted")
	}
	rep := &debug.Module{Path: "../smux"}
	if err := checkModules([]*debug.Module{{Path: "github.com/xtaci/smux", Version: "v1.5.55", Replace: rep}}); err == nil {
		t.Fatal("replaced module accepted")
	}
}

// requires parses the require lines of a go.mod file into path -> version.
func requires(t *testing.T, path string) map[string]string {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Skipf("%s: %v", path, err)
	}
	defer f.Close()
	out := map[string]string{}
	in := false
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		switch {
		case line == "require (":
			in = true
		case line == ")":
			in = false
		case in || strings.HasPrefix(line, "require "):
			fields := strings.Fields(strings.TrimPrefix(line, "require "))
			if len(fields) >= 2 {
				out[fields[0]] = fields[1]
			}
		}
	}
	return out
}

// go.mod, Pinned and the reference's go.mod must agree.
func TestGoModMatchesPinned(t *testing.T) {
	own := requires(t, "../../go.mod")
	for path, want := range Pinned {
		if got := own[path]; got != want {
			t.Errorf("go.mod requires %s %q, Pinned says %s", path, got, want)
		}
	}
	for path := range own {
		if _, ok := Pinned[path]; !ok {
			t.Errorf("go.mod requires %s, which is not in Pinned", path)
		}
	}
	ref := requires(t, "../../../../reference/kcptun/go.mod")
	for path, want := range Pinned {
		if got := ref[path]; got != want {
			t.Errorf("reference/kcptun/go.mod requires %s %q, Pinned says %s", path, got, want)
		}
	}
}
