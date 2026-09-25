package main

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// The generator's only randomness is newRNG, so its output sequence is part of the
// vector format: if these change, every vector file changes.
func TestNewRNGIsPinned(t *testing.T) {
	if got, want := hx(randBytes(newRNG("test", 7), 20)), "e4a7fe36f62fc726956de0924782b941f7b3a9d5"; got != want {
		t.Fatalf("newRNG(test, 7) bytes = %s, want %s", got, want)
	}
	if got, want := sha256Hex(randBytes(newRNG("crypt", 0), 1000)),
		"684ffc976a2ad92c9abb534650cd7fffa6fa51cfe74c276f1318b0793ac203a8"; got != want {
		t.Fatalf("sha256(newRNG(crypt, 0) x1000) = %s, want %s", got, want)
	}
}

func TestNewRNGStreamsDiffer(t *testing.T) {
	a := randBytes(newRNG("kcp", 0), 32)
	if bytes.Equal(a, randBytes(newRNG("kcp", 1), 32)) {
		t.Fatal("streams 0 and 1 of one area produce the same bytes")
	}
	if bytes.Equal(a, randBytes(newRNG("fec", 0), 32)) {
		t.Fatal("areas kcp and fec produce the same bytes")
	}
	if !bytes.Equal(a, randBytes(newRNG("kcp", 0), 32)) {
		t.Fatal("newRNG is not deterministic")
	}
}

func TestRandBytesPrefixStable(t *testing.T) {
	long := randBytes(newRNG("x", 0), 21)
	short := randBytes(newRNG("x", 0), 13)
	if !bytes.Equal(long[:13], short) {
		t.Fatalf("prefix differs: %x vs %x", long[:13], short)
	}
}

func TestNewBlob(t *testing.T) {
	b := newBlob([]byte("abc"))
	want := Blob{Len: 3, SHA256: "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad", Head: "616263", Tail: "616263"}
	if b != want {
		t.Fatalf("newBlob(abc) = %+v, want %+v", b, want)
	}
	long := make([]byte, 40)
	for i := range long {
		long[i] = byte(i)
	}
	b = newBlob(long)
	if b.Head != hx(long[:16]) || b.Tail != hx(long[24:]) || b.Len != 40 {
		t.Fatalf("newBlob(0..40) = %+v", b)
	}
	if b = newBlob(nil); b.Len != 0 || b.Head != "" || b.Tail != "" {
		t.Fatalf("newBlob(nil) = %+v", b)
	}
}

func TestEncodeVectorFile(t *testing.T) {
	f := &VectorFile{
		Generator: "govectors",
		Go:        "go0",
		Modules:   map[string]string{"z/mod": "v2", "a/mod": "v1"},
		Area:      "demo",
		Cases:     []any{Case{Name: "c<1>", Params: map[string]int{"b": 2, "a": 1}, In: "00ff"}},
	}
	got, err := encodeVectorFile(f)
	if err != nil {
		t.Fatal(err)
	}
	want := `{
  "generator": "govectors",
  "go": "go0",
  "modules": {
    "a/mod": "v1",
    "z/mod": "v2"
  },
  "area": "demo",
  "cases": [
    {
      "name": "c<1>",
      "params": {
        "a": 1,
        "b": 2
      },
      "in": "00ff"
    }
  ]
}
`
	if string(got) != want {
		t.Fatalf("encoded:\n%s\nwant:\n%s", got, want)
	}
	empty, err := encodeVectorFile(&VectorFile{Area: "e"})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(empty), `"cases": []`) || !strings.Contains(string(empty), `"modules": null`) {
		t.Fatalf("empty file encoded as:\n%s", empty)
	}
}

func TestCheckCaseNames(t *testing.T) {
	if err := checkCaseNames([]any{Case{Name: "a"}, &Case{Name: "b"}, 42}); err != nil {
		t.Fatal(err)
	}
	if err := checkCaseNames([]any{Case{Name: "a"}, &Case{Name: "a"}}); err == nil {
		t.Fatal("duplicate names accepted")
	}
	if err := checkCaseNames([]any{Case{}}); err == nil {
		t.Fatal("empty name accepted")
	}
}

func TestSelectAreas(t *testing.T) {
	sel, err := selectAreas([]string{"kcp", "crypt", "kcp"})
	if err != nil {
		t.Fatal(err)
	}
	if len(sel) != 2 || sel[0].name != "crypt" || sel[1].name != "kcp" {
		t.Fatalf("selectAreas order/dedup wrong: %v", sel)
	}
	if sel, _ := selectAreas([]string{"all"}); len(sel) != len(areas) {
		t.Fatalf("all selected %d areas, want %d", len(sel), len(areas))
	}
	for _, bad := range [][]string{nil, {"nope"}} {
		if _, err := selectAreas(bad); err == nil {
			t.Fatalf("selectAreas(%q) accepted", bad)
		}
	}
}

func TestPinnedModulesLinked(t *testing.T) {
	mods, err := moduleVersions()
	if err != nil {
		t.Fatal(err)
	}
	if err := checkPinned(mods); err != nil {
		t.Fatal(err)
	}
	if err := checkPinned(map[string]string{"github.com/xtaci/kcp-go/v5": "v5.6.72"}); err == nil {
		t.Fatal("wrong kcp-go version accepted")
	}
}

// Running the generator twice must give byte-identical files with the common header.
func TestGenerateDeterministic(t *testing.T) {
	d1, d2 := t.TempDir(), t.TempDir()
	if code := run([]string{"-out", d1, "all"}, io.Discard, os.Stderr); code != 0 {
		t.Fatalf("run exit %d", code)
	}
	if code := run([]string{"-out", d2, "all"}, io.Discard, os.Stderr); code != 0 {
		t.Fatalf("run exit %d", code)
	}
	for _, a := range areas {
		b1, err := os.ReadFile(filepath.Join(d1, a.name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		b2, err := os.ReadFile(filepath.Join(d2, a.name+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(b1, b2) {
			t.Fatalf("%s.json differs between runs", a.name)
		}
		var f struct {
			Generator string
			Go        string
			Modules   map[string]string
			Area      string
			Cases     []json.RawMessage
		}
		if err := json.Unmarshal(b1, &f); err != nil {
			t.Fatalf("%s.json: %v", a.name, err)
		}
		if f.Generator != "govectors" || f.Go != runtime.Version() || f.Area != a.name || f.Cases == nil {
			t.Fatalf("%s.json header wrong: %+v", a.name, f)
		}
		for path, v := range pinned {
			if f.Modules[path] != v {
				t.Fatalf("%s.json: modules[%s] = %q, want %q", a.name, path, f.Modules[path], v)
			}
		}
	}
	entries, err := os.ReadDir(d1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != len(areas) {
		t.Fatalf("output dir has %d entries, want %d (leftover temp files?)", len(entries), len(areas))
	}
}

func TestRunUsageErrors(t *testing.T) {
	var stderr bytes.Buffer
	if code := run([]string{"bogus"}, io.Discard, &stderr); code != 2 {
		t.Fatalf("unknown area: exit %d, want 2", code)
	}
	if !strings.Contains(stderr.String(), `unknown area "bogus"`) {
		t.Fatalf("stderr: %s", stderr.String())
	}
	if code := run([]string{"-nope"}, io.Discard, io.Discard); code != 2 {
		t.Fatalf("bad flag: exit %d, want 2", code)
	}
	if code := run([]string{"-h"}, io.Discard, io.Discard); code != 0 {
		t.Fatalf("-h: exit %d, want 0", code)
	}
}
