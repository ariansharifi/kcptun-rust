package main

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"strings"
	"testing"

	kcpcopy "github.com/kcptun-rust/tools/govectors/internal/kcpcopy"
)

// The digests hard-coded in crates/kcp/src/fec/tests.rs (stream_digest_matches_go_copy): SHA-1
// over every data packet and parity shard of a scripted 60-packet stream (lengths
// off + 8 + n*397 % 1450, bytes n*31 + i*7, 700 ms before every 17th packet, else n%5*30 ms),
// encoded by the copied fecEncoder at rto 500 from 1758000000000.
func TestFecStreamDigestsOfRustTest(t *testing.T) {
	for _, c := range []struct {
		ds, ps, off int
		want        string
	}{
		{1, 1, 0, "cc7ea35974b31cb24d6517567e62252337ff9fa8"},
		{3, 2, 20, "db8b8b95641e447e0fb5cad9495eae40c1d39d54"},
		{10, 3, 16, "06cf35815b9900e647b5f9b4b9975d7dfecbd12b"},
		{4, 4, 0, "dbcb48fdb82f03727b9870a134d16b1d49879242"},
	} {
		enc := kcpcopy.NewFECEncoder(c.ds, c.ps, c.off)
		h := sha1.New()
		now := int64(1758000000000)
		withClock(&now, func() {
			for n := range 60 {
				l := min(c.off+8+(n*397)%1450, 1500)
				b := make([]byte, l)
				for i := range b {
					b[i] = byte(n*31 + i*7)
				}
				if n%17 == 16 {
					now += 700
				} else {
					now += int64(n % 5 * 30)
				}
				ps := enc.Encode(b, 500)
				h.Write(b)
				for _, p := range ps {
					h.Write(p)
				}
			}
		})
		if got := hex.EncodeToString(h.Sum(nil)); got != c.want {
			t.Errorf("(%d,%d,%d): %s, want %s", c.ds, c.ps, c.off, got, c.want)
		}
	}
}

// The fec area is deterministic, and a clean feed of every stream with ds > 1 recovers nothing
// (with ds == 1 every parity packet decodes its group again and "recovers" the data shard).
func TestFecCleanFeeds(t *testing.T) {
	cases, err := genFec()
	if err != nil {
		t.Fatal(err)
	}
	again, err := genFec()
	if err != nil {
		t.Fatal(err)
	}
	a, _ := encodeVectorFile(&VectorFile{Cases: cases})
	b, _ := encodeVectorFile(&VectorFile{Cases: again})
	if !bytes.Equal(a, b) {
		t.Fatal("genFec is not deterministic")
	}
	for _, c := range cases {
		d, ok := c.(fecDecCase)
		if !ok || d.DS == 1 || !strings.HasSuffix(d.Name, "/clean") {
			continue
		}
		if d.Counters.Recovered != 0 || d.Counters.Errs != 0 || d.Counters.FullShardSet == 0 {
			t.Errorf("%s: counters %+v", d.Name, d.Counters)
		}
	}
}
