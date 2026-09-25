package main

import (
	"encoding/hex"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

// rsGaloisSrc is klauspost/reedsolomon v1.13.0 galois.go in the fetched reference.
const rsGaloisSrc = "../../reference/kcptun/vendor/github.com/klauspost/reedsolomon/galois.go"

// parseGoByteTable returns the values of `var <name> = [...]byte{...}` in src.
func parseGoByteTable(t *testing.T, src, name string) []byte {
	t.Helper()
	re := regexp.MustCompile(`(?s)var ` + name + ` = \[[a-zA-Z0-9]+\]byte\{(.*?)\}`)
	m := re.FindStringSubmatch(src)
	if m == nil {
		t.Fatalf("%s not found in galois.go", name)
	}
	var out []byte
	for _, f := range strings.Split(m[1], ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		v, err := strconv.ParseUint(f, 0, 8)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		out = append(out, byte(v))
	}
	return out
}

// The galois case is derived through the exported API; check it equals the literal tables of
// the pinned galois.go (skipped when reference/ has not been fetched).
func TestRsGaloisMatchesLiteralTables(t *testing.T) {
	src, err := os.ReadFile(rsGaloisSrc)
	if err != nil {
		t.Skipf("reference not fetched: %v", err)
	}
	g, err := genRsGalois()
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct{ name, got string }{
		{"logTable", g.Log}, {"expTable", g.Exp}, {"invTable", g.Inv},
	} {
		want := hex.EncodeToString(parseGoByteTable(t, string(src), tc.name))
		if tc.got != want {
			t.Errorf("%s differs from galois.go:\n got  %s\n want %s", tc.name, tc.got, want)
		}
	}
}

func TestGenRsShape(t *testing.T) {
	cases, err := genRs()
	if err != nil {
		t.Fatal(err)
	}
	want := 1 + len(rsConfigs) + len(rsConfigs)*len(rsShardLens)*(1+len(rsPatternNames)) + len(rsErrorOps)
	if len(cases) != want {
		t.Fatalf("%d rs cases, want %d", len(cases), want)
	}
	byName := map[string]any{}
	for _, c := range cases {
		byName[c.(namedCase).CaseName()] = c
	}
	// Hand-computed buildMatrix results: (1,1) copies the data; for (2,1) the Vandermonde rows
	// are [1 0], [1 1], [1 2], the top is its own inverse, so the parity row is [1^2, 2] = [3 2].
	if m := byName["matrix/ds=1,ps=1"].(rsMatrixCase); m.Parity != "01" {
		t.Errorf("matrix/ds=1,ps=1 = %s", m.Parity)
	}
	if m := byName["matrix/ds=2,ps=1"].(rsMatrixCase); m.Parity != "0302" {
		t.Errorf("matrix/ds=2,ps=1 = %s", m.Parity)
	}
	for _, c := range cases {
		rc, ok := c.(rsReconstructCase)
		if !ok {
			continue
		}
		if len(rc.Missing) == 0 || len(rc.Missing) > rc.Ps {
			t.Errorf("%s: %d missing, ps %d", rc.Name, len(rc.Missing), rc.Ps)
		}
		if strings.HasSuffix(rc.Name, "/first_data") && rc.Missing[0] != 0 {
			t.Errorf("%s: shard 0 not missing", rc.Name)
		}
		if strings.HasSuffix(rc.Name, "/all_parity") && len(rc.Recovered) != 0 {
			t.Errorf("%s: recovered %v", rc.Name, rc.Recovered)
		}
		if strings.HasSuffix(rc.Name, "/mixed") && rc.Missing[0] >= rc.Ds {
			t.Errorf("%s: no data shard missing", rc.Name)
		}
	}
	errs := map[string]string{
		"error/new_ds0":                 "cannot create Encoder with less than one data shard or less than zero parity shards",
		"error/encode_count_short":      "too few shards given",
		"error/encode_size_mismatch":    "shard sizes do not match",
		"error/encode_all_nil":          "no shard data",
		"error/reconstruct_too_few":     "too few shards given",
		"error/reconstruct_all_present": "",
	}
	for name, e := range errs {
		if got := byName[name].(rsErrorCase).Err; got != e {
			t.Errorf("%s: err %q, want %q", name, got, e)
		}
	}
}
