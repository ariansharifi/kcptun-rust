package std

import (
	"bytes"
	"encoding/hex"
	"os"
	"strings"
	"testing"
)

// The copied kcptun files must stay byte-identical to the reference below their provenance
// comment. Skipped when reference/ has not been fetched.
func TestVerbatimCopies(t *testing.T) {
	for _, name := range []string{"crypt.go", "smuxcfg.go", "comp.go"} {
		ref, err := os.ReadFile("../../../../reference/kcptun/std/" + name)
		if err != nil {
			t.Skipf("reference not fetched: %v", err)
		}
		own, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(own, []byte("\n\n"))
		if i < 0 || !strings.HasPrefix(string(own), "// Provenance: verbatim copy of kcptun std/"+name) {
			t.Fatalf("%s: missing provenance comment", name)
		}
		if !bytes.Equal(own[i+2:], ref) {
			t.Errorf("%s differs from reference/kcptun/std/%s", name, name)
		}
	}
}

func TestDeriveKey(t *testing.T) {
	// PBKDF2-HMAC-SHA1("it's a secrect", "kcp-go", 4096, 32): kcptun's default key.
	// Cross-checked with Python: hashlib.pbkdf2_hmac('sha1', b"it's a secrect", b'kcp-go', 4096, 32).
	const want = "25d7d7bd51050742d8d791f2b653c6c8b2366b7e25a124cf7a2e12eaf4ffa444"
	if got := hex.EncodeToString(DeriveKey("it's a secrect")); got != want {
		t.Fatalf("DeriveKey = %s, want %s", got, want)
	}
}

func TestSelectBlockCryptNames(t *testing.T) {
	pass := DeriveKey("it's a secrect")
	for _, name := range []string{"sm4", "tea", "xor", "none", "aes-128", "aes-192", "blowfish", "twofish", "cast5", "3des", "xtea", "salsa20", "aes-128-gcm"} {
		b, eff := SelectBlockCrypt(name, pass)
		if b == nil || eff != name {
			t.Errorf("%s: block %v, effective %q", name, b, eff)
		}
	}
	if b, eff := SelectBlockCrypt("null", pass); b != nil || eff != "null" {
		t.Errorf("null: block %v, effective %q", b, eff)
	}
	for _, name := range []string{"aes", "", "bogus"} {
		if b, eff := SelectBlockCrypt(name, pass); b == nil || eff != "aes" {
			t.Errorf("%q: block %v, effective %q", name, b, eff)
		}
	}
}
