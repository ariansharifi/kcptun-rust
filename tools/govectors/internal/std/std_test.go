package std

import (
	"bytes"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// refPath locates a file in the shared Go reference checkout.
func refPath(rel string) string {
	return filepath.Join("..", "..", "..", "..", "reference", "kcptun", rel)
}

// The whole-file copies under internal/ must stay byte-identical to the reference below their
// provenance comment, so that refreshing reference/ cannot leave the vectors quietly
// describing an older kcptun. Skipped when reference/ has not been fetched.
func TestVerbatimCopy(t *testing.T) {
	for _, tc := range []struct{ own, ref string }{
		{"crypt.go", "std/crypt.go"},
		{"config.go", "std/config.go"},
		{"multiport.go", "std/multiport.go"},
	} {
		t.Run(tc.own, func(t *testing.T) {
			ref, err := os.ReadFile(refPath(tc.ref))
			if err != nil {
				t.Skipf("reference not fetched: %v", err)
			}
			own, err := os.ReadFile(tc.own)
			if err != nil {
				t.Fatal(err)
			}
			want := "// Provenance: verbatim copy of kcptun " + tc.ref
			i := bytes.Index(own, []byte("\n\n"))
			if i < 0 || !strings.HasPrefix(string(own), want) {
				t.Fatalf("%s: missing provenance comment %q", tc.own, want)
			}
			if !bytes.Equal(own[i+2:], ref) {
				t.Errorf("%s differs from reference/kcptun/%s", tc.own, tc.ref)
			}
		})
	}
}

// The two Config structs cannot be whole-file copies: each needs its own package clause and
// import path, so their `type Config struct { ... }` block is compared instead. That block is
// exactly what encoding/json sees: the json tags, the field types and the embedded BaseConfig.
func TestConfigStructCopy(t *testing.T) {
	for _, tc := range []struct{ own, ref string }{
		{filepath.Join("..", "kcptunclient", "config.go"), "client/config.go"},
		{filepath.Join("..", "kcptunserver", "config.go"), "server/config.go"},
	} {
		t.Run(tc.ref, func(t *testing.T) {
			refSrc, err := os.ReadFile(refPath(tc.ref))
			if err != nil {
				t.Skipf("reference not fetched: %v", err)
			}
			ownSrc, err := os.ReadFile(tc.own)
			if err != nil {
				t.Fatal(err)
			}
			want := "// Provenance: the struct below is a verbatim copy of kcptun " + tc.ref
			if !strings.Contains(string(ownSrc), want) {
				t.Fatalf("%s: missing provenance comment %q", tc.own, want)
			}
			ref, err := configStructBlock(refSrc)
			if err != nil {
				t.Fatalf("reference/kcptun/%s: %v", tc.ref, err)
			}
			own, err := configStructBlock(ownSrc)
			if err != nil {
				t.Fatalf("%s: %v", tc.own, err)
			}
			if own != ref {
				t.Errorf("%s: Config differs from reference/kcptun/%s\n got:\n%s\nwant:\n%s",
					tc.own, tc.ref, own, ref)
			}
		})
	}
}

// errNoConfigStruct is returned when a source file holds no Config declaration.
var errNoConfigStruct = errors.New("no `type Config struct { ... }` declaration found")

// configStructBlock returns the `type Config struct { ... }` declaration of a Go source file,
// including the doc comment above it.
func configStructBlock(src []byte) (string, error) {
	s := string(src)
	i := strings.Index(s, "// Config ")
	if i < 0 {
		return "", errNoConfigStruct
	}
	rest := s[i:]
	j := strings.Index(rest, "\n}\n")
	if j < 0 || !strings.Contains(rest[:j], "type Config struct {") {
		return "", errNoConfigStruct
	}
	return rest[:j+3], nil
}

func TestDeriveKey(t *testing.T) {
	// PBKDF2-HMAC-SHA1("it's a secrect", "kcp-go", 4096, 32): kcptun's default key (same
	// value as tools/gointerop/internal/std, cross-checked there with Python's hashlib).
	const want = "25d7d7bd51050742d8d791f2b653c6c8b2366b7e25a124cf7a2e12eaf4ffa444"
	if got := hex.EncodeToString(DeriveKey("it's a secrect")); got != want {
		t.Fatalf("DeriveKey = %s, want %s", got, want)
	}
}

func TestCryptKeySize(t *testing.T) {
	for method, want := range map[string]int{"aes-128": 16, "aes-192": 24, "3des": 24, "cast5": 16, "salsa20": 0, "null": 0} {
		if got, ok := CryptKeySize(method); !ok || got != want {
			t.Errorf("CryptKeySize(%q) = %d, %v; want %d, true", method, got, ok, want)
		}
	}
	for _, method := range []string{"aes", "", "bogus"} {
		if _, ok := CryptKeySize(method); ok {
			t.Errorf("CryptKeySize(%q) reported a table entry", method)
		}
	}
}
