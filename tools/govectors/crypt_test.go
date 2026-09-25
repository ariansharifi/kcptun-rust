package main

import (
	"encoding/hex"
	"strings"
	"testing"
)

func cryptCasesByName(t *testing.T) map[string]Case {
	t.Helper()
	cases, err := genCrypt()
	if err != nil {
		t.Fatal(err)
	}
	m := make(map[string]Case, len(cases))
	for _, c := range cases {
		cc := c.(Case)
		m[cc.Name] = cc
	}
	return m
}

func TestGenCryptShape(t *testing.T) {
	m := cryptCasesByName(t)
	want := len(pbkdf2Keys) + len(cryptPassKeys) + 2*len(selectMethods) +
		len(cfbMethods)*len(cryptPassKeys)*len(cfbLens) + len(cryptPassKeys)*len(aeadPlainLens)
	if len(m) != want {
		t.Fatalf("%d crypt cases, want %d", len(m), want)
	}
	for name, c := range m {
		if strings.HasPrefix(name, "cfb/") && len(c.In) != len(c.Out) {
			t.Errorf("%s: in %d hex chars, out %d", name, len(c.In), len(c.Out))
		}
		if strings.HasPrefix(name, "aead/") && len(c.Out) != len(c.In)+2*(12+16) {
			t.Errorf("%s: in %d hex chars, out %d", name, len(c.In), len(c.Out))
		}
	}
	if got := m["pbkdf2/default"].Out; got != "25d7d7bd51050742d8d791f2b653c6c8b2366b7e25a124cf7a2e12eaf4ffa444" {
		t.Errorf("pbkdf2/default = %s", got)
	}
	// none is the identity; the header is part of the encrypted packet for every other method.
	if c := m["cfb/none/pass_id=0/len=1500"]; c.In != c.Out {
		t.Error("cfb/none is not the identity")
	}
	if c := m["cfb/aes/pass_id=0/len=20"]; c.In[:32] == c.Out[:32] {
		t.Error("cfb/aes left the nonce unencrypted")
	}
	// salsa20 keeps the first 8 bytes (its nonce) in clear.
	if c := m["cfb/salsa20/pass_id=1/len=64"]; c.In[:16] != c.Out[:16] || c.In[16:32] == c.Out[16:32] {
		t.Error("cfb/salsa20: unexpected nonce handling")
	}
}

func TestGenCryptSelect(t *testing.T) {
	m := cryptCasesByName(t)
	type want struct {
		eff    string
		nil    bool
		keyLen int
		log    string
	}
	for name, w := range map[string]want{
		"select/method=aes":               {"aes", false, 32, ""},
		"select/method=aes-128":           {"aes-128", false, 16, ""},
		"select/method=aes-192":           {"aes-192", false, 24, ""},
		"select/method=aes-128-gcm":       {"aes-128-gcm", false, 16, ""},
		"select/method=salsa20":           {"salsa20", false, 32, ""},
		"select/method=3des":              {"3des", false, 24, ""},
		"select/method=null":              {"null", true, 0, ""},
		"select/method=bogus":             {"aes", false, 32, ""},
		"select/method=":                  {"aes", false, 32, ""},
		"select_short/method=aes":         {"aes", false, 16, ""},
		"select_short/method=aes-192":     {"aes-192", false, 16, ""},
		"select_short/method=3des":        {"aes", false, 16, "crypt: failed to create 3des cipher: crypto/des: invalid key size 16, falling back to aes"},
		"select_short/method=blowfish":    {"blowfish", false, 16, ""},
		"select_short/method=xor":         {"xor", false, 16, ""},
		"select_short/method=null":        {"null", true, 0, ""},
		"select_short/method=aes-128-gcm": {"aes-128-gcm", false, 16, ""},
	} {
		c, ok := m[name]
		if !ok {
			t.Errorf("missing case %s", name)
			continue
		}
		p := c.Params.(*selectParams)
		if p.Effective != w.eff || p.Nil != w.nil || p.KeyLen != w.keyLen || p.Log != w.log {
			t.Errorf("%s: got %+v, want %+v", name, *p, w)
		}
		if (c.Out == "") != w.nil {
			t.Errorf("%s: out %q with nil=%v", name, c.Out, w.nil)
		}
	}
	// bogus and "" fall back to exactly the aes cipher.
	if m["select/method=bogus"].Out != m["select/method=aes"].Out || m["select/method="].Out != m["select/method=aes"].Out {
		t.Error("unknown methods do not encrypt like aes")
	}
	// aes (AES-256, full pass) and aes-128 (pass[:16]) must use different key schedules.
	if m["select/method=aes"].Out == m["select/method=aes-128"].Out {
		t.Error("aes and aes-128 encrypt identically")
	}
	if p := m["select/method=aes-128-gcm"].Params.(*selectParams); len(p.Nonce) != 2*12 {
		t.Errorf("aes-128-gcm nonce %q", p.Nonce)
	}
}

func TestGenCryptXorPad(t *testing.T) {
	m := cryptCasesByName(t)
	for _, name := range []string{"xor_pad/pass_id=0", "xor_pad/pass_id=1"} {
		pad, err := hex.DecodeString(m[name].Out)
		if err != nil || len(pad) != xorPadLen {
			t.Fatalf("%s: %d bytes, %v", name, len(pad), err)
		}
	}
}
