package main

// Area "crypt" (plan step 02.1): key derivation, cipher selection and packet encryption of
// kcp-go v5.6.66 (crypt.go) as driven by kcptun std/crypt.go (copied verbatim into
// internal/std). The case groups and their fields are documented in README.md.

import (
	"bytes"
	"crypto/sha1"
	"fmt"
	"log"
	"strings"

	kcp "github.com/xtaci/kcp-go/v5"
	"golang.org/x/crypto/pbkdf2"

	"github.com/kcptun-rust/tools/govectors/internal/std"
)

const (
	// defaultKey is kcptun's default -key (sic).
	defaultKey = "it's a secrect"
	// random32Key is a fixed, random-looking 32-character -key, like a production key.
	random32Key = "q7Vt2mXe9LkR4pZs8WnB1cYh6GdJ3fUa"

	// saltXor and xorPadLen are kcp-go crypt.go's saltxor and mtuLimit: the xor pad is
	// PBKDF2-HMAC-SHA1(pass, saltXor, 32, xorPadLen). Used only to cross-check the pad.
	saltXor   = "sH3CIVoF#rWLtJo6"
	xorIter   = 32
	xorPadLen = 1500

	// cryptNonceLen and cryptCRCLen form the header kcp-go prepends to every non-AEAD packet.
	cryptNonceLen = 16
	cryptCRCLen   = 4
	// selectPlainLen is the length of the fixed buffer the select cases encrypt.
	selectPlainLen = 64
)

// RNG streams of the crypt area (see newRNG). Per-length streams keep each payload stable
// when lengths are added or removed.
const (
	streamCfbNonce    = 1       // the 16-byte nonce at the start of every cfb input
	streamSelectPlain = 2       // the 64-byte buffer of the select cases
	streamAeadNonce   = 3       // the 12-byte AEAD nonce
	streamCfbPayload  = 1 << 16 // + packet length: the cfb payload after nonce and crc
	streamAeadPlain   = 2 << 16 // + plaintext length: the aead plaintext
)

// pbkdf2Keys are the -key values of the pbkdf2 group, by case label.
var pbkdf2Keys = []struct{ label, key string }{
	{"default", defaultKey},
	{"empty", ""},
	{"a", "a"},
	{"cjk", "中文密钥"},
	{"k300", strings.Repeat("k", 300)},
	{"random32", random32Key},
}

// cryptPassKeys are the -key values whose derived passes the xor_pad, cfb and aead groups
// use; a case's params.pass_id indexes this list.
var cryptPassKeys = []string{defaultKey, random32Key}

// selectMethods are the -crypt values of the select groups, in file order.
var selectMethods = []string{
	"aes", "aes-128", "aes-128-gcm", "aes-192", "salsa20", "blowfish", "twofish", "cast5",
	"3des", "tea", "xtea", "xor", "sm4", "none", "null", "bogus", "",
}

// cfbMethods are the non-AEAD methods of the cfb group: the CFB block ciphers plus the
// stream-like salsa20, xor and none, which share the nonce+crc packet layout.
var cfbMethods = []string{
	"aes", "aes-128", "aes-192", "salsa20", "blowfish", "twofish", "cast5", "3des", "tea",
	"xtea", "sm4", "xor", "none",
}

// cfbLens are the whole-packet lengths (nonce + crc + payload) of the cfb group: around
// both block sizes, multiples of the 8-block unrolled loop, and real MTU-derived sizes.
// Salsa20 panics on packets shorter than 8 bytes in kcp-go v5.6.66, so none is below 20.
var cfbLens = []int{20, 21, 23, 24, 25, 31, 32, 33, 63, 64, 65, 127, 128, 129, 1349, 1350, 1370, 1500}

// aeadPlainLens are the plaintext lengths of the aead group (1314: aes-128-gcm with FEC at
// mtu 1350).
var aeadPlainLens = []int{0, 1, 24, 1314}

// aeadMethod is the only AEAD -crypt value.
const aeadMethod = "aes-128-gcm"

// aeadCrypt is the method set of kcp-go's unexported *aeadCrypt that sess.go uses.
type aeadCrypt interface {
	Seal(dst, nonce, plaintext, additionalData []byte) []byte
	Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error)
	NonceSize() int
	Overhead() int
}

type pbkdf2Params struct {
	Key   string `json:"key"` // the -key string (UTF-8); "in" holds its bytes
	Salt  string `json:"salt"`
	Iter  int    `json:"iter"`
	DkLen int    `json:"dklen"`
}

type xorPadParams struct {
	PassID int    `json:"pass_id"`
	Pass   string `json:"pass"` // hex
}

type selectParams struct {
	Method    string `json:"method"`
	Pass      string `json:"pass"` // hex
	Effective string `json:"effective"`
	Nil       bool   `json:"nil"`
	KeyLen    int    `json:"key_len"`         // bytes of pass given to the effective constructor; 0 for null
	Nonce     string `json:"nonce,omitempty"` // hex; aes-128-gcm only
	Log       string `json:"log,omitempty"`   // what SelectBlockCrypt logged (fallback), without newline
}

type cfbParams struct {
	Method string `json:"method"`
	PassID int    `json:"pass_id"`
	Pass   string `json:"pass"` // hex
	KeyLen int    `json:"key_len"`
}

type aeadParams struct {
	Method string `json:"method"`
	PassID int    `json:"pass_id"`
	Pass   string `json:"pass"` // hex
	KeyLen int    `json:"key_len"`
	Nonce  string `json:"nonce"` // hex
}

func genCrypt() ([]any, error) {
	var cases []any
	add := func(c Case) { cases = append(cases, c) }

	// pbkdf2: pass = PBKDF2-HMAC-SHA1(key, "kcp-go", 4096, 32), as kcptun client/server main.go.
	for _, k := range pbkdf2Keys {
		add(Case{
			Name:   "pbkdf2/" + k.label,
			Params: pbkdf2Params{Key: k.key, Salt: std.SALT, Iter: std.KeyIter, DkLen: std.KeyLen},
			In:     hx([]byte(k.key)),
			Out:    hx(std.DeriveKey(k.key)),
		})
	}

	passes := make([][]byte, len(cryptPassKeys))
	for i, k := range cryptPassKeys {
		passes[i] = std.DeriveKey(k)
	}

	// xor_pad: the xortbl of NewSimpleXORBlockCrypt, read back by encrypting zeros.
	for id, pass := range passes {
		pad, err := xorPad(pass)
		if err != nil {
			return nil, err
		}
		add(Case{
			Name:   fmt.Sprintf("xor_pad/pass_id=%d", id),
			Params: xorPadParams{PassID: id, Pass: hx(pass)},
			Out:    hx(pad),
		})
	}

	// select: SelectBlockCrypt for every name, with the full 32-byte pass (as kcptun) and,
	// in select_short, with a 16-byte pass that makes 3des fail and fall back to aes.
	plain := randBytes(newRNG("crypt", streamSelectPlain), selectPlainLen)
	aeadNonce := randBytes(newRNG("crypt", streamAeadNonce), 12)
	for _, g := range []struct {
		group string
		pass  []byte
	}{{"select", passes[0]}, {"select_short", passes[0][:16]}} {
		for _, method := range selectMethods {
			c, err := selectCase(g.group, method, g.pass, plain, aeadNonce)
			if err != nil {
				return nil, err
			}
			add(c)
		}
	}

	// cfb: whole-packet Encrypt of nonce + crc placeholder + payload.
	nonce := randBytes(newRNG("crypt", streamCfbNonce), cryptNonceLen)
	for _, method := range cfbMethods {
		for id, pass := range passes {
			block, eff := std.SelectBlockCrypt(method, pass)
			if block == nil || eff != method {
				return nil, fmt.Errorf("cfb: SelectBlockCrypt(%q) = %v, %q", method, block, eff)
			}
			for _, n := range cfbLens {
				in := make([]byte, 0, n)
				in = append(in, nonce...)
				in = append(in, make([]byte, cryptCRCLen)...)
				in = append(in, randBytes(newRNG("crypt", streamCfbPayload+uint64(n)), n-len(in))...)
				out, err := encryptPacket(block, in)
				if err != nil {
					return nil, fmt.Errorf("cfb %s pass %d len %d: %w", method, id, n, err)
				}
				add(Case{
					Name:   fmt.Sprintf("cfb/%s/pass_id=%d/len=%d", method, id, n),
					Params: cfbParams{Method: method, PassID: id, Pass: hx(pass), KeyLen: keyLen(method, eff, pass)},
					In:     hx(in),
					Out:    hx(out),
				})
			}
		}
	}

	// aead: out = nonce || Seal(nonce, plaintext), the aes-128-gcm packet layout of sess.go.
	for id, pass := range passes {
		block, eff := std.SelectBlockCrypt(aeadMethod, pass)
		if block == nil || eff != aeadMethod {
			return nil, fmt.Errorf("aead: SelectBlockCrypt(%q) = %v, %q", aeadMethod, block, eff)
		}
		for _, n := range aeadPlainLens {
			in := randBytes(newRNG("crypt", streamAeadPlain+uint64(n)), n)
			out, err := sealPacket(block, aeadNonce, in)
			if err != nil {
				return nil, fmt.Errorf("aead pass %d len %d: %w", id, n, err)
			}
			add(Case{
				Name: fmt.Sprintf("aead/pass_id=%d/len=%d", id, n),
				Params: aeadParams{Method: aeadMethod, PassID: id, Pass: hx(pass),
					KeyLen: keyLen(aeadMethod, eff, pass), Nonce: hx(aeadNonce)},
				In:  hx(in),
				Out: hx(out),
			})
		}
	}
	return cases, nil
}

// xorPad returns the 1500-byte pad of NewSimpleXORBlockCrypt(pass), obtained through the
// public API by encrypting zeros, and cross-checks it against the documented derivation.
func xorPad(pass []byte) ([]byte, error) {
	block, err := kcp.NewSimpleXORBlockCrypt(pass)
	if err != nil {
		return nil, err
	}
	pad := make([]byte, xorPadLen)
	block.Encrypt(pad, pad)
	if want := pbkdf2.Key(pass, []byte(saltXor), xorIter, xorPadLen, sha1.New); !bytes.Equal(pad, want) {
		return nil, fmt.Errorf("xor pad differs from PBKDF2-HMAC-SHA1(pass, %q, %d, %d)", saltXor, xorIter, xorPadLen)
	}
	return pad, nil
}

// selectCase runs SelectBlockCrypt(method, pass), capturing its log output, and encrypts
// plain with the result (sealing with nonce for aes-128-gcm).
func selectCase(group, method string, pass, plain, nonce []byte) (Case, error) {
	block, eff, logged := selectBlockCryptLogged(method, pass)
	p := selectParams{Method: method, Pass: hx(pass), Effective: eff, Nil: block == nil, Log: logged}
	c := Case{Name: fmt.Sprintf("%s/method=%s", group, method), Params: &p, In: hx(plain)}
	if block == nil {
		if eff != "null" {
			return Case{}, fmt.Errorf("%s: SelectBlockCrypt(%q) returned nil with effective %q", group, method, eff)
		}
		return c, nil
	}
	p.KeyLen = keyLen(method, eff, pass)
	out, err := encryptAny(block, plain, nonce)
	if err != nil {
		return Case{}, fmt.Errorf("%s %q: %w", c.Name, method, err)
	}
	if _, ok := block.(aeadCrypt); ok {
		p.Nonce = hx(nonce)
	}
	// Consistency check: rebuilding the effective method from pass[:key_len] must agree. This
	// confirms the effective method; for sized methods SelectBlockCrypt re-slices the key, so
	// it does not by itself prove the exact key_len (that comes from the copied table).
	check, checkEff, _ := selectBlockCryptLogged(eff, pass[:p.KeyLen])
	if checkEff != eff || check == nil {
		return Case{}, fmt.Errorf("%s: rebuilding %q from %d key bytes gave %q", c.Name, eff, p.KeyLen, checkEff)
	}
	if again, err := encryptAny(check, plain, nonce); err != nil || !bytes.Equal(again, out) {
		return Case{}, fmt.Errorf("%s: %q from pass[:%d] encrypts differently (%v)", c.Name, eff, p.KeyLen, err)
	}
	c.Out = hx(out)
	return c, nil
}

// selectBlockCryptLogged calls std.SelectBlockCrypt with the standard logger redirected, and
// returns what it logged (flags off, trailing newline removed).
func selectBlockCryptLogged(method string, pass []byte) (kcp.BlockCrypt, string, string) {
	var buf bytes.Buffer
	w, flags, prefix := log.Writer(), log.Flags(), log.Prefix()
	log.SetOutput(&buf)
	log.SetFlags(0)
	log.SetPrefix("")
	block, eff := std.SelectBlockCrypt(method, pass)
	log.SetOutput(w)
	log.SetFlags(flags)
	log.SetPrefix(prefix)
	return block, eff, strings.TrimSuffix(buf.String(), "\n")
}

// keyLen is the number of bytes of pass that SelectBlockCrypt handed to the constructor of
// the effective method, following the cryptMethods table of kcptun std/crypt.go. Unknown
// methods and constructor failures fall back to NewAESBlockCrypt(pass). selectCase rebuilds
// the cipher from pass[:keyLen] as a consistency check (it confirms the effective method,
// not the exact keyLen for methods whose table entry re-slices the key).
func keyLen(method, effective string, pass []byte) int {
	size, ok := std.CryptKeySize(method)
	switch {
	case effective == "null":
		return 0
	case !ok || effective != method:
		return len(pass)
	case size > 0 && len(pass) >= size:
		return size
	default:
		return len(pass)
	}
}

// encryptAny encrypts plain with block: a whole-packet Encrypt, or nonce || Seal for AEAD.
func encryptAny(block kcp.BlockCrypt, plain, nonce []byte) ([]byte, error) {
	if _, ok := block.(aeadCrypt); ok {
		return sealPacket(block, nonce, plain)
	}
	return encryptPacket(block, plain)
}

// encryptPacket returns Encrypt(in) computed in place, as sess.go does, after checking that
// an out-of-place Encrypt gives the same bytes and that Decrypt restores in (both in place
// and out of place).
func encryptPacket(block kcp.BlockCrypt, in []byte) ([]byte, error) {
	out := bytes.Clone(in)
	block.Encrypt(out, out)
	sep := make([]byte, len(in))
	block.Encrypt(sep, in)
	if !bytes.Equal(sep, out) {
		return nil, fmt.Errorf("out-of-place Encrypt differs from in-place Encrypt")
	}
	dec := bytes.Clone(out)
	block.Decrypt(dec, dec)
	if !bytes.Equal(dec, in) {
		return nil, fmt.Errorf("in-place Decrypt(Encrypt(in)) != in")
	}
	sep = make([]byte, len(out))
	block.Decrypt(sep, out)
	if !bytes.Equal(sep, in) {
		return nil, fmt.Errorf("out-of-place Decrypt(Encrypt(in)) != in")
	}
	return out, nil
}

// sealPacket returns nonce || Seal(nonce, plain) with no additional data, sealing into a
// buffer with room for the tag as sess.go does, and checks that Open restores plain.
func sealPacket(block kcp.BlockCrypt, nonce, plain []byte) ([]byte, error) {
	a, ok := block.(aeadCrypt)
	if !ok {
		return nil, fmt.Errorf("%T is not an AEAD crypt", block)
	}
	if a.NonceSize() != len(nonce) || a.Overhead() != 16 {
		return nil, fmt.Errorf("AEAD nonce size %d, overhead %d; want %d, 16", a.NonceSize(), a.Overhead(), len(nonce))
	}
	buf := make([]byte, len(nonce), len(nonce)+len(plain)+a.Overhead())
	copy(buf, nonce)
	sealed := a.Seal(buf[len(nonce):], nonce, plain, nil)
	out := buf[:len(nonce)+len(sealed)]
	opened, err := a.Open(nil, nonce, sealed, nil)
	if err != nil {
		return nil, fmt.Errorf("Open(Seal(plain)): %w", err)
	}
	if !bytes.Equal(opened, plain) {
		return nil, fmt.Errorf("Open(Seal(plain)) != plain")
	}
	return out, nil
}
