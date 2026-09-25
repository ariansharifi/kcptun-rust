package main

// Packet crypto benchmarks (plan step 02.6, BenchmarkCrypt) and Reed-Solomon benchmarks (plan
// step 04.2, BenchmarkRS), the Go sides of crates/kcp/benches/crypt.rs and
// crates/kcp/benches/rs.rs respectively.
//
// BenchmarkCrypt and its Rust counterpart benchmark the same thing: one whole packet (nonce + crc + payload) encrypted or decrypted
// in place, as kcp-go's sess.go does (Encrypt(buf, buf), Decrypt(data, data)), with the pinned
// kcp-go v5.6.66 ciphers chosen and keyed exactly as kcptun does (SelectBlockCrypt with the
// pass derived from the default -key). b.SetBytes is the packet length, so ns/op and MB/s are
// per packet. For aes-128-gcm a "packet" of length L is nonce(12) + plaintext(L-28) + tag(16):
// "encrypt" is Seal in place and "decrypt" is Open in place of a freshly copied sealed packet
// (Open overwrites its input; the Rust bench does the same copy).
//
// Run (see docs/benchmarks/crypto.md):
//
//	cd tools/govectors && go test -run '^$' -bench Crypt -benchtime 2s
//
// Run (see docs/benchmarks/fec.md):
//
//	cd tools/govectors && go test -run '^$' -bench RS -benchtime 2s
//
// with GOMODCACHE=<repo>/reference/gomod GOFLAGS=-modcacherw GOTOOLCHAIN=local.

import (
	"fmt"
	"testing"

	"github.com/klauspost/reedsolomon"
	kcp "github.com/xtaci/kcp-go/v5"
	"github.com/xtaci/qpp"

	"github.com/kcptun-rust/tools/govectors/internal/std"
)

// benchCryptMethods are the -crypt values benchmarked: every method except null (no crypto).
var benchCryptMethods = []string{
	"aes", "aes-128", "aes-192", "aes-128-gcm", "salsa20", "blowfish", "twofish", "cast5",
	"3des", "tea", "xtea", "sm4", "xor", "none",
}

// benchPacketLens are the whole-packet lengths: kcptun's default MTU (1350) and kcp-go's
// mtuLimit (1500).
var benchPacketLens = []int{1350, 1500}

// benchPattern fills b with a fixed, non-trivial pattern (the content does not affect speed).
func benchPattern(b []byte) {
	for i := range b {
		b[i] = byte(i*131 + 7)
	}
}

// selectBenchCrypt returns kcptun's cipher for method, keyed with the default -key's pass.
func selectBenchCrypt(tb testing.TB, method string) kcp.BlockCrypt {
	tb.Helper()
	block, eff := std.SelectBlockCrypt(method, std.DeriveKey(defaultKey))
	if block == nil || eff != method {
		tb.Fatalf("SelectBlockCrypt(%q) = %v, %q", method, block, eff)
	}
	return block
}

func BenchmarkCrypt(b *testing.B) {
	for _, dir := range []string{"encrypt", "decrypt"} {
		for _, method := range benchCryptMethods {
			for _, n := range benchPacketLens {
				b.Run(fmt.Sprintf("%s/%s/%d", dir, method, n), func(b *testing.B) {
					block := selectBenchCrypt(b, method)
					if aead, ok := block.(aeadCrypt); ok {
						benchAead(b, aead, dir, n)
						return
					}
					buf := make([]byte, n)
					benchPattern(buf)
					b.SetBytes(int64(n))
					b.ReportAllocs()
					if dir == "encrypt" {
						for b.Loop() {
							block.Encrypt(buf, buf)
						}
					} else {
						for b.Loop() {
							block.Decrypt(buf, buf)
						}
					}
				})
			}
		}
	}
}

// benchAead measures Seal (encrypt) or Open (decrypt) of an n-byte packet in place, as
// sess.go:postProcess and sess.go:packetInput call them.
func benchAead(b *testing.B, aead aeadCrypt, dir string, n int) {
	const nonceSize, overhead = 12, 16
	buf := make([]byte, n)
	benchPattern(buf)
	plainLen := n - nonceSize - overhead
	nonce := buf[:nonceSize]
	b.SetBytes(int64(n))
	b.ReportAllocs()
	if dir == "encrypt" {
		for b.Loop() {
			aead.Seal(buf[:nonceSize], nonce, buf[nonceSize:nonceSize+plainLen], nil)
		}
		return
	}
	sealed := aead.Seal(buf[:nonceSize], nonce, buf[nonceSize:nonceSize+plainLen], nil)
	if len(sealed) != n {
		b.Fatalf("sealed %d bytes, want %d", len(sealed), n)
	}
	sealed = append([]byte(nil), sealed...)
	for b.Loop() {
		copy(buf, sealed)
		ct := buf[nonceSize:n]
		if _, err := aead.Open(ct[:0], buf[:nonceSize], ct, nil); err != nil {
			b.Fatal(err)
		}
	}
}

// Reed-Solomon shape benchmarked: kcptun's default -datashard 10 -parityshard 3 over 1370-byte
// shards (a full KCP segment at the default MTU), as kcp-go's fec.go codes them.
const (
	benchRSData   = 10
	benchRSParity = 3
	benchRSLen    = 1370
)

// benchRSMissing are the data shards removed in the ReconstructData benchmarks.
var benchRSMissing = [][]int{{0}, {0, 4, 9}}

// benchRSShards returns data shards filled with byte(i*131 + 7) over all data bytes (the same
// pattern as crates/kcp/benches/rs.rs) plus zeroed parity shards.
func benchRSShards() [][]byte {
	shards := make([][]byte, benchRSData+benchRSParity)
	for s := range shards {
		shards[s] = make([]byte, benchRSLen)
		if s < benchRSData {
			for i := range shards[s] {
				shards[s][i] = byte((s*benchRSLen+i)*131 + 7)
			}
		}
	}
	return shards
}

// BenchmarkRS measures klauspost/reedsolomon v1.13.0 (as pinned by kcp-go v5.6.66, default
// options) Encode and ReconstructData; b.SetBytes is the data bytes (10 x 1370). Before each
// ReconstructData the missing shards are resliced to length 0 (keeping their capacity), as
// kcp-go's fec.go hands them over. Results: docs/benchmarks/fec.md.
func BenchmarkRS(b *testing.B) {
	shape := fmt.Sprintf("%dx%d/%d", benchRSData, benchRSParity, benchRSLen)
	b.Run("encode/"+shape, func(b *testing.B) {
		enc, err := reedsolomon.New(benchRSData, benchRSParity)
		if err != nil {
			b.Fatal(err)
		}
		shards := benchRSShards()
		b.SetBytes(benchRSData * benchRSLen)
		b.ReportAllocs()
		for b.Loop() {
			if err := enc.Encode(shards); err != nil {
				b.Fatal(err)
			}
		}
	})
	for _, missing := range benchRSMissing {
		b.Run(fmt.Sprintf("reconstruct_data/%s/missing%d", shape, len(missing)), func(b *testing.B) {
			enc, err := reedsolomon.New(benchRSData, benchRSParity)
			if err != nil {
				b.Fatal(err)
			}
			shards := benchRSShards()
			if err := enc.Encode(shards); err != nil {
				b.Fatal(err)
			}
			want := make([][]byte, len(shards))
			for i := range shards {
				want[i] = append([]byte(nil), shards[i]...)
			}
			b.SetBytes(benchRSData * benchRSLen)
			b.ReportAllocs()
			for b.Loop() {
				for _, m := range missing {
					shards[m] = shards[m][:0]
				}
				if err := enc.ReconstructData(shards); err != nil {
					b.Fatal(err)
				}
			}
			for _, m := range missing {
				if string(shards[m]) != string(want[m]) {
					b.Fatalf("shard %d not reconstructed", m)
				}
			}
		})
	}
}

// QPP benchmarks (plan step 07.2, BenchmarkQPP), the Go side of crates/qpp/benches/qpp.rs.
//
// The shape is Go's own qpp_test.go:BenchmarkQPP: 64 pads, a message encrypted in place, one
// call per iteration, b.SetBytes the message length: extended to the sizes kcptun sees and to
// decryption, plus the 7-byte chunking that never lines up with the 8-byte pad switch, and the
// two setup costs (one NewQPP per session, one CreatePRNG per stream).
//
// Run (results in the 07.2 commit message):
//
//	cd tools/govectors && go test -run '^$' -bench QPP -benchtime 1s
func BenchmarkQPP(b *testing.B) {
	seed := []byte(defaultKey) // the QPP seed is the raw -key, not the PBKDF2 pass
	const benchPads = 64
	q := qpp.NewQPP(seed, benchPads)

	for _, size := range []int{512, 1350, 8192, 65536} {
		msg := make([]byte, size)
		benchPattern(msg)
		b.Run(fmt.Sprintf("encrypt/%d", size), func(b *testing.B) {
			rand := qpp.CreatePRNG(seed)
			b.SetBytes(int64(size))
			for b.Loop() {
				q.EncryptWithPRNG(msg, rand)
			}
		})
		b.Run(fmt.Sprintf("decrypt/%d", size), func(b *testing.B) {
			rand := qpp.CreatePRNG(seed)
			b.SetBytes(int64(size))
			for b.Loop() {
				q.DecryptWithPRNG(msg, rand)
			}
		})
	}

	msg := make([]byte, 8192)
	benchPattern(msg)
	b.Run("encrypt/chunked=7", func(b *testing.B) {
		rand := qpp.CreatePRNG(seed)
		off := 0
		b.SetBytes(7)
		for b.Loop() {
			q.EncryptWithPRNG(msg[off:off+7], rand)
			off = (off + 7) % (len(msg) - 7)
		}
	})

	for _, pads := range []uint16{1, 7, 61, 1024} {
		b.Run(fmt.Sprintf("new/%d", pads), func(b *testing.B) {
			for b.Loop() {
				_ = qpp.NewQPP(seed, pads)
			}
		})
	}
	b.Run("create_prng", func(b *testing.B) {
		for b.Loop() {
			_ = qpp.CreatePRNG(seed)
		}
	})
	b.Run("fast_prng", func(b *testing.B) {
		for b.Loop() {
			_ = qpp.FastPRNG(seed)
		}
	})
}
