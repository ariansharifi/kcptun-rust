// Command qppcheck exercises Quantum Permutation Pads exactly as kcptun's std.QPPPort does.
//
//	qppcheck encrypt [-key K] [-pads 61] [-chunk 4096[,…]] < plain  > cipher
//	qppcheck decrypt [-key K] [-pads 61] [-chunk 4096[,…]] < cipher > plain
//	qppcheck pads    [-key K] [-pads 61]                   prints {"pads":…,"pads_sha256":"…",…}
//
// As in kcptun (client/server main.go and std/qpp.go), the pad is
// qpp.NewQPP([]byte(key), uint16(pads)) with the raw -key as seed (no PBKDF2), and one PRNG per
// direction is qpp.CreatePRNG([]byte(key)). encrypt/decrypt read stdin in chunks whose sizes
// cycle through the -chunk list (each read in full except the last) and apply
// EncryptWithPRNG / DecryptWithPRNG to each chunk with the same PRNG, so the PRNG state
// carries across chunk boundaries like it does across QPPPort writes. Different chunkings must
// therefore produce the same output.
//
// pads prints the SHA-256 of the encryption pads and of the reverse (decryption) pads, their
// length (pads * 256) and the first 32 bytes of each, as one JSON line. The pads are unexported
// in qpp, so they are read with reflect.
//
// Exit status: 0 success, 1 I/O error, 2 bad usage, 3 pinned-version mismatch.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"os"
	"reflect"
	"unsafe"

	"github.com/xtaci/qpp"

	"github.com/kcptun-rust/tools/gointerop/internal/peer"
)

const prog = "qppcheck"

func main() {
	peer.CheckPinned(prog)
	if len(os.Args) < 2 {
		usage()
	}
	mode := os.Args[1]
	switch mode {
	case "encrypt", "decrypt", "pads":
	default:
		usage()
	}

	fs := flag.NewFlagSet(prog+" "+mode, flag.ContinueOnError)
	key := fs.String("key", "it's a secrect", "QPP seed (kcptun uses the raw -key)")
	pads := fs.Int("pads", 61, "number of pads (kcptun -QPPCount)")
	chunkList := fs.String("chunk", "4096", "comma-separated chunk sizes, cycled (encrypt/decrypt)")
	if err := fs.Parse(os.Args[2:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "%s: unexpected arguments: %v\n", prog, fs.Args())
		os.Exit(2)
	}
	if *pads < 1 || *pads > 65535 {
		fmt.Fprintf(os.Stderr, "%s: -pads must be in 1..65535\n", prog)
		os.Exit(2)
	}
	sizes, err := peer.ParseChunks(*chunkList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(2)
	}

	seed := []byte(*key)
	pad := qpp.NewQPP(seed, uint16(*pads))
	if mode == "pads" {
		printPads(pad, *pads)
		return
	}

	prng := qpp.CreatePRNG(seed)
	fn := func(b []byte) { pad.EncryptWithPRNG(b, prng) }
	if mode == "decrypt" {
		fn = func(b []byte) { pad.DecryptWithPRNG(b, prng) }
	}
	out := bufio.NewWriterSize(os.Stdout, 256*1024)
	if _, err := peer.ChunkedCopy(out, bufio.NewReader(os.Stdin), sizes, fn); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(1)
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(1)
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s encrypt|decrypt|pads [-key K] [-pads N] [-chunk N[,N...]]\n", prog)
	os.Exit(2)
}

type padsReport struct {
	Pads        int    `json:"pads"`
	Len         int    `json:"len"`
	PadsSHA256  string `json:"pads_sha256"`
	RPadsSHA256 string `json:"rpads_sha256"`
	PadsHead    string `json:"pads_head"`
	RPadsHead   string `json:"rpads_head"`
}

// unexportedBytes reads the unexported []byte field name of *q.
func unexportedBytes(q *qpp.QuantumPermutationPad, name string) []byte {
	f := reflect.ValueOf(q).Elem().FieldByName(name)
	if !f.IsValid() || f.Type() != reflect.TypeOf([]byte(nil)) {
		fmt.Fprintf(os.Stderr, "%s: qpp.QuantumPermutationPad has no []byte field %q\n", prog, name)
		os.Exit(1)
	}
	return *(*[]byte)(unsafe.Pointer(f.UnsafeAddr()))
}

func printPads(q *qpp.QuantumPermutationPad, n int) {
	p := unexportedBytes(q, "pads")
	r := unexportedBytes(q, "rpads")
	ps, rs := sha256.Sum256(p), sha256.Sum256(r)
	head := func(b []byte) string { return hex.EncodeToString(b[:min(32, len(b))]) }
	peer.PrintJSON(padsReport{
		Pads:        n,
		Len:         len(p),
		PadsSHA256:  hex.EncodeToString(ps[:]),
		RPadsSHA256: hex.EncodeToString(rs[:]),
		PadsHead:    head(p),
		RPadsHead:   head(r),
	})
}
