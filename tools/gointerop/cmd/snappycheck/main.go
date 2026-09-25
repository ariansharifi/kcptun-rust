// Command snappycheck exercises the snappy framing format exactly as kcptun uses it.
//
//	snappycheck decode [-o FILE]   < framed        prints {"ok":true,"len":N,"sha256":"…"}
//	snappycheck encode [-chunk 8200[,…]] < raw  > framed
//
// decode reads a framed snappy stream from stdin with snappy.NewReader (kcptun's
// CompStream read side) and prints the length and SHA-256 of the decoded bytes. On a decode
// error it prints {"ok":false,"len":<decoded so far>,"sha256":"…","error":"<Go error text>"}
// and exits 1; the error text is snappy's (e.g. "snappy: corrupt input"). -o also writes the
// decoded bytes to FILE.
//
// encode reads stdin in chunks (sizes cycle through the -chunk list; each chunk is read in
// full except the last) and passes every chunk to kcptun's CompStream.Write (verbatim copy in
// internal/std): one snappy.Writer.Write plus Flush per chunk, as kcptun does for every
// write to a compressed KCP session. The framed output goes to stdout. Empty input produces
// empty output (the stream identifier is only written with the first chunk).
//
// Exit status: 0 success, 1 decode or I/O error, 2 bad usage, 3 pinned-version mismatch.
package main

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"os"
	"time"

	"github.com/golang/snappy"

	"github.com/kcptun-rust/tools/gointerop/internal/peer"
	"github.com/kcptun-rust/tools/gointerop/internal/std"
)

const prog = "snappycheck"

func main() {
	peer.CheckPinned(prog)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "decode":
		os.Exit(runDecode(os.Args[2:]))
	case "encode":
		os.Exit(runEncode(os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s decode [-o FILE] | encode [-chunk N[,N...]]\n", prog)
	os.Exit(2)
}

func parse(fs *flag.FlagSet, args []string) {
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(2)
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "%s: unexpected arguments: %v\n", prog, fs.Args())
		os.Exit(2)
	}
}

type decodeReport struct {
	OK     bool   `json:"ok"`
	Len    int64  `json:"len"`
	SHA256 string `json:"sha256"`
	Error  string `json:"error,omitempty"`
}

func runDecode(args []string) int {
	fs := flag.NewFlagSet(prog+" decode", flag.ContinueOnError)
	out := fs.String("o", "", "also write the decoded bytes to this file")
	parse(fs, args)

	h := sha256.New()
	var dst io.Writer = h
	var f *os.File
	var bw *bufio.Writer
	if *out != "" {
		var err error
		if f, err = os.Create(*out); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
			return 1
		}
		bw = bufio.NewWriter(f)
		dst = io.MultiWriter(h, bw)
	}

	n, err := io.Copy(dst, snappy.NewReader(bufio.NewReader(os.Stdin)))
	if bw != nil {
		if ferr := bw.Flush(); ferr != nil && err == nil {
			err = ferr
		}
		if cerr := f.Close(); cerr != nil && err == nil {
			err = cerr
		}
	}
	rep := decodeReport{OK: err == nil, Len: n, SHA256: hex.EncodeToString(h.Sum(nil))}
	if err != nil {
		rep.Error = err.Error()
	}
	peer.PrintJSON(rep)
	if err != nil {
		return 1
	}
	return 0
}

func runEncode(args []string) int {
	fs := flag.NewFlagSet(prog+" encode", flag.ContinueOnError)
	chunkList := fs.String("chunk", "8200", "comma-separated chunk sizes, cycled")
	parse(fs, args)
	sizes, err := peer.ParseChunks(*chunkList)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		return 2
	}

	out := bufio.NewWriterSize(os.Stdout, 256*1024)
	cs := std.NewCompStream(&stdioConn{w: out})
	if _, err := peer.ChunkedCopy(cs, bufio.NewReader(os.Stdin), sizes, nil); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		return 1
	}
	if err := out.Flush(); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		return 1
	}
	return 0
}

// stdioConn is the minimal net.Conn that std.NewCompStream needs: writes go to w. The
// compressed stream is never read in encode mode.
type stdioConn struct{ w io.Writer }

func (c *stdioConn) Read([]byte) (int, error)         { return 0, io.EOF }
func (c *stdioConn) Write(p []byte) (int, error)      { return c.w.Write(p) }
func (c *stdioConn) Close() error                     { return nil }
func (c *stdioConn) LocalAddr() net.Addr              { return stdioAddr{} }
func (c *stdioConn) RemoteAddr() net.Addr             { return stdioAddr{} }
func (c *stdioConn) SetDeadline(time.Time) error      { return nil }
func (c *stdioConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stdioConn) SetWriteDeadline(time.Time) error { return nil }

type stdioAddr struct{}

func (stdioAddr) Network() string { return "stdio" }
func (stdioAddr) String() string  { return "stdio" }
