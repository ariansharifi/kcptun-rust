// Command smuxecho is an smux-over-TCP echo peer for interop tests.
//
//	smuxecho server -listen 127.0.0.1:20001 [smux flags]
//	smuxecho client -remote 127.0.0.1:20001 [smux flags] [-streams K -bytes N -seed S -chunk C -timeout T]
//
// smux flags mirror kcptun's: -ver 1|2, -smuxbuf, -streambuf, -framesize, -keepalive (seconds),
// with kcptun's defaults; the smux.Config is built with kcptun's std.BuildSmuxConfig
// (verbatim copy in internal/std).
//
// The server prints "listening on: <addr>" on stdout, runs smux.Server on every accepted TCP
// connection and echoes every stream with kcptun's half-close semantics (std.Pipe): copy the
// stream into itself until EOF, then CloseWrite, then Close.
//
// The client runs smux.Client on one TCP connection and opens K streams concurrently. Stream
// i sends -bytes of the deterministic stream with seed (-seed + i) (internal/peer.Stream),
// then CloseWrite; it reads the echo to EOF and verifies it. One JSON line summarises:
//
//	{"ok":true,"streams":K,"bytes_per_stream":N,"total_bytes":K*N,"duration_ms":D,
//	 "results":[{"index":0,"id":1,"seed":S,"received":N,"sha256":"…","ok":true},…]}
//
// Exit status: 0 success, 1 failure, 2 bad usage, 3 pinned-version mismatch.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/xtaci/smux"

	"github.com/kcptun-rust/tools/gointerop/internal/peer"
	"github.com/kcptun-rust/tools/gointerop/internal/std"
)

const prog = "smuxecho"

type smuxFlags struct {
	ver, smuxbuf, streambuf, framesize, keepalive int
}

func (s *smuxFlags) register(fs *flag.FlagSet) {
	fs.IntVar(&s.ver, "ver", 2, "smux protocol version, 1 or 2")
	fs.IntVar(&s.smuxbuf, "smuxbuf", 4194304, "smux session receive buffer in bytes")
	fs.IntVar(&s.streambuf, "streambuf", 2097152, "per-stream receive buffer in bytes (v2)")
	fs.IntVar(&s.framesize, "framesize", 8192, "smux maximum frame size")
	fs.IntVar(&s.keepalive, "keepalive", 10, "keepalive interval in seconds")
}

func (s *smuxFlags) config() (*smux.Config, error) {
	return std.BuildSmuxConfig(s.ver, s.smuxbuf, s.streambuf, s.framesize, s.keepalive)
}

func main() {
	peer.CheckPinned(prog)
	log.SetPrefix(prog + ": ")
	log.SetOutput(os.Stderr)
	if len(os.Args) < 2 {
		usage()
	}
	switch os.Args[1] {
	case "server":
		os.Exit(runServer(os.Args[2:]))
	case "client":
		os.Exit(runClient(os.Args[2:]))
	default:
		usage()
	}
}

func usage() {
	fmt.Fprintf(os.Stderr, "usage: %s server|client [flags]   (%s server -h for the flags)\n", prog, prog)
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

func runServer(args []string) int {
	fs := flag.NewFlagSet(prog+" server", flag.ContinueOnError)
	var s smuxFlags
	s.register(fs)
	listen := fs.String("listen", "127.0.0.1:0", "TCP address to listen on")
	parse(fs, args)
	cfg, err := s.config()
	if err != nil {
		log.Println(err)
		return 2
	}

	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Println(err)
		return 1
	}
	fmt.Printf("listening on: %v\n", ln.Addr())
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Println("accept:", err)
			return 1
		}
		go serveConn(conn, cfg)
	}
}

func serveConn(conn net.Conn, cfg *smux.Config) {
	log.Println("remote address:", conn.RemoteAddr())
	mux, err := smux.Server(conn, cfg)
	if err != nil {
		log.Println(err)
		conn.Close()
		return
	}
	defer mux.Close()
	for {
		stream, err := mux.AcceptStream()
		if err != nil {
			log.Printf("session %v: %v", conn.RemoteAddr(), err)
			return
		}
		go echoStream(stream)
	}
}

// echoStream mirrors one direction of kcptun's std.Pipe with the stream as both ends:
// Copy (the stream's WriteTo), then CloseWrite for half-close, then Close.
func echoStream(s *smux.Stream) {
	n, err := io.Copy(s, s)
	if err != nil && err != io.EOF { // smux's WriteTo reports the peer's FIN as io.EOF
		log.Printf("stream %d: copy: %v (echoed %d bytes)", s.ID(), err, n)
	}
	if err := s.CloseWrite(); err != nil {
		log.Printf("stream %d: CloseWrite: %v", s.ID(), err)
	}
	s.Close()
}

type streamResult struct {
	Index    int    `json:"index"`
	ID       uint32 `json:"id"`
	Seed     uint64 `json:"seed"`
	Received int64  `json:"received"`
	SHA256   string `json:"sha256"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
}

type clientReport struct {
	OK             bool           `json:"ok"`
	Version        int            `json:"ver"`
	Streams        int            `json:"streams"`
	BytesPerStream int64          `json:"bytes_per_stream"`
	TotalBytes     int64          `json:"total_bytes"`
	DurationMs     int64          `json:"duration_ms"`
	Error          string         `json:"error,omitempty"`
	Results        []streamResult `json:"results"`
}

func runClient(args []string) int {
	fs := flag.NewFlagSet(prog+" client", flag.ContinueOnError)
	var s smuxFlags
	s.register(fs)
	remote := fs.String("remote", "127.0.0.1:29900", "TCP address of the echo server")
	nstreams := fs.Int("streams", 4, "number of concurrent streams")
	nbytes := fs.Int64("bytes", 1<<20, "bytes to send on each stream")
	seed := fs.Uint64("seed", 1, "seed of stream 0; stream i uses seed+i")
	chunk := fs.Int("chunk", 32*1024, "bytes per Write call")
	timeout := fs.Int("timeout", 60, "overall deadline in seconds, 0 none")
	early := fs.Bool("early-closewrite", false, "CloseWrite right after sending (kcptun Pipe order) instead of after the whole echo arrived; exposes the pinned smux bug described in the README")
	parse(fs, args)
	if *nstreams <= 0 || *nbytes < 0 || *chunk <= 0 {
		fmt.Fprintf(os.Stderr, "%s: -streams and -chunk must be > 0, -bytes >= 0\n", prog)
		return 2
	}
	cfg, err := s.config()
	if err != nil {
		log.Println(err)
		return 2
	}

	start := time.Now()
	var deadline time.Time
	if *timeout > 0 {
		deadline = start.Add(time.Duration(*timeout) * time.Second)
	}
	rep := clientReport{Version: s.ver, Streams: *nstreams, BytesPerStream: *nbytes, TotalBytes: int64(*nstreams) * *nbytes}
	fail := func(err error) int {
		rep.Error = err.Error()
		rep.DurationMs = time.Since(start).Milliseconds()
		peer.PrintJSON(rep)
		return 1
	}

	conn, err := net.DialTimeout("tcp", *remote, 10*time.Second)
	if err != nil {
		return fail(err)
	}
	mux, err := smux.Client(conn, cfg)
	if err != nil {
		conn.Close()
		return fail(err)
	}
	defer mux.Close()

	rep.Results = make([]streamResult, *nstreams)
	var wg sync.WaitGroup
	for i := 0; i < *nstreams; i++ {
		st, err := mux.OpenStream()
		if err != nil {
			// Stop the already started streams and wait for them so rep.Results is not
			// written concurrently with the JSON encoding in fail.
			mux.Close()
			wg.Wait()
			return fail(fmt.Errorf("OpenStream %d: %w", i, err))
		}
		if !deadline.IsZero() {
			st.SetDeadline(deadline)
		}
		wg.Add(1)
		go func(i int, st *smux.Stream) {
			defer wg.Done()
			rep.Results[i] = runStream(i, st, *seed+uint64(i), *nbytes, *chunk, *early)
		}(i, st)
	}
	wg.Wait()
	rep.DurationMs = time.Since(start).Milliseconds()
	rep.OK = true
	for _, r := range rep.Results {
		rep.OK = rep.OK && r.OK
	}
	peer.PrintJSON(rep)
	if !rep.OK {
		return 1
	}
	return 0
}

// runStream sends the (seed, n) stream, half-closes, and verifies the echo up to EOF.
//
// By default CloseWrite is called only once all n echoed bytes have been read. With early
// set it is called as soon as everything was sent, like kcptun's std.Pipe does; with the
// pinned smux (v1.5.55, also current upstream) the stream is then torn down when the peer's
// FIN arrives (tryHalfCloseCleanup -> streamClosed -> recycleTokens), discarding echoed
// bytes that were received but not yet read, so the echo may come up short.
func runStream(i int, st *smux.Stream, seed uint64, n int64, chunk int, early bool) streamResult {
	defer st.Close()
	res := streamResult{Index: i, ID: st.ID(), Seed: seed}
	writeErr := make(chan error, 1)
	echoed := make(chan struct{})
	go func() {
		src := peer.NewStream(seed, n)
		buf := make([]byte, chunk)
		for {
			m, err := src.Read(buf)
			if err == io.EOF {
				if !early {
					<-echoed
				}
				writeErr <- st.CloseWrite()
				return
			}
			if _, err := st.Write(buf[:m]); err != nil {
				writeErr <- fmt.Errorf("write: %w", err)
				return
			}
		}
	}()

	v := peer.NewVerifier(seed, n)
	var err error
	buf := make([]byte, 64*1024)
	signalled := false
	for {
		if !signalled && v.Done() {
			close(echoed)
			signalled = true
		}
		m, rerr := st.Read(buf)
		if m > 0 {
			if _, verr := v.Write(buf[:m]); verr != nil {
				err = verr
				break
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			err = fmt.Errorf("read: %w", rerr)
			break
		}
	}
	if !signalled {
		close(echoed) // let the writer finish; the result is a failure anyway
	}
	if err == nil {
		if werr := <-writeErr; werr != nil {
			err = werr
		} else if !v.Done() {
			err = fmt.Errorf("echo ended after %d of %d bytes", v.Received(), n)
		}
	}
	res.Received = v.Received()
	res.SHA256 = v.SHA256()
	res.OK = err == nil
	if err != nil {
		res.Error = err.Error()
	}
	return res
}
