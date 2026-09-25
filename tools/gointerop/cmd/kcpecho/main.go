// Command kcpecho is a raw kcp-go echo peer (no smux, no compression) for interop tests.
//
//	kcpecho server -listen 127.0.0.1:20000 [KCP flags] [-idle 60]
//	kcpecho client -remote 127.0.0.1:20000 [KCP flags] [-bytes N -seed S -chunk C -timeout T]
//
// The KCP flags mirror kcptun's knobs (-crypt -key -ds -ps -mtu -sndwnd -rcvwnd -nodelay
// -interval -resend -nc -acknodelay -stream -writedelay -dscp -sockbuf -ratelimit) with
// kcptun's defaults ("fast" mode for nodelay/interval/resend/nc). The key is derived and
// the cipher selected exactly like kcptun (internal/std), and the session options are
// applied in the same order as kcptun's client (createConn) and server (serveListener).
//
// The server prints "listening on: <addr>" on stdout once the UDP socket is bound, then
// echoes every accepted session until it fails or stays idle for -idle seconds (KCP has
// no close handshake, so the idle timeout reaps sessions of finished clients).
//
// The client sends -bytes of the deterministic stream (internal/peer.Stream, seed -seed),
// reads the echo concurrently, verifies it byte by byte and prints one JSON line:
//
//	{"ok":true,"bytes":N,"received":N,"duration_ms":D,"sha256":"…","expected_sha256":"…",
//	 "crypt":"aes","snmp":{"BytesSent":…,…}}
//
// "sha256" hashes the received echo, "snmp" is kcp.DefaultSnmp with Go's field names. The
// exit status is 0 on success, 1 on mismatch, timeout or I/O error, 2 on bad usage and
// 3 if a pinned module is linked at the wrong version.
package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"time"

	kcp "github.com/xtaci/kcp-go/v5"

	"github.com/kcptun-rust/tools/gointerop/internal/peer"
	"github.com/kcptun-rust/tools/gointerop/internal/std"
)

const prog = "kcpecho"

// kcpFlags are kcptun's KCP knobs.
type kcpFlags struct {
	crypt, key                     string
	ds, ps, mtu, sndwnd, rcvwnd    int
	nodelay, interval, resend, nc  int
	acknodelay, stream, writedelay bool
	dscp, sockbuf, ratelimit       int
}

// register adds the KCP flags to fs. sndwnd/rcvwnd defaults differ between kcptun's
// client (128/512) and server (1024/1024).
func (k *kcpFlags) register(fs *flag.FlagSet, sndwnd, rcvwnd int) {
	fs.StringVar(&k.crypt, "crypt", "aes", "aes, aes-128, aes-192, salsa20, blowfish, twofish, cast5, 3des, tea, xtea, xor, sm4, none, null, aes-128-gcm")
	fs.StringVar(&k.key, "key", "it's a secrect", "pre-shared secret (PBKDF2 salt kcp-go, 4096 rounds, 32 bytes, SHA-1)")
	fs.IntVar(&k.ds, "ds", 10, "FEC data shards")
	fs.IntVar(&k.ps, "ps", 3, "FEC parity shards")
	fs.IntVar(&k.mtu, "mtu", 1350, "maximum transmission unit for UDP packets")
	fs.IntVar(&k.sndwnd, "sndwnd", sndwnd, "send window size (packets)")
	fs.IntVar(&k.rcvwnd, "rcvwnd", rcvwnd, "receive window size (packets)")
	fs.IntVar(&k.nodelay, "nodelay", 0, "KCP nodelay (kcptun mode fast: 0)")
	fs.IntVar(&k.interval, "interval", 30, "KCP update interval in ms (kcptun mode fast: 30)")
	fs.IntVar(&k.resend, "resend", 2, "KCP fast resend (kcptun mode fast: 2)")
	fs.IntVar(&k.nc, "nc", 1, "KCP no congestion control (kcptun mode fast: 1)")
	fs.BoolVar(&k.acknodelay, "acknodelay", false, "flush ACKs immediately")
	fs.BoolVar(&k.stream, "stream", true, "KCP stream mode (kcptun always uses true)")
	fs.BoolVar(&k.writedelay, "writedelay", false, "delay writes (kcptun always uses false)")
	fs.IntVar(&k.dscp, "dscp", 0, "DSCP value (6 bit)")
	fs.IntVar(&k.sockbuf, "sockbuf", 4194304, "UDP socket buffer size in bytes")
	fs.IntVar(&k.ratelimit, "ratelimit", 0, "outgoing rate limit in bytes per second, 0 disables")
}

func (k *kcpFlags) block() (kcp.BlockCrypt, string) {
	return std.SelectBlockCrypt(k.crypt, std.DeriveKey(k.key))
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
	var k kcpFlags
	k.register(fs, 1024, 1024)
	listen := fs.String("listen", "127.0.0.1:0", "UDP address to listen on")
	idle := fs.Int("idle", 60, "close a session after this many seconds without data, 0 never")
	parse(fs, args)

	block, crypt := k.block()
	lis, err := kcp.ListenWithOptions(*listen, block, k.ds, k.ps)
	if err != nil {
		log.Printf("ListenWithOptions: %v", err)
		return 1
	}
	// Go: kcptun server/main.go:serveListener() — listener options first.
	if err := lis.SetDSCP(k.dscp); err != nil {
		log.Println("SetDSCP:", err)
	}
	if err := lis.SetReadBuffer(k.sockbuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := lis.SetWriteBuffer(k.sockbuf); err != nil {
		log.Println("SetWriteBuffer:", err)
	}
	log.Printf("crypt: %s, ds %d, ps %d, mtu %d, stream %v", crypt, k.ds, k.ps, k.mtu, k.stream)
	fmt.Printf("listening on: %v\n", lis.Addr())

	for {
		conn, err := lis.AcceptKCP()
		if err != nil {
			log.Printf("AcceptKCP: %v", err)
			return 1
		}
		log.Println("remote address:", conn.RemoteAddr())
		// Go: kcptun server/main.go:serveListener() — per-session options, same order.
		conn.SetStreamMode(k.stream)
		conn.SetWriteDelay(k.writedelay)
		conn.SetNoDelay(k.nodelay, k.interval, k.resend, k.nc)
		if !conn.SetMtu(k.mtu) {
			log.Printf("SetMtu(%d) rejected", k.mtu)
		}
		conn.SetWindowSize(k.sndwnd, k.rcvwnd)
		conn.SetACKNoDelay(k.acknodelay)
		conn.SetRateLimit(uint32(k.ratelimit))
		go echo(conn, time.Duration(*idle)*time.Second)
	}
}

// echoBufSize exceeds the largest KCP message (255 fragments * mss, mss < 1500), so in
// message mode every Read returns exactly one whole message (kcp-go sess.go Read only
// splits a message across Reads when the caller's buffer is smaller than PeekSize).
const echoBufSize = 512 * 1024

// echo writes back everything read from conn until an error or the idle timeout (which
// bounds both reads and writes, so sessions of dead clients are reaped too). Every
// Read result is written back with one Write, so message boundaries (message mode) are
// preserved; in stream mode the byte stream is echoed unchanged.
func echo(conn *kcp.UDPSession, idle time.Duration) {
	defer conn.Close()
	buf := make([]byte, echoBufSize)
	var total int64
	for {
		if idle > 0 {
			// Bound both Read and Write: kcp-go never declares a peer dead, so a Write
			// to a vanished client would otherwise block forever on a full send window.
			conn.SetDeadline(time.Now().Add(idle))
		}
		n, err := conn.Read(buf)
		if n > 0 {
			if _, werr := conn.Write(buf[:n]); werr != nil {
				log.Printf("session %v: write: %v (echoed %d bytes)", conn.RemoteAddr(), werr, total)
				return
			}
			total += int64(n)
		}
		if err != nil {
			log.Printf("session %v: read: %v (echoed %d bytes)", conn.RemoteAddr(), err, total)
			return
		}
	}
}

// clientReport is the client's JSON summary line.
type clientReport struct {
	OK             bool      `json:"ok"`
	Bytes          int64     `json:"bytes"`
	Received       int64     `json:"received"`
	DurationMs     int64     `json:"duration_ms"`
	SHA256         string    `json:"sha256"`
	ExpectedSHA256 string    `json:"expected_sha256"`
	Crypt          string    `json:"crypt"`
	Mismatch       int64     `json:"mismatch_offset"`
	Error          string    `json:"error,omitempty"`
	Snmp           *kcp.Snmp `json:"snmp"`
}

func runClient(args []string) int {
	fs := flag.NewFlagSet(prog+" client", flag.ContinueOnError)
	var k kcpFlags
	k.register(fs, 128, 512)
	remote := fs.String("remote", "127.0.0.1:29900", "UDP address of the echo server")
	nbytes := fs.Int64("bytes", 1<<20, "number of bytes to send")
	seed := fs.Uint64("seed", 1, "seed of the deterministic stream")
	chunk := fs.Int("chunk", 32*1024, "bytes per Write call")
	timeout := fs.Int("timeout", 60, "overall deadline in seconds, 0 none")
	parse(fs, args)
	if *nbytes < 0 || *chunk <= 0 {
		fmt.Fprintf(os.Stderr, "%s: -bytes must be >= 0 and -chunk > 0\n", prog)
		return 2
	}

	block, crypt := k.block()
	sess, err := kcp.DialWithOptions(*remote, block, k.ds, k.ps)
	if err != nil {
		log.Printf("DialWithOptions: %v", err)
		return 1
	}
	defer sess.Close()
	// Go: kcptun client/main.go:createConn() — same order.
	sess.SetStreamMode(k.stream)
	sess.SetWriteDelay(k.writedelay)
	sess.SetNoDelay(k.nodelay, k.interval, k.resend, k.nc)
	sess.SetWindowSize(k.sndwnd, k.rcvwnd)
	if !sess.SetMtu(k.mtu) {
		log.Printf("SetMtu(%d) rejected", k.mtu)
	}
	sess.SetACKNoDelay(k.acknodelay)
	sess.SetRateLimit(uint32(k.ratelimit))
	if err := sess.SetDSCP(k.dscp); err != nil {
		log.Println("SetDSCP:", err)
	}
	if err := sess.SetReadBuffer(k.sockbuf); err != nil {
		log.Println("SetReadBuffer:", err)
	}
	if err := sess.SetWriteBuffer(k.sockbuf); err != nil {
		log.Println("SetWriteBuffer:", err)
	}

	start := time.Now()
	if *timeout > 0 {
		sess.SetDeadline(start.Add(time.Duration(*timeout) * time.Second))
	}

	writeErr := make(chan error, 1)
	go func() {
		src := peer.NewStream(*seed, *nbytes)
		buf := make([]byte, *chunk)
		for {
			n, err := src.Read(buf)
			if err == io.EOF {
				writeErr <- nil
				return
			}
			if _, err := sess.Write(buf[:n]); err != nil {
				writeErr <- fmt.Errorf("write: %w", err)
				return
			}
		}
	}()

	v := peer.NewVerifier(*seed, *nbytes)
	var runErr error
	buf := make([]byte, 64*1024)
	for !v.Done() && runErr == nil {
		n, err := sess.Read(buf)
		if n > 0 {
			if _, verr := v.Write(buf[:n]); verr != nil {
				runErr = verr
				break
			}
		}
		if err != nil {
			runErr = fmt.Errorf("read: %w", err)
		}
	}
	if runErr == nil {
		runErr = <-writeErr
	}
	elapsed := time.Since(start)

	rep := clientReport{
		OK:             runErr == nil && v.Done(),
		Bytes:          *nbytes,
		Received:       v.Received(),
		DurationMs:     elapsed.Milliseconds(),
		SHA256:         v.SHA256(),
		ExpectedSHA256: peer.StreamSHA256(*seed, *nbytes),
		Crypt:          crypt,
		Mismatch:       v.Mismatch(),
		Snmp:           kcp.DefaultSnmp.Copy(),
	}
	if runErr != nil {
		rep.Error = runErr.Error()
	}
	peer.PrintJSON(rep)
	if !rep.OK {
		return 1
	}
	return 0
}
