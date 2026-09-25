package main

// Area "smux" (plan step 06.1): the exact bytes xtaci/smux v1.5.55 puts on the wire for every
// command in both protocol versions, its DefaultConfig, every VerifyConfig branch and the exact
// error texts.
//
// frame.go (rawHeader, newFrame, updHeader) and the session constants are unexported, so the
// frames are not built here: they are captured from real sessions driven through the exported
// API. The capture conn deliberately has no WriteBuffers method, so sendLoop takes the
// `copy(buf[headerSize:], data); conn.Write(...)` branch and each Write call is exactly one
// complete frame (header + payload). Every captured frame is checked against the expected
// version/command/stream id/length before it becomes a vector.
//
// Case groups are documented in README.md.

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math"
	"sync"
	"time"

	"github.com/xtaci/smux"
)

// RNG streams of the smux area (see newRNG): PSH payloads get one stream per payload length,
// so adding a length never changes the bytes of the others.
func smuxPayloadStream(n int) uint64 { return 1<<16 + uint64(n) }

// Byte strings longer than this are stored as a Blob instead of hex (see README, area rs).
const smuxMaxInlineBytes = 4096

// How long to wait for a frame the session is expected to write.
const smuxFrameTimeout = 10 * time.Second

// Quiet period that decides the writer has stopped (flow-control case).
const smuxQuietPeriod = 500 * time.Millisecond

// PSH payload lengths, in case order. 65535 is the largest frame smux can emit
// (VerifyConfig caps MaxFrameSize at 65535, and the length field is a uint16).
var smuxPayloadLens = []int{16, 1370, 65535}

// frameCase is one captured frame: the wire bytes plus the fields they encode.
type frameCase struct {
	Name string `json:"name"`
	Ver  uint8  `json:"ver"`
	Cmd  uint8  `json:"cmd"`
	Sid  uint32 `json:"sid"`
	Len  int    `json:"len"` // payload length = the header's length field
	// PayloadStream is the newRNG("smux", stream) that produced the PSH payload.
	PayloadStream uint64 `json:"payload_stream,omitempty"`
	// Consumed and Window are the decoded cmdUPD payload.
	Consumed *uint32 `json:"consumed,omitempty"`
	Window   *uint32 `json:"window,omitempty"`
	// Out is the whole frame (header + payload) as hex, or, when it is longer than
	// smuxMaxInlineBytes, OutBlob summarises it and the payload is regenerated from
	// PayloadStream.
	Out     string `json:"out,omitempty"`
	OutBlob *Blob  `json:"out_blob,omitempty"`
}

// CaseName implements namedCase.
func (c frameCase) CaseName() string { return c.Name }

// smuxConfig mirrors smux.Config; durations are nanoseconds, as Go stores them.
type smuxConfig struct {
	Version             int   `json:"version"`
	KeepAliveDisabled   bool  `json:"keep_alive_disabled"`
	KeepAliveIntervalNs int64 `json:"keep_alive_interval_ns"`
	KeepAliveTimeoutNs  int64 `json:"keep_alive_timeout_ns"`
	MaxFrameSize        int   `json:"max_frame_size"`
	MaxReceiveBuffer    int   `json:"max_receive_buffer"`
	MaxStreamBuffer     int   `json:"max_stream_buffer"`
}

func newSmuxConfig(c *smux.Config) smuxConfig {
	return smuxConfig{
		Version:             c.Version,
		KeepAliveDisabled:   c.KeepAliveDisabled,
		KeepAliveIntervalNs: int64(c.KeepAliveInterval),
		KeepAliveTimeoutNs:  int64(c.KeepAliveTimeout),
		MaxFrameSize:        c.MaxFrameSize,
		MaxReceiveBuffer:    c.MaxReceiveBuffer,
		MaxStreamBuffer:     c.MaxStreamBuffer,
	}
}

// smuxConfigCase is one smux.VerifyConfig call: the configuration and the error text it returns
// ("" when the configuration is accepted).
type smuxConfigCase struct {
	Name   string     `json:"name"`
	Config smuxConfig `json:"config"`
	Err    string     `json:"err"`
}

// CaseName implements namedCase.
func (c smuxConfigCase) CaseName() string { return c.Name }

// windowCase records the frames a v2 writer emits before the initial peer window
// (initialPeerWindow, unexported) stops it.
type windowCase struct {
	Name         string `json:"name"`
	Ver          int    `json:"ver"`
	MaxFrameSize int    `json:"max_frame_size"`
	Written      int    `json:"written"` // bytes handed to Write
	Lens         []int  `json:"lens"`    // payload length of each PSH frame, in order
	Total        int    `json:"total"`   // sum of Lens = the initial peer window
}

// CaseName implements namedCase.
func (c windowCase) CaseName() string { return c.Name }

// capConn is the io.ReadWriteCloser a captured session runs on: writes are recorded frame by
// frame, reads come from bytes the generator feeds in. It must NOT implement WriteBuffers (see
// the file comment).
type capConn struct {
	pr     *io.PipeReader
	pw     *io.PipeWriter
	frames chan []byte
	once   sync.Once
}

func newCapConn() *capConn {
	pr, pw := io.Pipe()
	return &capConn{pr: pr, pw: pw, frames: make(chan []byte, 1024)}
}

func (c *capConn) Read(p []byte) (int, error) { return c.pr.Read(p) }

func (c *capConn) Write(p []byte) (int, error) {
	b := make([]byte, len(p))
	copy(b, p)
	select {
	case c.frames <- b:
		return len(p), nil
	default:
		return 0, errors.New("capConn: frame buffer full")
	}
}

func (c *capConn) Close() error {
	c.once.Do(func() {
		c.pw.Close()
		c.pr.Close()
	})
	return nil
}

// feed delivers raw bytes to the session's recvLoop and returns once they have all been read.
func (c *capConn) feed(b []byte) error {
	_, err := c.pw.Write(b)
	return err
}

// next returns the next frame the session wrote.
func (c *capConn) next() (capturedFrame, error) {
	select {
	case b := <-c.frames:
		return parseFrame(b)
	case <-time.After(smuxFrameTimeout):
		return capturedFrame{}, errors.New("timed out waiting for a frame")
	}
}

// drainQuiet collects frames until none arrives for smuxQuietPeriod.
func (c *capConn) drainQuiet() ([]capturedFrame, error) {
	var out []capturedFrame
	for {
		select {
		case b := <-c.frames:
			f, err := parseFrame(b)
			if err != nil {
				return nil, err
			}
			out = append(out, f)
		case <-time.After(smuxQuietPeriod):
			return out, nil
		}
	}
}

// capturedFrame is one complete frame as written by sendLoop.
type capturedFrame struct {
	raw  []byte
	ver  byte
	cmd  byte
	len  uint16
	sid  uint32
	data []byte
}

func parseFrame(b []byte) (capturedFrame, error) {
	const headerSize = 8
	if len(b) < headerSize {
		return capturedFrame{}, fmt.Errorf("short frame: %d bytes", len(b))
	}
	f := capturedFrame{
		raw:  b,
		ver:  b[0],
		cmd:  b[1],
		len:  binary.LittleEndian.Uint16(b[2:]),
		sid:  binary.LittleEndian.Uint32(b[4:]),
		data: b[headerSize:],
	}
	if int(f.len) != len(f.data) {
		return capturedFrame{}, fmt.Errorf("frame length field %d, payload %d bytes", f.len, len(f.data))
	}
	return f, nil
}

// expect fails unless the captured frame has exactly these fields.
func (f capturedFrame) expect(ver, cmd byte, sid uint32, length int) error {
	if f.ver != ver || f.cmd != cmd || f.sid != sid || int(f.len) != length {
		return fmt.Errorf("captured frame ver=%d cmd=%d sid=%d len=%d, want ver=%d cmd=%d sid=%d len=%d",
			f.ver, f.cmd, f.sid, f.len, ver, cmd, sid, length)
	}
	return nil
}

// newFrameCase renders a captured frame, inline or as a Blob.
func newFrameCase(name string, f capturedFrame) frameCase {
	c := frameCase{Name: name, Ver: f.ver, Cmd: f.cmd, Sid: f.sid, Len: int(f.len)}
	if len(f.raw) <= smuxMaxInlineBytes {
		c.Out = hx(f.raw)
	} else {
		b := newBlob(f.raw)
		c.OutBlob = &b
	}
	return c
}

// rawFrame builds a frame the generator feeds INTO a session (input, never a vector).
func rawFrame(ver, cmd byte, sid uint32, data []byte) []byte {
	b := make([]byte, 8+len(data))
	b[0] = ver
	b[1] = cmd
	binary.LittleEndian.PutUint16(b[2:], uint16(len(data)))
	binary.LittleEndian.PutUint32(b[4:], sid)
	copy(b[8:], data)
	return b
}

func genSmux() ([]any, error) {
	cases := []any{Case{Name: "errors", Params: smuxErrorTexts()}}
	cases = append(cases, genSmuxConfigCases()...)
	for _, ver := range []int{1, 2} {
		fc, err := genSmuxFrames(ver)
		if err != nil {
			return nil, fmt.Errorf("v%d frames: %w", ver, err)
		}
		cases = append(cases, fc...)
	}
	upd, err := genSmuxUpdFrames()
	if err != nil {
		return nil, fmt.Errorf("upd frames: %w", err)
	}
	cases = append(cases, upd...)

	win, err := genSmuxInitialPeerWindow()
	if err != nil {
		return nil, fmt.Errorf("initial peer window: %w", err)
	}
	return append(cases, win), nil
}

// smuxErrorTexts records the exported error values (mux.go, session.go) and the io errors smux
// returns, so the Rust enum can be compared text by text.
func smuxErrorTexts() map[string]any {
	return map[string]any{
		"ErrInvalidProtocol":   smux.ErrInvalidProtocol.Error(),
		"ErrConsumed":          smux.ErrConsumed.Error(),
		"ErrGoAway":            smux.ErrGoAway.Error(),
		"ErrTimeout":           smux.ErrTimeout.Error(),
		"ErrTimeout.Timeout":   smux.ErrTimeout.Timeout(),
		"ErrTimeout.Temporary": smux.ErrTimeout.Temporary(),
		"ErrWouldBlock":        smux.ErrWouldBlock.Error(),
		"io.EOF":               io.EOF.Error(),
		"io.ErrClosedPipe":     io.ErrClosedPipe.Error(),
	}
}

// genSmuxConfigCases runs smux.VerifyConfig over DefaultConfig and every branch of it.
func genSmuxConfigCases() []any {
	const maxInt32 = math.MaxInt32

	mutations := []struct {
		name   string
		mutate func(*smux.Config)
	}{
		{"default", nil},
		{"version=2", func(c *smux.Config) { c.Version = 2 }},
		{"version=0", func(c *smux.Config) { c.Version = 0 }},
		{"version=3", func(c *smux.Config) { c.Version = 3 }},
		{"version=-1", func(c *smux.Config) { c.Version = -1 }},
		{"keepalive_interval=0", func(c *smux.Config) { c.KeepAliveInterval = 0 }},
		// Disabled keepalive skips both keepalive checks.
		{"keepalive_disabled", func(c *smux.Config) {
			c.KeepAliveDisabled = true
			c.KeepAliveInterval = 0
			c.KeepAliveTimeout = 0
		}},
		{"keepalive_timeout<interval", func(c *smux.Config) {
			c.KeepAliveInterval = 30 * time.Second
			c.KeepAliveTimeout = 10 * time.Second
		}},
		{"keepalive_timeout=interval", func(c *smux.Config) {
			c.KeepAliveInterval = 10 * time.Second
			c.KeepAliveTimeout = 10 * time.Second
		}},
		// A negative interval passes VerifyConfig (it is neither 0 nor larger than the
		// timeout); keepalive() then panics in time.NewTicker. Recorded, not adopted.
		{"keepalive_interval=-1s", func(c *smux.Config) { c.KeepAliveInterval = -1 * time.Second }},
		{"frame_size=0", func(c *smux.Config) { c.MaxFrameSize = 0 }},
		{"frame_size=-1", func(c *smux.Config) { c.MaxFrameSize = -1 }},
		{"frame_size=65535", func(c *smux.Config) { c.MaxFrameSize = 65535 }},
		{"frame_size=65536", func(c *smux.Config) { c.MaxFrameSize = 65536 }},
		{"recv_buffer=0", func(c *smux.Config) { c.MaxReceiveBuffer = 0 }},
		{"recv_buffer=-1", func(c *smux.Config) { c.MaxReceiveBuffer = -1 }},
		{"recv_buffer=maxint32", func(c *smux.Config) { c.MaxReceiveBuffer = maxInt32 }},
		{"recv_buffer=maxint32+1", func(c *smux.Config) { c.MaxReceiveBuffer = maxInt32 + 1 }},
		{"stream_buffer=0", func(c *smux.Config) { c.MaxStreamBuffer = 0 }},
		{"stream_buffer=-1", func(c *smux.Config) { c.MaxStreamBuffer = -1 }},
		{"stream_buffer=recv_buffer", func(c *smux.Config) { c.MaxStreamBuffer = c.MaxReceiveBuffer }},
		{"stream_buffer>recv_buffer", func(c *smux.Config) { c.MaxStreamBuffer = c.MaxReceiveBuffer + 1 }},
		// The "max stream buffer cannot be larger than 2147483647" branch is unreachable: it
		// needs MaxReceiveBuffer >= MaxStreamBuffer > MaxInt32, which the receive-buffer check
		// already rejects. This case records which error actually comes out.
		{"stream_buffer=maxint32+1", func(c *smux.Config) {
			c.MaxReceiveBuffer = maxInt32
			c.MaxStreamBuffer = maxInt32 + 1
		}},
	}

	cases := make([]any, 0, len(mutations))
	for _, m := range mutations {
		cfg := smux.DefaultConfig()
		if m.mutate != nil {
			m.mutate(cfg)
		}
		name := "config/verify/" + m.name
		if m.name == "default" {
			name = "config/default"
		}
		errText := ""
		if err := smux.VerifyConfig(cfg); err != nil {
			errText = err.Error()
		}
		cases = append(cases, smuxConfigCase{Name: name, Config: newSmuxConfig(cfg), Err: errText})
	}
	return cases
}

// genSmuxFrames captures cmdSYN, cmdPSH, cmdFIN (one client session) and cmdNOP (a second
// session, with keepalive enabled) for one protocol version.
func genSmuxFrames(ver int) ([]any, error) {
	cfg := smux.DefaultConfig()
	cfg.Version = ver
	cfg.KeepAliveDisabled = true // no NOPs in between: keeps the capture ordered
	cfg.MaxFrameSize = 65535

	conn := newCapConn()
	sess, err := smux.Client(conn, cfg)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	// Client sessions start at nextStreamID 1 and add 2 before use.
	const sid = 3
	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	f, err := conn.next()
	if err != nil {
		return nil, err
	}
	if err := f.expect(byte(ver), 0 /*cmdSYN*/, sid, 0); err != nil {
		return nil, err
	}
	cases := []any{newFrameCase(fmt.Sprintf("frame/v%d/syn/sid=%d", ver, sid), f)}

	for _, n := range smuxPayloadLens {
		stream := smuxPayloadStream(n)
		payload := randBytes(newRNG("smux", stream), n)
		if _, err := st.Write(payload); err != nil {
			return nil, err
		}
		f, err := conn.next()
		if err != nil {
			return nil, err
		}
		if err := f.expect(byte(ver), 2 /*cmdPSH*/, sid, n); err != nil {
			return nil, err
		}
		c := newFrameCase(fmt.Sprintf("frame/v%d/psh/len=%d", ver, n), f)
		c.PayloadStream = stream
		cases = append(cases, c)
	}

	if err := st.Close(); err != nil {
		return nil, err
	}
	f, err = conn.next()
	if err != nil {
		return nil, err
	}
	if err := f.expect(byte(ver), 1 /*cmdFIN*/, sid, 0); err != nil {
		return nil, err
	}
	cases = append(cases, newFrameCase(fmt.Sprintf("frame/v%d/fin/sid=%d", ver, sid), f))

	nop, err := genSmuxNop(ver)
	if err != nil {
		return nil, err
	}
	return append(cases, nop), nil
}

// genSmuxNop captures the keepalive frame of a session whose keepalive ticker is short.
func genSmuxNop(ver int) (any, error) {
	cfg := smux.DefaultConfig()
	cfg.Version = ver
	cfg.KeepAliveInterval = 20 * time.Millisecond
	cfg.KeepAliveTimeout = 10 * time.Second

	conn := newCapConn()
	sess, err := smux.Client(conn, cfg)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	f, err := conn.next()
	if err != nil {
		return nil, err
	}
	if err := f.expect(byte(ver), 3 /*cmdNOP*/, 0, 0); err != nil {
		return nil, err
	}
	return newFrameCase(fmt.Sprintf("frame/v%d/nop", ver), f), nil
}

// genSmuxUpdFrames captures cmdUPD (v2 only). A server session is fed a SYN and one PSH for a
// stream id near the uint32 wrap; reading from the accepted stream makes it answer with window
// updates, and closing it gives a FIN for the same id. The fed frames are inputs, never
// vectors; every recorded frame is written by the library.
func genSmuxUpdFrames() ([]any, error) {
	const (
		sid          = uint32(0xfffffffd)
		streamBuffer = 4096
		payloadLen   = 4096
	)
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveDisabled = true
	cfg.MaxStreamBuffer = streamBuffer
	cfg.MaxReceiveBuffer = 65536

	conn := newCapConn()
	sess, err := smux.Server(conn, cfg)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	payload := randBytes(newRNG("smux", smuxPayloadStream(payloadLen)), payloadLen)
	if err := conn.feed(rawFrame(2, 0 /*cmdSYN*/, sid, nil)); err != nil {
		return nil, err
	}
	st, err := sess.AcceptStream()
	if err != nil {
		return nil, err
	}
	if err := conn.feed(rawFrame(2, 2 /*cmdPSH*/, sid, payload)); err != nil {
		return nil, err
	}

	// reads[i] is the size of read i; an update follows the initial read (numRead == n) and
	// then every time incr reaches MaxStreamBuffer/2.
	type readStep struct {
		size         int
		wantUpdate   bool
		wantConsumed uint32
	}
	steps := []readStep{
		{size: 1, wantUpdate: true, wantConsumed: 1},
		{size: streamBuffer/2 - 1, wantUpdate: false},
		{size: 1, wantUpdate: true, wantConsumed: uint32(streamBuffer/2 + 1)},
	}
	names := []string{"first_read", "", "half_buffer"}

	var cases []any
	for i, step := range steps {
		buf := make([]byte, step.size)
		if _, err := io.ReadFull(st, buf); err != nil {
			return nil, err
		}
		if !step.wantUpdate {
			continue
		}
		f, err := conn.next()
		if err != nil {
			return nil, err
		}
		if err := f.expect(2, 4 /*cmdUPD*/, sid, 8 /*szCmdUPD*/); err != nil {
			return nil, err
		}
		consumed := binary.LittleEndian.Uint32(f.data)
		window := binary.LittleEndian.Uint32(f.data[4:])
		if consumed != step.wantConsumed || window != streamBuffer {
			return nil, fmt.Errorf("upd %d: consumed=%d window=%d, want consumed=%d window=%d",
				i, consumed, window, step.wantConsumed, streamBuffer)
		}
		c := newFrameCase("frame/v2/upd/"+names[i], f)
		c.Consumed = &consumed
		c.Window = &window
		cases = append(cases, c)
	}

	if err := st.Close(); err != nil {
		return nil, err
	}
	f, err := conn.next()
	if err != nil {
		return nil, err
	}
	if err := f.expect(2, 1 /*cmdFIN*/, sid, 0); err != nil {
		return nil, err
	}
	return append(cases, newFrameCase(fmt.Sprintf("frame/v2/fin/sid=%d", sid), f)), nil
}

// genSmuxInitialPeerWindow records how many bytes a v2 writer may put in flight before the
// peer's window (initialPeerWindow, unexported) blocks it: the peer never sends a cmdUPD, so
// the writer stops after exactly initialPeerWindow bytes.
func genSmuxInitialPeerWindow() (any, error) {
	const (
		frameSize = 65535
		written   = 5 * frameSize // more than the window, so the writer must block
		wantTotal = 262144        // initialPeerWindow
	)
	cfg := smux.DefaultConfig()
	cfg.Version = 2
	cfg.KeepAliveDisabled = true
	cfg.MaxFrameSize = frameSize

	conn := newCapConn()
	sess, err := smux.Client(conn, cfg)
	if err != nil {
		return nil, err
	}
	defer sess.Close()

	st, err := sess.OpenStream()
	if err != nil {
		return nil, err
	}
	if f, err := conn.next(); err != nil { // the SYN
		return nil, err
	} else if err := f.expect(2, 0, 3, 0); err != nil {
		return nil, err
	}

	done := make(chan struct{})
	go func() {
		defer close(done)
		st.Write(make([]byte, written)) //nolint:errcheck // unblocked by sess.Close below
	}()

	frames, err := conn.drainQuiet()
	if err != nil {
		return nil, err
	}
	lens := make([]int, 0, len(frames))
	total := 0
	for _, f := range frames {
		if err := f.expect(2, 2 /*cmdPSH*/, 3, int(f.len)); err != nil {
			return nil, err
		}
		lens = append(lens, int(f.len))
		total += int(f.len)
	}
	if total != wantTotal {
		return nil, fmt.Errorf("writer sent %d bytes before blocking, want %d", total, wantTotal)
	}
	sess.Close()
	<-done

	return windowCase{
		Name:         "flow/v2/initial_peer_window",
		Ver:          2,
		MaxFrameSize: frameSize,
		Written:      written,
		Lens:         lens,
		Total:        total,
	}, nil
}
