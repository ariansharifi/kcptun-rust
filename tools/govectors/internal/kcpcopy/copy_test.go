package kcp

import (
	"bytes"
	"os"
	"sync/atomic"
	"testing"
)

const refDir = "../../../../reference/kcptun/vendor/github.com/xtaci/kcp-go/v5/"

// The files copied from kcp-go v5.6.66 and the only lines allowed to differ (copy -> original).
var copied = []struct {
	file    string
	changes map[string]string
}{
	{"kcp.go", map[string]string{
		"func currentMs() uint32 { return Clock() }\n": "func currentMs() uint32 { return uint32(time.Since(refTime) / time.Millisecond) }\n",
	}},
	{"ringbuffer.go", nil},
	{"bufferpool.go", nil},
	{"snmp.go", nil},
	{"kcp_trace_off.go", nil},
	{"autotune.go", nil},
	{"fec.go", map[string]string{
		"\tnow := FecClock(time.Now)\n": "\tnow := time.Now().UnixMilli()\n",
	}},
}

// Below the marker, each copied file must equal the pinned kcp-go file after undoing the
// documented changes (each must occur exactly once). Skipped when reference/ has not been
// fetched.
func TestVerbatimCopy(t *testing.T) {
	const marker = "// ---- verbatim below ----\n"
	for _, c := range copied {
		ref, err := os.ReadFile(refDir + c.file)
		if err != nil {
			t.Skipf("reference not fetched: %v", err)
		}
		own, err := os.ReadFile(c.file)
		if err != nil {
			t.Fatal(err)
		}
		i := bytes.Index(own, []byte(marker))
		if i < 0 {
			t.Fatalf("%s: marker missing", c.file)
		}
		body := own[i+len(marker):]
		for from, to := range c.changes {
			if n := bytes.Count(body, []byte(from)); n != 1 {
				t.Fatalf("%s: changed line %q found %d times, want 1", c.file, from, n)
			}
			body = bytes.Replace(body, []byte(from), []byte(to), 1)
		}
		if !bytes.Equal(body, ref) {
			t.Errorf("%s differs from the pinned reference beyond the documented change", c.file)
		}
	}
}

func TestEncodeDecodeRoundTrip(t *testing.T) {
	s := Segment{Conv: 0x01020304, Cmd: 81, Frg: 7, Wnd: 0xA0B0, Ts: 0xDEADBEEF, Sn: 5, Una: 0xFFFFFFFF, Data: []byte("hello")}
	before := atomic.LoadUint64(&DefaultSnmp.OutSegs)
	b := Encode(s)
	if got := atomic.LoadUint64(&DefaultSnmp.OutSegs); got != before+1 {
		t.Fatalf("OutSegs = %d, want %d", got, before+1)
	}
	want := []byte{4, 3, 2, 1, 81, 7, 0xB0, 0xA0, 0xEF, 0xBE, 0xAD, 0xDE, 5, 0, 0, 0, 0xFF, 0xFF, 0xFF, 0xFF, 5, 0, 0, 0}
	if !bytes.Equal(b, want) {
		t.Fatalf("Encode = %x, want %x", b, want)
	}
	h, rest, ok := DecodeHeader(append(b, s.Data...))
	if !ok || string(rest) != "hello" {
		t.Fatalf("DecodeHeader: ok=%v rest=%q", ok, rest)
	}
	if h != (Header{Conv: s.Conv, Cmd: s.Cmd, Frg: s.Frg, Wnd: s.Wnd, Ts: s.Ts, Sn: s.Sn, Una: s.Una, Len: 5}) {
		t.Fatalf("DecodeHeader = %+v", h)
	}
	if _, _, ok := DecodeHeader(b[:23]); ok {
		t.Fatal("DecodeHeader accepted 23 bytes")
	}
}

// The injected clock is what the copied KCP reads: Check() before the first Update returns
// the current time, and Update stamps ts_flush with it.
func TestInjectedClock(t *testing.T) {
	saved := Clock
	defer func() { Clock = saved }()
	now := uint32(0xFFFFFFF0)
	reads := 0
	Clock = func() uint32 { reads++; return now }
	k := NewKCP(1, func([]byte, int) {})
	if got := k.Check(); got != now || reads != 1 {
		t.Fatalf("Check = %d after %d reads, want %d after 1", got, reads, now)
	}
	k.Update()
	if k.ts_flush != now+k.interval {
		t.Fatalf("ts_flush = %d, want %d", k.ts_flush, now+k.interval)
	}
}
