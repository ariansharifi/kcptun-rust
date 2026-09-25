package main

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"testing"
)

// smuxFrameCases returns the generated frame cases, keyed by name.
func smuxFrameCases(t *testing.T) map[string]frameCase {
	t.Helper()
	cases, err := genSmux()
	if err != nil {
		t.Fatalf("genSmux: %v", err)
	}
	out := make(map[string]frameCase)
	for _, c := range cases {
		if fc, ok := c.(frameCase); ok {
			out[fc.Name] = fc
		}
	}
	return out
}

// Every command must be covered in both protocol versions (cmdUPD is v2 only).
func TestSmuxFrameCasesCoverEveryCommand(t *testing.T) {
	cases := smuxFrameCases(t)
	want := []string{
		"frame/v1/syn/sid=3", "frame/v1/psh/len=16", "frame/v1/psh/len=65535",
		"frame/v1/fin/sid=3", "frame/v1/nop",
		"frame/v2/syn/sid=3", "frame/v2/psh/len=16", "frame/v2/psh/len=65535",
		"frame/v2/fin/sid=3", "frame/v2/nop",
		"frame/v2/upd/first_read", "frame/v2/upd/half_buffer",
	}
	for _, name := range want {
		if _, ok := cases[name]; !ok {
			t.Errorf("missing case %q", name)
		}
	}
	seen := map[uint8]bool{}
	for _, c := range cases {
		seen[c.Cmd] = true
	}
	for cmd := uint8(0); cmd <= 4; cmd++ {
		if !seen[cmd] {
			t.Errorf("no case for cmd %d", cmd)
		}
	}
}

// The declared fields of every inline frame case must be what its bytes encode, and the header
// must be the 8 bytes documented in docs/WIRE-FORMAT.md §7.
func TestSmuxFrameCaseFieldsMatchBytes(t *testing.T) {
	for name, c := range smuxFrameCases(t) {
		raw := ""
		switch {
		case c.Out != "":
			raw = c.Out
		case c.OutBlob != nil:
			raw = c.OutBlob.Head // the header plus the first 8 payload bytes
		default:
			t.Errorf("%s: neither out nor out_blob", name)
			continue
		}
		b, err := hex.DecodeString(raw)
		if err != nil || len(b) < 8 {
			t.Errorf("%s: bad out %q: %v", name, raw, err)
			continue
		}
		got := fmt.Sprintf("ver=%d cmd=%d len=%d sid=%d",
			b[0], b[1], binary.LittleEndian.Uint16(b[2:]), binary.LittleEndian.Uint32(b[4:]))
		want := fmt.Sprintf("ver=%d cmd=%d len=%d sid=%d", c.Ver, c.Cmd, c.Len, c.Sid)
		if got != want {
			t.Errorf("%s: header says %s, case says %s", name, got, want)
		}
		if c.Out != "" && len(b) != 8+c.Len {
			t.Errorf("%s: %d bytes, want %d", name, len(b), 8+c.Len)
		}
		if c.Cmd == 4 { // cmdUPD: |4B consumed|4B window|
			if c.Consumed == nil || c.Window == nil || c.Len != 8 || len(b) != 16 {
				t.Errorf("%s: cmdUPD case without an 8-byte consumed/window payload", name)
				continue
			}
			if got := binary.LittleEndian.Uint32(b[8:]); got != *c.Consumed {
				t.Errorf("%s: payload consumed %d, case says %d", name, got, *c.Consumed)
			}
			if got := binary.LittleEndian.Uint32(b[12:]); got != *c.Window {
				t.Errorf("%s: payload window %d, case says %d", name, got, *c.Window)
			}
		}
	}
}

// The VerifyConfig cases must cover every error text of mux.go, plus the accepted ones.
func TestSmuxConfigCasesCoverEveryVerifyBranch(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range genSmuxConfigCases() {
		if cc, ok := c.(smuxConfigCase); ok {
			seen[cc.Err] = true
		}
	}
	for _, want := range []string{
		"",
		"unsupported protocol version",
		"keep-alive interval must be positive",
		"keep-alive timeout must be larger than keep-alive interval",
		"max frame size must be positive",
		"max frame size must not be larger than 65535",
		"max receive buffer must be positive",
		"max receive buffer cannot be larger than 2147483647",
		"max stream buffer must be positive",
		"max stream buffer must not be larger than max receive buffer",
	} {
		if !seen[want] {
			t.Errorf("no config case produces %q", want)
		}
	}
	// "max stream buffer cannot be larger than 2147483647" is unreachable (see smux.go).
	if seen["max stream buffer cannot be larger than 2147483647"] {
		t.Error("the unreachable stream-buffer branch produced an error; recheck mux.go")
	}
}
