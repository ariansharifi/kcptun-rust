package main

// Area "multiport" (plan step 08.4): the two address parsers kcptun uses before it opens a
// socket.
//
//   - std.ParseMultiPort (kcptun std/multiport.go, copied verbatim into internal/std) turns
//     "host:port" or "host:minport-maxport" into a *MultiPort. It is regexp-based
//     (`(.*)\:([0-9]{1,5})-?([0-9]{1,5})?`, unanchored and leftmost-first), so it accepts
//     surrounding junk and produces surprising splits for out-of-range ports; the cases below
//     pin every one of those quirks down.
//   - net.SplitHostPort (Go standard library, net/ipsock.go) is used for its *failure*:
//     client/main.go:319 and server/main.go:449 treat an address it rejects as the path of a
//     unix socket, so which addresses it rejects (and with which message) decides whether
//     kcptun listens on TCP or on AF_UNIX.
//
// Each case records the function, the address, whether it succeeded, the results and the
// error text (errors.Errorf / *net.AddrError, both printed with %v as kcptun's log.Println
// prints them). Cases are grouped by function; within a group the order is the order of the
// address table below.

import (
	"net"

	"github.com/kcptun-rust/tools/govectors/internal/std"
)

// multiportCase is one std.ParseMultiPort vector.
type multiportCase struct {
	Name string `json:"name"`
	Func string `json:"func"` // always "ParseMultiPort"
	Addr string `json:"addr"`
	OK   bool   `json:"ok"`
	// Host, MinPort and MaxPort are the *MultiPort fields; only present on success.
	Host    string `json:"host,omitempty"`
	MinPort uint64 `json:"minport,omitempty"`
	MaxPort uint64 `json:"maxport,omitempty"`
	// Err is the error text ("" on success).
	Err string `json:"err,omitempty"`
}

func (c multiportCase) CaseName() string { return c.Name }

// splitHostPortCase is one net.SplitHostPort vector.
type splitHostPortCase struct {
	Name string `json:"name"`
	Func string `json:"func"` // always "SplitHostPort"
	Addr string `json:"addr"`
	OK   bool   `json:"ok"`
	Host string `json:"host,omitempty"`
	Port string `json:"port,omitempty"`
	Err  string `json:"err,omitempty"`
}

func (c splitHostPortCase) CaseName() string { return c.Name }

// multiportAddrs are the addresses ParseMultiPort is run on. The comment on each line is the
// behaviour it pins down; the plan step names the first nine.
var multiportAddrs = []string{
	":29900",                 // no host, the kcptun server's default -listen
	"1.2.3.4:3000-4000",      // a port range
	"[::1]:1-2",              // a bracketed IPv6 literal keeps its brackets in Host
	"vps:29900",              // the client's default -remoteaddr
	"host:123456",            // 6 digits: 12345 + 6, then the range check fails
	"a:0",                    // port 0 is rejected
	"a:5-3",                  // minport > maxport
	"nocolon",                // no match at all
	"x:65536",                // above 65535
	"",                       // empty address
	":",                      // a colon with no digits: no match
	"a:",                     // ditto
	"a:1",                    // the smallest accepted port
	"a:65535",                // the largest accepted port
	"a:1-65535",              // the widest accepted range
	"a:5-5",                  // a single-port range
	"a:012",                  // strconv.Atoi is base 10: 12, not octal 10
	"a:00",                   // "00" parses as 0 and is rejected
	"a:0-1",                  // a zero endpoint is rejected even inside a range
	"a:1-0",                  // ditto, on the other side
	"a:1-",                   // a dangling '-' is simply not part of the match
	"a:1-2-3",                // only the first two numbers are looked at
	"a:1-2junk",              // unanchored: trailing junk is ignored
	"junk a:1-2",             // unanchored: leading junk lands in Host
	"host:80:90",             // greedy (.*): the LAST colon wins, so Host is "host:80"
	"[2001:db8::1]:443",      // a real IPv6 address
	"2001:db8::1:443",        // without brackets the last colon still wins
	"unix:/tmp/kcptun.sock",  // a unix socket path: no digits after the colon, no match
	"/tmp/kcptun.sock",       // ditto without a colon
	"sub.domain.example:443", // a normal hostname
	"HOST:80",                // the regexp is case-blind; Host is copied verbatim
	"héllo:80",               // non-ASCII host, byte-exact in Host
	"a\nb:80",                // '.' does not match '\n', so the match starts after it
	"a:80\n",                 // a trailing newline is outside the match
	"a:1234567",              // 7 digits: 12345 + 67
	"a:99999",                // 5 digits, above 65535
	"-5:80",                  // a '-' in the host is nothing special
	"a:-1",                   // the sign is not part of ([0-9]{1,5})
	"::80",                   // Host is ":"
	"a:1e2",                  // only the leading digits match
}

// splitHostPortAddrs are the addresses net.SplitHostPort is run on: kcptun's own -l / -t
// shapes plus every branch of net/ipsock.go:SplitHostPort.
var splitHostPortAddrs = []string{
	":29900",                    // the server's default -listen: an empty host
	"127.0.0.1:12948",           // the client's default -localaddr shape
	"vps:29900",                 // a hostname
	"1.2.3.4:3000-4000",         // a port range: SplitHostPort does not validate the port
	"[::1]:80",                  // a bracketed IPv6 literal, brackets removed
	"[fe80::1%eth0]:80",         // a zone identifier stays in Host
	"[2001:db8::1]:443",         //
	"host:",                     // an empty port is accepted
	"host:port",                 // the port is not parsed
	"nocolon",                   // "missing port in address"
	"",                          // the empty address: the error carries no address
	":",                         // host "" port ""
	"::1:80",                    // unbracketed IPv6: "too many colons in address"
	"[::1]",                     // "missing port in address"
	"[::1]80",                   // ']' not followed by ':': "missing port in address"
	"[::1]:80:90",               // ']' followed by a non-final colon: "too many colons"
	"[::1:80",                   // "missing ']' in address"
	"a]:80",                     // "unexpected ']' in address"
	"a[b:80",                    // "unexpected '[' in address"
	"[a]b:80",                   // ']' is followed by 'b': "missing port in address"
	"/tmp/kcptun.sock",          // a unix path: rejected, which is how kcptun detects one
	"/tmp/kcptun.sock:80",       // a path with a port-looking suffix is accepted
	"unix:/tmp/kcptun.sock",     // accepted: host "unix", port "/tmp/kcptun.sock"
	"./relative.sock",           // rejected
	"@abstract",                 // rejected (Linux abstract socket name)
	"[]:80",                     // an empty bracketed host is accepted
	"[]",                        // "missing port in address"
	"héllo:80",                  // non-ASCII host
	"host:80\n",                 // the port is taken verbatim, newline included
	"[::ffff:1.2.3.4]:80",       // an IPv4-mapped IPv6 literal
	"::ffff:1.2.3.4:80",         // the same without brackets: too many colons
	"kcptun-server.example:443", //
}

// genMultiport runs both parsers over their address tables.
func genMultiport() ([]any, error) {
	cases := make([]any, 0, len(multiportAddrs)+len(splitHostPortAddrs))
	for _, addr := range multiportAddrs {
		c := multiportCase{Name: "parse/" + addr, Func: "ParseMultiPort", Addr: addr}
		mp, err := std.ParseMultiPort(addr)
		if err != nil {
			c.Err = err.Error()
		} else {
			c.OK = true
			c.Host, c.MinPort, c.MaxPort = mp.Host, mp.MinPort, mp.MaxPort
		}
		cases = append(cases, c)
	}
	for _, addr := range splitHostPortAddrs {
		c := splitHostPortCase{Name: "splithostport/" + addr, Func: "SplitHostPort", Addr: addr}
		host, port, err := net.SplitHostPort(addr)
		if err != nil {
			c.Err = err.Error()
		} else {
			c.OK = true
			c.Host, c.Port = host, port
		}
		cases = append(cases, c)
	}
	return cases, nil
}
