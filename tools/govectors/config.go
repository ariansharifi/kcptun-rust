package main

// Area "config" (plan step 08.2): the JSON configuration overlay and the -mode presets, as
// performed by kcptun std/config.go (ParseJSONConfig + ApplyMode, copied verbatim into
// internal/std) on top of Go's encoding/json.
//
// Each case starts from a configuration the command line could have produced ("before"),
// decodes one JSON document over it exactly as kcptun's `-c file` does, runs ApplyMode and
// records what Go ended up with ("config"), whether ApplyMode found the mode ("mode_applied")
// and the error text ParseJSONConfig returned ("err"). The Rust port must reproduce all four
// from "before" and "json" alone.
//
// Two things are normalised so the vectors describe the real binaries rather than this
// generator: the whole-document type error names the Go type of the configuration struct,
// which is "main.Config" in kcptun and "kcptunclient.Config" here, and the "before"/"config"
// objects are Go's own json.Marshal of the struct (field order, json tags).
//
// Note on the Go toolchain: since Go 1.25 encoding/json is implemented by the v2 engine behind
// the v1 API, so syntax-error texts come from jsontext and are rewritten into the historical
// v1 wording by v2_scanner.go:transformSyntacticError. The "go" field of the vector file
// records the toolchain these strings were produced with.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"github.com/kcptun-rust/tools/govectors/internal/kcptunclient"
	"github.com/kcptun-rust/tools/govectors/internal/kcptunserver"
	"github.com/kcptun-rust/tools/govectors/internal/std"
)

// configCase is one vector of the config area.
type configCase struct {
	Name string `json:"name"`
	Side string `json:"side"` // "client" or "server"
	// Before is the configuration the command line produced, as json.Marshal renders it.
	Before json.RawMessage `json:"before"`
	// JSON is the content of the -c file. It is omitted when the bytes are not valid UTF-8,
	// since JSON strings cannot carry them; JSONHex then has the exact bytes.
	JSON string `json:"json,omitempty"`
	// JSONHex is the -c file in lower-case hex, present only when JSON cannot hold it.
	JSONHex string `json:"json_hex,omitempty"`
	// Err is ParseJSONConfig's error text ("" when it succeeded).
	Err string `json:"err,omitempty"`
	// ModeApplied is what ApplyMode returned.
	ModeApplied bool `json:"mode_applied"`
	// Config is the configuration after the overlay and ApplyMode.
	Config json.RawMessage `json:"config"`
}

func (c configCase) CaseName() string { return c.Name }

// clientDefaults is the configuration an empty client command line produces
// (kcptun client/main.go's flag table).
func clientDefaults() *kcptunclient.Config {
	c := &kcptunclient.Config{}
	c.BaseConfig = baseDefaults()
	c.LocalAddr = ":12948"
	c.RemoteAddr = "vps:29900"
	c.Conn = 1
	c.AutoExpire = 0
	c.ScavengeTTL = 600
	c.SndWnd = 128
	c.RcvWnd = 512
	c.CloseWait = 0
	return c
}

// serverDefaults is the configuration an empty server command line produces
// (kcptun server/main.go's flag table).
func serverDefaults() *kcptunserver.Config {
	c := &kcptunserver.Config{}
	c.BaseConfig = baseDefaults()
	c.Listen = ":29900"
	c.Target = "127.0.0.1:12948"
	c.SndWnd = 1024
	c.RcvWnd = 1024
	c.CloseWait = 30
	return c
}

// baseDefaults holds the flag defaults both tables share; the two callers above override the
// ones that differ (sndwnd, rcvwnd, closewait).
func baseDefaults() std.BaseConfig {
	return std.BaseConfig{
		Key:         "it's a secrect",
		Crypt:       "aes",
		Mode:        "fast",
		MTU:         1350,
		DataShard:   10,
		ParityShard: 3,
		NoDelay:     0,
		Interval:    50,
		Resend:      0,
		SockBuf:     4194304,
		SmuxVer:     2,
		SmuxBuf:     4194304,
		FrameSize:   8192,
		StreamBuf:   2097152,
		KeepAlive:   10,
		SnmpPeriod:  60,
		QPPCount:    61,
	}
}

// configCaseSpec describes one case before it is run.
type configCaseSpec struct {
	name string
	side string // "client" (default) or "server"
	// pre is an optional JSON document applied to the defaults first, standing in for flags
	// the user gave on the command line. It must decode without error.
	pre  string
	body string // the -c file under test
}

// allConfigKeys sets every field of the client configuration, used by the "full" cases.
const allConfigKeys = `{
  "key": "sekrit", "crypt": "salsa20", "mode": "manual", "mtu": 1200,
  "ratelimit": 1048576, "sndwnd": 256, "rcvwnd": 2048, "datashard": 20,
  "parityshard": 5, "dscp": 46, "nocomp": true, "acknodelay": true,
  "nodelay": 1, "interval": 20, "resend": 2, "nc": 1, "sockbuf": 8388608,
  "smuxver": 1, "smuxbuf": 8388608, "framesize": 4096, "streambuf": 1048576,
  "keepalive": 15, "log": "/var/log/kcptun.log", "snmplog": "./snmp-20060102.log",
  "snmpperiod": 30, "quiet": true, "tcp": true, "pprof": true, "qpp": true,
  "qpp-count": 127, "closewait": 5,
  "localaddr": ":9000", "remoteaddr": "example:4000-4010", "conn": 4,
  "autoexpire": 3600, "scavengettl": 120
}`

// configSpecs lists every case, in file order.
var configSpecs = []configCaseSpec{
	// --- the plain paths -----------------------------------------------------------------
	{name: "client/defaults", body: `{}`},
	{name: "server/defaults", side: "server", body: `{}`},
	{name: "client/partial", body: `{"mtu":1200,"sndwnd":77}`},
	{name: "client/keeps-cli-values", pre: `{"mtu":1400,"conn":8}`, body: `{"sndwnd":99}`},
	{name: "client/json-wins-over-cli", pre: `{"mtu":1400}`, body: `{"mtu":1200}`},
	{name: "client/full", body: allConfigKeys},
	{name: "server/full", side: "server", body: `{"listen":":4100","target":"127.0.0.1:8080",
		"key":"sekrit","crypt":"none","mode":"normal","mtu":1400,"sndwnd":2048,"rcvwnd":4096,
		"closewait":7,"qpp":true,"qpp-count":127}`},
	{name: "client/empty-object-with-space", body: "  {  }  "},
	{name: "client/trailing-junk-ignored", body: `{"mtu":1200} and some junk`},
	{name: "client/second-document-ignored", body: `{"mtu":1200}{"mtu":1300}`},

	// --- key matching --------------------------------------------------------------------
	{name: "keys/mixed-case", body: `{"MTU":1200,"Mode":"fast2","SndWnd":77,"qpp-count":13,"unknownkey":1}`},
	{name: "keys/upper-hyphen-qpp", body: `{"QPP":true,"QPP-Count":7}`},
	{name: "keys/qppcount-without-hyphen-is-unknown", body: `{"QPPCount":7}`},
	{name: "keys/exact-beats-fold", body: `{"MTU":1,"mtu":2}`},
	{name: "keys/last-duplicate-wins", body: `{"mtu":1,"mtu":2}`},
	{name: "keys/last-folded-duplicate-wins", body: `{"KEY":"a","Key":"b"}`},
	{name: "keys/unknown-nested-ignored", body: `{"unknown":{"a":[1,{"b":null}]},"mtu":1200}`},
	{name: "keys/empty-key-ignored", body: `{"":2,"mtu":1200}`},
	{name: "keys/escaped-key", body: `{"\u006ctu":1,"m\u0074u":1200}`},
	// The v1 API sets MatchCaseSensitiveDelimiter, so the fallback match is
	// strings.EqualFold (v2/fields.go:matchFoldedName): U+017F and U+212A share a fold set
	// with ASCII `s` and `k`, and no other non-ASCII rune folds into ASCII.
	{name: "keys/fold-long-s", body: "{\"ſndwnd\":77}"},
	{name: "keys/fold-kelvin-sign", body: "{\"Key\":\"folded\"}"},
	{name: "keys/fold-non-ascii-no-match", body: "{\"фey\":\"none\",\"mtu\":1200}"},
	{name: "keys/invalid-utf8-in-key", body: "{\"m\xfftu\":1,\"mtu\":1200}"},
	{name: "keys/client-key-on-server", side: "server", body: `{"localaddr":":1","listen":":4100"}`},
	{name: "keys/server-key-on-client", body: `{"listen":":1","localaddr":":9000"}`},

	// --- null and type handling ----------------------------------------------------------
	{name: "null/leaves-fields", pre: `{"mtu":1400,"key":"cli","nocomp":true}`,
		body: `{"mtu":null,"key":null,"nocomp":null,"localaddr":null}`},
	{name: "null/document", body: `null`},
	{name: "types/string-into-int", body: `{"mtu":"1200"}`},
	{name: "types/bool-into-int", body: `{"mtu":true}`},
	{name: "types/object-into-int", body: `{"mtu":{"a":1}}`},
	{name: "types/array-into-int", body: `{"mtu":[1]}`},
	{name: "types/number-into-string", body: `{"key":123}`},
	{name: "types/bool-into-string", body: `{"key":true}`},
	{name: "types/number-into-bool", body: `{"nocomp":1}`},
	{name: "types/string-into-bool", body: `{"nocomp":"true"}`},
	{name: "types/first-error-wins", body: `{"mtu":"x","key":1,"sndwnd":99}`},
	{name: "types/later-fields-still-applied", body: `{"mtu":"x","sndwnd":99,"conn":3}`},
	// Go's errorContext.FieldStack carries the key as the document spells it (unescaped),
	// not the json tag it matched, so these five name a field that is not a tag.
	{name: "types/mixed-case-key", body: `{"MTU":"x"}`},
	{name: "types/folded-key", body: "{\"\u017Fndwnd\":true}"},
	{name: "types/hyphen-key", body: `{"QPP-Count":"x"}`},
	{name: "types/escaped-key", body: `{"\u004DTU":"x"}`},
	{name: "types/client-only-key-folded", body: `{"LOCALADDR":1}`},

	// --- numbers -------------------------------------------------------------------------
	{name: "number/negative", body: `{"ratelimit":-5,"dscp":-1}`},
	{name: "number/negative-zero", body: `{"mtu":-0}`},
	{name: "number/fraction", body: `{"mtu":1.5}`},
	{name: "number/trailing-zero-fraction", body: `{"mtu":1200.0}`},
	{name: "number/exponent", body: `{"mtu":1e3}`},
	{name: "number/exponent-signed", body: `{"mtu":1e+3}`},
	{name: "number/exponent-upper", body: `{"mtu":1E3}`},
	{name: "number/int64-max", body: `{"sockbuf":9223372036854775807}`},
	{name: "number/int64-min", body: `{"sockbuf":-9223372036854775808}`},
	{name: "number/int64-overflow", body: `{"sockbuf":9223372036854775808}`},
	{name: "number/huge", body: `{"mtu":99999999999999999999}`},
	{name: "number/mixed-case-fraction", body: `{"MTU":1.5}`},

	// --- strings -------------------------------------------------------------------------
	{name: "string/escapes", body: `{"log":"C:\\logs\\kcptun\t\"x\"\u00e9\/y"}`},
	{name: "string/surrogate-pair", body: `{"key":"\ud83d\ude00"}`},
	{name: "string/lone-high-surrogate", body: `{"key":"\ud800"}`},
	{name: "string/lone-low-surrogate", body: `{"key":"\udc00"}`},
	{name: "string/empty", body: `{"key":""}`},
	// The v1 API decodes with AllowInvalidUTF8, and jsonwire replaces one byte at a time
	// (decode.go: `dst = append(dst, "�"...); n += rn` with rn == 1), so a GBK or
	// Latin-1 value yields one U+FFFD per byte rather than one per invalid subsequence.
	{name: "string/invalid-utf8-three-bytes", body: "{\"key\":\"\xe3\xba\xc3\"}"},
	{name: "string/invalid-utf8-mixed", body: "{\"key\":\"\xc4\xe3\xba\xc3\"}"},
	{name: "string/invalid-utf8-single-byte", body: "{\"log\":\"\xff\"}"},
	{name: "string/invalid-utf8-truncated-rune", body: "{\"key\":\"\xe3\xba\"}"},
	{name: "string/invalid-utf8-around-ascii", body: "{\"key\":\"a\xe3b\xbac\"}"},
	{name: "string/replacement-character", body: "{\"key\":\"a�b\"}"},

	// --- mode presets --------------------------------------------------------------------
	{name: "mode/normal", pre: `{"nodelay":1,"interval":7,"resend":9,"nc":1}`, body: `{"mode":"normal"}`},
	{name: "mode/fast", body: `{"mode":"fast"}`},
	{name: "mode/fast2", body: `{"mode":"fast2"}`},
	{name: "mode/fast3", body: `{"mode":"fast3"}`},
	{name: "mode/manual-keeps-json-values", body: `{"mode":"manual","nodelay":1,"interval":20,"resend":3,"nc":1}`},
	{name: "mode/unknown-keeps-cli-values", pre: `{"nodelay":1,"interval":7,"resend":9,"nc":1}`,
		body: `{"mode":"bogus"}`},
	{name: "mode/preset-overrides-json-knobs", body: `{"mode":"fast3","nodelay":0,"interval":99,"resend":0,"nc":0}`},
	{name: "mode/case-sensitive", body: `{"mode":"FAST3"}`},
	{name: "mode/from-cli-applies", pre: `{"mode":"fast2","interval":99}`, body: `{}`},

	// --- documents that are not objects ---------------------------------------------------
	{name: "document/array", body: `[1,2]`},
	{name: "document/string", body: `"x"`},
	{name: "document/number", body: `123`},
	{name: "document/bool", body: `true`},
	{name: "document/number-trailing-junk", body: `123x`},

	// --- syntax errors ---------------------------------------------------------------------
	{name: "syntax/empty", body: ``},
	{name: "syntax/whitespace-only", body: "\n\t "},
	{name: "syntax/truncated-object", body: `{`},
	{name: "syntax/truncated-after-key", body: `{"mtu"`},
	{name: "syntax/truncated-after-colon", body: `{"mtu":`},
	{name: "syntax/truncated-after-value", body: `{"mtu":1`},
	{name: "syntax/truncated-after-comma", body: `{"mtu":1,`},
	{name: "syntax/truncated-string", body: `{"key":"abc`},
	{name: "syntax/truncated-literal", body: `tru`},
	{name: "syntax/missing-value", body: `{"mtu":}`},
	{name: "syntax/trailing-comma", body: `{"mtu":1,}`},
	{name: "syntax/unquoted-key", body: `{mtu:1}`},
	{name: "syntax/missing-colon", body: `{"mtu" 1}`},
	{name: "syntax/double-colon", body: `{"mtu"::1}`},
	{name: "syntax/missing-comma", body: `{"mtu":1 "conn":2}`},
	{name: "syntax/leading-plus", body: `{"mtu":+1}`},
	{name: "syntax/leading-zero", body: `{"mtu":01}`},
	{name: "syntax/dangling-fraction", body: `{"mtu":1.}`},
	{name: "syntax/dangling-exponent", body: `{"mtu":1e}`},
	{name: "syntax/lone-minus", body: `{"mtu":-}`},
	{name: "syntax/two-dots", body: `{"mtu":1.2.3}`},
	{name: "syntax/bad-literal-first", body: `{"nocomp":tXue}`},
	{name: "syntax/bad-literal-last", body: `{"nocomp":fals}`},
	{name: "syntax/bad-literal-null", body: `{"mtu":nul}`},
	{name: "syntax/control-in-string", body: "{\"key\":\"a\tb\"}"},
	{name: "syntax/nul-in-string", body: "{\"key\":\"a\x00b\"}"},
	{name: "syntax/bad-escape", body: `{"key":"a\qb"}`},
	{name: "syntax/bad-unicode-escape", body: `{"key":"a\u00zz"}`},
	{name: "syntax/short-unicode-escape", body: `{"key":"a\u"}`},
	{name: "syntax/byte-order-mark", body: "\ufeff{\"mtu\":1}"},
	// A literal U+FFFD among the hex digits: jsonwire's needEscape test is `r ==
	// utf8.RuneError` over the runes, which is true for a correctly encoded U+FFFD too, so
	// the offending text is printed with strconv.Quote rather than in backquotes.
	{name: "syntax/replacement-char-in-escape", body: "{\"key\":\"a\\u�X\"}"},
	{name: "syntax/invalid-utf8-value", body: "\xffx"},
	{name: "syntax/invalid-utf8-key", body: "{\xff}"},
	{name: "syntax/array-missing-comma", body: `{"unknown":[1 2]}`},

	// --- nesting depth ---------------------------------------------------------------------
	// jsontext caps nesting at maxNestingDepth = 10000 "to prevent stack overflows"
	// (state.go); the 10001st container returns errMaxDepth, so a hostile -c file cannot
	// crash the process. At the cap the decoder only runs out of input.
	{name: "depth/at-max", body: strings.Repeat("[", maxNestingDepth)},
	{name: "depth/over-max", body: strings.Repeat("[", maxNestingDepth+1)},
}

// maxNestingDepth mirrors encoding/json/jsontext/state.go.
const maxNestingDepth = 10000

// genConfig produces the config area.
func genConfig() ([]any, error) {
	cases := make([]any, 0, len(configSpecs))
	for _, spec := range configSpecs {
		c, err := runConfigCase(spec)
		if err != nil {
			return nil, fmt.Errorf("case %s: %w", spec.name, err)
		}
		cases = append(cases, c)
	}
	return cases, nil
}

// runConfigCase builds the starting configuration, overlays spec.body and applies the mode.
func runConfigCase(spec configCaseSpec) (configCase, error) {
	side := spec.side
	if side == "" {
		side = "client"
	}
	var config any
	switch side {
	case "client":
		config = clientDefaults()
	case "server":
		config = serverDefaults()
	default:
		return configCase{}, fmt.Errorf("unknown side %q", side)
	}

	if spec.pre != "" {
		if err := decodeConfigString(config, spec.pre); err != nil {
			return configCase{}, fmt.Errorf("pre: %w", err)
		}
	}
	before, err := json.Marshal(config)
	if err != nil {
		return configCase{}, err
	}

	decodeErr := decodeConfigString(config, spec.body)
	applied := configBase(config).ApplyMode()

	after, err := json.Marshal(config)
	if err != nil {
		return configCase{}, err
	}
	out := configCase{
		Name:        spec.name,
		Side:        side,
		Before:      before,
		Err:         normalizeConfigError(decodeErr),
		ModeApplied: applied,
		Config:      after,
	}
	if utf8.ValidString(spec.body) {
		out.JSON = spec.body
	} else {
		out.JSONHex = hx([]byte(spec.body))
	}
	return out, nil
}

// configBase returns the embedded BaseConfig of either side's Config.
func configBase(config any) *std.BaseConfig {
	switch c := config.(type) {
	case *kcptunclient.Config:
		return &c.BaseConfig
	case *kcptunserver.Config:
		return &c.BaseConfig
	}
	panic("configBase: unexpected config type")
}

// decodeConfigString runs kcptun's ParseJSONConfig over a document held in memory, by writing
// it to a temporary file: the code path under test is std.ParseJSONConfig itself, not a
// re-implementation of it.
func decodeConfigString(config any, body string) error {
	dir, err := os.MkdirTemp("", "govectors-config-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(dir)
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return err
	}
	return std.ParseJSONConfig(config, path)
}

// normalizeConfigError renders ParseJSONConfig's error with the Go type name kcptun's own
// binaries print. encoding/json names the configuration's type in the whole-document error;
// in client/main.go and server/main.go that type is `main.Config`, while the copies used here
// live in their own packages so that both can be called `Config`.
func normalizeConfigError(err error) string {
	if err == nil {
		return ""
	}
	s := err.Error()
	for _, pkg := range []string{"kcptunclient.", "kcptunserver."} {
		s = strings.ReplaceAll(s, pkg+"Config", "main.Config")
	}
	return s
}
