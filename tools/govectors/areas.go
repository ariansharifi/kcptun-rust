package main

// area is one vector file: testdata/vectors/<name>.json.
type area struct {
	name string
	gen  func() ([]any, error) // returns the cases in file order
}

// areas lists every area in the order "all" generates them. The plan step that fills
// each one in is noted; until then an area writes the header with an empty cases array.
var areas = []area{
	{"crypt", genCrypt},         // 02.1: BlockCrypt ciphers, nonce/CRC32 packet layout
	{"fec", genFec},             // 04.6: FEC encoder/decoder packet streams
	{"autotune", genAutotune},   // 04.3: FEC autotune period detection
	{"rs", genRs},               // 04.1: Reed-Solomon shards
	{"kcp", genKcp},             // 03.1: KCP segment codec and ARQ traces
	{"smux", genSmux},           // 06.1: smux frame headers and sessions
	{"snappy", genSnappy},       // 07.1: framed snappy streams
	{"qpp", genQpp},             // 07.2: QPP pads, PRNG and streams
	{"cli", genCli},             // 08.1: Go flag / urfave-cli v1 parsing and help
	{"config", genConfig},       // 08.2: JSON config overlay, mode presets
	{"multiport", genMultiport}, // 08.4: multi-port and host:port address parsing
	{"timefmt", genTimefmt},     // 08.4: Go reference-layout time formatting
	{"errno", genErrno},         // 10.6: Go's syscall errno -> string table (D30)
}

func noCases() ([]any, error) { return []any{}, nil }
