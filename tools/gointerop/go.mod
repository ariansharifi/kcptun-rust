// gointerop holds small Go programs that expose single kcptun layers (raw kcp-go sessions,
// smux over TCP, snappy framing, QPP) for interop tests against the Rust port. Every version
// below must stay identical to reference/kcptun/go.mod; the programs refuse to run otherwise
// (internal/peer.CheckPinned).
module github.com/kcptun-rust/tools/gointerop

go 1.24.0

require (
	github.com/golang/snappy v1.0.0
	github.com/pkg/errors v0.9.1
	github.com/xtaci/kcp-go/v5 v5.6.66
	github.com/xtaci/qpp v1.1.25
	github.com/xtaci/smux v1.5.55
	golang.org/x/crypto v0.47.0
)

require (
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.13.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
