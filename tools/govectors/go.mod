// govectors writes the golden test vectors in testdata/vectors/ using the exact
// library versions pinned by the Go reference (reference/kcptun/go.mod). Every
// version below must stay identical to that file; the generator refuses to run otherwise
// (checkPinned in buildinfo.go, against the table in deps.go).
module github.com/kcptun-rust/tools/govectors

go 1.24.0

require (
	github.com/golang/snappy v1.0.0
	github.com/klauspost/reedsolomon v1.13.0
	github.com/urfave/cli v1.22.17
	github.com/xtaci/kcp-go/v5 v5.6.66
	github.com/xtaci/qpp v1.1.25
	github.com/xtaci/smux v1.5.55
	golang.org/x/crypto v0.47.0
)

require (
	github.com/cpuguy83/go-md2man/v2 v2.0.7 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/pkg/errors v0.9.1 // indirect
	github.com/russross/blackfriday/v2 v2.1.0 // indirect
	github.com/tjfoc/gmsm v1.4.1 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)
