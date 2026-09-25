package main

// The blank imports below link every pinned library into the binary, even while an
// area is still a stub. That keeps them as direct requirements in go.mod and makes
// them visible to debug.ReadBuildInfo, so every vector file records (and checkPinned
// verifies) the exact versions it was produced with. Remove an import here only once
// a real area imports the package for its own use.
import (
	_ "github.com/xtaci/qpp"
)

// pinned lists the module versions of the Go reference (reference/kcptun/go.mod,
// kcptun v0.0.0-20260208051026-39935d5307f0). Vectors produced with any other version
// would not describe the implementation the Rust port must match, so the generator
// refuses to run if the linked versions differ.
var pinned = map[string]string{
	"github.com/golang/snappy":         "v1.0.0",
	"github.com/klauspost/cpuid/v2":    "v2.3.0",
	"github.com/klauspost/reedsolomon": "v1.13.0",
	"github.com/pkg/errors":            "v0.9.1",
	"github.com/tjfoc/gmsm":            "v1.4.1",
	"github.com/urfave/cli":            "v1.22.17",
	"github.com/xtaci/kcp-go/v5":       "v5.6.66",
	"github.com/xtaci/qpp":             "v1.1.25",
	"github.com/xtaci/smux":            "v1.5.55",
	"golang.org/x/crypto":              "v0.47.0",
	"golang.org/x/net":                 "v0.49.0",
	"golang.org/x/sys":                 "v0.40.0",
	"golang.org/x/time":                "v0.14.0",
}
