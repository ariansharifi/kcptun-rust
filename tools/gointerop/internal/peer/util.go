package peer

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
)

// Pinned lists the module versions of the Go reference (reference/kcptun/go.mod, kcptun
// v0.0.0-20260208051026-39935d5307f0). The peers must exercise exactly these versions;
// CheckPinned refuses to run a binary that links any of them at another version or replaced.
var Pinned = map[string]string{
	"github.com/golang/snappy":         "v1.0.0",
	"github.com/klauspost/cpuid/v2":    "v2.3.0",
	"github.com/klauspost/reedsolomon": "v1.13.0",
	"github.com/pkg/errors":            "v0.9.1",
	"github.com/tjfoc/gmsm":            "v1.4.1",
	"github.com/xtaci/kcp-go/v5":       "v5.6.66",
	"github.com/xtaci/qpp":             "v1.1.25",
	"github.com/xtaci/smux":            "v1.5.55",
	"golang.org/x/crypto":              "v0.47.0",
	"golang.org/x/net":                 "v0.49.0",
	"golang.org/x/sys":                 "v0.40.0",
	"golang.org/x/time":                "v0.14.0",
}

// checkModules verifies deps against Pinned: every pinned module that is linked must be at
// its pinned version and not replaced. Modules a program does not link are ignored.
func checkModules(deps []*debug.Module) error {
	var bad []string
	for _, d := range deps {
		want, ok := Pinned[d.Path]
		if !ok {
			continue
		}
		if d.Replace != nil {
			bad = append(bad, fmt.Sprintf("%s: replaced by %s %s", d.Path, d.Replace.Path, d.Replace.Version))
		} else if d.Version != want {
			bad = append(bad, fmt.Sprintf("%s: linked %s, pinned %s", d.Path, d.Version, want))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("module versions differ from reference/kcptun/go.mod:\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}

// CheckPinned exits with status 3 if the running binary links a pinned module at another
// version (see Pinned). Call it first in main.
func CheckPinned(prog string) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		fmt.Fprintf(os.Stderr, "%s: no build information embedded in the binary\n", prog)
		os.Exit(3)
	}
	if err := checkModules(bi.Deps); err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", prog, err)
		os.Exit(3)
	}
}

// ParseChunks parses a comma-separated list of positive chunk sizes, such as "1,7,4096".
func ParseChunks(s string) ([]int, error) {
	var out []int
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		n, err := strconv.Atoi(f)
		if err != nil || n <= 0 {
			return nil, fmt.Errorf("invalid chunk size %q: want a positive integer", f)
		}
		out = append(out, n)
	}
	return out, nil
}

// ChunkedCopy copies src to dst in chunks whose sizes cycle through sizes. Each chunk is
// read in full (io.ReadFull; only the last one may be shorter) and passed to fn, which may
// transform it in place, before being written with a single dst.Write call. It returns the
// number of bytes copied.
func ChunkedCopy(dst io.Writer, src io.Reader, sizes []int, fn func([]byte)) (int64, error) {
	max := 0
	for _, s := range sizes {
		if s > max {
			max = s
		}
	}
	buf := make([]byte, max)
	var total int64
	for i := 0; ; i++ {
		chunk := buf[:sizes[i%len(sizes)]]
		n, err := io.ReadFull(src, chunk)
		if n > 0 {
			if fn != nil {
				fn(chunk[:n])
			}
			if _, werr := dst.Write(chunk[:n]); werr != nil {
				return total, werr
			}
			total += int64(n)
		}
		if err == io.EOF || err == io.ErrUnexpectedEOF {
			return total, nil
		}
		if err != nil {
			return total, err
		}
	}
}

// PrintJSON writes v to stdout as one JSON line.
func PrintJSON(v any) {
	b, err := json.Marshal(v)
	if err != nil {
		fmt.Fprintf(os.Stderr, "json: %v\n", err)
		os.Exit(1)
	}
	os.Stdout.Write(append(b, '\n'))
}
