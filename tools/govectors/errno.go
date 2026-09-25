package main

// Area "errno" (plan step 10.6, DECISIONS D30): Go's own syscall error table.
//
// Go never calls strerror(3). Every syscall.Errno renders itself from a table the Go
// distribution generates per GOOS/GOARCH (syscall/zerrors_<goos>_<goarch>.go, `var errors
// = [...]string{...}`) and falls back to a numeric form for anything the table has no text
// for (syscall/syscall_unix.go, `func (e Errno) Error()`). Taking the C library's message
// instead only ever looked right because glibc happens to agree for the common errnos: a
// static musl build's strerror spells EADDRINUSE "Address in use" where glibc's spells it
// "Address already in use", and Go's table entry is the lower-case "address already in use" --
// so the port printed "bind: address in use" on musl where Go prints "bind: address already in
// use". Since the port's log lines are a byte-for-byte contract (porting guide section 4, and
// the CLI differential of step 09.5), the table is ported rather than borrowed.
//
// This area dumps the table for every target triple the port builds for (DECISIONS D22),
// plus the numeric fallback, so `kcptun_kcp::goerrno` can be checked against the Go source
// on a host that is not the target. The tables are read out of the Go distribution's own
// source, which is why the file records the toolchain version in its header like every other
// vector file.

import (
	"fmt"
	"go/build"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
)

// errnoCase is one GOOS/GOARCH pair's error table.
type errnoCase struct {
	Name   string `json:"name"` // "<goos>/<goarch>"
	GOOS   string `json:"goos"`
	GOARCH string `json:"goarch"`
	// Source is the file in the Go distribution the table was read from.
	Source string `json:"source"`
	// Errors is Go's `errors` array: index == errno, "" for an index the table leaves
	// empty (Go's own tables are sparse; index 0 is always empty).
	Errors []string `json:"errors"`
	// Probes are `syscall.Errno(errno).Error()` for values in and around the table,
	// including the ones that take the numeric fallback.
	Probes []errnoProbe `json:"probes"`
}

// CaseName implements namedCase.
func (c errnoCase) CaseName() string { return c.Name }

// errnoProbe is one syscall.Errno rendered the way Go renders it.
type errnoProbe struct {
	Errno int    `json:"errno"`
	Text  string `json:"text"`
}

// errnoTargets are the GOOS/GOARCH pairs whose tables the port carries, in file order.
// They are exactly the platforms of DECISIONS D22: Linux (the supported platform) on
// x86_64, i686, aarch64 and arm, macOS (the development host) and FreeBSD (best effort).
var errnoTargets = []struct{ goos, goarch string }{
	{"linux", "amd64"},
	{"linux", "386"},
	{"linux", "arm64"},
	{"linux", "arm"},
	{"darwin", "amd64"},
	{"darwin", "arm64"},
	{"freebsd", "amd64"},
}

// errnoProbePoints returns the errno values probed for a table: every hole (an index the Go
// table leaves empty, which takes the numeric fallback), the ends, and a few values past the
// end that take the fallback too.
func errnoProbePoints(table []string) []int {
	n := len(table)
	seen := map[int]bool{}
	var out []int
	add := func(v int) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(-1)
	add(0)
	add(1)
	// Index 0 on every platform, plus 41 and 58 on Linux.
	for i, text := range table {
		if text == "" {
			add(i)
		}
	}
	add(n - 1)
	add(n)
	add(n + 1)
	add(4095)
	return out
}

// goroot locates the Go distribution whose tables are read. `go build -trimpath` (which
// tools/gen-vectors.sh uses) strips the compiled-in GOROOT, so the environment and the
// toolchain itself are asked first.
func goroot() (string, error) {
	if dir := os.Getenv("GOROOT"); dir != "" {
		return dir, nil
	}
	if out, err := exec.Command("go", "env", "GOROOT").Output(); err == nil {
		if dir := strings.TrimSpace(string(out)); dir != "" {
			return dir, nil
		}
	}
	if dir := build.Default.GOROOT; dir != "" {
		return dir, nil
	}
	return "", fmt.Errorf("cannot locate GOROOT: set GOROOT or put go(1) on PATH")
}

// genErrno reads one table per entry of errnoTargets out of the Go distribution.
func genErrno() ([]any, error) {
	goroot, err := goroot()
	if err != nil {
		return nil, err
	}
	cases := make([]any, 0, len(errnoTargets))
	hostChecked := false
	for _, t := range errnoTargets {
		rel := filepath.Join("src", "syscall", fmt.Sprintf("zerrors_%s_%s.go", t.goos, t.goarch))
		table, err := parseErrnoTable(filepath.Join(goroot, rel))
		if err != nil {
			return nil, err
		}
		probes := make([]errnoProbe, 0, 8)
		for _, n := range errnoProbePoints(table) {
			probes = append(probes, errnoProbe{Errno: n, Text: errnoError(table, n)})
		}
		// The host's own table is the one the running toolchain uses, so it can be
		// checked against the real syscall.Errno.Error() rather than only parsed.
		if t.goos == runtime.GOOS && t.goarch == runtime.GOARCH {
			if err := checkErrnoAgainstRuntime(table); err != nil {
				return nil, err
			}
			hostChecked = true
		}
		cases = append(cases, errnoCase{
			Name:   t.goos + "/" + t.goarch,
			GOOS:   t.goos,
			GOARCH: t.goarch,
			Source: filepath.ToSlash(rel),
			Errors: table,
			Probes: probes,
		})
	}
	// The whole pipeline rests on parseErrnoTable reading Go's files correctly, and the only
	// proof of that is checkErrnoAgainstRuntime — which can only run when the generating host
	// is itself one of errnoTargets. Regenerating anywhere else would write the file with no
	// proof at all, so refuse rather than produce an unchecked vector file.
	if !hostChecked {
		return nil, fmt.Errorf("errno: host %s/%s is not in errnoTargets, so the parser was "+
			"never checked against the real syscall.Errno; regenerate on a listed platform",
			runtime.GOOS, runtime.GOARCH)
	}
	return cases, nil
}

// errnoError is Go's syscall.Errno.Error() over an already-read table.
//
// Go: go1.27.1 syscall/syscall_unix.go:(Errno).Error()
func errnoError(table []string, errno int) string {
	if 0 <= errno && errno < len(table) {
		if s := table[errno]; s != "" {
			return s
		}
	}
	return "errno " + strconv.Itoa(errno)
}

// checkErrnoAgainstRuntime confirms that the parsed table reproduces the linked Go
// runtime's own syscall.Errno.Error() for every value in and well past the table. It is
// the generator's proof that parseErrnoTable reads the tables correctly; the tables of
// the other targets come out of the same generated files by the same parser.
func checkErrnoAgainstRuntime(table []string) error {
	for n := 0; n < len(table)+64; n++ {
		if got, want := errnoError(table, n), syscall.Errno(n).Error(); got != want {
			return fmt.Errorf("errno %d: parsed table says %q, syscall.Errno says %q", n, got, want)
		}
	}
	return nil
}

// parseErrnoTable reads `var errors = [...]string{ N: "text", ... }` out of one
// zerrors_<goos>_<goarch>.go and returns it indexed by errno.
func parseErrnoTable(path string) ([]string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("errno table: %w", err)
	}
	const marker = "var errors = [...]string{"
	start := strings.Index(string(data), marker)
	if start < 0 {
		return nil, fmt.Errorf("errno table: %s has no %q", path, marker)
	}
	body := string(data[start+len(marker):])
	end := strings.Index(body, "\n}")
	if end < 0 {
		return nil, fmt.Errorf("errno table: %s has an unterminated table", path)
	}
	var table []string
	for _, line := range strings.Split(body[:end], "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		colon := strings.Index(line, ":")
		if colon < 0 {
			return nil, fmt.Errorf("errno table: %s: cannot parse %q", path, line)
		}
		idx, err := strconv.Atoi(strings.TrimSpace(line[:colon]))
		if err != nil {
			return nil, fmt.Errorf("errno table: %s: cannot parse %q: %w", path, line, err)
		}
		text, err := strconv.Unquote(strings.TrimSuffix(strings.TrimSpace(line[colon+1:]), ","))
		if err != nil {
			return nil, fmt.Errorf("errno table: %s: cannot parse %q: %w", path, line, err)
		}
		if idx < 0 {
			return nil, fmt.Errorf("errno table: %s: negative index in %q", path, line)
		}
		for len(table) <= idx {
			table = append(table, "")
		}
		if table[idx] != "" {
			return nil, fmt.Errorf("errno table: %s: duplicate index %d", path, idx)
		}
		table[idx] = text
	}
	if len(table) == 0 {
		return nil, fmt.Errorf("errno table: %s: empty table", path)
	}
	return table, nil
}
