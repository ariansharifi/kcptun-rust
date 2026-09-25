// Command govectors writes deterministic golden test vectors for the Rust port of
// kcptun, using the exact Go libraries pinned by the reference (see go.mod and deps.go).
//
// Usage:
//
//	govectors [-out DIR] all | AREA...
//
// AREA is one of: crypt fec autotune rs kcp smux snappy qpp cli config multiport timefmt.
// Each area is written to DIR/<area>.json (default DIR: testdata/vectors). Output is
// byte-identical between runs. Normally run through tools/gen-vectors.sh.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const generatorName = "govectors"

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func usage(w io.Writer, fs *flag.FlagSet) {
	fmt.Fprintf(w, "usage: %s [-out DIR] all | AREA...\n\nareas: %s\n\nflags:\n",
		generatorName, strings.Join(areaNames(), " "))
	fs.SetOutput(w)
	fs.PrintDefaults()
}

func areaNames() []string {
	names := make([]string, len(areas))
	for i, a := range areas {
		names[i] = a.name
	}
	return names
}

// selectAreas resolves the command-line arguments to areas, in the order of the areas
// table and without duplicates.
func selectAreas(args []string) ([]area, error) {
	if len(args) == 0 {
		return nil, fmt.Errorf("no area given")
	}
	want := make(map[string]bool, len(args))
	for _, a := range args {
		if a == "all" {
			return areas, nil
		}
		found := false
		for _, ar := range areas {
			if ar.name == a {
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("unknown area %q", a)
		}
		want[a] = true
	}
	var sel []area
	for _, ar := range areas {
		if want[ar.name] {
			sel = append(sel, ar)
		}
	}
	return sel, nil
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet(generatorName, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	out := fs.String("out", "testdata/vectors", "output directory for <area>.json files")
	if err := fs.Parse(args); err != nil {
		if err == flag.ErrHelp {
			usage(stdout, fs)
			return 0
		}
		fmt.Fprintf(stderr, "%s: %v\n", generatorName, err)
		usage(stderr, fs)
		return 2
	}
	sel, err := selectAreas(fs.Args())
	if err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", generatorName, err)
		usage(stderr, fs)
		return 2
	}
	if err := generate(*out, sel, stdout); err != nil {
		fmt.Fprintf(stderr, "%s: %v\n", generatorName, err)
		return 1
	}
	return 0
}

// generate writes one vector file per selected area into dir.
func generate(dir string, sel []area, log io.Writer) error {
	mods, err := moduleVersions()
	if err != nil {
		return err
	}
	if err := checkPinned(mods); err != nil {
		return err
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	for _, a := range sel {
		cases, err := a.gen()
		if err != nil {
			return fmt.Errorf("area %s: %w", a.name, err)
		}
		if err := checkCaseNames(cases); err != nil {
			return fmt.Errorf("area %s: %w", a.name, err)
		}
		data, err := encodeVectorFile(&VectorFile{
			Generator: generatorName,
			Go:        runtime.Version(),
			Modules:   mods,
			Area:      a.name,
			Cases:     cases,
		})
		if err != nil {
			return fmt.Errorf("area %s: encode: %w", a.name, err)
		}
		path := filepath.Join(dir, a.name+".json")
		if err := writeFileAtomic(path, data); err != nil {
			return fmt.Errorf("area %s: %w", a.name, err)
		}
		fmt.Fprintf(log, "wrote %s (%d cases, %d bytes)\n", path, len(cases), len(data))
	}
	return nil
}

// checkCaseNames rejects empty or duplicate names among the cases that implement
// namedCase (Case does), since the Rust tests look vectors up and report failures by name.
func checkCaseNames(cases []any) error {
	seen := make(map[string]bool, len(cases))
	for i, c := range cases {
		nc, ok := c.(namedCase)
		if !ok {
			continue
		}
		name := nc.CaseName()
		if name == "" {
			return fmt.Errorf("case %d has an empty name", i)
		}
		if seen[name] {
			return fmt.Errorf("duplicate case name %q", name)
		}
		seen[name] = true
	}
	return nil
}
