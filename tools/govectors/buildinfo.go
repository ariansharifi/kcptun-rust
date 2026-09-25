package main

import (
	"fmt"
	"runtime/debug"
	"sort"
	"strings"
)

// moduleVersions returns the path -> version map of every module linked into this
// binary, as recorded by the Go toolchain.
func moduleVersions() (map[string]string, error) {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return nil, fmt.Errorf("no build information embedded in the binary")
	}
	mods := make(map[string]string, len(bi.Deps))
	for _, d := range bi.Deps {
		if d.Replace != nil {
			return nil, fmt.Errorf("module %s is replaced by %s %s; vectors must come from the pinned upstream module",
				d.Path, d.Replace.Path, d.Replace.Version)
		}
		mods[d.Path] = d.Version
	}
	return mods, nil
}

// checkPinned verifies that every pinned module is linked at exactly its pinned version.
func checkPinned(mods map[string]string) error {
	var bad []string
	for path, want := range pinned {
		got, ok := mods[path]
		switch {
		case !ok:
			bad = append(bad, fmt.Sprintf("%s: not linked (want %s)", path, want))
		case got != want:
			bad = append(bad, fmt.Sprintf("%s: linked %s, pinned %s", path, got, want))
		}
	}
	if len(bad) > 0 {
		sort.Strings(bad)
		return fmt.Errorf("module versions differ from reference/kcptun/go.mod:\n  %s", strings.Join(bad, "\n  "))
	}
	return nil
}
