// Package kcptunserver holds kcptun's server Config struct.
//
// Provenance: the struct below is a verbatim copy of kcptun server/config.go
// (github.com/xtaci/kcptun v0.0.0-20260208051026-39935d5307f0). See the package comment of
// internal/kcptunclient for why it lives in a package of its own.
package kcptunserver

import "github.com/kcptun-rust/tools/govectors/internal/std"

// Config defines the server-side settings supplied via flags or JSON.
type Config struct {
	std.BaseConfig        // Embed shared configuration
	Listen         string `json:"listen"`
	Target         string `json:"target"`
}
