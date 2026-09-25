// Package kcptunclient holds kcptun's client Config struct.
//
// Provenance: the struct below is a verbatim copy of kcptun client/config.go
// (github.com/xtaci/kcptun v0.0.0-20260208051026-39935d5307f0). It lives in its own package
// only because Go allows one `Config` per package and the vectors need both sides; the type
// name is what encoding/json reports in field errors ("Config.mtu"), so it must stay `Config`.
// The package path shows up only in the whole-document error ("main.Config" in the real
// binary), which tools/govectors/config.go rewrites.
package kcptunclient

import "github.com/kcptun-rust/tools/govectors/internal/std"

// Config models the client-side configuration loaded via flags or JSON.
type Config struct {
	std.BaseConfig        // Embed shared configuration
	LocalAddr      string `json:"localaddr"`
	RemoteAddr     string `json:"remoteaddr"`
	Conn           int    `json:"conn"`
	AutoExpire     int    `json:"autoexpire"`
	ScavengeTTL    int    `json:"scavengettl"`
}
