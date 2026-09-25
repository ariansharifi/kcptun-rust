// Key derivation shared by kcptun's client and server.
//
// Provenance: kcptun client/main.go and server/main.go
// (github.com/xtaci/kcptun v0.0.0-20260208051026-39935d5307f0): the SALT constant and the
// expression `pbkdf2.Key([]byte(config.Key), []byte(SALT), 4096, 32, sha1.New)`, which both
// binaries evaluate before calling SelectBlockCrypt. It is not part of kcptun's std package; it
// lives here so every interop peer derives keys the same way.
package std

import (
	"crypto/sha1"

	"golang.org/x/crypto/pbkdf2"
)

// SALT is used as the PBKDF2 salt while deriving the shared session key (kcptun client/main.go).
const SALT = "kcp-go"

// DeriveKey returns the 32-byte session key kcptun derives from the -key flag.
func DeriveKey(key string) []byte {
	return pbkdf2.Key([]byte(key), []byte(SALT), 4096, 32, sha1.New)
}
