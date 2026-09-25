// Not part of kcptun: read-only access to the cryptMethods table of the verbatim copy in
// crypt.go, so the vectors can record which key slice SelectBlockCrypt hands to a constructor.
package std

// CryptKeySize reports the keySize column of kcptun's cryptMethods table for method
// (0 = the full pass) and whether method is in the table at all.
func CryptKeySize(method string) (keySize int, ok bool) {
	m, ok := cryptMethods[method]
	return m.keySize, ok
}
