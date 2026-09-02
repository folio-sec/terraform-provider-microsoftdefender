package validation

import "encoding/hex"

const (
	MD5HexLength    = 32
	SHA1HexLength   = 40
	SHA256HexLength = 64
)

// IsHexHash reports whether value is a supported, fixed-length hexadecimal
// hash. Restricting the accepted lengths bounds decoding work and allocation.
func IsHexHash(value string, expectedLength int) bool {
	switch expectedLength {
	case MD5HexLength, SHA1HexLength, SHA256HexLength:
	default:
		return false
	}
	if len(value) != expectedLength {
		return false
	}
	var decoded [SHA256HexLength / 2]byte
	_, err := hex.Decode(decoded[:hex.DecodedLen(expectedLength)], []byte(value))
	return err == nil
}

func IsSupportedHash(value string) bool {
	return IsHexHash(value, len(value))
}
