package validation

import (
	"strings"
	"testing"
)

func TestIsHexHash(t *testing.T) {
	t.Parallel()
	for name, test := range map[string]struct {
		value  string
		length int
		valid  bool
	}{
		"lowercase SHA256": {value: strings.Repeat("ab", 32), length: SHA256HexLength, valid: true},
		"uppercase SHA1":   {value: strings.Repeat("AB", 20), length: SHA1HexLength, valid: true},
		"MD5":              {value: strings.Repeat("01", 16), length: MD5HexLength, valid: true},
		"invalid byte":     {value: strings.Repeat("0", 63) + "g", length: SHA256HexLength},
		"unicode":          {value: strings.Repeat("0", 62) + "é", length: SHA256HexLength},
		"wrong length":     {value: strings.Repeat("0", 63), length: SHA256HexLength},
		"unsupported size": {value: strings.Repeat("0", 128), length: 128},
		"empty":            {value: "", length: 0},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if got := IsHexHash(test.value, test.length); got != test.valid {
				t.Fatalf("IsHexHash() = %t, want %t", got, test.valid)
			}
		})
	}
}

func TestIsSupportedHash(t *testing.T) {
	t.Parallel()
	if !IsSupportedHash(strings.Repeat("a", SHA256HexLength)) {
		t.Fatal("valid SHA256 rejected")
	}
	if IsSupportedHash(strings.Repeat("a", SHA256HexLength+2)) {
		t.Fatal("unsupported hash length accepted")
	}
}
