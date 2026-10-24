package xwing

import (
	"bytes"
	"encoding/hex"
	"errors"
	"testing"
)

// DecodeHex decodes the hexstring.
func DecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("failed to decode hex %s: %v", s, err)
	}

	return b
}

// AssertBytesEqual checks got againt want for bytes equality.
func AssertBytesEqual(t *testing.T, got []byte, want []byte) {
	t.Helper()

	if !bytes.Equal(got, want) {
		t.Errorf("got: %v, want: %v", got, want)
	}
}

// AssertError checks got against want error using errors.Is.
func AssertError(t *testing.T, got error, want error) {
	t.Helper()

	if !errors.Is(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
