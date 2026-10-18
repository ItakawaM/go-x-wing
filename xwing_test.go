package xwing

import (
	"bytes"
	"testing"
)

func TestXWingRoundtrip(t *testing.T) {
	t.Run("roundtrip", func(t *testing.T) {
		priv, pub, err := GenerateKeyPair()
		if err != nil {
			t.Fatalf("failed to generate key pair: %s", err)
		}

		sharedSecretEncap, ciphertext, err := Encapsulate(pub)
		if err != nil {
			t.Fatalf("failed to encapsulate: %s", err)
		}

		sharedSecretDecap, err := priv.Decapsulate(ciphertext)
		if err != nil {
			t.Fatalf("failed to decapsulate: %s", err)
		}

		if !bytes.Equal(sharedSecretEncap, sharedSecretDecap) {
			t.Errorf("shared secrets don't match encap = %v, decap = %v",
				sharedSecretEncap, sharedSecretDecap)
		}
	})
}
