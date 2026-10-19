// Package xwing implements X-Wing, a general-purpose hybrid post-quantum KEM
// as defined in draft-connolly-cfrg-xwing-kem-11.html dated 23 September 2026.
//
// This is an EDUCATIONAL project and is not verified/recommended for usage
// in any software.
//
// Authors of the draft:
//   - Deirdre Connolly Selkie Cryptography durumcrustulum@gmail.com
//   - Peter Schwabe MPI-SP & Radboud University peter@cryptojedi.org
//   - Bas Westerbaan Cloudflare bas@cloudflare.com
//
// Source:
// https://www.ietf.org/archive/id/draft-connolly-cfrg-xwing-kem-11.html
package xwing

import (
	"bytes"
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
)

// This implementation uses the following naming conventions:
// 	- sk = Secret Key/Private Key/Decapsulation Key
//	- pk = Public Key/Encapsulation Key
//	- ss = Shared Secret
// 	- ct = Ciphertext
//	- m  = ML-KEM-768
// 	- x  = X25519
//
// Those are used interchangeably in code and documentation.
// Decapsulation Key and Encapsulation Key were preferred
// to match the implementation of ML-KEM.

const (
	// DecapsulationKeySize is the size of the decapsulation key in bytes.
	DecapsulationKeySize = 32

	// EncapsulationKeySize is the size of the encapsulation key in bytes.
	// ML-KEM-768 key (1184) || X25519 key (32)
	EncapsulationKeySize = 1216

	// CiphertextSize is the size of the ciphertext
	// produced by X-Wing in bytes.
	// ML-KEM ciphertext (1088) || X25519 ciphertext (32)
	CiphertextSize = 1120

	// SharedSecretSize is the size of the shared secret
	// produced by X-Wing in bytes.
	SharedSecretSize = 32

	// expandedDecapsulationKeySize is the size to which
	// SumSHAKE256 expands the decapsulation key.
	expandedDecapsulationKeySize = 96
)

var (
	// ErrInvalidEncapsulationKey is returned when the provided encapsulation key
	// is invalid: length mismatch, invalid x25519 or mlkem keys.
	ErrInvalidEncapsulationKey = errors.New("invalid encapsulation key")

	// ErrInvalidDecapsulationKey is returned when the provided decapsulation key
	// is invalid: length mismatch, invalid x25519 or mlkem keys.
	ErrInvalidDecapsulationKey = errors.New("invalid decapsulation key")

	// ErrInvalidCiphertext is returned when the provided ciphertext
	// is invalid: length mismatch, invalid x25519 ciphertext.
	ErrInvalidCiphertext = errors.New("invalid ciphertext")
)

// xWingLabel is a constant defined in the draft.
// It is appended at the end of combiner before taking the hashsum.
//
//	\./
//	/^\
var xWingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// GenerateKeyPair creates a pair of Decapsulation and Encapsulation keys
// using a secure entropy source.
func GenerateKeyPair() (*DecapsulationKey, *EncapsulationKey, error) {
	seed := make([]byte, DecapsulationKeySize)
	_, _ = rand.Read(seed) // rand.Read never errors and always fills the buffer

	skM, skX, pkM, pkX, err := expandSecretKey(seed)
	if err != nil {
		return nil, nil, err
	}

	return &DecapsulationKey{
		seed: seed,
		skM:  skM,
		skX:  skX,
	}, &EncapsulationKey{
		pkM: pkM,
		pkX: pkX,
	}, nil
}

// DecapsulationKey represents the Decapsulation Key of X-Wing KEM.
// It caches the necessary keys of mlkem and x25519 for faster decapsulation.
// Only seed should ever be exposed via the Bytes method.
//
// Create with NewDecapsulationKey or GenerateKeyPair.
type DecapsulationKey struct {
	seed []byte

	// cached
	skM *mlkem.DecapsulationKey768
	skX *ecdh.PrivateKey
}

// NewDecapsulationKey initializes a new DecapsulationKey with key as the seed.
// It errors with ErrInvalidDecapsulationKey when the length of the provided key
// does not match DecapsulationKeySize.
func NewDecapsulationKey(key []byte) (*DecapsulationKey, error) {
	if len(key) != DecapsulationKeySize {
		return nil, fmt.Errorf("%w: length mismatch: want = %d, got = %d",
			ErrInvalidDecapsulationKey, DecapsulationKeySize, len(key))
	}

	k := bytes.Clone(key)
	skM, skX, _, _, err := expandSecretKey(k)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidDecapsulationKey, err)
	}

	return &DecapsulationKey{
		seed: k,
		skM:  skM,
		skX:  skX,
	}, nil
}

// Decapsulate recovers the shared secret from the provided ciphertext.
// It errors with ErrInvalidCiphertext when the length of the provided ciphertext
// does not match CiphertextSize or x25519 ciphertext is invalid.
func (d *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("%w: length mismatch: want = %d, got = %d",
			ErrInvalidCiphertext, CiphertextSize, len(ciphertext))
	}

	ctM := ciphertext[:mlkem.CiphertextSize768]
	ctX := ciphertext[mlkem.CiphertextSize768:]

	ssM, err := d.skM.Decapsulate(ctM)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCiphertext, err)
	}

	ctKey, err := ecdh.X25519().NewPublicKey(ctX)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCiphertext, err)
	}

	ssX, err := d.skX.ECDH(ctKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCiphertext, err)
	}

	return combiner(ssM, ssX, ctX, d.skX.PublicKey().Bytes()), nil
}

// Bytes returns a copy of the key in bytes.
func (d *DecapsulationKey) Bytes() []byte {
	return bytes.Clone(d.seed)
}

// EncapsulationKey returns the corresponding EncapsulationKey.
func (d *DecapsulationKey) EncapsulationKey() *EncapsulationKey {
	return &EncapsulationKey{
		pkM: d.skM.EncapsulationKey(),
		pkX: d.skX.PublicKey(),
	}
}

// EncapsulationKey represents the Encapsulation Key of X-Wing KEM.
//
// Create with NewEncapsulationKey or GenerateKeyPair.
type EncapsulationKey struct {
	pkM *mlkem.EncapsulationKey768
	pkX *ecdh.PublicKey
}

// NewEncapsulationKey parses the provided key and returns it as a new EncapsulationKey.
// It errors with ErrInvalidEncapsulationKey when the length of the provided key
// does not match EncapsulationKeySize or ml-kem encoding is invalid.
func NewEncapsulationKey(key []byte) (*EncapsulationKey, error) {
	if len(key) != EncapsulationKeySize {
		return nil, fmt.Errorf("%w: length mismatch: want = %d, got = %d",
			ErrInvalidEncapsulationKey, EncapsulationKeySize, len(key))
	}

	pkM, err := mlkem.NewEncapsulationKey768(key[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEncapsulationKey, err)
	}

	pkX, err := ecdh.X25519().NewPublicKey(key[mlkem.EncapsulationKeySize768:])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEncapsulationKey, err)
	}

	return &EncapsulationKey{
		pkM: pkM,
		pkX: pkX,
	}, nil
}

// Encapsulate creates a shared secret and its corresponding ciphertext.
// It errors with ErrInvalidEncapsulationKey when x25519 key is invalid.
func (e *EncapsulationKey) Encapsulate() (sharedSecret, ciphertext []byte, err error) {
	ekX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidEncapsulationKey, err)
	}
	ctX := ekX.PublicKey().Bytes()

	ssX, err := ekX.ECDH(e.pkX)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidEncapsulationKey, err)
	}

	ssM, ctM := e.pkM.Encapsulate()

	sharedSecret = combiner(ssM, ssX, ctX, e.pkX.Bytes())
	return sharedSecret, append(ctM, ctX...), nil
}

// Bytes returns a copy of the key in bytes.
func (e *EncapsulationKey) Bytes() []byte {
	// both return a copy
	return append(e.pkM.Bytes(), e.pkX.Bytes()...)
}

func expandSecretKey(secretKey []byte) (skM *mlkem.DecapsulationKey768, skX *ecdh.PrivateKey, pkM *mlkem.EncapsulationKey768, pkX *ecdh.PublicKey, err error) {
	expanded := sha3.SumSHAKE256(secretKey, expandedDecapsulationKeySize)
	skM, err = mlkem.NewDecapsulationKey768(expanded[:64])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pkM = skM.EncapsulationKey()

	skX, err = ecdh.X25519().NewPrivateKey(expanded[64:])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pkX = skX.PublicKey()

	return skM, skX, pkM, pkX, nil
}

func combiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	_, _ = h.Write(ssM)
	_, _ = h.Write(ssX)
	_, _ = h.Write(ctX)
	_, _ = h.Write(pkX)
	_, _ = h.Write(xWingLabel)

	return h.Sum(nil)
}
