// Package xwing implements X-Wing, a general-purpose hybrid post-quantum KEM
// as defined in draft-connolly-cfrg-xwing-kem-11 dated 23 September 2026.
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
	"crypto/fips140"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
)

// This implementation uses the following naming conventions:
//	- sk = Secret Key/Private Key/Decapsulation Key
//	- pk = Public Key/Encapsulation Key
//	- ss = Shared Secret
//	- ct = Ciphertext
//	- m  = ML-KEM-768
//	- x  = X25519
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
	// ErrInvalidEncapsulationKey is returned when the provided encapsulation key is invalid.
	ErrInvalidEncapsulationKey = errors.New("xwing: invalid encapsulation key")

	// ErrInvalidDecapsulationKey is returned when the provided decapsulation key is invalid.
	ErrInvalidDecapsulationKey = errors.New("xwing: invalid decapsulation key")

	// ErrInvalidCiphertext is returned when the provided ciphertext is invalid.
	ErrInvalidCiphertext = errors.New("xwing: invalid ciphertext")

	// ErrUnsupported is returned when X25519, which X-Wing requires, is not
	// available due to fips-140 enforcement: GODEBUG=fips140=only.
	ErrUnsupported = errors.New("xwing: unsupported when FIPS 140-only mode is enforced")
)

// fipsEnforced checks whether fips-140 mode is enforced.
//
// It can be overridden by tests.
var fipsEnforced = fips140.Enforced

// xWingLabel is appended at the end of combiner before taking the hashsum.
//
//	\./
//	/^\
var xWingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

// GenerateKeyPair creates a pair of Decapsulation and Encapsulation keys
// using a secure entropy source.
//
// It returns ErrUnsupported when fips-140 is enforced.
func GenerateKeyPair() (*DecapsulationKey, *EncapsulationKey, error) {
	seed := make([]byte, DecapsulationKeySize)
	_, _ = rand.Read(seed) // never errors
	return generateKeyPair(seed)
}

// generateKeyPair generates an X-Wing key pair from the provided seed.
func generateKeyPair(seed []byte) (*DecapsulationKey, *EncapsulationKey, error) {
	if fipsEnforced() {
		return nil, nil, ErrUnsupported
	}

	k := bytes.Clone(seed)
	skM, skX, pkM, pkX := expandDecapsulationKey(k)
	return &DecapsulationKey{
		seed: k,
		skM:  skM,
		skX:  skX,
		pkX:  pkX.Bytes(),
	}, &EncapsulationKey{
		pkM: pkM,
		pkX: pkX,
	}, nil
}

// DecapsulationKey is the Decapsulation Key of X-Wing KEM. Safe for concurrent use.
//
// It caches the necessary keys of mlkem and x25519 for faster decapsulation.
//
// Create with NewDecapsulationKey or GenerateKeyPair.
type DecapsulationKey struct {
	seed []byte

	// cached
	skM *mlkem.DecapsulationKey768
	skX *ecdh.PrivateKey
	pkX []byte
}

// NewDecapsulationKey initializes a new DecapsulationKey with key as the seed.
//
// It returns ErrInvalidDecapsulationKey when the length of the provided key
// does not match DecapsulationKeySize.
//
// It returns ErrUnsupported when fips-140 is enforced.
func NewDecapsulationKey(key []byte) (*DecapsulationKey, error) {
	if fipsEnforced() {
		return nil, ErrUnsupported
	}

	if len(key) != DecapsulationKeySize {
		return nil, fmt.Errorf("%w: length mismatch: want = %d, got = %d",
			ErrInvalidDecapsulationKey, DecapsulationKeySize, len(key))
	}

	k := bytes.Clone(key)
	skM, skX, _, pkX := expandDecapsulationKey(k)
	return &DecapsulationKey{
		seed: k,
		skM:  skM,
		skX:  skX,
		pkX:  pkX.Bytes(),
	}, nil
}

// Decapsulate recovers the shared secret from the provided ciphertext.
// Tampered mlkem part of the right length produces a pseudorandom secret (implicit rejection).
//
// It returns ErrInvalidCiphertext when the length of the provided ciphertext
// does not match CiphertextSize or x25519 ciphertext is a low-order point.
//
// It returns ErrUnsupported when fips-140 is enforced.
func (d *DecapsulationKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if fipsEnforced() {
		return nil, ErrUnsupported
	}

	if len(ciphertext) != CiphertextSize {
		return nil, fmt.Errorf("%w: length mismatch: want = %d, got = %d",
			ErrInvalidCiphertext, CiphertextSize, len(ciphertext))
	}

	ctM := ciphertext[:mlkem.CiphertextSize768]
	ctX := ciphertext[mlkem.CiphertextSize768:]

	ssM := must(d.skM.Decapsulate(ctM))            // size was checked
	ctKey := must(ecdh.X25519().NewPublicKey(ctX)) // size and fips-140 was checked

	ssX, err := d.skX.ECDH(ctKey)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCiphertext, err)
	}

	return combiner(ssM, ssX, ctX, d.pkX), nil
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

// EncapsulationKey is the Encapsulation Key of X-Wing KEM. Safe for concurrent use.
//
// Create with NewEncapsulationKey or GenerateKeyPair.
type EncapsulationKey struct {
	pkM *mlkem.EncapsulationKey768
	pkX *ecdh.PublicKey
}

// NewEncapsulationKey parses the provided key and returns it as a new EncapsulationKey.
//
// It accepts a low-order x25519 key, but Encapsulate returns ErrInvalidEncapsulationKey.
//
// It returns ErrInvalidEncapsulationKey when the length of the provided key
// does not match EncapsulationKeySize or mlkem encoding is invalid.
//
// It returns ErrUnsupported when fips-140 is enforced.
func NewEncapsulationKey(key []byte) (*EncapsulationKey, error) {
	if fipsEnforced() {
		return nil, ErrUnsupported
	}

	if len(key) != EncapsulationKeySize {
		return nil, fmt.Errorf("%w: length mismatch: want = %d, got = %d",
			ErrInvalidEncapsulationKey, EncapsulationKeySize, len(key))
	}

	pkM, err := mlkem.NewEncapsulationKey768(key[:mlkem.EncapsulationKeySize768])
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidEncapsulationKey, err)
	}

	pkX := must(ecdh.X25519().NewPublicKey(key[mlkem.EncapsulationKeySize768:])) // size and fips-140 was checked
	return &EncapsulationKey{
		pkM: pkM,
		pkX: pkX,
	}, nil
}

// Encapsulate creates a shared secret and its ciphertext.
//
// It may return a plain entropy source error.
//
// It returns ErrInvalidEncapsulationKey when x25519 key is a low-order key.
//
// It returns ErrUnsupported when fips-140 is enforced.
func (e *EncapsulationKey) Encapsulate() (sharedSecret, ciphertext []byte, err error) {
	if fipsEnforced() {
		return nil, nil, ErrUnsupported
	}

	ekX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err // rand source error
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

// expandDecapsulationKey expands decapsulationKey using SHAKE256
// and constructs mlkem and x25519 key pairs.
func expandDecapsulationKey(decapsulationKey []byte) (skM *mlkem.DecapsulationKey768, skX *ecdh.PrivateKey, pkM *mlkem.EncapsulationKey768, pkX *ecdh.PublicKey) {
	expanded := sha3.SumSHAKE256(decapsulationKey, expandedDecapsulationKeySize)
	skM = must(mlkem.NewDecapsulationKey768(expanded[:mlkem.SeedSize])) // expanded is always 96 bytes
	pkM = skM.EncapsulationKey()

	skX = must(ecdh.X25519().NewPrivateKey(expanded[mlkem.SeedSize:])) // expanded is always 96 bytes and fips is checked in parent
	pkX = skX.PublicKey()

	return skM, skX, pkM, pkX
}

// combiner creates a shared secret by hashing the provided values with SHA3-256.
func combiner(ssM, ssX, ctX, pkX []byte) []byte {
	h := sha3.New256()
	_, _ = h.Write(ssM)
	_, _ = h.Write(ssX)
	_, _ = h.Write(ctX)
	_, _ = h.Write(pkX)
	_, _ = h.Write(xWingLabel)

	return h.Sum(nil)
}

// must panics when the function errors.
func must[T any](v T, err error) T {
	if err != nil {
		panic("xwing: internal error: " + err.Error())
	}

	return v
}
