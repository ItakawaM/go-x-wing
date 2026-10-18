package xwing

import (
	"crypto/ecdh"
	"crypto/mlkem"
	"crypto/rand"
	"crypto/sha3"
	"errors"
	"fmt"
)

const (
	SecretKeySize  = 32
	PublicKeySize  = 1216
	CiphertextSize = 1120

	SharedSecretSize      = 32
	ExpandedSecretKeySize = 96
)

var (
	ErrInvalidPublicKey = errors.New("invalid public key")

	ErrInvalidCipherText = errors.New("invalid cipher text")
)

var xWingLabel = []byte{0x5c, 0x2e, 0x2f, 0x2f, 0x5e, 0x5c}

type PrivateKey struct {
	secretKey [SecretKeySize]byte

	secretKeyM *mlkem.DecapsulationKey768

	secretKeyX *ecdh.PrivateKey
	publicKeyX []byte
}

func GenerateKeyPair() (*PrivateKey, []byte, error) {
	secretKey := make([]byte, SecretKeySize)
	_, _ = rand.Read(secretKey) // rand.Read never errors and always fills the buffer

	skM, skX, pkM, pkX, err := expandSecretKey(secretKey)
	if err != nil {
		return nil, nil, err
	}

	publicKey := append(pkM, pkX...)
	return &PrivateKey{
		secretKey:  *(*[SecretKeySize]byte)(secretKey),
		secretKeyM: skM,
		secretKeyX: skX,
		publicKeyX: pkX,
	}, publicKey, nil
}

func Encapsulate(publicKey []byte) (sharedSecret, ciphertext []byte, err error) {
	if len(publicKey) != PublicKeySize {
		return nil, nil,
			fmt.Errorf("%w: invalid length want = %d, got = %d", ErrInvalidPublicKey, PublicKeySize, len(publicKey))
	}

	publicKeyMbytes := publicKey[:mlkem.EncapsulationKeySize768]
	publicKeyXbytes := publicKey[mlkem.EncapsulationKeySize768:]

	ephemeralKeyX, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	ciphertextX := ephemeralKeyX.PublicKey().Bytes()

	publicKeyX, err := ecdh.X25519().NewPublicKey(publicKeyXbytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}

	sharedSecretX, err := ephemeralKeyX.ECDH(publicKeyX)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}

	publicKeyM, err := mlkem.NewEncapsulationKey768(publicKeyMbytes)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrInvalidPublicKey, err)
	}
	sharedSecretM, ciphertextM := publicKeyM.Encapsulate()

	sharedSecret = combiner(sharedSecretM, sharedSecretX, ciphertextX, publicKeyX.Bytes())
	return sharedSecret, append(ciphertextM, ciphertextX...), nil
}

func (k *PrivateKey) Decapsulate(ciphertext []byte) (sharedSecret []byte, err error) {
	if len(ciphertext) != CiphertextSize {
		return nil,
			fmt.Errorf("%w: invalid length want = %d, got = %d", ErrInvalidCipherText, CiphertextSize, len(ciphertext))
	}

	ciphertextM := ciphertext[:mlkem.CiphertextSize768]
	ciphertextX := ciphertext[mlkem.CiphertextSize768:]

	sharedSecretM, err := k.secretKeyM.Decapsulate(ciphertextM)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCipherText, err)
	}

	publicKeyX, err := ecdh.X25519().NewPublicKey(ciphertextX)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCipherText, err)
	}

	sharedSecretX, err := k.secretKeyX.ECDH(publicKeyX)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidCipherText, err)
	}

	return combiner(sharedSecretM, sharedSecretX, ciphertextX, k.publicKeyX), nil
}

func expandSecretKey(secretKey []byte) (skM *mlkem.DecapsulationKey768, skX *ecdh.PrivateKey, pkM, pkX []byte, err error) {
	expanded := sha3.SumSHAKE256(secretKey, ExpandedSecretKeySize)
	secretKeyM, err := mlkem.NewDecapsulationKey768(expanded[:64])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	publicKeyM := secretKeyM.EncapsulationKey().Bytes()

	secretKeyX, err := ecdh.X25519().NewPrivateKey(expanded[64:])
	if err != nil {
		return nil, nil, nil, nil, err
	}
	publicKeyX := secretKeyX.PublicKey().Bytes()

	return secretKeyM, secretKeyX, publicKeyM, publicKeyX, nil
}

func combiner(sharedSecretM, sharedSecretX, ciphertextX, publicKeyX []byte) []byte {
	h := sha3.New256()
	_, _ = h.Write(sharedSecretM)
	_, _ = h.Write(sharedSecretX)
	_, _ = h.Write(ciphertextX)
	_, _ = h.Write(publicKeyX)
	_, _ = h.Write(xWingLabel)

	return h.Sum(nil)
}
