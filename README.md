# go-x-wing

[![Release](https://img.shields.io/github/release/ItakawaM/go-x-wing.svg?style=for-the-badge)](https://github.com/ItakawaM/go-x-wing/releases/latest)
[![Build](https://img.shields.io/github/actions/workflow/status/ItakawaM/go-x-wing/ci.yml?style=for-the-badge&branch=main)](https://github.com/ItakawaM/go-x-wing/actions)
[![Go Version](https://img.shields.io/github/go-mod/go-version/ItakawaM/go-x-wing?style=for-the-badge)](go.mod)
[![Go Reference](https://img.shields.io/badge/go.dev-reference-blue?style=for-the-badge)](https://pkg.go.dev/github.com/ItakawaM/go-x-wing)
[![Codecov branch](https://img.shields.io/codecov/c/github/ItakawaM/go-x-wing/main.svg?style=for-the-badge)](https://codecov.io/gh/ItakawaM/go-x-wing)
[![License](https://img.shields.io/github/license/ItakawaM/go-x-wing?style=for-the-badge)](LICENSE)

![X-Wing Logo](README/xwing.webp)

## About

This package implements X-Wing, a general-purpose post-quantum/traditional
hybrid key encapsulation mechanism (PQ/T KEM) built on X25519 and ML-KEM-768, 
in Golang based on [draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/)
dated 23rd of September 2026.

It uses `crypto/mlkem` and `crypto/ecdh` for ML-KEM-768 and X25519 cryptographic primitives and passes all of the KATs specified in [draft-connolly-cfrg-xwing-kem-11](https://datatracker.ietf.org/doc/draft-connolly-cfrg-xwing-kem/).

All of the credits for X-Wing go to the authors of the draft:
- Deirdre Connolly (Selkie Cryptography)
- Peter Schwabe (MPI-SP & Radboud University)
- Bas Westerbaan (Cloudflare)

> [!CAUTION]
> This implementation is strictly educational and was not verified, so it **should NOT** be used in any software.

## Contributing

Issues are welcome, but this most likely won't be actively maintained.

P.S: I might merge this into my other crypto project.

## Specification

| Element           | Size       |
|-------------------|------------|
| Decapsulation Key | 32 bytes   |
| Encapsulation Key | 1216 bytes |
| Ciphertext        | 1120 bytes |
| Shared Secret     | 32 bytes   |


## Installation

Download the package using the following command:

```bash
go get github.com/ItakawaM/go-x-wing@latest
```

**Requires**: go 1.27.3+

## Usage Example

```go
package main

import (
	"bytes"
	"fmt"
	"log"

	xwing "github.com/ItakawaM/go-x-wing"
)

func main() {
	// Alice generates a pair of keys and sends pk to Bob:
	skAlice, pkAlice, err := xwing.GenerateKeyPair()
	if err != nil {
		log.Fatal(err)
	}
	sent := pkAlice.Bytes()

	// Bob receives pk:
	pkBob, err := xwing.NewEncapsulationKey(sent)
	if err != nil {
		log.Fatal(err)
	}

	// Bob creates a shared secret and sends the ciphertext to Alice:
	ssBob, ct, err := pkBob.Encapsulate()
	if err != nil {
		log.Fatal(err)
	}

	// Alice receives the ciphertext and decapsulates it to get the shared secret:
	ssAlice, err := skAlice.Decapsulate(ct)
	if err != nil {
		log.Fatal(err)
	}

	// Bob and Alice now hold the same shared secret:
	fmt.Println(bytes.Equal(ssBob, ssAlice))
}
```

## License
[MIT](LICENSE)