package xwing_test

import (
	"bytes"
	"fmt"
	"log"

	xwing "github.com/ItakawaM/go-x-wing"
)

func Example() {
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
	// Output: true
}
