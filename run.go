package main

import (
	"crypto/rand"
	"fmt"

	"github.com/radicalrafi/gomorph/gaillier"
)

func main() {

	os := rand.Reader
	/*
		m, n, err := primes.GenPrimes(1024, rand.Reader)
		fmt.Println(m, n, err)

		if m.ProbablyPrime(1000) == false {
			fmt.Println("m is not a prime")
		}
		fmt.Println(m.BitLen(), n.BitLen())
	*/
	a, b, err := gaillier.GenerateKeyPair(os, 1024)
	fmt.Println(a.G, a.N, b, err)
	h := []byte{'1', '2', '3'}
	kp, err := gaillier.Encrypt(a, h)
	deckp, err := gaillier.Decrypt(b, kp)
	fmt.Println(string(deckp), err)
}
