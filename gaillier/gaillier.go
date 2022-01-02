/*
	This package implements a Paillier cryptosystem

	Provides primitives for Public & Private Key Generation /  Encryption / Decryption
	Provides Functions to operate on the Cyphertext according to Paillier algorithm

	@author: actuallyachraf
	@license: Apache 2.0

*/

//	Homomorphic Properties of Paillier Cryptosystem
//
//	* The product of two ciphers decrypts to the sum of the plain text
//	* The product of a cipher with a non-cipher raising g will decrypt to their sum
//	* A Cipher raised to a non-cipher decrypts to their product
//	* Any cipher raised to an integer k will decrypt to the product of the deciphered and k

package gaillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

//Errors definition

// The Paillier crypto system picks two keys p & q and denotes n = p*q
// Messages have to be in the ring Z/nZ (integers modulo n)
// Therefore a Message can't be bigger than n
var ErrLongMessage = errors.New("message should be smaller than choosen public key size")

var one = big.NewInt(1)

// PubKey is a struct to hold the public key used to encrypt
type PubKey struct {
	Len int
	N   *big.Int //n = p*q (where p & q are two primes)
	G   *big.Int //g random integer in Z\*\n^2
	Nsq *big.Int //N^2
}

// PrivKey is a struct to hold the private key used to decrypt
type PrivKey struct {
	Len int
	PubKey
	L *big.Int //lcm((p-1)*(q-1))
	U *big.Int //L^-1 modulo n mu = U = (L(g^L mod N^2)^-1)
}

// GenerateKeyPair generates a key pair using a random source and a number of bits
func GenerateKeyPair(random io.Reader, bits int) (*PubKey, *PrivKey, error) {

	p, err := rand.Prime(random, bits/2)

	if err != nil {
		return nil, nil, err
	}

	q, err := rand.Prime(random, bits/2)

	if err != nil {
		return nil, nil, err
	}

	//N = p*q

	n := new(big.Int).Mul(p, q)

	nSquared := new(big.Int).Mul(n, n)

	g := new(big.Int).Add(n, one)

	//p-1
	pMin := new(big.Int).Sub(p, one)
	//q-1
	qMin := new(big.Int).Sub(q, one)
	//(p-1)*(q-1)
	l := new(big.Int).Mul(pMin, qMin)
	//l^-1 mod n
	u := new(big.Int).ModInverse(l, n)
	pub := &PubKey{Len: bits, N: n, Nsq: nSquared, G: g}
	return pub, &PrivKey{PubKey: *pub, Len: bits, L: l, U: u}, nil
}

//	Encrypt function to encrypt the message into a paillier cipher text
//	using the following rule :
//	cipher = g^m * r^n mod n^2
//	r is random integer such as 0 <= r <= n
//	m is the message
func Encrypt(pubkey *PubKey, message []byte) ([]byte, error) {
	// We need to generate an r such that 0 < r < n is true and r and n are relatively prime
	r, err := generateRelativelyPrimeInt(pubkey.N)
	if err != nil {
		return nil, err
	}

	m := new(big.Int).SetBytes(message)
	if pubkey.N.Cmp(m) < 1 {
		return nil, ErrLongMessage
	}
	//c = g^m * r^nmod n^2

	//g^m
	gm := new(big.Int).Exp(pubkey.G, m, pubkey.Nsq)
	//r^n
	rn := new(big.Int).Exp(r, pubkey.N, pubkey.Nsq)
	//prod = g^m * r^n
	prod := new(big.Int).Mul(gm, rn)

	c := new(big.Int).Mod(prod, pubkey.Nsq)

	return c.Bytes(), nil
}

//	Decrypts a given ciphertext following the rule:
//	m = L(c^lambda mod n^2).mu mod n
//	lambda : L
//	mu : U
func Decrypt(privkey *PrivKey, cipher []byte) ([]byte, error) {

	c := new(big.Int).SetBytes(cipher)

	if privkey.Nsq.Cmp(c) < 1 {
		return nil, ErrLongMessage
	}

	//c^l mod n^2
	a := new(big.Int).Exp(c, privkey.L, privkey.Nsq)

	//L(x) = x-1 / n we compute L(a)
	l := new(big.Int).Div(new(big.Int).Sub(a, one), privkey.N)

	//computing m
	m := new(big.Int).Mod(new(big.Int).Mul(l, privkey.U), privkey.N)

	return m.Bytes(), nil

}

//Add two ciphers together
func Add(pubkey *PubKey, c1, c2 []byte) []byte {

	a := new(big.Int).SetBytes(c1)
	b := new(big.Int).SetBytes(c2)

	// a * b mod n^²
	res := new(big.Int).Mod(new(big.Int).Mul(a, b), pubkey.Nsq)

	return res.Bytes()
}

//Add a constant & a cipher
func AddConstant(pubkey *PubKey, cipher, constant []byte) []byte {

	c := new(big.Int).SetBytes(cipher)
	k := new(big.Int).SetBytes(constant)

	//result = c * g^k mod n^2
	res := new(big.Int).Mod(
		new(big.Int).Mul(c, new(big.Int).Exp(pubkey.G, k, pubkey.Nsq)), pubkey.Nsq)

	return res.Bytes()

}

//Multiplication by a constant integer
func Mul(pubkey *PubKey, cipher, constant []byte) []byte {

	c := new(big.Int).SetBytes(cipher)
	k := new(big.Int).SetBytes(constant)

	//res = c^k mod n^2
	res := new(big.Int).Exp(c, k, pubkey.Nsq)

	return res.Bytes()
}

// Generates an Int that is relatively prime with the input Int. Relative primeness is defined by gcd(r, n) = 1.
// So we enter an infinite loop to generate r's until this is true. It is very unlikely that we will ever iterate
// through this loop more than once since our search space is so large.
func generateRelativelyPrimeInt(n *big.Int) (*big.Int, error) {
	for {
		randR, err := rand.Int(rand.Reader, n)
		if err != nil {
			return nil, err
		}

		// We only care about z here, but need references to x & y because of the GCD function
		x, y, z := new(big.Int), new(big.Int), new(big.Int)
		z.GCD(x, y, n, randR)

		// Check that the GCD is 1
		if z.Cmp(one) == 0 {
			// If so, we are done
			return randR, nil
		}
	}
}
