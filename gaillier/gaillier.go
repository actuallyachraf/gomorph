/*
	This package implements a Paillier cryptosystem

	Provides primitives for Public & Private Key Generation /  Encryption / Decryption
	Provides Functions to operate on the Cyphertext according to Paillier algorithm

	@author: radicalrafi
	@license: Apache 2.0

*/

package gaillier

import (
	"crypto/rand"
	"errors"
	"io"
	"math/big"
)

//Errors definition

/* The Paillier crypto system picks two keys p & q and denotes n = p*q
Messages have to be in the ring Z/nZ (integers modulo n)
Therefore a Message can't be bigger than n
*/
var ErrLongMessage = errors.New("Gaillier Error #1: Message is too long for The Public-Key Size \n Message should be smaller than Key size you choose")

//constants

var one = big.NewInt(1)

//Key structs

type PubKey struct {
	KeyLen int
	N      *big.Int //n = p*q (where p & q are two primes)
	G      *big.Int //g random integer in Z\*\n^2
	Nsq    *big.Int //N^2
}

type PrivKey struct {
	KeyLen int
	PubKey
	L *big.Int //lcm((p-1)*(q-1))
	U *big.Int //L^-1 modulo n mu = U = (L(g^L mod N^2)^-1)
}

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

	nSq := new(big.Int).Mul(n, n)

	g := new(big.Int).Add(n, one)

	//p-1
	pMin := new(big.Int).Sub(p, one)
	//q-1
	qMin := new(big.Int).Sub(q, one)
	//(p-1)*(q-1)
	l := new(big.Int).Mul(pMin, qMin)
	//l^-1 mod n
	u := new(big.Int).ModInverse(l, n)
	pub := &PubKey{KeyLen: bits, N: n, Nsq: nSq, G: g}
	return pub, &PrivKey{PubKey: *pub, KeyLen: bits, L: l, U: u}, nil
}

/*
	Encrypt :function to encrypt the message into a paillier cipher text
	using the following rule :
	cipher = g^m * r^n mod n^2
	* r is random integer such as 0 <= r <= n
	* m is the message
*/
func Encrypt(pubkey *PubKey, message []byte) ([]byte, error) {

	r, err := rand.Prime(rand.Reader, pubkey.KeyLen)
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

/*
	Decrypts a given ciphertext following the rule:
	m = L(c^lambda mod n^2).mu mod n
	* lambda : L
	* mu : U

*/
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
