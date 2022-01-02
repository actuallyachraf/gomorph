package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/actuallyachraf/gomorph/gaillier"
)

func AddEncrypted() error {

	case1 := new(big.Int).SetInt64(1)
	case2 := new(big.Int).SetInt64(1)

	fmt.Println("==== Adding two Encrypted Numbers === ")
	fmt.Println("A = ", case1)
	fmt.Println("B = ", case2)

	pub, priv, err := gaillier.GenerateKeyPair(rand.Reader, 512)
	fmt.Println("=== Generating Keypairs ====")
	fmt.Println("KeySize = ", pub.Len)
	if err != nil {
		return fmt.Errorf("error Generating Keypair")
	}
	//Encrypt
	encCase1, err1 := gaillier.Encrypt(pub, case1.Bytes())
	encCase2, err2 := gaillier.Encrypt(pub, case2.Bytes())

	fmt.Println("==== Encrypting Inputs === ")
	fmt.Println("Enc(A) = ", hex.EncodeToString(encCase1))
	fmt.Println("Enc(B) = ", hex.EncodeToString(encCase2))

	if err1 != nil || err2 != nil {
		return fmt.Errorf("error Encrypting Integers")
	}

	res := gaillier.Add(pub, encCase1, encCase2)

	fmt.Println("==== Encrypted Add Result === ")
	fmt.Println("Enc(A) + Enc(B) = ", hex.EncodeToString(res))

	corr := new(big.Int).SetInt64(2)

	decRes, err := gaillier.Decrypt(priv, res)
	if err != nil {
		return fmt.Errorf("failed to Decrypt Result got %v want %v with Error : %v", decRes, corr, err)
	}
	resB := new(big.Int).SetBytes(decRes)
	if resB.Cmp(corr) != 0 {
		return fmt.Errorf("failed to Add two ciphers got %v want %v", resB, corr)
	}
	fmt.Println("==== Decrpyted Add Result === ")
	fmt.Println("Dec(Enc(A) + Enc(B)) = ", resB)

	return nil
}

func main() {

	err := AddEncrypted()
	if err != nil {
		fmt.Println(err.Error())
	}
}
