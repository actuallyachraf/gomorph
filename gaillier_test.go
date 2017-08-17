package main

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/radicalrafi/gomorph/gaillier"
)

func TestKeyGen(t *testing.T) {
	puba, priva, err1 := gaillier.GenerateKeyPair(rand.Reader, 1024)
	pubb, privb, err2 := gaillier.GenerateKeyPair(rand.Reader, 2048)
	pubc, privc, err3 := gaillier.GenerateKeyPair(rand.Reader, 4096)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Errorf("Error Generating Keypair :\n Size:1024  %v\nSize:2048  %v\nSize 4096  %v\n", err1, err2, err3)
	}
	if puba.KeyLen != 1024 || priva.KeyLen != 1024 {
		t.Errorf("Error generating correct keypair of size 1024 byte got %d want 1024", puba.KeyLen)
	}
	if pubb.KeyLen != 2048 || privb.KeyLen != 2048 {
		t.Errorf("Error generating correct keypair of size 1024 byte got %d want 2048", puba.KeyLen)
	}
	if pubc.KeyLen != 4096 || privc.KeyLen != 4096 {
		t.Errorf("Error generating correct keypair of size 1024 byte got %d want 4096", puba.KeyLen)
	}

}
func TestEncryptDecrypt(t *testing.T) {

	case1 := new(big.Int).SetInt64(9132)
	case2 := new(big.Int).SetInt64(1492)

	pub, priv, err := gaillier.GenerateKeyPair(rand.Reader, 512)

	if err != nil {
		t.Errorf("Error Generating Keypair")
	}
	encCase1, errCase1 := gaillier.Encrypt(pub, case1.Bytes())
	encCase2, errCase2 := gaillier.Encrypt(pub, case2.Bytes())

	if errCase1 != nil || errCase2 != nil {
		t.Errorf("Error encrypting keypair %v \n %v", errCase1, errCase2)
	}

	d1, errDec1 := gaillier.Decrypt(priv, encCase1)
	d2, errDec2 := gaillier.Decrypt(priv, encCase2)

	decCase1 := new(big.Int).SetBytes(d1)
	decCase2 := new(big.Int).SetBytes(d2)
	if decCase1.Cmp(case1) != 0 || decCase2.Cmp(case2) != 0 {
		t.Errorf("Error Decrypting the message %v \n %v", errDec1, errDec2)
	}

}
