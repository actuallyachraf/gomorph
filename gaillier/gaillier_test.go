package gaillier

import (
	"crypto/rand"
	"math/big"
	"testing"
)

func TestKeyGen(t *testing.T) {
	puba, priva, err1 := GenerateKeyPair(rand.Reader, 1024)
	pubb, privb, err2 := GenerateKeyPair(rand.Reader, 2048)
	pubc, privc, err3 := GenerateKeyPair(rand.Reader, 4096)

	if err1 != nil || err2 != nil || err3 != nil {
		t.Errorf("Error Generating Keypair :\n Size:1024  %v\nSize:2048  %v\nSize 4096  %v\n", err1, err2, err3)
	}
	if puba.Len != 1024 || priva.Len != 1024 {
		t.Errorf("Error generating correct keypair of size 1024 byte got %d want 1024", puba.Len)
	}
	if pubb.Len != 2048 || privb.Len != 2048 {
		t.Errorf("Error generating correct keypair of size 1024 byte got %d want 2048", puba.Len)
	}
	if pubc.Len != 4096 || privc.Len != 4096 {
		t.Errorf("Error generating correct keypair of size 1024 byte got %d want 4096", puba.Len)
	}

}
func TestEncryptDecrypt(t *testing.T) {

	case1 := new(big.Int).SetInt64(9132)
	case2 := new(big.Int).SetInt64(1492)

	pub, priv, err := GenerateKeyPair(rand.Reader, 512)

	if err != nil {
		t.Errorf("Error Generating Keypair")
	}
	encCase1, errCase1 := Encrypt(pub, case1.Bytes())
	encCase2, errCase2 := Encrypt(pub, case2.Bytes())

	if errCase1 != nil || errCase2 != nil {
		t.Errorf("Error encrypting keypair %v \n %v", errCase1, errCase2)
	}

	d1, errDec1 := Decrypt(priv, encCase1)
	d2, errDec2 := Decrypt(priv, encCase2)

	decCase1 := new(big.Int).SetBytes(d1)
	decCase2 := new(big.Int).SetBytes(d2)
	if decCase1.Cmp(case1) != 0 || decCase2.Cmp(case2) != 0 {
		t.Errorf("Error Decrypting the message %v \n %v", errDec1, errDec2)
	}

}

func TestAdd(t *testing.T) {
	case1 := new(big.Int).SetInt64(1)
	case2 := new(big.Int).SetInt64(1)

	pub, priv, err := GenerateKeyPair(rand.Reader, 512)

	if err != nil {
		t.Errorf("Error Generating Keypair")
	}
	//Encrypt
	encCase1, err1 := Encrypt(pub, case1.Bytes())
	encCase2, err2 := Encrypt(pub, case2.Bytes())

	if err1 != nil || err2 != nil {
		t.Errorf("Error Encrypting Integers")
	}

	res := Add(pub, encCase1, encCase2)

	corr := new(big.Int).SetInt64(2)

	decRes, err := Decrypt(priv, res)
	if err != nil {
		t.Errorf("Failed to Decrypt Result got %v want %v with Error : %v", decRes, corr, err)
	}

	resB := new(big.Int).SetBytes(decRes)

	if resB.Cmp(corr) != 0 {
		t.Errorf("Failed to Add two ciphers got %v want %v", resB, corr)
	}

}

func TestAddConstant(t *testing.T) {

	k := new(big.Int).SetInt64(10)
	c := new(big.Int).SetInt64(32)

	pub, priv, err := GenerateKeyPair(rand.Reader, 102)

	if err != nil {
		t.Errorf("Failed to generated keypair %v", err)
	}

	//encrypt
	encC, err := Encrypt(pub, c.Bytes())
	if err != nil {
		t.Errorf("Failed to encrypt c")
	}
	res := AddConstant(pub, encC, k.Bytes())

	decRes, err := Decrypt(priv, res)
	if err != nil {
		t.Errorf("Failed to decrypt result")
	}

	result := new(big.Int).SetBytes(decRes)
	corr := new(big.Int).SetInt64(42)
	if result.Cmp(corr) != 0 {
		t.Errorf("Error Add Constant function want %d , got %d", corr, result)
	}

}

func TestMul(t *testing.T) {

	k := new(big.Int).SetInt64(10)
	c := new(big.Int).SetInt64(32)

	pub, priv, err := GenerateKeyPair(rand.Reader, 102)

	if err != nil {
		t.Errorf("Failed to generated keypair %v", err)
	}

	//encrypt
	encC, err := Encrypt(pub, c.Bytes())
	if err != nil {
		t.Errorf("Failed to encrypt c")
	}
	res := Mul(pub, encC, k.Bytes())

	decRes, err := Decrypt(priv, res)
	if err != nil {
		t.Errorf("Failed to decrypt result")
	}

	result := new(big.Int).SetBytes(decRes)
	corr := new(big.Int).SetInt64(320)
	if result.Cmp(corr) != 0 {
		t.Errorf("Error Mul function want %d , got %d", corr, result)
	}
}
func BenchmarkEncrypt(b *testing.B) {
	pubKey, _, _ := GenerateKeyPair(rand.Reader, 2048)
	val := new(big.Int).SetInt64(int64(1234)).Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := Encrypt(pubKey, val)
		if err != nil {
			b.Fail()
		}
	}
}

func BenchmarkAdd(b *testing.B) {

	case1 := new(big.Int).SetInt64(1)
	case2 := new(big.Int).SetInt64(1)

	pub, priv, err := GenerateKeyPair(rand.Reader, 512)

	if err != nil {
		b.Errorf("Error Generating Keypair")
	}
	//Encrypt
	encCase1, err1 := Encrypt(pub, case1.Bytes())
	encCase2, err2 := Encrypt(pub, case2.Bytes())

	if err1 != nil || err2 != nil {
		b.Errorf("Error Encrypting Integers")
	}
	for i := 0; i < b.N; i++ {
		Add(pub, encCase1, encCase2)
	}
	res := Add(pub, encCase1, encCase2)

	corr := new(big.Int).SetInt64(2)

	decRes, err := Decrypt(priv, res)
	if err != nil {
		b.Errorf("Failed to Decrypt Result got %v want %v with Error : %v", decRes, corr, err)
	}

	resB := new(big.Int).SetBytes(decRes)

	if resB.Cmp(corr) != 0 {
		b.Errorf("Failed to Add two ciphers got %v want %v", resB, corr)
	}

}
