package agka09

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"testing"
)

func NewSignMessage(bytes []byte) *SignMessage {
	return &SignMessage{
		S: bytes,
	}
}

func NewRandomPlainText() *PlainText {
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		panic(err)
	}
	msg := new(bn254.GT).SetOne()
	msg.Exp(*msg, r.BigInt(new(big.Int)))
	return &PlainText{
		M: *msg,
	}
}

// TestSignVerify1 正确身份验证正确签名
func TestSignVerify1(t *testing.T) {
	pp, err := ParaGen()
	if err != nil {
		t.Fatal(err)
	}

	pk, sk, err := KeyGen(pp)
	if err != nil {
		t.Fatal(err)
	}

	s1 := NewSignMessage([]byte("Hello World"))
	sigma1, err := Sign(s1, sk)
	if err != nil {
		t.Fatal(err)
	}

	isValid, err := Verify(s1, sigma1, pk)
	if err != nil {
		t.Fatal(err)
	}
	if !isValid {
		t.Fatal("invalid signature")
	}
}

// TestSignVerify_WrongIdentity 错误身份与正确签名
func TestSignVerify_WrongIdentity(t *testing.T) {
	pp, _ := ParaGen()

	// 生成两套密钥对
	_, skA, _ := KeyGen(pp)
	pkB, _, _ := KeyGen(pp)

	msg := NewSignMessage([]byte("Important Data"))

	// 使用 A 的私钥签名
	sigma, err := Sign(msg, skA)
	if err != nil {
		t.Fatal(err)
	}

	// 尝试用 B 的公钥验证 A 的签名，预期结果应该是 isValid == false
	isValid, err := Verify(msg, sigma, pkB)
	if err != nil {
		t.Log("Note: Verify returned error for mismatch, which is acceptable depending on implementation")
	}
	if isValid {
		t.Fatal("Security flaw: Verified signature with wrong public key")
	}
}

// TestSignVerify_WrongSignature 正确身份与错误签名
func TestSignVerify_WrongSignature(t *testing.T) {
	pp, _ := ParaGen()
	pk, sk, _ := KeyGen(pp)

	msg := NewSignMessage([]byte("Original Message"))
	sigma, _ := Sign(msg, sk)

	// 模拟消息被篡改
	tamperedMsg := NewSignMessage([]byte("Tampered Message"))

	// 验证篡改后的消息与原签名，预期失败
	isValid, err := Verify(tamperedMsg, sigma, pk)
	if err != nil {
		t.Log("Note: Verify might return error for tampered data")
	}
	if isValid {
		t.Fatal("Security flaw: Verified tampered message")
	}
}

// TestSignVerify_MultiParty 正确的多个身份与正确的多签名
func TestSignVerify_MultiParty(t *testing.T) {
	pp, _ := ParaGen()
	numParties := 3

	pks := make([]*PublicKey, numParties)    // 替换为你的公钥类型
	sks := make([]*PrivateKey, numParties)   // 替换为你的私钥类型
	sigmas := make([]*Signature, numParties) // 替换为你的签名类型

	msg := NewSignMessage([]byte("Group Consensus"))

	// 1. 所有成员生成密钥并对同一消息签名
	for i := 0; i < numParties; i++ {
		pks[i], sks[i], _ = KeyGen(pp)
		sigmas[i], _ = Sign(msg, sks[i])
	}

	// 2. 验证每个成员的签名
	for i := 0; i < numParties; i++ {
		isValid, err := Verify(msg, sigmas[i], pks[i])
		if err != nil || !isValid {
			t.Errorf("Party %d signature verification failed", i)
		}
	}
}

func TestEncryptDecrypt_Success(t *testing.T) {
	pp, _ := ParaGen()
	pk, sk, _ := KeyGen(pp)

	// 1. 准备明文
	originalPlaintext := NewRandomPlainText()

	// 2. 加密
	cipher, err := Encrypt(originalPlaintext, pk)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 3. 生成合法签名（作为解密令牌）
	msg := NewSignMessage([]byte("Authorized Access"))
	sigma, err := Sign(msg, sk)
	if err != nil {
		t.Fatalf("Signing failed: %v", err)
	}

	// 4. 解密
	decryptedPlaintext, err := Decrypt(*cipher, msg, sigma)
	if err != nil {
		t.Fatalf("Decryption failed: %v", err)
	}

	// 5. 校验结果
	if !decryptedPlaintext.M.Equal(&originalPlaintext.M) {
		t.Fatal("Decrypted plaintext does not match the original")
	}
}

func TestEncryptDecrypt_WrongMessage(t *testing.T) {
	pp, _ := ParaGen()
	pk, sk, _ := KeyGen(pp)

	originalPlaintext := NewRandomPlainText()
	cipher, _ := Encrypt(originalPlaintext, pk)

	// 使用消息 A 签名
	msgA := NewSignMessage([]byte("Message A"))
	sigma, _ := Sign(msgA, sk)

	// 尝试使用消息 B 和针对消息 A 的签名进行解密
	msgB := NewSignMessage([]byte("Message B"))
	decryptedPlaintext, err := Decrypt(*cipher, msgB, sigma)

	// 预期结果：由于 H(s) 不同，解密出来的结果应该是错误的（不等于原明文）
	if err == nil && decryptedPlaintext.M.Equal(&originalPlaintext.M) {
		t.Fatal("Security flaw: Decrypted successfully with wrong message context")
	}
}

func TestEncryptDecrypt_UnauthorizedSigner(t *testing.T) {
	pp, _ := ParaGen()
	pk, _, _ := KeyGen(pp)      // 目标用户的公钥
	_, skOther, _ := KeyGen(pp) // 攻击者的私钥

	originalPlaintext := NewRandomPlainText()
	cipher, _ := Encrypt(originalPlaintext, pk)

	// 攻击者尝试用自己的私钥对消息签名
	msg := NewSignMessage([]byte("I am the owner"))
	sigmaOther, _ := Sign(msg, skOther)

	// 尝试使用攻击者的签名解密发给目标用户的密文
	decryptedPlaintext, err := Decrypt(*cipher, msg, sigmaOther)

	// 校验：解密结果不应匹配
	if err == nil && decryptedPlaintext.M.Equal(&originalPlaintext.M) {
		t.Fatal("Security flaw: Decrypted ciphertext using an unauthorized person's signature")
	}
}
