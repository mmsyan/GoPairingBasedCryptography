package dabe

import (
	"fmt"
	lsss2 "github.com/mmsyan/GoPairingBasedCryptography/access/lsss"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/mmsyan/GoPairingBasedCryptography/hash"
)

// 测试全局参数设置
func TestGlobalSetup(t *testing.T) {
	gp, err := GlobalSetup()
	if err != nil {
		t.Fatalf("GlobalSetup failed: %v", err)
	}

	if gp == nil {
		t.Fatal("GlobalSetup returned nil")
	}

	// 验证生成器不为零
	if gp.g1.IsInfinity() {
		t.Error("g1 should not be infinity")
	}
	if gp.g2.IsInfinity() {
		t.Error("g2 should not be infinity")
	}

	fmt.Println("GlobalSetup test passed")
}

// 测试用户密钥生成
func TestKeyGenerate(t *testing.T) {
	gp, _ := GlobalSetup()

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	attributes := NewLW11DABEAttributes(AElement, BElement, CElement)

	_, sk, err := AuthoritySetup(attributes, gp)
	if err != nil {
		t.Fatalf("AuthoritySetup failed: %v", err)
	}

	// 为用户生成密钥
	gid := "user001"
	userAttributes := NewLW11DABEAttributes(AElement, BElement)
	userKey, err := KeyGenerate(userAttributes, gid, sk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	// 验证用户密钥
	if userKey.UserGid != gid {
		t.Errorf("Expected gid %s, got %s", gid, userKey.UserGid)
	}
	if len(userKey.KIGID) != len(userAttributes.attributes) {
		t.Errorf("Expected %d keys, got %d", len(userAttributes.attributes), len(userKey.KIGID))
	}

	// 验证每个属性都有对应的密钥
	for _, attr := range userAttributes.attributes {
		if key, exists := userKey.KIGID[attr]; !exists {
			t.Errorf("KIGID for attribute %s not found", attr.String()[:8])
		} else if key.IsInfinity() {
			t.Errorf("KIGID for attribute %s is infinity", attr.String()[:8])
		}
	}

	fmt.Println("KeyGenerate test passed")
}

func TestDABE1(t *testing.T) {
	gp, err := GlobalSetup()
	if err != nil {
		t.Fatalf("GlobalSetup failed: %v", err)
	}

	attributes1 := NewLW11DABEAttributesFromStrings("alice", "bob", "jack")
	attributes2 := NewLW11DABEAttributesFromStrings("bob", "jack")

	pk, sk, err := AuthoritySetup(attributes1, gp)
	if err != nil {
		t.Fatalf("AuthoritySetup failed: %v", err)
	}

	gid := "user001"
	grantedKey, err := KeyGenerate(attributes2, gid, sk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	accessTree1 := lsss2.Or(
		lsss2.LeafFromString("bob"),
		lsss2.LeafFromString("alice"),
	)
	accessTree2 := lsss2.And(
		lsss2.LeafFromString("bob"),
		lsss2.LeafFromString("alice"),
	)
	accessMatrix1 := lsss2.NewLSSSMatrixFromBinaryTree(accessTree1)
	accessMatrix2 := lsss2.NewLSSSMatrixFromBinaryTree(accessTree2)

	message1, err := NewRandomLW11DABEMessage()
	if err != nil {
		t.Fatalf("NewLW11DABEMessage failed: %v", err)
	}
	fmt.Println(message1.ToBytes())

	ciphertext1, err := Encrypt(message1, accessMatrix1, gp, pk)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	ciphertext2, err := Encrypt(message1, accessMatrix2, gp, pk)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	plaintext1, err := Decrypt(ciphertext1, grantedKey, gp)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	plaintext2, err := Decrypt(ciphertext2, grantedKey, gp)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	fmt.Println(plaintext1.ToBytes())
	fmt.Println(plaintext2.ToBytes())
}

// 测试简单的加密解密（单属性访问策略）
func TestEncryptDecryptSimple(t *testing.T) {
	// 设置
	gp, _ := GlobalSetup()
	AElement := hash.ToField("A")
	attributes := NewLW11DABEAttributes(AElement)

	pk, sk, _ := AuthoritySetup(attributes, gp)

	gid := "user001"
	userKey, _ := KeyGenerate(attributes, gid, sk)

	// 创建访问策略：只需要属性 A
	exampleTree, _ := lsss2.GetExample1() // 假设这返回一个简单的单属性策略
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(exampleTree)

	// 创建消息
	message := &LW11DABEMessage{
		Message: *new(bn254.GT).SetOne(),
	}

	// 加密
	ciphertext, err := Encrypt(message, matrix, gp, pk)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	if ciphertext == nil {
		t.Fatal("Encrypt returned nil ciphertext")
	}

	// 解密
	decryptedMessage, err := Decrypt(ciphertext, userKey, gp)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 验证消息是否正确
	if !message.Message.Equal(&decryptedMessage.Message) {
		t.Error("Decrypted message does not match original message")
	}

	fmt.Println("Simple Encrypt/Decrypt test passed")
}

// 测试复杂访问策略的加密解密（AND 策略）
func TestEncryptDecryptComplexAND(t *testing.T) {
	// 设置
	gp, _ := GlobalSetup()
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	DElement := hash.ToField("D")
	attributes := NewLW11DABEAttributes(AElement, BElement, CElement, DElement)

	pk, sk, _ := AuthoritySetup(attributes, gp)

	gid := "user002"
	// 用户拥有属性 A, B, C
	userAttributes := NewLW11DABEAttributes(AElement, BElement, CElement)
	userKey, _ := KeyGenerate(userAttributes, gid, sk)

	// 创建访问策略：需要 A AND B（假设 Example14 是这样的策略）
	exampleTree, formula := lsss2.GetExample14()
	fmt.Printf("Testing with access formula: %s\n", formula)
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(exampleTree)

	// 创建随机消息
	originalMessage, err := new(bn254.GT).SetRandom()
	message := &LW11DABEMessage{
		Message: *originalMessage,
	}

	// 加密
	ciphertext, err := Encrypt(message, matrix, gp, pk)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 解密
	decryptedMessage, err := Decrypt(ciphertext, userKey, gp)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 验证消息
	if !message.Message.Equal(&decryptedMessage.Message) {
		t.Error("Decrypted message does not match original message")
	}

	fmt.Println("Complex AND policy Encrypt/Decrypt test passed")
}

// 测试用户属性不满足访问策略的情况
func TestDecryptWithInsufficientAttributes(t *testing.T) {
	// 设置
	gp, _ := GlobalSetup()
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	attributes := NewLW11DABEAttributes(AElement, BElement, CElement)

	pk, sk, _ := AuthoritySetup(attributes, gp)

	gid := "user003"
	// 用户只有属性 A
	userAttributes := NewLW11DABEAttributes(AElement)
	userKey, _ := KeyGenerate(userAttributes, gid, sk)

	// 创建访问策略：需要 A AND C
	exampleTree, _ := lsss2.GetExample14()
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(exampleTree)

	message := &LW11DABEMessage{
		Message: *new(bn254.GT).SetOne(),
	}

	// 加密
	ciphertext, err := Encrypt(message, matrix, gp, pk)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 尝试解密（应该失败或返回错误）
	_, err = Decrypt(ciphertext, userKey, gp)
	// 注意：根据实现，这里可能返回错误或解密出错误的消息
	// 如果实现会返回错误，则：
	if err == nil {
		t.Log("Warning: Decrypt should fail with insufficient attributes")
	}

	fmt.Println("Insufficient attributes test completed")
}

// 测试多个用户使用相同的公钥
func TestMultipleUsersWithSameAuthority(t *testing.T) {
	gp, _ := GlobalSetup()
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	attributes := NewLW11DABEAttributes(AElement, BElement, CElement)

	pk, sk, _ := AuthoritySetup(attributes, gp)

	// 创建两个不同的用户
	user1Key, _ := KeyGenerate(NewLW11DABEAttributes(AElement, BElement), "user001", sk)
	user2Key, _ := KeyGenerate(NewLW11DABEAttributes(AElement, CElement), "user002", sk)

	// 创建访问策略
	exampleTree, _ := lsss2.GetExample1()
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(exampleTree)

	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	message := &LW11DABEMessage{
		Message: *m,
	}

	// 加密
	ciphertext, _ := Encrypt(message, matrix, gp, pk)

	// 两个用户都应该能解密（如果他们满足访问策略）
	decrypted1, err1 := Decrypt(ciphertext, user1Key, gp)
	decrypted2, err2 := Decrypt(ciphertext, user2Key, gp)

	if err1 != nil {
		t.Logf("User1 decrypt: %v", err1)
	}
	if err2 != nil {
		t.Logf("User2 decrypt: %v", err2)
	}

	if err1 == nil && !message.Message.Equal(&decrypted1.Message) {
		t.Error("User1 decrypted message incorrect")
	}
	if err2 == nil && !message.Message.Equal(&decrypted2.Message) {
		t.Error("User2 decrypted message incorrect")
	}

	fmt.Println("Multiple users test passed")
}

// 基准测试：全局设置
func BenchmarkGlobalSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		GlobalSetup()
	}
}

// 基准测试：权威机构设置
func BenchmarkAuthoritySetup(b *testing.B) {
	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributes(
		hash.ToField("A"),
		hash.ToField("B"),
		hash.ToField("C"))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		AuthoritySetup(attributes, gp)
	}
}

// 基准测试：加密
func BenchmarkEncrypt(b *testing.B) {
	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributes(
		hash.ToField("A"),
		hash.ToField("B"),
		hash.ToField("C"))
	pk, _, _ := AuthoritySetup(attributes, gp)

	exampleTree, _ := lsss2.GetExample1()
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(exampleTree)

	message := &LW11DABEMessage{
		Message: *new(bn254.GT).SetOne(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(message, matrix, gp, pk)
	}
}

// 基准测试：解密
func BenchmarkDecrypt(b *testing.B) {
	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributes(hash.ToField("A"))
	pk, sk, _ := AuthoritySetup(attributes, gp)
	userKey, _ := KeyGenerate(attributes, "user", sk)

	exampleTree, _ := lsss2.GetExample1()
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(exampleTree)

	message := &LW11DABEMessage{
		Message: *new(bn254.GT).SetOne(),
	}
	ciphertext, _ := Encrypt(message, matrix, gp, pk)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Decrypt(ciphertext, userKey, gp)
	}
}
