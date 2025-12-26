package bibe

import (
	"math/big"
	"testing"
)

func TestBatchIBE(t *testing.T) {
	// 1. Setup
	B := 5
	params, err := Setup(B)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	t.Logf("Setup completed with batch size B=%d", B)

	// 2. KeyGen
	pk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}
	t.Logf("KeyGen completed")

	// 3. 创建身份批次
	identities := []*Identity{
		NewIdentity(big.NewInt(2)),
		NewIdentity(big.NewInt(5)),
		NewIdentity(big.NewInt(7)),
	}
	t.Logf("Created %d identities", len(identities))

	// 4. Digest
	digest, err := Digest(pk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}
	t.Logf("Digest computed")

	// 5. 批标签
	batchLabel := NewBatchLabel([]byte("batch-2024-01"))

	// 6. ComputeKey
	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}
	t.Logf("Secret key computed")

	// 7. 生成随机消息
	message, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}
	t.Logf("Random message generated")

	// 8. 加密给身份 id=5
	targetID := identities[1] // id=5
	ciphertext, err := Encrypt(pk, message, targetID, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	t.Logf("Message encrypted for identity %v", targetID.Id.String())

	// 9. 解密
	decrypted, err := Decrypt(ciphertext, sk, digest, identities, targetID, batchLabel, pk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	t.Logf("Message decrypted")

	// 10. 验证正确性
	if !decrypted.M.Equal(&message.M) {
		t.Fatalf("Decryption failed: messages don't match")
	}
	t.Logf("✓ Decryption successful: message matches!")
}

func TestInvalidDecryption(t *testing.T) {
	// 测试用错误的身份解密
	B := 3
	params, _ := Setup(B)
	pk, msk, _ := KeyGen(params)

	identities := []*Identity{
		NewIdentity(big.NewInt(2)),
		NewIdentity(big.NewInt(5)),
	}

	digest, _ := Digest(pk, identities)
	batchLabel := NewBatchLabel([]byte("test-batch"))
	sk, _ := ComputeKey(msk, digest, batchLabel)

	message, _ := RandomMessage()
	targetID := identities[0] // id=2
	ciphertext, _ := Encrypt(pk, message, targetID, batchLabel)

	// 尝试用错误的身份解密
	wrongID := NewIdentity(big.NewInt(999))
	_, err := Decrypt(ciphertext, sk, digest, identities, wrongID, batchLabel, pk)

	if err == nil {
		t.Fatalf("Expected error when decrypting with wrong identity")
	}
	t.Logf("✓ Correctly rejected decryption with invalid identity")
}
