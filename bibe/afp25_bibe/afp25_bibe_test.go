package afp25_bibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
	"testing"
)

// NewIdentity - 从大整数创建身份
func NewIdentity(id *big.Int) *Identity {
	var idElem fr.Element
	idElem.SetBigInt(id)
	return &Identity{Id: idElem}
}

// NewBatchLabel - 创建批标签
func NewBatchLabel(data []byte) *BatchLabel {
	return &BatchLabel{T: data}
}

// NewMessage - 从 GT 元素创建消息
func NewMessage(m bn254.GT) *Message {
	return &Message{M: m}
}

// RandomMessage - 生成随机消息 (用于测试)
func RandomMessage() (*Message, error) {
	// 生成一个随机的 GT 元素
	// GT 元素通常通过配对生成
	_, _, g1Gen, g2Gen := bn254.Generators()

	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	var g1Rand bn254.G1Affine
	g1Rand.ScalarMultiplication(&g1Gen, r.BigInt(new(big.Int)))

	gt, err := bn254.Pair([]bn254.G1Affine{g1Rand}, []bn254.G2Affine{g2Gen})
	if err != nil {
		return nil, err
	}

	return &Message{M: gt}, nil
}

// TestBasicEncryptionDecryption 测试基本的加密解密流程
func TestBasicEncryptionDecryption(t *testing.T) {
	// 1. Setup
	batchSize := 10
	params, err := Setup(batchSize)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 2. KeyGen
	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	// 3. 创建身份和批标签
	id1 := NewIdentity(big.NewInt(100))
	id2 := NewIdentity(big.NewInt(200))
	id3 := NewIdentity(big.NewInt(300))
	id4 := NewIdentity(big.NewInt(400))
	identities := []*Identity{id1, id2, id3, id4}

	batchLabel := NewBatchLabel([]byte("batch-2025-01-12"))

	// 4. 生成批摘要
	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	// 5. 计算解密密钥
	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	// 6. 加密消息给 id4
	msg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, msg, id4, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 7. id4 解密
	decryptedMsg, err := Decrypt(ct, sk, digest, identities, id4, batchLabel, mpk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 8. 验证消息相等
	if !msg.M.Equal(&decryptedMsg.M) {
		t.Errorf("Decrypted message does not match original")
	}
}

// TestSingleIdentity1 测试单身份(正确)
func TestSingleIdentity1(t *testing.T) {
	batchSize := 10
	params, err := Setup(batchSize)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	id1 := NewIdentity(big.NewInt(100))
	identities := []*Identity{id1}
	batchLabel := NewBatchLabel([]byte("batch-2026-01-13"))

	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	msg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, msg, id1, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decryptedMsg, err := Decrypt(ct, sk, digest, identities, id1, batchLabel, mpk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !msg.M.Equal(&decryptedMsg.M) {
		t.Errorf("Decrypted message does not match original")
	}
}

// TestSingleIdentity1 测试单身份(错误)
func TestSingleIdentity2(t *testing.T) {
	batchSize := 10
	params, err := Setup(batchSize)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	id1 := NewIdentity(big.NewInt(100))
	id2 := NewIdentity(big.NewInt(200))
	identities := []*Identity{id1}
	batchLabel := NewBatchLabel([]byte("batch-2026-01-13"))

	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	msg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, msg, id1, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	_, err = Decrypt(ct, sk, digest, identities, id2, batchLabel, mpk)
	if err != nil {
		fmt.Println("pass, id2 is not valid")
	} else {
		t.Fatalf("pass, id2 is valid")
	}

}

// TestMultiIdentities1 测试多身份(正确)
func TestMultiIdentities1(t *testing.T) {
	batchSize := 10
	params, err := Setup(batchSize)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	id1 := NewIdentity(big.NewInt(100))
	id2 := NewIdentity(big.NewInt(200))
	id3 := NewIdentity(big.NewInt(300))
	id4 := NewIdentity(big.NewInt(400))
	id5 := NewIdentity(big.NewInt(500))
	id6 := NewIdentity(big.NewInt(600))
	identities := []*Identity{id1, id2, id3, id4, id5, id6}
	batchLabel := NewBatchLabel([]byte("batch-2026-01-13"))

	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest failed: %v", err)
	}

	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey failed: %v", err)
	}

	msg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}

	ct, err := Encrypt(mpk, msg, id6, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decryptedMsg, err := Decrypt(ct, sk, digest, identities, id6, batchLabel, mpk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	if !msg.M.Equal(&decryptedMsg.M) {
		t.Errorf("Decrypted message does not match original")
	}
}

// TestMultipleRecipientsInBatch 测试批量中的多个接收者
func TestMultipleRecipientsInBatch(t *testing.T) {
	params, _ := Setup(20)
	mpk, msk, _ := KeyGen(params)

	// 创建5个身份
	identities := make([]*Identity, 5)
	for i := 0; i < 5; i++ {
		identities[i] = NewIdentity(big.NewInt(int64(1000 + i*100)))
	}

	batchLabel := NewBatchLabel([]byte("multi-recipient-batch"))
	digest, _ := Digest(mpk, identities)
	sk, _ := ComputeKey(msk, digest, batchLabel)

	// 为每个身份加密不同的消息
	messages := make([]*Message, 5)
	ciphertexts := make([]*Ciphertext, 5)

	for i := 0; i < 5; i++ {
		msg, _ := RandomMessage()
		messages[i] = msg
		ct, err := Encrypt(mpk, msg, identities[i], batchLabel)
		if err != nil {
			t.Fatalf("Encrypt for identity %d failed: %v", i, err)
		}
		ciphertexts[i] = ct
	}

	// 每个身份都应该能用同一个 sk 解密自己的消息
	for i := 0; i < 5; i++ {
		decrypted, err := Decrypt(ciphertexts[i], sk, digest, identities, identities[i], batchLabel, mpk)
		if err != nil {
			t.Fatalf("Decrypt for identity %d failed: %v", i, err)
		}

		if !messages[i].M.Equal(&decrypted.M) {
			t.Errorf("Identity %d: decrypted message does not match", i)
		}
	}
}

// TestDifferentBatchLabels 测试不同批标签的隔离性
func TestDifferentBatchLabels(t *testing.T) {
	params, _ := Setup(10)
	mpk, msk, _ := KeyGen(params)

	id := NewIdentity(big.NewInt(500))
	identities := []*Identity{id}

	// 两个不同的批标签
	label1 := NewBatchLabel([]byte("batch-morning"))
	label2 := NewBatchLabel([]byte("batch-evening"))

	digest, _ := Digest(mpk, identities)

	// 使用 label1 和 label2 生成密钥
	sk1, _ := ComputeKey(msk, digest, label1)
	sk2, _ := ComputeKey(msk, digest, label2)

	// 使用 label1 加密
	msg, _ := RandomMessage()
	ct1, _ := Encrypt(mpk, msg, id, label1)

	// 使用 label1 的密钥和 label1 应该能解密
	decrypted, err := Decrypt(ct1, sk1, digest, identities, id, label1, mpk)
	if err != nil {
		t.Fatalf("Decrypt with matching label failed: %v", err)
	}
	if !msg.M.Equal(&decrypted.M) {
		t.Errorf("Decrypted message does not match with correct label")
	}

	// 使用 label1 的密钥但用 label2 尝试解密应该失败（得到错误的消息）
	decrypted2, err := Decrypt(ct1, sk2, digest, identities, id, label2, mpk)
	if err != nil {
		t.Fatalf("Decrypt with wrong label returned error: %v", err)
	}
	if msg.M.Equal(&decrypted2.M) {
		t.Errorf("Decryption with wrong label should not produce correct message")
	}
}

// TestIdentityNotInBatch 测试不在批量中的身份无法解密
func TestIdentityNotInBatch(t *testing.T) {
	params, _ := Setup(10)
	mpk, msk, _ := KeyGen(params)

	id1 := NewIdentity(big.NewInt(100))
	id2 := NewIdentity(big.NewInt(200))
	id3 := NewIdentity(big.NewInt(300)) // 不在批量中

	identities := []*Identity{id1, id2} // 只包含 id1 和 id2
	batchLabel := NewBatchLabel([]byte("exclusive-batch"))

	digest, _ := Digest(mpk, identities)
	sk, _ := ComputeKey(msk, digest, batchLabel)

	// 加密给 id1
	msg, _ := RandomMessage()
	ct, _ := Encrypt(mpk, msg, id1, batchLabel)

	// id1 可以解密
	_, err := Decrypt(ct, sk, digest, identities, id1, batchLabel, mpk)
	if err != nil {
		t.Errorf("Valid identity id1 should be able to decrypt: %v", err)
	}

	// id3 不在批量中，尝试解密应该返回错误
	identitiesWithId3 := []*Identity{id1, id2, id3}
	decrypted, err := Decrypt(ct, sk, digest, identitiesWithId3, id3, batchLabel, mpk)
	if err == nil && decrypted.M.Equal(&msg.M) {
		t.Errorf("Identity not in original batch should not decrypt successfully")
	}
}

// TestLargeBatchSize 测试大批量场景
func TestLargeBatchSize(t *testing.T) {
	batchSize := 100
	params, _ := Setup(batchSize)
	mpk, msk, _ := KeyGen(params)

	// 创建50个身份
	numIdentities := 50
	identities := make([]*Identity, numIdentities)
	for i := 0; i < numIdentities; i++ {
		identities[i] = NewIdentity(big.NewInt(int64(10000 + i*10)))
	}

	batchLabel := NewBatchLabel([]byte("large-batch"))
	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest for large batch failed: %v", err)
	}

	sk, _ := ComputeKey(msk, digest, batchLabel)

	// 随机选择几个身份进行测试
	testIndices := []int{0, 10, 25, 40, 49}
	for _, idx := range testIndices {
		msg, _ := RandomMessage()
		ct, _ := Encrypt(mpk, msg, identities[idx], batchLabel)

		decrypted, err := Decrypt(ct, sk, digest, identities, identities[idx], batchLabel, mpk)
		if err != nil {
			t.Errorf("Decrypt failed for identity at index %d: %v", idx, err)
			continue
		}

		if !msg.M.Equal(&decrypted.M) {
			t.Errorf("Message mismatch for identity at index %d", idx)
		}
	}
}

// TestSingleIdentityBatch 测试只有一个身份的批量
func TestSingleIdentityBatch(t *testing.T) {
	batchSize := 10
	params, err := Setup(batchSize)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	mpk, msk, err := KeyGen(params)
	if err != nil {
		t.Fatalf("KeyGen failed: %v", err)
	}

	id1 := NewIdentity(big.NewInt(100))
	id2 := NewIdentity(big.NewInt(200))
	id3 := NewIdentity(big.NewInt(300))
	identities := []*Identity{id1, id2, id3}

	batchLabel := NewBatchLabel([]byte("single-id-batch"))

	digest, err := Digest(mpk, identities)
	if err != nil {
		t.Fatalf("Digest for single identity failed: %v", err)
	}

	sk, err := ComputeKey(msk, digest, batchLabel)
	if err != nil {
		t.Fatalf("ComputeKey for single identity failed: %v", err)
	}

	msg, err := RandomMessage()
	if err != nil {
		t.Fatalf("RandomMessage failed: %v", err)
	}
	ct, err := Encrypt(mpk, msg, id1, batchLabel)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	decryptedMsg, err := Decrypt(ct, sk, digest, identities, id1, batchLabel, mpk)
	if err != nil {
		t.Fatalf("Decrypt for single identity batch failed: %v", err)
	}

	if !msg.M.Equal(&decryptedMsg.M) {
		t.Errorf("Single identity batch: message mismatch")
	}
}

// TestEmptyIdentityList 测试空身份列表应该失败
func TestEmptyIdentityList(t *testing.T) {
	params, _ := Setup(10)
	mpk, _, _ := KeyGen(params)

	emptyIdentities := []*Identity{}

	_, err := Digest(mpk, emptyIdentities)
	if err == nil {
		t.Errorf("Digest should fail with empty identity list")
	}
	fmt.Println(err)
}

// TestBatchSizeExceeded 测试超过批量大小限制
func TestBatchSizeExceeded(t *testing.T) {
	batchSize := 5
	params, _ := Setup(batchSize)
	mpk, _, _ := KeyGen(params)

	// 创建超过批量大小的身份列表
	identities := make([]*Identity, batchSize+1)
	for i := 0; i < batchSize+1; i++ {
		identities[i] = NewIdentity(big.NewInt(int64(i)))
	}

	_, err := Digest(mpk, identities)
	if err == nil {
		t.Errorf("Digest should fail when identity count exceeds batch size")
	}
	fmt.Println(err)
}

// TestInvalidBatchSize 测试无效的批量大小
func TestInvalidBatchSize(t *testing.T) {
	_, err := Setup(0)
	if err == nil {
		t.Errorf("Setup should fail with batch size 0")
	}
	fmt.Println(err)

	_, err = Setup(-5)
	if err == nil {
		t.Errorf("Setup should fail with negative batch size")
	}
	fmt.Println(err)
}

// TestMultipleBatchesWithSameIdentities 测试相同身份在不同批次中
func TestMultipleBatchesWithSameIdentities(t *testing.T) {
	params, _ := Setup(10)
	mpk, msk, _ := KeyGen(params)

	id1 := NewIdentity(big.NewInt(100))
	id2 := NewIdentity(big.NewInt(200))
	identities := []*Identity{id1, id2}

	// 批次1
	label1 := NewBatchLabel([]byte("batch-1"))
	digest1, _ := Digest(mpk, identities)
	sk1, _ := ComputeKey(msk, digest1, label1)

	msg1, _ := RandomMessage()
	ct1, _ := Encrypt(mpk, msg1, id1, label1)

	// 批次2（相同身份，不同标签）
	label2 := NewBatchLabel([]byte("batch-2"))
	digest2, _ := Digest(mpk, identities)
	sk2, _ := ComputeKey(msk, digest2, label2)

	msg2, _ := RandomMessage()
	ct2, _ := Encrypt(mpk, msg2, id1, label2)

	// 批次1的密钥应该只能解密批次1的密文
	decrypted1, err := Decrypt(ct1, sk1, digest1, identities, id1, label1, mpk)
	if err != nil {
		t.Fatalf("Decrypt batch1 with sk1 failed: %v", err)
	}
	if !msg1.M.Equal(&decrypted1.M) {
		t.Errorf("Batch 1 message mismatch")
	}

	// 批次2的密钥应该只能解密批次2的密文
	decrypted2, err := Decrypt(ct2, sk2, digest2, identities, id1, label2, mpk)
	if err != nil {
		t.Fatalf("Decrypt batch2 with sk2 failed: %v", err)
	}
	if !msg2.M.Equal(&decrypted2.M) {
		t.Errorf("Batch 2 message mismatch")
	}

	// 交叉使用应该失败（得到错误消息）
	wrongDecrypt, err := Decrypt(ct1, sk2, digest2, identities, id1, label2, mpk)
	if err != nil {
		t.Fatalf("Cross-batch decrypt returned error: %v", err)
	}
	if msg1.M.Equal(&wrongDecrypt.M) {
		t.Errorf("Cross-batch decryption should not produce correct message")
	}
}

// TestSequentialEncryption 测试连续加密多条消息
func TestSequentialEncryption(t *testing.T) {
	params, _ := Setup(10)
	mpk, msk, _ := KeyGen(params)

	id := NewIdentity(big.NewInt(777))
	identities := []*Identity{id}
	batchLabel := NewBatchLabel([]byte("sequential-test"))

	digest, _ := Digest(mpk, identities)
	sk, _ := ComputeKey(msk, digest, batchLabel)

	numMessages := 10
	messages := make([]*Message, numMessages)
	ciphertexts := make([]*Ciphertext, numMessages)

	// 连续加密多条消息
	for i := 0; i < numMessages; i++ {
		msg, _ := RandomMessage()
		messages[i] = msg
		ct, err := Encrypt(mpk, msg, id, batchLabel)
		if err != nil {
			t.Fatalf("Encryption %d failed: %v", i, err)
		}
		ciphertexts[i] = ct
	}

	// 验证所有消息都能正确解密
	for i := 0; i < numMessages; i++ {
		decrypted, err := Decrypt(ciphertexts[i], sk, digest, identities, id, batchLabel, mpk)
		if err != nil {
			t.Errorf("Decryption %d failed: %v", i, err)
			continue
		}

		if !messages[i].M.Equal(&decrypted.M) {
			t.Errorf("Message %d mismatch", i)
		}
	}
}

// TestDifferentMasterKeys 测试不同主密钥的隔离性
func TestDifferentMasterKeys(t *testing.T) {
	params, _ := Setup(10)

	// 生成两组不同的主密钥对
	mpk1, msk1, _ := KeyGen(params)
	mpk2, msk2, _ := KeyGen(params)

	id := NewIdentity(big.NewInt(888))
	identities := []*Identity{id}
	batchLabel := NewBatchLabel([]byte("cross-key-test"))

	// 使用第一组密钥
	digest1, _ := Digest(mpk1, identities)
	sk1, _ := ComputeKey(msk1, digest1, batchLabel)

	msg, _ := RandomMessage()
	ct1, _ := Encrypt(mpk1, msg, id, batchLabel)

	// 使用第一组密钥解密应该成功
	decrypted, err := Decrypt(ct1, sk1, digest1, identities, id, batchLabel, mpk1)
	if err != nil {
		t.Fatalf("Decrypt with correct keys failed: %v", err)
	}
	if !msg.M.Equal(&decrypted.M) {
		t.Errorf("Message mismatch with correct keys")
	}

	// 使用第二组密钥的解密密钥尝试解密应该失败（得到错误消息）
	digest2, _ := Digest(mpk2, identities)
	sk2, _ := ComputeKey(msk2, digest2, batchLabel)

	wrongDecrypt, err := Decrypt(ct1, sk2, digest2, identities, id, batchLabel, mpk2)
	if err != nil {
		t.Fatalf("Cross-key decrypt returned error: %v", err)
	}
	if msg.M.Equal(&wrongDecrypt.M) {
		t.Errorf("Cross-key decryption should not produce correct message")
	}
}

// BenchmarkEncrypt 基准测试：加密性能
func BenchmarkEncrypt(b *testing.B) {
	params, _ := Setup(100)
	mpk, _, _ := KeyGen(params)

	id := NewIdentity(big.NewInt(12345))
	batchLabel := NewBatchLabel([]byte("benchmark-batch"))
	msg, _ := RandomMessage()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Encrypt(mpk, msg, id, batchLabel)
	}
}

// BenchmarkDecrypt 基准测试：解密性能
func BenchmarkDecrypt(b *testing.B) {
	params, _ := Setup(100)
	mpk, msk, _ := KeyGen(params)

	// 准备10个身份的批量
	identities := make([]*Identity, 10)
	for i := 0; i < 10; i++ {
		identities[i] = NewIdentity(big.NewInt(int64(1000 + i)))
	}

	batchLabel := NewBatchLabel([]byte("benchmark-batch"))
	digest, _ := Digest(mpk, identities)
	sk, _ := ComputeKey(msk, digest, batchLabel)

	msg, _ := RandomMessage()
	ct, _ := Encrypt(mpk, msg, identities[0], batchLabel)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Decrypt(ct, sk, digest, identities, identities[0], batchLabel, mpk)
	}
}

// BenchmarkDigest 基准测试：批摘要生成性能
func BenchmarkDigest(b *testing.B) {
	params, _ := Setup(100)
	mpk, _, _ := KeyGen(params)

	identities := make([]*Identity, 50)
	for i := 0; i < 50; i++ {
		identities[i] = NewIdentity(big.NewInt(int64(i * 100)))
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Digest(mpk, identities)
	}
}

// BenchmarkKeyGen 基准测试：密钥生成性能
func BenchmarkKeyGen(b *testing.B) {
	params, _ := Setup(100)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, _ = KeyGen(params)
	}
}
