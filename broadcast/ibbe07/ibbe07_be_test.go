package ibbe07

import (
	"testing"
)

// TestBasicFlow 覆盖最基本的功能：Setup -> Extract -> Encrypt -> Decrypt
func TestBasicFlow(t *testing.T) {
	// 1. 系统初始化，设定最大广播人数为 5
	maxUsers := 5
	pk, msk, err := Setup(maxUsers)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 2. 准备用户身份和提取私钥
	// 模拟集合 S = {Alice, Bob, Charlie}
	aliceID := Identity{Id: []byte("Alice")}
	bobID := Identity{Id: []byte("Bob")}
	charlieID := Identity{Id: []byte("Charlie")}

	S := []Identity{aliceID, bobID, charlieID}

	aliceSK, err := Extract(msk, &aliceID)
	if err != nil {
		t.Fatalf("Extract Alice SK failed: %v", err)
	}

	// 3. 执行广播加密
	hdr, ek, err := Encrypt(S, pk)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 4. 解密测试 - Alice 尝试解密
	dek, err := Decrypt(S, &aliceID, aliceSK, hdr, pk)
	if err != nil {
		t.Fatalf("Decryption for Alice failed: %v", err)
	}

	// 5. 验证解密出的对称密钥 K 是否一致
	if !dek.K.Equal(&ek.K) {
		t.Error("Decrypted key does not match original encryption key")
	} else {
		t.Log("Basic encryption/decryption success!")
	}
}

// TestMultipleRecipients 验证集合中不同位置的用户是否都能解密成功
func TestMultipleRecipients(t *testing.T) {
	pk, msk, _ := Setup(10)

	// 创建 4 个用户
	ids := []string{"UserA", "UserB", "UserC", "UserD"}
	S := make([]Identity, len(ids))
	sks := make([]*UserSecretKey, len(ids))

	for i, name := range ids {
		S[i] = Identity{Id: []byte(name)}
		sks[i], _ = Extract(msk, &S[i])
	}

	// 对这 4 个用户加密
	hdr, ek, _ := Encrypt(S, pk)

	// 验证集合中的每一个用户都能解密
	for i := range S {
		dek, err := Decrypt(S, &S[i], sks[i], hdr, pk)
		if err != nil {
			t.Errorf("User %s failed to decrypt: %v", ids[i], err)
			continue
		}
		if !dek.K.Equal(&ek.K) {
			t.Errorf("User %s decrypted wrong key", ids[i])
		}
	}
}

func TestIBBEFullWorkflow(t *testing.T) {
	// 1. Setup: 设置最大广播人数为 10
	maxUsers := 10
	pk, msk, err := Setup(maxUsers)
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 2. 定义身份集合
	userIds := []string{"alice", "bob", "charlie", "david"}
	identities := make([]Identity, len(userIds))
	for i, id := range userIds {
		identities[i] = Identity{Id: []byte(id)}
	}

	// 3. 为 "bob" 提取私钥 (Index 1)
	targetUser := identities[1]
	skBob, err := Extract(msk, &targetUser)
	if err != nil {
		t.Fatalf("Extract failed for bob: %v", err)
	}

	// 4. Encrypt: 对全集进行加密
	header, encKey, err := Encrypt(identities, pk)
	if err != nil {
		t.Fatalf("Encryption failed: %v", err)
	}

	// 5. Decrypt: Bob 尝试解密
	decKey, err := Decrypt(identities, &targetUser, skBob, header, pk)
	if err != nil {
		t.Fatalf("Decryption failed for bob: %v", err)
	}

	// 6. 验证密钥是否一致
	if !encKey.K.Equal(&decKey.K) {
		t.Error("Decrypted key does not match original encryption key!")
	} else {
		t.Log("Success: Decrypted key matches encryption key.")
	}

	// 7. 负面测试：不在集合中的用户尝试解密
	eve := Identity{Id: []byte("eve")}
	skEve, _ := Extract(msk, &eve)
	_, err = Decrypt(identities, &eve, skEve, header, pk)
	if err == nil {
		t.Error("Security breach: User NOT in set successfully decrypted the message!")
	} else {
		t.Logf("Correctly rejected unauthorized user: %v", err)
	}
}
