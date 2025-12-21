package bb04_ibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"testing"
)

// TestBB04Ibe1 测试正确的情况
// 场景：使用正确的身份和密钥进行加密解密，验证能否正确恢复原始消息
func TestBB04Ibe1(t *testing.T) {
	var err error

	// 1. 创建用户身份 (使用字符串)
	identityString := "test_bb04_user_alpha"
	identity, err := NewBB04IBEIdentity(identityString)
	if err != nil {
		t.Fatalf("创建身份失败: %v", err)
	}

	// 2. 生成随机消息 (位于 GT 群)
	m, _ := new(bn254.GT).SetRandom()
	message := &BB04IBEMessage{
		Message: *m,
	}
	fmt.Println("原始消息:", message.Message)

	// 3. 系统初始化
	instance, err := NewBB04IBEInstance()
	if err != nil {
		t.Fatalf("创建IBE实例失败: %v", err)
	}

	// 4. 生成公共参数
	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatalf("系统初始化失败: %v", err)
	}

	// 5. 为用户生成密钥
	secretKey, err := instance.KeyGenerate(identity, publicParams)
	if err != nil {
		t.Fatalf("密钥生成失败: %v", err)
	}

	// 6. 使用用户身份加密消息
	ciphertext, err := instance.Encrypt(identity, message, publicParams)
	if err != nil {
		t.Fatalf("加密失败: %v", err)
	}

	// 7. 使用用户密钥解密消息
	decryptedMessage, err := instance.Decrypt(ciphertext, secretKey, publicParams)
	if err != nil {
		t.Fatalf("解密失败: %v", err)
	}

	fmt.Println("解密消息:", decryptedMessage.Message)

	// 8. 验证解密后的消息与原始消息是否一致
	if decryptedMessage.Message.String() != message.Message.String() {
		t.Fatal("解密消息与原始消息不匹配")
	}

	fmt.Println("✓ 测试通过：正确的身份和密钥成功解密")
}

// TestBB04Ibe2 测试一个用户可以多次加密、多次解密并均得到正确结果
// 场景：使用Bob的身份进行多次独立的加密解密操作，验证每次都能成功恢复原始消息。
func TestBB04Ibe2(t *testing.T) {
	var err error

	// --- 1. 初始化和密钥生成 ---

	// 创建Bob的身份
	bobIdentityString := "bob_multi_session_bb04"
	bobIdentity, err := NewBB04IBEIdentity(bobIdentityString)
	if err != nil {
		t.Fatalf("创建Bob身份失败: %v", err)
	}

	// 系统初始化
	instance, err := NewBB04IBEInstance()
	if err != nil {
		t.Fatalf("创建IBE实例失败: %v", err)
	}

	// 生成公共参数
	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatalf("系统初始化失败: %v", err)
	}

	// 为Bob生成密钥 (只生成一次)
	bobSecretKey, err := instance.KeyGenerate(bobIdentity, publicParams)
	if err != nil {
		t.Fatalf("为Bob生成密钥失败: %v", err)
	}

	// --- 2. 循环测试多次加密/解密 ---

	const numTests = 3
	fmt.Printf("开始对用户 %s 进行 %d 次独立的加密解密测试...\n", bobIdentityString, numTests)

	for i := 1; i <= numTests; i++ {
		fmt.Printf("\n--- 轮次 %d ---\n", i)

		// a. 生成随机消息
		m, _ := new(bn254.GT).SetRandom()
		message := &BB04IBEMessage{
			Message: *m,
		}
		fmt.Printf("原始消息 %d: %s...\n", i, message.Message.String()[:10]) // 打印前10个字符

		// b. 使用Bob的身份加密消息
		ciphertext, err := instance.Encrypt(bobIdentity, message, publicParams)
		if err != nil {
			t.Fatalf("轮次 %d: 加密失败: %v", i, err)
		}

		// c. 使用Bob的密钥解密消息
		decryptedMessage, err := instance.Decrypt(ciphertext, bobSecretKey, publicParams)
		if err != nil {
			t.Fatalf("轮次 %d: 解密失败: %v", i, err)
		}

		fmt.Printf("解密消息 %d: %s...\n", i, decryptedMessage.Message.String()[:10]) // 打印前10个字符

		// d. 验证解密后的消息与原始消息是否一致
		if decryptedMessage.Message.String() != message.Message.String() {
			t.Fatalf("轮次 %d: 致命错误：解密消息与原始消息不匹配", i)
		}

		fmt.Printf("✓ 轮次 %d 通过：加密/解密成功\n", i)
	}

	fmt.Println("\n✅ 测试通过：一个用户可以多次加密、多次解密并均得到正确结果。")
}

// TestBB04Ibe3 测试多个用户的独立性
// 场景：同一个系统中有多个用户，每个用户只能解密发给自己的消息
func TestBB04Ibe3(t *testing.T) {
	// 系统初始化
	instance, err := NewBB04IBEInstance()
	if err != nil {
		t.Fatalf("创建IBE实例失败: %v", err)
	}

	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatalf("系统初始化失败: %v", err)
	}

	// 创建三个用户身份 (使用不同的字符串)
	alice, err := NewBB04IBEIdentity("alice-bb04_signature-user-1001")
	bob, err := NewBB04IBEIdentity("bob-bb04_signature-user-2002")
	charlie, err := NewBB04IBEIdentity("charlie-bb04_signature-user-3003")

	// 为每个用户生成密钥
	aliceKey, err := instance.KeyGenerate(alice, publicParams)
	if err != nil {
		t.Fatalf("为Alice生成密钥失败: %v", err)
	}

	bobKey, err := instance.KeyGenerate(bob, publicParams)
	if err != nil {
		t.Fatalf("为Bob生成密钥失败: %v", err)
	}

	charlieKey, err := instance.KeyGenerate(charlie, publicParams)
	if err != nil {
		t.Fatalf("为Charlie生成密钥失败: %v", err)
	}

	// 生成三条不同的消息
	m1, _ := new(bn254.GT).SetRandom()
	m2, _ := new(bn254.GT).SetRandom()
	m3, _ := new(bn254.GT).SetRandom()

	msg1 := &BB04IBEMessage{Message: *m1} // 发给 Alice
	msg2 := &BB04IBEMessage{Message: *m2} // 发给 Bob
	msg3 := &BB04IBEMessage{Message: *m3} // 发给 Charlie

	// 分别加密发给不同的用户
	ct1, err := instance.Encrypt(alice, msg1, publicParams)
	if err != nil {
		t.Fatalf("加密消息1(给Alice)失败: %v", err)
	}

	ct2, err := instance.Encrypt(bob, msg2, publicParams)
	if err != nil {
		t.Fatalf("加密消息2(给Bob)失败: %v", err)
	}

	ct3, err := instance.Encrypt(charlie, msg3, publicParams)
	if err != nil {
		t.Fatalf("加密消息3(给Charlie)失败: %v", err)
	}

	// --- 验证每个用户只能解密自己的消息 ---

	// Alice 解密 ct1
	decrypted1, err := instance.Decrypt(ct1, aliceKey, publicParams)
	if err != nil {
		t.Fatalf("Alice解密自己的消息失败: %v", err)
	}
	if decrypted1.Message.String() != msg1.Message.String() {
		t.Fatal("Alice解密的消息不正确")
	}
	fmt.Println("✓ Alice成功解密自己的消息")

	// Bob 解密 ct2
	decrypted2, err := instance.Decrypt(ct2, bobKey, publicParams)
	if err != nil {
		t.Fatalf("Bob解密自己的消息失败: %v", err)
	}
	if decrypted2.Message.String() != msg2.Message.String() {
		t.Fatal("Bob解密的消息不正确")
	}
	fmt.Println("✓ Bob成功解密自己的消息")

	// Charlie 解密 ct3
	decrypted3, err := instance.Decrypt(ct3, charlieKey, publicParams)
	if err != nil {
		t.Fatalf("Charlie解密自己的消息失败: %v", err)
	}
	if decrypted3.Message.String() != msg3.Message.String() {
		t.Fatal("Charlie解密的消息不正确")
	}
	fmt.Println("✓ Charlie成功解密自己的消息")

	// --- 验证独立性 (可选，检查失败情况) ---

	// 尝试 Alice 用自己的密钥解密 Bob 的消息 (理论上会失败或得到错误结果)
	unintendedDecryption, err := instance.Decrypt(ct2, aliceKey, publicParams)
	if err != nil {
		t.Fatalf("意外错误: Alice解密Bob消息时出错: %v", err)
	}
	if unintendedDecryption.Message.String() == msg2.Message.String() {
		t.Fatal("致命错误：Alice竟然成功解密了Bob的消息！独立性失败。")
	}
	fmt.Println("✓ 独立性检查通过：Alice无法解密Bob的消息 (得到随机值)")

	fmt.Println("✅ 测试通过：多用户独立性验证成功")
}

// TestBB04Ibe4 测试边界情况和特殊身份值
// 场景：测试使用特殊身份字符串的情况
func TestBB04Ibe4(t *testing.T) {
	// 系统初始化
	instance, err := NewBB04IBEInstance()
	if err != nil {
		t.Fatalf("创建IBE实例失败: %v", err)
	}

	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatalf("系统初始化失败: %v", err)
	}

	// 测试用例：不同的特殊身份值字符串
	testCases := []struct {
		name        string
		identityStr string
		expectError bool // 是否期望身份创建时失败 (如空字符串)
	}{
		{"短字符串", "1", false},
		{"长字符串 (哈希碰撞几率低)", "This is a very very long identity string that should definitely produce a unique hash value and a unique key for BB04.", false},
		{"特殊字符", "!@#$%^&*()_+", false},
		{"空字符串 (预期失败)", "", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {

			// 1. 创建身份
			identity, err := NewBB04IBEIdentity(tc.identityStr)

			if tc.expectError {
				if err == nil {
					t.Fatal("预期创建身份失败，但成功了")
				}
				fmt.Printf("✓ %s 预期失败，测试通过\n", tc.name)
				return // 失败测试用例结束
			}

			if err != nil {
				t.Fatalf("创建身份失败: %v", err)
			}

			fmt.Printf("\n测试 %s (ID字符串: %s)\n", tc.name, tc.identityStr)

			// 2. 生成密钥
			secretKey, err := instance.KeyGenerate(identity, publicParams)
			if err != nil {
				t.Fatalf("为 %s 生成密钥失败: %v", tc.name, err)
			}

			// 3. 生成消息
			m, _ := new(bn254.GT).SetRandom()
			message := &BB04IBEMessage{Message: *m}

			// 4. 加密
			ciphertext, err := instance.Encrypt(identity, message, publicParams)
			if err != nil {
				t.Fatalf("使用 %s 加密失败: %v", tc.name, err)
			}

			// 5. 解密
			decrypted, err := instance.Decrypt(ciphertext, secretKey, publicParams)
			if err != nil {
				t.Fatalf("使用 %s 解密失败: %v", tc.name, err)
			}

			// 6. 验证
			if decrypted.Message.String() != message.Message.String() {
				t.Fatalf("%s: 解密消息与原始消息不匹配", tc.name)
			}

			fmt.Printf("✓ %s 测试通过\n", tc.name)
		})
	}

	fmt.Println("\n✅ 测试通过：所有身份编码和特殊身份值都能正常工作")
}
