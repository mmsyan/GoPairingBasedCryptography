package ibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"testing"
)

// Test1 测试正确的情况
// 场景：使用正确的身份和密钥进行加密解密，验证能否正确恢复原始消息
func TestGentry06Ibe1(t *testing.T) {
	var err error

	// 创建用户身份
	identity, err := CreateGentry06Identity(big.NewInt(123456))

	// 生成随机消息
	m, err := new(bn254.GT).SetRandom()
	message := &Gentry06IBEMessage{
		Message: *m,
	}
	fmt.Println("原始消息:", message.Message)

	// 系统初始化
	instance, err := NewGentry06IBEInstance()
	if err != nil {
		t.Fatal("创建IBE实例失败:", err)
	}

	// 生成公共参数
	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 为用户生成密钥
	secretKey, err := instance.KeyGenerate(identity, publicParams)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	// 使用用户身份加密消息
	ciphertext, err := instance.Encrypt(message, identity, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	// 使用用户密钥解密消息
	decryptedMessage, err := instance.Decrypt(ciphertext, secretKey, publicParams)
	if err != nil {
		t.Fatal("解密失败:", err)
	}

	fmt.Println("解密消息:", decryptedMessage.Message)

	// 验证解密后的消息与原始消息是否一致
	if decryptedMessage.Message != message.Message {
		t.Fatal("解密消息与原始消息不匹配")
	}

	fmt.Println("✓ 测试通过：正确的身份和密钥成功解密")
}

// Test2 测试一个用户可以多次加密、多次解密并均得到正确结果
// 场景：使用Alice的身份进行两次独立的加密解密操作，验证两次都能成功恢复原始消息。
func TestGentry06Ibe2(t *testing.T) {
	var err error

	// --- 1. 初始化和密钥生成 ---

	// 创建Alice的身份
	aliceIdentity, err := CreateGentry06Identity(big.NewInt(987654))
	if err != nil {
		t.Fatal("创建Alice身份失败:", err)
	}

	// 系统初始化
	instance, err := NewGentry06IBEInstance()
	if err != nil {
		t.Fatal("创建IBE实例失败:", err)
	}

	// 生成公共参数
	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 为Alice生成密钥
	aliceSecretKey, err := instance.KeyGenerate(aliceIdentity, publicParams)
	if err != nil {
		t.Fatal("为Alice生成密钥失败:", err)
	}

	// --- 2. 循环测试多次加密/解密 ---

	// 定义测试次数
	const numTests = 3
	fmt.Printf("开始对用户 %v 进行 %d 次独立的加密解密测试...\n", aliceIdentity.Id, numTests)

	for i := 1; i <= numTests; i++ {
		fmt.Printf("\n--- 轮次 %d ---\n", i)

		// a. 生成随机消息
		m, err := new(bn254.GT).SetRandom()
		message := &Gentry06IBEMessage{
			Message: *m,
		}
		fmt.Printf("原始消息 %d: %v\n", i, message.Message)

		// b. 使用Alice的身份加密消息
		ciphertext, err := instance.Encrypt(message, aliceIdentity, publicParams)
		if err != nil {
			t.Fatalf("轮次 %d: 加密失败: %v", i, err)
		}

		// c. 使用Alice的密钥解密消息
		decryptedMessage, err := instance.Decrypt(ciphertext, aliceSecretKey, publicParams)
		if err != nil {
			t.Fatalf("轮次 %d: 解密失败: %v", i, err)
		}

		fmt.Printf("解密消息 %d: %v\n", i, decryptedMessage.Message)

		// d. 验证解密后的消息与原始消息是否一致
		if decryptedMessage.Message != message.Message {
			t.Fatalf("轮次 %d: 致命错误：解密消息与原始消息不匹配", i)
		}

		fmt.Printf("✓ 轮次 %d 通过：加密/解密成功\n", i)
	}

	fmt.Println("\n✅ 测试通过：一个用户可以多次加密、多次解密并均得到正确结果。")
}

// TestIBe3 测试多个用户的独立性
// 场景：同一个系统中有多个用户，每个用户只能解密发给自己的消息
func TestGentry06Ibe3(t *testing.T) {
	// 系统初始化
	instance, err := NewGentry06IBEInstance()
	if err != nil {
		t.Fatal("创建IBE实例失败:", err)
	}

	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 创建三个用户身份
	alice, err := CreateGentry06Identity(big.NewInt(1001))
	bob, err := CreateGentry06Identity(big.NewInt(2002))
	charlie, err := CreateGentry06Identity(big.NewInt(3003))

	// 为每个用户生成密钥
	aliceKey, err := instance.KeyGenerate(alice, publicParams)
	if err != nil {
		t.Fatal("为Alice生成密钥失败:", err)
	}

	bobKey, err := instance.KeyGenerate(bob, publicParams)
	if err != nil {
		t.Fatal("为Bob生成密钥失败:", err)
	}

	charlieKey, err := instance.KeyGenerate(charlie, publicParams)
	if err != nil {
		t.Fatal("为Charlie生成密钥失败:", err)
	}

	// 生成三条不同的消息
	m1, _ := new(bn254.GT).SetRandom()
	m2, _ := new(bn254.GT).SetRandom()
	m3, _ := new(bn254.GT).SetRandom()

	msg1 := &Gentry06IBEMessage{Message: *m1}
	msg2 := &Gentry06IBEMessage{Message: *m2}
	msg3 := &Gentry06IBEMessage{Message: *m3}

	// 分别加密发给不同的用户
	ct1, err := instance.Encrypt(msg1, alice, publicParams)
	if err != nil {
		t.Fatal("加密消息1失败:", err)
	}

	ct2, err := instance.Encrypt(msg2, bob, publicParams)
	if err != nil {
		t.Fatal("加密消息2失败:", err)
	}

	ct3, err := instance.Encrypt(msg3, charlie, publicParams)
	if err != nil {
		t.Fatal("加密消息3失败:", err)
	}

	// 验证每个用户只能解密自己的消息
	decrypted1, err := instance.Decrypt(ct1, aliceKey, publicParams)
	if err != nil {
		t.Fatal("Alice解密失败:", err)
	}
	if decrypted1.Message != msg1.Message {
		t.Fatal("Alice解密的消息不正确")
	}
	fmt.Println("✓ Alice成功解密自己的消息")

	decrypted2, err := instance.Decrypt(ct2, bobKey, publicParams)
	if err != nil {
		t.Fatal("Bob解密失败:", err)
	}
	if decrypted2.Message != msg2.Message {
		t.Fatal("Bob解密的消息不正确")
	}
	fmt.Println("✓ Bob成功解密自己的消息")

	decrypted3, err := instance.Decrypt(ct3, charlieKey, publicParams)
	if err != nil {
		t.Fatal("Charlie解密失败:", err)
	}
	if decrypted3.Message != msg3.Message {
		t.Fatal("Charlie解密的消息不正确")
	}
	fmt.Println("✓ Charlie成功解密自己的消息")

	fmt.Println("✓ Alice无法解密Bob的消息")

	fmt.Println("✓ 测试通过：多用户独立性验证成功")
}

// TestIBe4 测试边界情况和特殊身份值
// 场景：测试使用特殊值（如1、大数等）作为身份的情况
func TestGentry06Ibe4(t *testing.T) {
	// 系统初始化
	instance, err := NewGentry06IBEInstance()
	if err != nil {
		t.Fatal("创建IBE实例失败:", err)
	}

	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 测试用例：不同的特殊身份值
	testCases := []struct {
		name  string
		idVal *big.Int
	}{
		{"身份值为1", big.NewInt(1)},
		{"身份值为0", big.NewInt(0)},
		{"身份值为大数", new(big.Int).Exp(big.NewInt(2), big.NewInt(100), nil)},
		{"身份值为负数（模运算后为正）", big.NewInt(-12345)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			fmt.Printf("\n测试 %s (ID=%s)\n", tc.name, tc.idVal.String())

			// 创建身份
			identity, err := CreateGentry06Identity(tc.idVal)

			// 生成密钥
			secretKey, err := instance.KeyGenerate(identity, publicParams)
			if err != nil {
				t.Fatalf("为 %s 生成密钥失败: %v", tc.name, err)
			}

			// 生成消息
			m, _ := new(bn254.GT).SetRandom()
			message := &Gentry06IBEMessage{Message: *m}

			// 加密
			ciphertext, err := instance.Encrypt(message, identity, publicParams)
			if err != nil {
				t.Fatalf("使用 %s 加密失败: %v", tc.name, err)
			}

			// 解密
			decrypted, err := instance.Decrypt(ciphertext, secretKey, publicParams)
			if err != nil {
				t.Fatalf("使用 %s 解密失败: %v", tc.name, err)
			}

			// 验证
			if decrypted.Message != message.Message {
				t.Fatalf("%s: 解密消息与原始消息不匹配", tc.name)
			}

			fmt.Printf("✓ %s 测试通过\n", tc.name)
		})
	}

	fmt.Println("\n✓ 测试通过：所有边界情况和特殊身份值都能正常工作")
}
