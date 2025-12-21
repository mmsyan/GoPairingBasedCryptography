package bb04_sibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
	"testing"
)

// TestBB04sIbe1 测试基本的加密解密流程
// 场景：使用正确的身份和密钥进行加密解密，验证能否正确恢复原始消息
func TestBB04sIbe1(t *testing.T) {
	var err error

	// 创建用户身份
	identity, err := NewBB04sIBEIdentity(big.NewInt(123456))

	// 生成随机消息
	m, err := new(bn254.GT).SetRandom()
	message := &BB04sIBEMessage{
		Message: *m,
	}
	fmt.Println("原始消息:", message.Message)

	// 系统初始化
	instance, err := NewBB04sIBEInstance()
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

// TestBB04sIbe2 测试错误密钥无法解密的情况
// 场景：使用Alice的密钥尝试解密发给Bob的消息，应该解密失败（得到错误的明文）
func TestBB04sIbe2(t *testing.T) {
	var err error

	// 创建Alice的身份
	aliceIdentity, err := NewBB04sIBEIdentity(big.NewInt(123456))

	// 创建Bob的身份
	bobIdentity, err := NewBB04sIBEIdentity(big.NewInt(456789))

	// 生成随机消息
	m, err := new(bn254.GT).SetRandom()
	message := &BB04sIBEMessage{
		Message: *m,
	}
	fmt.Println("原始消息:", message.Message)

	// 系统初始化
	instance, err := NewBB04sIBEInstance()
	if err != nil {
		t.Fatal("创建IBE实例失败:", err)
	}

	// 生成公共参数
	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 为Alice生成密钥
	secretKey, err := instance.KeyGenerate(aliceIdentity, publicParams)
	if err != nil {
		t.Fatal("为Alice生成密钥失败:", err)
	}

	// 使用Bob的身份加密消息（消息是发给Bob的）
	ciphertext, err := instance.Encrypt(message, bobIdentity, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	// 尝试使用Alice的密钥解密（应该得到错误的结果）
	decryptedMessage, err := instance.Decrypt(ciphertext, secretKey, publicParams)
	if err != nil {
		t.Fatal("解密操作失败:", err)
	}

	fmt.Println("错误解密结果:", decryptedMessage.Message)

	// 验证解密后的消息与原始消息不一致（因为用了错误的密钥）
	if decryptedMessage.Message == message.Message {
		t.Fatal("错误：使用错误的密钥不应该得到正确的明文")
	}

	fmt.Println("✓ 测试通过：错误的密钥无法正确解密")
}

// TestBB04sIbe3 测试多个用户的独立性
// 场景：同一个系统中有多个用户，每个用户只能解密发给自己的消息
func TestBB04sIbe3(t *testing.T) {
	// 系统初始化
	instance, err := NewBB04sIBEInstance()
	if err != nil {
		t.Fatal("创建IBE实例失败:", err)
	}

	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 创建三个用户身份
	alice, err := NewBB04sIBEIdentity(big.NewInt(1001))
	bob, err := NewBB04sIBEIdentity(big.NewInt(2002))
	charlie, err := NewBB04sIBEIdentity(big.NewInt(3003))

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

	msg1 := &BB04sIBEMessage{Message: *m1}
	msg2 := &BB04sIBEMessage{Message: *m2}
	msg3 := &BB04sIBEMessage{Message: *m3}

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

	// 验证用户无法解密其他人的消息
	wrongDecrypted, _ := instance.Decrypt(ct2, aliceKey, publicParams)
	if wrongDecrypted.Message == msg2.Message {
		t.Fatal("错误：Alice不应该能解密Bob的消息")
	}
	fmt.Println("✓ Alice无法解密Bob的消息")

	fmt.Println("✓ 测试通过：多用户独立性验证成功")
}

// TestBB04sIbe4 测试同一消息多次加密的不确定性
// 场景：同一消息多次加密应该产生不同的密文（由于随机数s的不同）
func TestBB04sIbe4(t *testing.T) {
	// 系统初始化
	instance, err := NewBB04sIBEInstance()
	if err != nil {
		t.Fatal("创建IBE实例失败:", err)
	}

	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 创建用户身份和密钥
	identity, err := NewBB04sIBEIdentity(big.NewInt(123456))
	secretKey, err := instance.KeyGenerate(identity, publicParams)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	// 生成一条消息
	m, _ := new(bn254.GT).SetRandom()
	message := &BB04sIBEMessage{Message: *m}
	fmt.Println("原始消息:", message.Message)

	// 对同一消息进行三次加密
	ct1, err := instance.Encrypt(message, identity, publicParams)
	if err != nil {
		t.Fatal("第一次加密失败:", err)
	}

	ct2, err := instance.Encrypt(message, identity, publicParams)
	if err != nil {
		t.Fatal("第二次加密失败:", err)
	}

	ct3, err := instance.Encrypt(message, identity, publicParams)
	if err != nil {
		t.Fatal("第三次加密失败:", err)
	}

	// 验证三次密文的组件都不相同（概率性加密）
	if ct1.a.Equal(&ct2.a) || ct1.a.Equal(&ct3.a) || ct2.a.Equal(&ct3.a) {
		t.Fatal("错误：多次加密产生了相同的密文组件a")
	}
	if ct1.b.Equal(&ct2.b) || ct1.b.Equal(&ct3.b) || ct2.b.Equal(&ct3.b) {
		t.Fatal("错误：多次加密产生了相同的密文组件b")
	}
	if ct1.c == ct2.c || ct1.c == ct3.c || ct2.c == ct3.c {
		t.Fatal("错误：多次加密产生了相同的密文组件c")
	}
	fmt.Println("✓ 三次加密产生了不同的密文")

	// 验证所有密文都能正确解密
	dec1, err := instance.Decrypt(ct1, secretKey, publicParams)
	if err != nil || dec1.Message != message.Message {
		t.Fatal("密文1解密失败或结果不正确")
	}

	dec2, err := instance.Decrypt(ct2, secretKey, publicParams)
	if err != nil || dec2.Message != message.Message {
		t.Fatal("密文2解密失败或结果不正确")
	}

	dec3, err := instance.Decrypt(ct3, secretKey, publicParams)
	if err != nil || dec3.Message != message.Message {
		t.Fatal("密文3解密失败或结果不正确")
	}

	fmt.Println("✓ 所有不同的密文都能正确解密为原始消息")
	fmt.Println("✓ 测试通过：加密的概率性和正确性验证成功")
}

// TestBB04sIbe5 测试边界情况和特殊身份值
// 场景：测试使用特殊值（如1、大数等）作为身份的情况
func TestBB04sIbe5(t *testing.T) {
	// 系统初始化
	instance, err := NewBB04sIBEInstance()
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
			identity, err := NewBB04sIBEIdentity(tc.idVal)

			// 生成密钥
			secretKey, err := instance.KeyGenerate(identity, publicParams)
			if err != nil {
				t.Fatalf("为 %s 生成密钥失败: %v", tc.name, err)
			}

			// 生成消息
			m, _ := new(bn254.GT).SetRandom()
			message := &BB04sIBEMessage{Message: *m}

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
