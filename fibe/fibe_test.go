package fibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"testing"
)

// TestFIBE1 - 基础测试：完全匹配的属性集
func TestFIBE1(t *testing.T) {
	var err error

	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal(err)
	}
	message := &FIBEMessage{
		Message: *m,
	}
	fmt.Println("原始消息:", message.Message)

	userAttributes := []int{1, 2, 3, 4}
	messageAttributes := []int{1, 2, 3, 4}

	fibeInstance := NewFIBEInstance(10, 3)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}
	secretKey, err := fibeInstance.KeyGenerate(userAttributes)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}
	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext)
	if err != nil {
		t.Fatal("解密失败:", err)
	}

	fmt.Println("解密消息:", decryptedMessage.Message)

	// 验证解密后的消息与原始消息是否一致
	if decryptedMessage.Message != message.Message {
		t.Fatal("解密消息与原始消息不匹配")
	}
}

// TestFIBE2 - 模糊匹配测试：属性部分重叠，满足阈值d
func TestFIBE2(t *testing.T) {
	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal("随机消息生成失败:", err)
	}
	message := &FIBEMessage{Message: *m}

	// 用户属性：1,2,3,4,5
	userAttributes := []int{1, 2, 3, 4, 5}
	// 消息属性：1,2,3,6,7 (与用户属性有3个重叠)
	messageAttributes := []int{1, 2, 3, 6, 7}

	// n=10, d=3：需要至少3个属性匹配
	fibeInstance := NewFIBEInstance(10, 3)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	secretKey, err := fibeInstance.KeyGenerate(userAttributes)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext)
	if err != nil {
		t.Fatal("解密失败:", err)
	}

	if decryptedMessage.Message != message.Message {
		t.Fatal("解密消息与原始消息不匹配")
	}

	fmt.Println("✓ 模糊匹配测试通过：3个属性重叠，阈值d=3")
}

// TestFIBE3 - 边界测试：刚好满足阈值d的最小重叠
func TestFIBE3(t *testing.T) {
	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal("随机消息生成失败:", err)
	}
	message := &FIBEMessage{Message: *m}

	// 用户属性：1,2,3,4,5,6,7
	userAttributes := []int{1, 2, 3, 4, 5, 6, 7}
	// 消息属性：1,2,3,4,8,9,10 (刚好4个重叠)
	messageAttributes := []int{1, 2, 3, 4, 8, 9, 10}

	// d=4：需要至少4个属性匹配
	fibeInstance := NewFIBEInstance(15, 4)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	secretKey, err := fibeInstance.KeyGenerate(userAttributes)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext)
	if err != nil {
		t.Fatal("解密失败:", err)
	}

	if decryptedMessage.Message != message.Message {
		t.Fatal("解密消息与原始消息不匹配")
	}

	fmt.Println("✓ 边界测试通过：刚好满足阈值d=4")
}

// TestFIBE4 - 失败测试：属性重叠不足，不满足阈值d
func TestFIBE4(t *testing.T) {
	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal("随机消息生成失败:", err)
	}
	message := &FIBEMessage{Message: *m}

	// 用户属性：1,2,3
	userAttributes := []int{1, 2, 3}
	// 消息属性：4,5,6,7,8 (没有重叠)
	messageAttributes := []int{4, 5, 6, 7, 8}

	// d=3：需要至少3个属性匹配，但实际重叠为0
	fibeInstance := NewFIBEInstance(10, 3)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	secretKey, err := fibeInstance.KeyGenerate(userAttributes)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	_, err = fibeInstance.Decrypt(secretKey, ciphertext)
	// 解密失败这里err不为空，如果为空则不通过这个测试案例
	if err == nil {
		t.Fatal("解密失败的测试案例错误")
	}
	fmt.Println("✓ 失败测试通过：属性不匹配导致解密得到错误消息")
}

// TestFIBE5 - 多消息测试：同一密钥对不同消息的加解密
func TestFIBE5(t *testing.T) {
	userAttributes := []int{1, 2, 3, 4, 5}
	messageAttributes := []int{1, 2, 3, 4, 5}

	fibeInstance := NewFIBEInstance(10, 3)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	secretKey, err := fibeInstance.KeyGenerate(userAttributes)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	// 测试多个不同的消息
	for i := 0; i < 5; i++ {
		m, err := new(bn254.GT).SetRandom()
		if err != nil {
			t.Fatal("随机消息生成失败:", err)
		}
		message := &FIBEMessage{Message: *m}

		ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
		if err != nil {
			t.Fatalf("第%d次加密失败: %v", i+1, err)
		}

		decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext)
		if err != nil {
			t.Fatalf("第%d次解密失败: %v", i+1, err)
		}

		if decryptedMessage.Message != message.Message {
			t.Fatalf("第%d次：解密消息与原始消息不匹配", i+1)
		}
	}

	fmt.Println("✓ 多消息测试通过：5个不同消息均成功加解密")
}

// TestFIBE6 - 不同阈值测试：测试不同的d值
func TestFIBE6(t *testing.T) {
	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal("随机消息生成失败:", err)
	}
	message := &FIBEMessage{Message: *m}

	userAttributes := []int{1, 2, 3, 4, 5, 6}
	messageAttributes := []int{1, 2, 3, 4, 7, 8}

	testCases := []struct {
		d           int
		shouldMatch bool
		description string
	}{
		{3, true, "d=3，重叠4个，应该成功"},
		{4, true, "d=4，重叠4个，应该成功"},
	}

	for _, tc := range testCases {
		fibeInstance := NewFIBEInstance(10, tc.d)
		publicParams, err := fibeInstance.SetUp()
		if err != nil {
			t.Fatal("系统初始化失败:", err)
		}

		secretKey, err := fibeInstance.KeyGenerate(userAttributes)
		if err != nil {
			t.Fatal("密钥生成失败:", err)
		}

		ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
		if err != nil {
			t.Fatal("加密失败:", err)
		}

		decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext)
		if err != nil {
			t.Fatal("解密失败:", err)
		}

		matched := decryptedMessage.Message == message.Message
		if matched != tc.shouldMatch {
			t.Fatalf("%s - 实际结果与预期不符", tc.description)
		}

		fmt.Printf("✓ %s\n", tc.description)
	}
}

// TestFIBE7 - 大属性集测试：测试较大的属性空间
func TestFIBE7(t *testing.T) {
	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal("随机消息生成失败:", err)
	}
	message := &FIBEMessage{Message: *m}

	// 大属性集：20个属性
	userAttributes := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	messageAttributes := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30}

	// n=50, d=10：需要至少10个属性匹配
	fibeInstance := NewFIBEInstance(50, 10)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	secretKey, err := fibeInstance.KeyGenerate(userAttributes)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext)
	if err != nil {
		t.Fatal("解密失败:", err)
	}

	if decryptedMessage.Message != message.Message {
		t.Fatal("解密消息与原始消息不匹配")
	}

	fmt.Println("✓ 大属性集测试通过：20个属性，10个重叠")
}

// TestFIBE8 - 单属性测试：最小属性集（d=1）
func TestFIBE8(t *testing.T) {
	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal("随机消息生成失败:", err)
	}
	message := &FIBEMessage{Message: *m}

	userAttributes := []int{1}
	messageAttributes := []int{1}

	// n=5, d=1：只需1个属性匹配
	fibeInstance := NewFIBEInstance(5, 1)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	secretKey, err := fibeInstance.KeyGenerate(userAttributes)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}

	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext)
	if err != nil {
		t.Fatal("解密失败:", err)
	}

	if decryptedMessage.Message != message.Message {
		t.Fatal("解密消息与原始消息不匹配")
	}

	fmt.Println("✓ 单属性测试通过：d=1，单个属性匹配")
}

// TestFIBE9 - 属性顺序无关测试：不同顺序的属性集应产生相同结果
func TestFIBE9(t *testing.T) {
	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal("随机消息生成失败:", err)
	}
	fmt.Println("原始消息:", *m)
	message := &FIBEMessage{Message: *m}

	// 相同属性，不同顺序
	userAttributes1 := []int{1, 2, 3, 4, 5}
	userAttributes2 := []int{5, 4, 3, 2, 1}
	messageAttributes := []int{3, 1, 5, 2, 4}

	fibeInstance := NewFIBEInstance(10, 3)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}

	// 第一组密钥
	secretKey1, err := fibeInstance.KeyGenerate(userAttributes1)
	if err != nil {
		t.Fatal("密钥1生成失败:", err)
	}

	// 第二组密钥（不同顺序）
	secretKey2, err := fibeInstance.KeyGenerate(userAttributes2)
	if err != nil {
		t.Fatal("密钥2生成失败:", err)
	}

	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	// 两个密钥都应该能成功解密
	decryptedMessage1, err := fibeInstance.Decrypt(secretKey1, ciphertext)
	if err != nil {
		t.Fatal("密钥1解密失败:", err)
	}
	fmt.Println("密钥1解密消息:", decryptedMessage1.Message)

	decryptedMessage2, err := fibeInstance.Decrypt(secretKey2, ciphertext)
	if err != nil {
		t.Fatal("密钥2解密失败:", err)
	}
	fmt.Println("密钥2解密消息:", decryptedMessage2.Message)

	if decryptedMessage1.Message != message.Message {
		t.Fatal("密钥1的解密消息与原始消息不匹配")
	}

	if decryptedMessage2.Message != message.Message {
		t.Fatal("密钥2的解密消息与原始消息不匹配")
	}

	fmt.Println("✓ 属性顺序无关测试通过：不同顺序产生相同结果")
}

// TestFIBE10 - 性能基准测试：测量加密和解密性能
func TestFIBE10(t *testing.T) {
	if testing.Short() {
		t.Skip("跳过性能测试")
	}

	m, _ := new(bn254.GT).SetRandom()
	message := &FIBEMessage{Message: *m}

	userAttributes := []int{1, 2, 3, 4, 5}
	messageAttributes := []int{1, 2, 3, 4, 5}

	fibeInstance := NewFIBEInstance(10, 3)
	publicParams, _ := fibeInstance.SetUp()
	secretKey, _ := fibeInstance.KeyGenerate(userAttributes)

	iterations := 10
	fmt.Printf("\n性能测试（%d次迭代）:\n", iterations)

	// 测试加密性能
	for i := 0; i < iterations; i++ {
		_, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
		if err != nil {
			t.Fatal("加密失败:", err)
		}
	}
	fmt.Printf("✓ 完成%d次加密操作\n", iterations)

	// 测试解密性能
	ciphertext, _ := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	for i := 0; i < iterations; i++ {
		_, err := fibeInstance.Decrypt(secretKey, ciphertext)
		if err != nil {
			t.Fatal("解密失败:", err)
		}
	}
	fmt.Printf("✓ 完成%d次解密操作\n", iterations)
}
