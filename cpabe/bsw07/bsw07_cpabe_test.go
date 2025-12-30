package bsw07

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GoPairingBasedCryptography/access/tree"
	"testing"
)

// TestCPABEBasic 测试基本的加密解密流程
func TestCPABEBasic(t *testing.T) {
	fmt.Println("=== 测试1: 基本加密解密 ===")

	instance := &CPABEInstance{}

	// 1. Setup
	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}
	fmt.Println("✓ Setup 完成")

	// 2. 定义用户属性: {1, 2, 3}
	userAttr := &CPABEUserAttributes{
		Attributes: []fr.Element{
			fr.NewElement(1),
			fr.NewElement(2),
			fr.NewElement(3),
		},
	}

	// 3. 密钥生成
	usk, err := instance.KeyGenerate(userAttr, msk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}
	fmt.Printf("✓ 为用户生成密钥，属性集合: {1, 2, 3}\n")

	// 4. 创建访问策略: (1 AND 2) OR 3 (threshold gate: 2-of-3)
	accessPolicy := &CPABEAccessPolicy{
		accessTree: tree.NewThresholdNode(2,
			tree.NewLeafNode(fr.NewElement(1)),
			tree.NewLeafNode(fr.NewElement(2)),
			tree.NewLeafNode(fr.NewElement(3)),
		),
	}

	// 5. 生成随机消息
	_, _, g1, g2 := bn254.Generators()
	messageGT, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		t.Fatalf("Pairing failed: %v", err)
	}
	message := &CPABEMessage{Message: messageGT}
	fmt.Println("✓ 生成随机消息")
	fmt.Println(messageGT)

	// 6. 加密
	ciphertext, err := instance.Encrypt(message, accessPolicy, pp)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Println("✓ 加密完成")

	// 7. 解密
	decryptedMessage, err := instance.Decrypt(ciphertext, usk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}
	fmt.Println("✓ 解密完成")

	fmt.Println(decryptedMessage.Message)

	// 8. 验证
	if !message.Message.Equal(&decryptedMessage.Message) {
		t.Fatalf("❌ 解密失败: 消息不匹配")
	}
	fmt.Println("✅ 测试通过: 解密消息与原始消息匹配")
}

// TestCPABEAttributeMismatch 测试属性不匹配的情况
func TestCPABEAttributeMismatch(t *testing.T) {
	fmt.Println("\n=== 测试2: 属性不匹配 ===")

	instance := &CPABEInstance{}

	// Setup
	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 用户属性: {4, 5, 6} - 与访问策略不匹配
	userAttr := &CPABEUserAttributes{
		Attributes: []fr.Element{
			fr.NewElement(4),
			fr.NewElement(5),
			fr.NewElement(6),
		},
	}

	usk, err := instance.KeyGenerate(userAttr, msk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}
	fmt.Printf("✓ 用户属性: {4, 5, 6}\n")

	// 访问策略需要: 2-of-{1, 2, 3}
	accessPolicy := &CPABEAccessPolicy{
		accessTree: tree.NewThresholdNode(2,
			tree.NewLeafNode(fr.NewElement(1)),
			tree.NewLeafNode(fr.NewElement(2)),
			tree.NewLeafNode(fr.NewElement(3)),
		),
	}
	fmt.Printf("✓ 访问策略: 2-of-{1, 2, 3}\n")

	// 生成消息并加密
	_, _, g1, g2 := bn254.Generators()
	messageGT, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	message := &CPABEMessage{Message: messageGT}

	ciphertext, err := instance.Encrypt(message, accessPolicy, pp)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 尝试解密 - 应该失败或返回错误结果
	decryptedMessage, err := instance.Decrypt(ciphertext, usk)
	if err != nil {
		fmt.Println("✓ 解密失败（符合预期）:", err)
		return
	}

	// 如果解密"成功"，验证结果应该不匹配
	if message.Message.Equal(&decryptedMessage.Message) {
		t.Fatalf("❌ 错误: 属性不匹配但解密成功")
	}
	fmt.Println("✅ 测试通过: 属性不匹配时无法正确解密")
}

// TestCPABEComplexAccessTree 测试复杂访问树
func TestCPABEComplexAccessTree(t *testing.T) {
	fmt.Println("\n=== 测试3: 复杂访问树 ===")

	instance := &CPABEInstance{}

	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 用户属性: {1, 2, 3, 4}
	userAttr := &CPABEUserAttributes{
		Attributes: []fr.Element{
			fr.NewElement(1),
			fr.NewElement(2),
			fr.NewElement(3),
			fr.NewElement(4),
		},
	}

	usk, err := instance.KeyGenerate(userAttr, msk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}
	fmt.Printf("✓ 用户属性: {1, 2, 3, 4}\n")

	// 创建复杂访问树: 根节点需要3个子节点满足
	// 子树1: 1-of-{1, 2}
	// 子树2: 1-of-{3, 4}
	// 子树3: 叶子节点 5
	subtree1 := tree.NewThresholdNode(1,
		tree.NewLeafNode(fr.NewElement(1)),
		tree.NewLeafNode(fr.NewElement(2)),
	)

	subtree2 := tree.NewThresholdNode(1,
		tree.NewLeafNode(fr.NewElement(3)),
		tree.NewLeafNode(fr.NewElement(4)),
	)

	accessPolicy := &CPABEAccessPolicy{
		accessTree: tree.NewThresholdNode(3,
			subtree1,
			subtree2,
			tree.NewLeafNode(fr.NewElement(5)),
		),
	}
	fmt.Println("✓ 访问策略: 3-of-{(1 OR 2), (3 OR 4), 5}")

	// 生成消息并加密
	_, _, g1, g2 := bn254.Generators()
	messageGT, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	message := &CPABEMessage{Message: messageGT}

	ciphertext, err := instance.Encrypt(message, accessPolicy, pp)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}
	fmt.Println("✓ 加密完成")

	// 解密 - 用户有 {1, 2, 3, 4} 但缺少 5，应该失败
	decryptedMessage, err := instance.Decrypt(ciphertext, usk)
	if err != nil {
		fmt.Println("✓ 解密失败（符合预期）: 缺少属性5")
		return
	}

	if message.Message.Equal(&decryptedMessage.Message) {
		t.Fatalf("❌ 错误: 缺少必需属性但解密成功")
	}
	fmt.Println("✅ 测试通过: 缺少必需属性时无法正确解密")
}

// TestCPABEMinimalThreshold 测试最小阈值 (1-of-n)
func TestCPABEMinimalThreshold(t *testing.T) {
	fmt.Println("\n=== 测试4: 最小阈值 (1-of-3) ===")

	instance := &CPABEInstance{}

	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 用户只有属性 3
	userAttr := &CPABEUserAttributes{
		Attributes: []fr.Element{fr.NewElement(3)},
	}

	usk, err := instance.KeyGenerate(userAttr, msk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}
	fmt.Printf("✓ 用户属性: {3}\n")

	// 访问策略: 1-of-{1, 2, 3} (只需满足一个)
	accessPolicy := &CPABEAccessPolicy{
		accessTree: tree.NewThresholdNode(1,
			tree.NewLeafNode(fr.NewElement(1)),
			tree.NewLeafNode(fr.NewElement(2)),
			tree.NewLeafNode(fr.NewElement(3)),
		),
	}
	fmt.Println("✓ 访问策略: 1-of-{1, 2, 3}")

	// 生成消息并加密
	_, _, g1, g2 := bn254.Generators()
	messageGT, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	message := &CPABEMessage{Message: messageGT}

	ciphertext, err := instance.Encrypt(message, accessPolicy, pp)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 解密
	decryptedMessage, err := instance.Decrypt(ciphertext, usk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 验证
	if !message.Message.Equal(&decryptedMessage.Message) {
		t.Fatalf("❌ 解密失败: 消息不匹配")
	}
	fmt.Println("✅ 测试通过: 最小阈值解密成功")
}

// TestCPABEMaximalThreshold 测试最大阈值 (n-of-n)
func TestCPABEMaximalThreshold(t *testing.T) {
	fmt.Println("\n=== 测试5: 最大阈值 (3-of-3, AND gate) ===")

	instance := &CPABEInstance{}

	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 用户拥有所有三个属性
	userAttr := &CPABEUserAttributes{
		Attributes: []fr.Element{
			fr.NewElement(1),
			fr.NewElement(2),
			fr.NewElement(3),
		},
	}

	usk, err := instance.KeyGenerate(userAttr, msk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}
	fmt.Printf("✓ 用户属性: {1, 2, 3}\n")

	// 访问策略: 3-of-{1, 2, 3} (必须全部满足)
	accessPolicy := &CPABEAccessPolicy{
		accessTree: tree.NewThresholdNode(3,
			tree.NewLeafNode(fr.NewElement(1)),
			tree.NewLeafNode(fr.NewElement(2)),
			tree.NewLeafNode(fr.NewElement(3)),
		),
	}
	fmt.Println("✓ 访问策略: 3-of-{1, 2, 3} (AND)")

	// 生成消息并加密
	_, _, g1, g2 := bn254.Generators()
	messageGT, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	message := &CPABEMessage{Message: messageGT}

	ciphertext, err := instance.Encrypt(message, accessPolicy, pp)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 解密
	decryptedMessage, err := instance.Decrypt(ciphertext, usk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 验证
	if !message.Message.Equal(&decryptedMessage.Message) {
		t.Fatalf("❌ 解密失败: 消息不匹配")
	}
	fmt.Println("✅ 测试通过: 最大阈值解密成功")
}

// TestCPABEPartialMatch 测试部分属性匹配
func TestCPABEPartialMatch(t *testing.T) {
	fmt.Println("\n=== 测试6: 部分属性匹配 ===")

	instance := &CPABEInstance{}

	pp, msk, err := instance.SetUp()
	if err != nil {
		t.Fatalf("Setup failed: %v", err)
	}

	// 用户只有属性 {1, 2}
	userAttr := &CPABEUserAttributes{
		Attributes: []fr.Element{
			fr.NewElement(1),
			fr.NewElement(2),
		},
	}

	usk, err := instance.KeyGenerate(userAttr, msk)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}
	fmt.Printf("✓ 用户属性: {1, 2}\n")

	// 访问策略: 2-of-{1, 2, 3}
	accessPolicy := &CPABEAccessPolicy{
		accessTree: tree.NewThresholdNode(2,
			tree.NewLeafNode(fr.NewElement(1)),
			tree.NewLeafNode(fr.NewElement(2)),
			tree.NewLeafNode(fr.NewElement(3)),
		),
	}
	fmt.Println("✓ 访问策略: 2-of-{1, 2, 3}")

	// 生成消息并加密
	_, _, g1, g2 := bn254.Generators()
	messageGT, _ := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	message := &CPABEMessage{Message: messageGT}

	ciphertext, err := instance.Encrypt(message, accessPolicy, pp)
	if err != nil {
		t.Fatalf("Encrypt failed: %v", err)
	}

	// 解密 - 应该成功，因为用户有 {1, 2}，满足 2-of-3
	decryptedMessage, err := instance.Decrypt(ciphertext, usk)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// 验证
	if !message.Message.Equal(&decryptedMessage.Message) {
		t.Fatalf("❌ 解密失败: 消息不匹配")
	}
	fmt.Println("✅ 测试通过: 部分属性匹配解密成功")
}

// 运行所有测试的辅助函数
func TestAll(t *testing.T) {
	t.Run("BasicEncryptDecrypt", TestCPABEBasic)
	t.Run("AttributeMismatch", TestCPABEAttributeMismatch)
	t.Run("ComplexAccessTree", TestCPABEComplexAccessTree)
	t.Run("MinimalThreshold", TestCPABEMinimalThreshold)
	t.Run("MaximalThreshold", TestCPABEMaximalThreshold)
	t.Run("PartialMatch", TestCPABEPartialMatch)
}
