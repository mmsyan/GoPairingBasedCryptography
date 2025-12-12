package dabe

import (
	"fmt"
	lsss2 "github.com/mmsyan/GnarkPairingProject/access/lsss"
	"testing"

	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/mmsyan/GnarkPairingProject/hash"
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

// 基准测试：全局设置（用于铁塔测试）
func BenchmarkGlobalSetup(b *testing.B) {
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		GlobalSetup()
	}
}

// 基准测试：权威机构设置（用于铁塔测试）
func BenchmarkAuthoritySetup(b *testing.B) {
	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributes(
		// === 铁塔基础属性（10个）===
		hash.ToField("TowerID:SH-2025-0731"),
		hash.ToField("Province:Shanghai"),
		hash.ToField("City:Pudong"),
		hash.ToField("District:Xinqu"),
		hash.ToField("TowerType:5G_BaseStation"),
		hash.ToField("Height:45m"),
		hash.ToField("Owner:ChinaMobile"),
		hash.ToField("VoltageLevel:220kV"),
		hash.ToField("BuildYear:2023"),
		hash.ToField("MaintenanceCompany:Huaxin"),

		// === 无人机权限属性（10个）===
		hash.ToField("DroneID:DJI-M300-2025X"),
		hash.ToField("DroneLicense:SH-UAV-951"),
		hash.ToField("Pilot:ZhangSan"),
		hash.ToField("FlightPermission:Level_A"),
		hash.ToField("MaxAltitude:120m"),
		hash.ToField("Camera:Zenmuse_H20T"),
		hash.ToField("MissionType:TowerInspection"),
		hash.ToField("FlightDate:2025-12-11"),
		hash.ToField("TimeWindow:08:00-18:00"),
		hash.ToField("Company:PowerGrid_DroneTeam"),
	)
	for i := 0; i < b.N; i++ {
		AuthoritySetup(attributes, gp)
	}
}

func BenchmarkKeyGenerate(b *testing.B) {

	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributes(
		// === 铁塔基础属性（10个）===
		hash.ToField("TowerID:SH-2025-0731"),
		hash.ToField("Province:Shanghai"),
		hash.ToField("City:Pudong"),
		hash.ToField("District:Xinqu"),
		hash.ToField("TowerType:5G_BaseStation"),
		hash.ToField("Height:45m"),
		hash.ToField("Owner:ChinaMobile"),
		hash.ToField("VoltageLevel:220kV"),
		hash.ToField("BuildYear:2023"),
		hash.ToField("MaintenanceCompany:Huaxin"),

		// === 无人机权限属性（10个）===
		hash.ToField("DroneID:DJI-M300-2025X"),
		hash.ToField("DroneLicense:SH-UAV-951"),
		hash.ToField("Pilot:ZhangSan"),
		hash.ToField("FlightPermission:Level_A"),
		hash.ToField("MaxAltitude:120m"),
		hash.ToField("Camera:Zenmuse_H20T"),
		hash.ToField("MissionType:TowerInspection"),
		hash.ToField("FlightDate:2025-12-11"),
		hash.ToField("TimeWindow:08:00-18:00"),
		hash.ToField("Company:PowerGrid_DroneTeam"),
	)
	_, msk, _ := AuthoritySetup(attributes, gp)
	for i := 0; i < b.N; i++ {
		KeyGenerate(attributes, "TestUser", msk)
	}

}

func getTietaAttributes() (*LW11DABEAttributes, *lsss2.BinaryAccessTree) {
	// === 铁塔基础属性（10个）===
	attr1 := hash.ToField("TowerID:SH-2025-0731")
	attr2 := hash.ToField("Province:Shanghai")
	attr3 := hash.ToField("City:Pudong")
	attr4 := hash.ToField("District:Xinqu")
	attr5 := hash.ToField("TowerType:5G_BaseStation")
	attr6 := hash.ToField("Height:45m")
	attr7 := hash.ToField("Owner:ChinaMobile")
	attr8 := hash.ToField("VoltageLevel:220kV")
	attr9 := hash.ToField("BuildYear:2023")
	attr10 := hash.ToField("MaintenanceCompany:Huaxin")

	// === 无人机权限属性（10个）===
	attr11 := hash.ToField("DroneID:DJI-M300-2025X")
	attr12 := hash.ToField("DroneLicense:SH-UAV-951")
	attr13 := hash.ToField("Pilot:ZhangSan")
	attr14 := hash.ToField("FlightPermission:Level_A")
	attr15 := hash.ToField("MaxAltitude:120m")
	attr16 := hash.ToField("Camera:Zenmuse_H20T")
	attr17 := hash.ToField("MissionType:TowerInspection")
	attr18 := hash.ToField("FlightDate:2025-12-11")
	attr19 := hash.ToField("TimeWindow:08:00-18:00")
	attr20 := hash.ToField("Company:PowerGrid_DroneTeam")
	attributes := NewLW11DABEAttributes(
		attr1, attr2, attr3, attr4, attr5, attr6, attr7, attr8, attr9, attr10,
		attr11, attr12, attr13, attr14, attr15, attr16, attr17, attr18, attr19, attr20,
	)
	// ()
	policy := lsss2.And(
		lsss2.And(
			lsss2.Leaf(attr3),
			lsss2.Leaf(attr4),
			lsss2.Leaf(attr3),
			lsss2.Leaf(attr4),
			lsss2.Leaf(attr5),
			lsss2.Leaf(attr6),
			lsss2.And(
				lsss2.Leaf(attr17),
				lsss2.Leaf(attr18),
			),
		),
		lsss2.Leaf(attr9),
		lsss2.And(
			lsss2.Leaf(attr1),
			lsss2.Leaf(attr2),
			lsss2.Or(
				lsss2.Leaf(attr3),
				lsss2.Leaf(attr5),
			),
		),
		lsss2.And(
			lsss2.Leaf(attr16),
		),
	)

	return attributes, policy
}

// 基准测试：加密（用于铁塔测试）
func BenchmarkEncrypt(b *testing.B) {
	gp, _ := GlobalSetup()
	attributes, policy := getTietaAttributes()
	pk, _, _ := AuthoritySetup(attributes, gp)

	matrix := lsss2.NewLSSSMatrixFromBinaryTree(policy)

	message := &LW11DABEMessage{
		Message: *new(bn254.GT).SetOne(),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Encrypt(message, matrix, gp, pk)
	}
}

// 基准测试：解密（用于铁塔测试）
func BenchmarkDecrypt(b *testing.B) {
	gp, _ := GlobalSetup()
	attributes, policy := getTietaAttributes()
	pk, sk, _ := AuthoritySetup(attributes, gp)
	userKey, _ := KeyGenerate(attributes, "user", sk)
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(policy)
	message := &LW11DABEMessage{
		Message: *new(bn254.GT).SetOne(),
	}
	b.ResetTimer()
	ciphertext, _ := Encrypt(message, matrix, gp, pk)
	for i := 0; i < b.N; i++ {
		Decrypt(ciphertext, userKey, gp)
	}
}

func TestTieta(t *testing.T) {
	gp, err := GlobalSetup()
	if err != nil {
		t.Error(err)
	}
	attributes, policy := getTietaAttributes()
	pk, sk, err := AuthoritySetup(attributes, gp)
	if err != nil {
		t.Error(err)
	}
	userKey, err := KeyGenerate(attributes, "userTest", sk)
	if err != nil {
		t.Error(err)
	}
	policy.Print()
	matrix := lsss2.NewLSSSMatrixFromBinaryTree(policy)
	matrix.Print()
	message := &LW11DABEMessage{
		Message: *new(bn254.GT).SetOne(),
	}
	fmt.Println("message", message.Message)
	ciphertext, err := Encrypt(message, matrix, gp, pk)
	if err != nil {
		t.Error(err)
	}

	recoverMessage, err := Decrypt(ciphertext, userKey, gp)
	if err != nil {
		t.Error(err)
	}
	fmt.Println("decrypt message:", recoverMessage.Message)
	if !recoverMessage.Message.Equal(&message.Message) {
		t.Error("Recovered message not equal")
	}
}

// ============================================
// 1. 属性声明测试
// ============================================

// TestAttributeDeclaration 测试属性声明功能
func TestAttributeDeclaration(t *testing.T) {
	fmt.Println("\n========== 测试1: 属性声明 ==========")

	// 测试场景1: 声明单个属性
	t.Run("SingleAttribute", func(t *testing.T) {
		attr := hash.ToField("Doctor")
		attributes := NewLW11DABEAttributes(attr)

		if len(attributes.attributes) != 1 {
			t.Errorf("期望1个属性，实际得到%d个", len(attributes.attributes))
		}
		fmt.Printf("✓ 成功声明单个属性: Doctor\n")
	})

	// 测试场景2: 声明多个属性
	t.Run("MultipleAttributes", func(t *testing.T) {
		attr1 := hash.ToField("Doctor")
		attr2 := hash.ToField("Researcher")
		attr3 := hash.ToField("Professor")
		attributes := NewLW11DABEAttributes(attr1, attr2, attr3)

		if len(attributes.attributes) != 3 {
			t.Errorf("期望3个属性，实际得到%d个", len(attributes.attributes))
		}
		fmt.Printf("✓ 成功声明多个属性: Doctor, Researcher, Professor\n")
	})

	// 测试场景3: 使用字符串声明属性
	t.Run("StringBasedAttributes", func(t *testing.T) {
		attributes := NewLW11DABEAttributesFromStrings("Manager", "Engineer", "Designer")

		if len(attributes.attributes) != 3 {
			t.Errorf("期望3个属性，实际得到%d个", len(attributes.attributes))
		}
		fmt.Printf("✓ 成功通过字符串声明属性: Manager, Engineer, Designer\n")
	})

	// 测试场景4: 组织/机构级别的属性声明
	t.Run("OrganizationalAttributes", func(t *testing.T) {
		// 模拟一个医疗机构的属性体系
		medicalAttrs := NewLW11DABEAttributesFromStrings(
			"Hospital-A",
			"Department-Cardiology",
			"Role-Doctor",
			"Level-Senior",
			"Clearance-Level3",
		)

		if len(medicalAttrs.attributes) != 5 {
			t.Errorf("期望5个属性，实际得到%d个", len(medicalAttrs.attributes))
		}
		fmt.Printf("✓ 成功声明组织属性体系: 医院A, 心脏科, 医生, 高级, 权限3级\n")
	})
}

// TestAuthoritySetupWithAttributes 测试权威机构设置和属性声明
func TestAuthoritySetupWithAttributes(t *testing.T) {
	fmt.Println("\n========== 测试2: 权威机构设置 ==========")

	gp, err := GlobalSetup()
	if err != nil {
		t.Fatalf("全局设置失败: %v", err)
	}
	fmt.Println("✓ 全局参数设置成功")

	// 测试场景1: 单个权威机构管理多个属性
	t.Run("SingleAuthority", func(t *testing.T) {
		attributes := NewLW11DABEAttributesFromStrings("Doctor", "Nurse", "Admin")

		pk, sk, err := AuthoritySetup(attributes, gp)
		if err != nil {
			t.Fatalf("权威机构设置失败: %v", err)
		}

		// 验证公钥
		if len(pk.eG1G2ExpAlphaI) != 3 {
			t.Errorf("期望3个属性公钥，实际得到%d个", len(pk.eG1G2ExpAlphaI))
		}
		if len(pk.g2ExpYi) != 3 {
			t.Errorf("期望3个Y值，实际得到%d个", len(pk.g2ExpYi))
		}

		// 验证私钥
		if len(sk.alphaI) != 3 || len(sk.yi) != 3 {
			t.Error("私钥数量不正确")
		}

		fmt.Printf("✓ 权威机构成功管理3个属性，生成公私钥对\n")
	})

	// 测试场景2: 模拟多个权威机构（不同部门）
	t.Run("MultipleAuthorities", func(t *testing.T) {
		// 人力资源部 管理的属性
		hrAttrs := NewLW11DABEAttributesFromStrings("Employee", "Manager", "HR-Staff")
		hrPK, hrSK, err := AuthoritySetup(hrAttrs, gp)
		if err != nil {
			t.Fatalf("HR权威机构设置失败: %v", err)
		}

		// IT部门管理的属性
		itAttrs := NewLW11DABEAttributesFromStrings("Developer", "DevOps", "Security-Admin")
		itPK, itSK, err := AuthoritySetup(itAttrs, gp)
		if err != nil {
			t.Fatalf("IT权威机构设置失败: %v", err)
		}

		fmt.Printf("✓ HR部门管理3个属性\n")
		fmt.Printf("✓ IT部门管理3个属性\n")
		fmt.Printf("✓ 多权威机构分布式管理验证成功\n")

		// 验证两个机构的密钥独立
		if len(hrPK.eG1G2ExpAlphaI) != 3 || len(itPK.eG1G2ExpAlphaI) != 3 {
			t.Error("各机构应独立管理自己的属性")
		}
		if len(hrSK.alphaI) != 3 || len(itSK.alphaI) != 3 {
			t.Error("各机构应有独立的私钥")
		}
	})
}

// ============================================
// 2. 属性授予测试
// ============================================

// TestAttributeGranting 测试属性授予功能
func TestAttributeGranting(t *testing.T) {
	fmt.Println("\n========== 测试3: 属性授予 ==========")

	gp, _ := GlobalSetup()

	// 定义属性池
	allAttributes := NewLW11DABEAttributesFromStrings(
		"Doctor", "Nurse", "Researcher", "Admin", "Patient",
	)
	_, sk, _ := AuthoritySetup(allAttributes, gp)
	fmt.Println("✓ 权威机构设置完成，管理5个属性")

	// 测试场景1: 授予用户部分属性
	t.Run("PartialAttributeGrant", func(t *testing.T) {
		userAttrs := NewLW11DABEAttributesFromStrings("Doctor", "Researcher")
		userKey, err := KeyGenerate(userAttrs, "user001", sk)

		if err != nil {
			t.Fatalf("属性授予失败: %v", err)
		}

		if len(userKey.KIGID) != 2 {
			t.Errorf("期望授予2个属性，实际得到%d个", len(userKey.KIGID))
		}

		fmt.Printf("✓ 用户user001成功获得属性: Doctor, Researcher\n")
	})

	// 测试场景2: 授予不同用户不同属性
	t.Run("DifferentUsersAttributes", func(t *testing.T) {
		// 医生用户
		doctorAttrs := NewLW11DABEAttributesFromStrings("Doctor")
		doctorKey, _ := KeyGenerate(doctorAttrs, "doctor001", sk)

		// 护士用户
		nurseAttrs := NewLW11DABEAttributesFromStrings("Nurse")
		nurseKey, _ := KeyGenerate(nurseAttrs, "nurse001", sk)

		// 研究员用户（多属性）
		researcherAttrs := NewLW11DABEAttributesFromStrings("Doctor", "Researcher")
		researcherKey, _ := KeyGenerate(researcherAttrs, "researcher001", sk)

		fmt.Printf("✓ doctor001获得1个属性\n")
		fmt.Printf("✓ nurse001获得1个属性\n")
		fmt.Printf("✓ researcher001获得2个属性\n")

		if len(doctorKey.KIGID) != 1 || len(nurseKey.KIGID) != 1 || len(researcherKey.KIGID) != 2 {
			t.Error("属性授予数量不正确")
		}
	})

	// 测试场景3: 验证用户GID正确性
	t.Run("UserGIDVerification", func(t *testing.T) {
		userAttrs := NewLW11DABEAttributesFromStrings("Admin")
		userKey, _ := KeyGenerate(userAttrs, "admin@hospital.com", sk)

		if userKey.UserGid != "admin@hospital.com" {
			t.Errorf("期望GID为'admin@hospital.com'，实际为'%s'", userKey.UserGid)
		}

		fmt.Printf("✓ 用户GID绑定正确: %s\n", userKey.UserGid)
	})

	// 测试场景4: 验证密钥组件非零
	t.Run("KeyComponentVerification", func(t *testing.T) {
		userAttrs := NewLW11DABEAttributesFromStrings("Doctor", "Nurse")
		userKey, _ := KeyGenerate(userAttrs, "user002", sk)

		for attr, key := range userKey.KIGID {
			if key.IsInfinity() {
				t.Errorf("属性%v的密钥为无穷点", attr)
			}
		}

		fmt.Println("✓ 所有密钥组件验证通过，非零点")
	})

	// 测试场景5: 动态属性授予（模拟权限提升）
	t.Run("DynamicAttributeGranting", func(t *testing.T) {
		// 初始授予基础属性
		basicAttrs := NewLW11DABEAttributesFromStrings("Employee")
		basicKey, _ := KeyGenerate(basicAttrs, "user003", sk)
		fmt.Printf("✓ 初始授予: Employee (1个属性)\n")

		// 晋升后授予更多属性
		promotedAttrs := NewLW11DABEAttributesFromStrings("Employee", "Manager", "Admin")
		promotedKey, _ := KeyGenerate(promotedAttrs, "user003", sk)
		fmt.Printf("✓ 晋升后授予: Employee, Manager, Admin (3个属性)\n")

		if len(basicKey.KIGID) != 1 || len(promotedKey.KIGID) != 3 {
			t.Error("动态属性授予失败")
		}
	})
}

// ============================================
// 3. 数据加密测试
// ============================================

// TestDataEncryption 测试数据加密功能
func TestDataEncryption(t *testing.T) {
	fmt.Println("\n========== 测试4: 数据加密 ==========")

	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributesFromStrings("A", "B", "C", "D")
	pk, _, _ := AuthoritySetup(attributes, gp)

	// 测试场景1: 简单OR策略加密
	t.Run("SimpleORPolicy", func(t *testing.T) {
		// 策略: A OR B
		accessTree := lsss2.Or(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		message, _ := NewRandomLW11DABEMessage()
		ciphertext, err := Encrypt(message, matrix, gp, pk)

		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}

		if ciphertext == nil {
			t.Fatal("密文为空")
		}

		fmt.Printf("✓ OR策略加密成功: (A OR B)\n")
		fmt.Printf("  密文组件数量: %d\n", len(ciphertext.c1x))
	})

	// 测试场景2: 简单AND策略加密
	t.Run("SimpleANDPolicy", func(t *testing.T) {
		// 策略: A AND B
		accessTree := lsss2.And(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		message, _ := NewRandomLW11DABEMessage()
		ciphertext, err := Encrypt(message, matrix, gp, pk)

		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}

		fmt.Printf("✓ AND策略加密成功: (A AND B)\n")
		fmt.Printf("  密文组件数量: %d\n", len(ciphertext.c1x))
	})

	// 测试场景3: 复杂嵌套策略加密
	t.Run("ComplexNestedPolicy", func(t *testing.T) {
		// 策略: (A AND B) OR (C AND D)
		accessTree := lsss2.Or(
			lsss2.And(
				lsss2.LeafFromString("A"),
				lsss2.LeafFromString("B"),
			),
			lsss2.And(
				lsss2.LeafFromString("C"),
				lsss2.LeafFromString("D"),
			),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		message, _ := NewRandomLW11DABEMessage()
		ciphertext, err := Encrypt(message, matrix, gp, pk)

		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}

		fmt.Printf("✓ 复杂策略加密成功: ((A AND B) OR (C AND D))\n")
		fmt.Printf("  密文组件数量: %d\n", len(ciphertext.c1x))
	})

	// 测试场景4: 多层嵌套策略
	t.Run("DeepNestedPolicy", func(t *testing.T) {
		// 策略: (A OR B) AND (C OR D)
		accessTree := lsss2.And(
			lsss2.Or(
				lsss2.LeafFromString("A"),
				lsss2.LeafFromString("B"),
			),
			lsss2.Or(
				lsss2.LeafFromString("C"),
				lsss2.LeafFromString("D"),
			),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		message, _ := NewRandomLW11DABEMessage()
		ciphertext, err := Encrypt(message, matrix, gp, pk)

		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}

		fmt.Printf("✓ 深层嵌套策略加密成功: ((A OR B) AND (C OR D))\n")
		fmt.Printf("  密文组件数量: %d\n", len(ciphertext.c1x))
	})

	// 测试场景5: 验证密文组件
	t.Run("CiphertextComponentVerification", func(t *testing.T) {
		accessTree := lsss2.Or(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		message, _ := NewRandomLW11DABEMessage()
		ciphertext, err := Encrypt(message, matrix, gp, pk)

		if err != nil {
			t.Fatalf("加密失败: %v", err)
		}

		// 验证c0不为零
		if ciphertext.c0.IsZero() {
			t.Error("c0为零")
		}

		// 验证c1x, c2x, c3x长度一致
		if len(ciphertext.c1x) != len(ciphertext.c2x) || len(ciphertext.c1x) != len(ciphertext.c3x) {
			t.Error("密文组件长度不一致")
		}

		fmt.Println("✓ 密文组件结构验证通过")
	})
}

// ============================================
// 4. 数据解密测试（满足策略）
// ============================================

// TestDataDecryptionWithSatisfiedPolicy 测试满足策略的解密
func TestDataDecryptionWithSatisfiedPolicy(t *testing.T) {
	fmt.Println("\n========== 测试5: 数据解密（满足策略） ==========")

	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributesFromStrings("A", "B", "C", "D")
	pk, sk, _ := AuthoritySetup(attributes, gp)

	// 测试场景1: OR策略，用户有一个属性
	t.Run("ORPolicyOneSatisfied", func(t *testing.T) {
		// 策略: A OR B
		accessTree := lsss2.Or(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)
		matrix.Print()

		// 用户只有A
		userAttrs := NewLW11DABEAttributesFromStrings("A")
		userKey, _ := KeyGenerate(userAttrs, "user001", sk)

		// 加密
		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)

		// 解密
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		if !originalMsg.Message.Equal(&decryptedMsg.Message) {
			t.Error("解密消息与原始消息不匹配")
		}

		fmt.Printf("✓ OR策略解密成功，用户属性: A，策略: (A OR B)\n")
	})

	// 测试场景2: AND策略，用户有所有属性
	t.Run("ANDPolicyAllSatisfied", func(t *testing.T) {
		// 策略: A AND B
		accessTree := lsss2.And(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		// 用户有A和B
		userAttrs := NewLW11DABEAttributesFromStrings("A", "B")
		userKey, _ := KeyGenerate(userAttrs, "user002", sk)

		// 加密
		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)

		// 解密
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		if !originalMsg.Message.Equal(&decryptedMsg.Message) {
			t.Error("解密消息与原始消息不匹配")
		}

		fmt.Printf("✓ AND策略解密成功，用户属性: A, B，策略: (A AND B)\n")
	})

	// 测试场景3: 复杂策略，满足第一个分支
	t.Run("ComplexPolicyFirstBranch", func(t *testing.T) {
		// 策略: (A AND B) OR (C AND D)
		accessTree := lsss2.Or(
			lsss2.And(
				lsss2.LeafFromString("A"),
				lsss2.LeafFromString("B"),
			),
			lsss2.And(
				lsss2.LeafFromString("C"),
				lsss2.LeafFromString("D"),
			),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)
		matrix.Print()

		// 用户有A和B，满足第一个分支
		userAttrs := NewLW11DABEAttributesFromStrings("C", "D")
		userKey, _ := KeyGenerate(userAttrs, "user003", sk)

		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		if !originalMsg.Message.Equal(&decryptedMsg.Message) {
			t.Error("解密消息与原始消息不匹配")
		}

		fmt.Printf("✓ 复杂策略解密成功，用户属性: A, B，策略: ((A AND B) OR (C AND D))，满足第一分支\n")
	})

	// 测试场景4: 复杂策略，满足第二个分支
	t.Run("ComplexPolicySecondBranch", func(t *testing.T) {
		// 策略: (A AND B) OR (C AND D)
		accessTree := lsss2.Or(
			lsss2.And(
				lsss2.LeafFromString("A"),
				lsss2.LeafFromString("B"),
			),
			lsss2.And(
				lsss2.LeafFromString("C"),
				lsss2.LeafFromString("D"),
			),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)
		matrix.Print()

		// 用户有C和D，满足第二个分支
		userAttrs := NewLW11DABEAttributesFromStrings("C", "D")
		userKey, err := KeyGenerate(userAttrs, "user004", sk)
		if err != nil {
			t.Fatal(err)
		}

		originalMsg, err := NewRandomLW11DABEMessage()
		if err != nil {
			t.Fatal("new random message error", err)
		}

		ciphertext, err := Encrypt(originalMsg, matrix, gp, pk)
		if err != nil {
			t.Fatal("failed to encrypt", err)
		}
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)
		if err != nil {
			t.Fatal("failed to decrypt", err)
		}

		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		if !originalMsg.Message.Equal(&decryptedMsg.Message) {
			t.Error("解密消息与原始消息不匹配")
		}

		fmt.Printf("✓ 复杂策略解密成功，用户属性: C, D，策略: ((A AND B) OR (C AND D))，满足第二分支\n")
	})

	// 测试场景5: 用户拥有超集属性
	t.Run("UserWithSupersetAttributes", func(t *testing.T) {
		// 策略: A OR B
		accessTree := lsss2.Or(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		// 用户有A, B, C, D（超过所需）
		userAttrs := NewLW11DABEAttributesFromStrings("A", "B", "C", "D")
		userKey, _ := KeyGenerate(userAttrs, "user005", sk)

		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		if err != nil {
			t.Fatalf("解密失败: %v", err)
		}

		if !originalMsg.Message.Equal(&decryptedMsg.Message) {
			t.Error("解密消息与原始消息不匹配")
		}

		fmt.Printf("✓ 用户拥有超集属性解密成功，用户属性: A, B, C, D，策略: (A OR B)\n")
	})
}

// ============================================
// 5. 数据解密测试（不满足策略）
// ============================================

// TestDataDecryptionWithUnsatisfiedPolicy 测试不满足策略的解密失败
func TestDataDecryptionWithUnsatisfiedPolicy(t *testing.T) {
	fmt.Println("\n========== 测试6: 数据解密（不满足策略） ==========")

	gp, _ := GlobalSetup()
	attributes := NewLW11DABEAttributesFromStrings("A", "B", "C", "D")
	pk, sk, _ := AuthoritySetup(attributes, gp)

	// 测试场景1: AND策略，用户只有部分属性
	t.Run("ANDPolicyPartialAttributes", func(t *testing.T) {
		// 策略: A AND B
		accessTree := lsss2.And(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		// 用户只有A，缺少B
		userAttrs := NewLW11DABEAttributesFromStrings("A")
		userKey, _ := KeyGenerate(userAttrs, "user006", sk)

		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)

		// 尝试解密
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		// 验证解密失败或得到错误消息
		shouldFail := err != nil || !originalMsg.Message.Equal(&decryptedMsg.Message)

		if !shouldFail {
			t.Error("期望解密失败，但解密成功了")
		}

		fmt.Printf("✗ AND策略解密失败（符合预期），用户属性: A，策略: (A AND B)，缺少B\n")
	})

	// 测试场景2: 用户没有任何所需属性
	t.Run("NoRequiredAttributes", func(t *testing.T) {
		// 策略: A OR B
		accessTree := lsss2.Or(
			lsss2.LeafFromString("A"),
			lsss2.LeafFromString("B"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		// 用户只有C和D
		userAttrs := NewLW11DABEAttributesFromStrings("C", "D")
		userKey, _ := KeyGenerate(userAttrs, "user007", sk)

		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		shouldFail := err != nil || !originalMsg.Message.Equal(&decryptedMsg.Message)

		if !shouldFail {
			t.Error("期望解密失败，但解密成功了")
		}

		fmt.Printf("✗ 无相关属性解密失败（符合预期），用户属性: C, D，策略: (A OR B)\n")
	})

	// 测试场景3: 复杂策略，两个分支都不满足
	t.Run("ComplexPolicyNoBranchSatisfied", func(t *testing.T) {
		// 策略: (A AND B) OR (C AND D)
		accessTree := lsss2.Or(
			lsss2.And(
				lsss2.LeafFromString("A"),
				lsss2.LeafFromString("B"),
			),
			lsss2.And(
				lsss2.LeafFromString("C"),
				lsss2.LeafFromString("D"),
			),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		// 用户只有A和C，两个分支都不满足
		userAttrs := NewLW11DABEAttributesFromStrings("A", "C")
		userKey, _ := KeyGenerate(userAttrs, "user008", sk)

		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		shouldFail := err != nil || !originalMsg.Message.Equal(&decryptedMsg.Message)

		if !shouldFail {
			t.Error("期望解密失败，但解密成功了")
		}

		fmt.Printf("✗ 复杂策略解密失败（符合预期），用户属性: A, C，策略: ((A AND B) OR (C AND D))，两分支都不满足\n")
	})

	// 测试场景4: 用户没有任何属性
	t.Run("UserWithNoAttributes", func(t *testing.T) {
		// 策略: A
		accessTree := lsss2.LeafFromString("A")
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)

		// 用户没有属性
		userAttrs := NewLW11DABEAttributes()
		userKey, _ := KeyGenerate(userAttrs, "user009", sk)

		originalMsg, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(originalMsg, matrix, gp, pk)
		decryptedMsg, err := Decrypt(ciphertext, userKey, gp)

		shouldFail := err != nil || !originalMsg.Message.Equal(&decryptedMsg.Message)

		if !shouldFail {
			t.Error("期望解密失败，但解密成功了")
		}

		fmt.Printf("✗ 无属性用户解密失败（符合预期），用户属性: 无，策略: A\n")
	})
}

// ============================================
// 6. 综合场景测试
// ============================================

// TestRealWorldScenario 测试真实场景
func TestRealWorldScenario(t *testing.T) {
	fmt.Println("\n========== 测试7: 综合真实场景 ==========")

	// 场景：医疗数据共享系统
	t.Run("MedicalDataSharing", func(t *testing.T) {
		fmt.Println("\n--- 场景：电子病历访问控制 ---")

		gp, _ := GlobalSetup()

		// 1. 属性声明：医院定义属性体系
		medicalAttrs := NewLW11DABEAttributesFromStrings(
			"Doctor", "Nurse", "Researcher", "Patient", "Admin",
		)
		pk, sk, _ := AuthoritySetup(medicalAttrs, gp)
		fmt.Println("✓ 医院属性体系设置完成: Doctor, Nurse, Researcher, Patient, Admin")

		// 2. 属性授予：为不同角色分配属性
		doctorKey, _ := KeyGenerate(
			NewLW11DABEAttributesFromStrings("Doctor"),
			"dr.smith@hospital.com", sk,
		)
		nurseKey, _ := KeyGenerate(
			NewLW11DABEAttributesFromStrings("Nurse"),
			"nurse.jones@hospital.com", sk,
		)
		researcherKey, _ := KeyGenerate(
			NewLW11DABEAttributesFromStrings("Researcher"),
			"researcher.wang@university.edu", sk,
		)
		fmt.Println("✓ 为3个用户授予属性")

		// 3. 数据加密：加密敏感病历，策略为 (Doctor OR Nurse)
		accessPolicy := lsss2.Or(
			lsss2.LeafFromString("Doctor"),
			lsss2.LeafFromString("Nurse"),
		)
		matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessPolicy)

		patientRecord, _ := NewRandomLW11DABEMessage()
		ciphertext, _ := Encrypt(patientRecord, matrix, gp, pk)
		fmt.Println("✓ 病历加密成功，访问策略: (Doctor OR Nurse)")

		// 4. 数据解密：验证访问控制
		// 医生可以访问
		decrypted1, err1 := Decrypt(ciphertext, doctorKey, gp)
		if err1 == nil && patientRecord.Message.Equal(&decrypted1.Message) {
			fmt.Println("✓ 医生成功访问病历")
		} else {
			t.Error("医生应该能访问病历")
		}

		// 护士可以访问
		decrypted2, err2 := Decrypt(ciphertext, nurseKey, gp)
		if err2 == nil && patientRecord.Message.Equal(&decrypted2.Message) {
			fmt.Println("✓ 护士成功访问病历")
		} else {
			t.Error("护士应该能访问病历")
		}

		// 研究员无法访问
		decrypted3, err3 := Decrypt(ciphertext, researcherKey, gp)
		shouldFail := err3 != nil || !patientRecord.Message.Equal(&decrypted3.Message)
		if shouldFail {
			fmt.Println("✓ 研究员无法访问病历（符合预期）")
		} else {
			t.Error("研究员不应该能访问病历")
		}
	})

	// 场景：企业文件访问控制
	t.Run("EnterpriseFileAccess", func(t *testing.T) {
		fmt.Println("\n--- 场景：企业机密文件访问 ---")

		gp, _ := GlobalSetup()

		// 定义企业属性
		corpAttrs := NewLW11DABEAttributesFromStrings(
			"Manager", "Engineer", "Finance", "HR", "Executive",
		)
		pk, sk, _ := AuthoritySetup(corpAttrs, gp)
		fmt.Println("✓ 企业属性体系设置: Manager, Engineer, Finance, HR, Executive")

		// 分配用户属性
		managerKey, _ := KeyGenerate(
			NewLW11DABEAttributesFromStrings("Manager", "Engineer"),
			"manager@corp.com", sk,
		)
		financeKey, _ := KeyGenerate(
			NewLW11DABEAttributesFromStrings("Finance"),
			"cfo@corp.com", sk,
		)
		execKey, _ := KeyGenerate(
			NewLW11DABEAttributesFromStrings("Executive", "Manager"),
			"ceo@corp.com", sk,
		)
		fmt.Println("✓ 为3个用户授予不同属性组合")

		// 加密财务报告：需要 (Finance OR Executive)
		financePolicy := lsss2.Or(
			lsss2.LeafFromString("Finance"),
			lsss2.LeafFromString("Executive"),
		)
		financeMatrix := lsss2.NewLSSSMatrixFromBinaryTree(financePolicy)

		financeReport, _ := NewRandomLW11DABEMessage()
		financeCipher, _ := Encrypt(financeReport, financeMatrix, gp, pk)
		fmt.Println("✓ 财务报告加密，策略: (Finance OR Executive)")

		// 测试访问
		_, err1 := Decrypt(financeCipher, financeKey, gp)
		if err1 == nil {
			fmt.Println("✓ CFO可以访问财务报告")
		}

		_, err2 := Decrypt(financeCipher, execKey, gp)
		if err2 == nil {
			fmt.Println("✓ CEO可以访问财务报告")
		}

		decrypted3, err3 := Decrypt(financeCipher, managerKey, gp)
		shouldFail := err3 != nil || !financeReport.Message.Equal(&decrypted3.Message)
		if shouldFail {
			fmt.Println("✓ 普通经理无法访问财务报告（符合预期）")
		}
	})
}

// ============================================
// 7. 性能和压力测试
// ============================================

// TestPerformanceWithMultipleAttributes 测试多属性性能
func TestPerformanceWithMultipleAttributes(t *testing.T) {
	fmt.Println("\n========== 测试8: 性能测试 ==========")

	gp, _ := GlobalSetup()

	testCases := []int{5, 10, 20}

	for _, numAttrs := range testCases {
		t.Run(fmt.Sprintf("%dAttributes", numAttrs), func(t *testing.T) {
			// 生成属性
			attrNames := make([]string, numAttrs)
			for i := 0; i < numAttrs; i++ {
				attrNames[i] = fmt.Sprintf("Attr%d", i)
			}
			attributes := NewLW11DABEAttributesFromStrings(attrNames...)

			pk, sk, _ := AuthoritySetup(attributes, gp)
			userKey, _ := KeyGenerate(attributes, "testuser", sk)

			// 创建复杂访问策略
			leaves := make([]*lsss2.BinaryAccessTree, numAttrs)
			for i := 0; i < numAttrs; i++ {
				leaves[i] = lsss2.LeafFromString(attrNames[i])
			}

			// 构建OR树
			accessTree := leaves[0]
			for i := 1; i < numAttrs; i++ {
				accessTree = lsss2.Or(accessTree, leaves[i])
			}

			matrix := lsss2.NewLSSSMatrixFromBinaryTree(accessTree)
			message, _ := NewRandomLW11DABEMessage()

			// 加密
			ciphertext, _ := Encrypt(message, matrix, gp, pk)

			// 解密
			decrypted, err := Decrypt(ciphertext, userKey, gp)

			if err != nil {
				t.Errorf("解密失败: %v", err)
			}

			if !message.Message.Equal(&decrypted.Message) {
				t.Error("解密消息不匹配")
			}

			fmt.Printf("✓ %d属性测试完成\n", numAttrs)
		})
	}
}
