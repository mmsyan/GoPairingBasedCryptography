package zss04

import (
	"crypto/rand"
	"testing"
)

// TestParamsGenerate 测试公共参数生成
func TestParamsGenerate(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate 失败: %v", err)
	}

	if pp == nil {
		t.Fatal("公共参数为 nil")
	}

	// 验证 eG1G2 不是零元素
	if pp.eG1G2.IsZero() {
		t.Error("eG1G2 是零元素")
	}
}

// TestParamsGenerateConsistency 测试公共参数生成的一致性
func TestParamsGenerateConsistency(t *testing.T) {
	pp1, err1 := ParamsGenerate()
	pp2, err2 := ParamsGenerate()

	if err1 != nil || err2 != nil {
		t.Fatalf("ParamsGenerate 失败: %v, %v", err1, err2)
	}

	// 公共参数应该是一致的（固定的生成元配对）
	if !pp1.eG1G2.Equal(&pp2.eG1G2) {
		t.Error("多次生成的公共参数不一致")
	}
}

// TestKeyGenerate 测试密钥生成
func TestKeyGenerate(t *testing.T) {
	pk, sk, err := KeyGenerate()

	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	if pk == nil {
		t.Fatal("公钥为 nil")
	}

	if sk == nil {
		t.Fatal("私钥为 nil")
	}

	// 验证私钥不是零
	if sk.x.IsZero() {
		t.Error("私钥 x 是零")
	}

	// 验证公钥点在正确的子群中
	if !pk.p.IsInSubGroup() {
		t.Error("公钥点不在正确的子群中")
	}
}

// TestKeyGenerateUniqueness 测试密钥生成的唯一性
func TestKeyGenerateUniqueness(t *testing.T) {
	pk1, sk1, err1 := KeyGenerate()
	pk2, sk2, err2 := KeyGenerate()

	if err1 != nil || err2 != nil {
		t.Fatalf("KeyGenerate 失败: %v, %v", err1, err2)
	}

	// 两次生成的密钥应该不同
	if sk1.x.Equal(&sk2.x) {
		t.Error("两次密钥生成产生了相同的私钥")
	}

	if pk1.p.Equal(&pk2.p) {
		t.Error("两次密钥生成产生了相同的公钥")
	}
}

// TestSignBasic 测试基本签名功能
func TestSignBasic(t *testing.T) {
	_, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	msg := &Message{
		MessageBytes: []byte("Hello, World!"),
	}

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	if sig == nil {
		t.Fatal("签名为 nil")
	}

	// 验证签名点在正确的子群中
	if !sig.S.IsInSubGroup() {
		t.Error("签名点不在正确的子群中")
	}
}

// TestSignEmptyMessage 测试空消息签名
func TestSignEmptyMessage(t *testing.T) {
	_, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	msg := &Message{
		MessageBytes: []byte(""),
	}

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	if sig == nil {
		t.Fatal("签名为 nil")
	}
}

// TestSignLargeMessage 测试大消息签名
func TestSignLargeMessage(t *testing.T) {
	_, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	// 生成 1MB 的随机数据
	largeData := make([]byte, 1024*1024)
	_, err = rand.Read(largeData)
	if err != nil {
		t.Fatalf("生成随机数据失败: %v", err)
	}

	msg := &Message{
		MessageBytes: largeData,
	}

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	if sig == nil {
		t.Fatal("签名为 nil")
	}
}

// TestVerifyValid 测试有效签名的验证
func TestVerifyValid(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate 失败: %v", err)
	}

	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	msg := &Message{
		MessageBytes: []byte("Test message"),
	}

	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	valid, err := Verify(pk, msg, sig, pp)
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}

	if !valid {
		t.Error("有效签名验证失败")
	}
}

// TestVerifyWrongMessage 测试错误消息的验证失败
func TestVerifyWrongMessage(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate 失败: %v", err)
	}

	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	msg1 := &Message{
		MessageBytes: []byte("Original message"),
	}

	sig, err := Sign(sk, msg1)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	// 使用不同的消息验证
	msg2 := &Message{
		MessageBytes: []byte("Different message"),
	}

	valid, err := Verify(pk, msg2, sig, pp)
	if err == nil {
		t.Error("期望验证失败但没有返回错误")
	}

	if valid {
		t.Error("错误消息的签名验证通过")
	}
}

// TestVerifyWrongPublicKey 测试错误公钥的验证失败
func TestVerifyWrongPublicKey(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate 失败: %v", err)
	}

	pk1, sk1, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	pk2, _, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	msg := &Message{
		MessageBytes: []byte("Test message"),
	}

	sig, err := Sign(sk1, msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	// 用正确的公钥验证应该成功
	valid, err := Verify(pk1, msg, sig, pp)
	if err != nil {
		t.Fatalf("Verify 失败: %v", err)
	}
	if !valid {
		t.Error("有效签名验证失败")
	}

	// 用错误的公钥验证应该失败
	valid, err = Verify(pk2, msg, sig, pp)
	if err == nil {
		t.Error("期望验证失败但没有返回错误")
	}
	if valid {
		t.Error("使用错误公钥的签名验证通过")
	}
}

// TestVerifyMultipleMessages 测试多个消息的签名和验证
func TestVerifyMultipleMessages(t *testing.T) {
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("ParamsGenerate 失败: %v", err)
	}

	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	messages := []string{
		"Message 1",
		"Message 2",
		"Message 3",
		"",
		"A very long message with lots of text to test the signature scheme",
	}

	for i, msgText := range messages {
		msg := &Message{
			MessageBytes: []byte(msgText),
		}

		sig, err := Sign(sk, msg)
		if err != nil {
			t.Fatalf("Sign 失败 (消息 %d): %v", i, err)
		}

		valid, err := Verify(pk, msg, sig, pp)
		if err != nil {
			t.Fatalf("Verify 失败 (消息 %d): %v", i, err)
		}

		if !valid {
			t.Errorf("消息 %d 的签名验证失败: %s", i, msgText)
		}
	}
}

// TestSignDeterminism 测试签名的非确定性
func TestSignDeterminism(t *testing.T) {
	_, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate 失败: %v", err)
	}

	msg := &Message{
		MessageBytes: []byte("Same message"),
	}

	sig1, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	sig2, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("Sign 失败: %v", err)
	}

	// ZSS04 签名是确定性的，同一消息应产生相同的签名
	if !sig1.S.Equal(&sig2.S) {
		t.Error("同一消息的两次签名产生了不同的结果")
	}
}

// TestCompleteWorkflow 测试完整的工作流程
func TestCompleteWorkflow(t *testing.T) {
	// 1. 生成公共参数
	pp, err := ParamsGenerate()
	if err != nil {
		t.Fatalf("生成公共参数失败: %v", err)
	}

	// 2. 生成密钥对
	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("生成密钥失败: %v", err)
	}

	// 3. 创建消息
	msg := &Message{
		MessageBytes: []byte("Complete workflow test message"),
	}

	// 4. 签名
	sig, err := Sign(sk, msg)
	if err != nil {
		t.Fatalf("签名失败: %v", err)
	}

	// 5. 验证
	valid, err := Verify(pk, msg, sig, pp)
	if err != nil {
		t.Fatalf("验证失败: %v", err)
	}

	if !valid {
		t.Error("完整工作流程：签名验证失败")
	}

	// 6. 验证篡改检测
	tamperedMsg := &Message{
		MessageBytes: []byte("Tampered message"),
	}

	valid, err = Verify(pk, tamperedMsg, sig, pp)
	if valid || err == nil {
		t.Error("完整工作流程：未能检测到消息篡改")
	}
}

// BenchmarkParamsGenerate 性能测试：公共参数生成
func BenchmarkParamsGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _ = ParamsGenerate()
	}
}

// BenchmarkKeyGenerate 性能测试：密钥生成
func BenchmarkKeyGenerate(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, _ = KeyGenerate()
	}
}

// BenchmarkSign 性能测试：签名生成
func BenchmarkSign(b *testing.B) {
	_, sk, _ := KeyGenerate()
	msg := &Message{
		MessageBytes: []byte("Benchmark message"),
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(sk, msg)
	}
}

// BenchmarkVerify 性能测试：签名验证
func BenchmarkVerify(b *testing.B) {
	pp, _ := ParamsGenerate()
	pk, sk, _ := KeyGenerate()
	msg := &Message{
		MessageBytes: []byte("Benchmark message"),
	}
	sig, _ := Sign(sk, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(pk, msg, sig, pp)
	}
}

// BenchmarkSignLargeMessage 性能测试：大消息签名
func BenchmarkSignLargeMessage(b *testing.B) {
	_, sk, _ := KeyGenerate()
	largeData := make([]byte, 1024*1024) // 1MB
	rand.Read(largeData)
	msg := &Message{
		MessageBytes: largeData,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Sign(sk, msg)
	}
}

// BenchmarkVerifyLargeMessage 性能测试：大消息验证
func BenchmarkVerifyLargeMessage(b *testing.B) {
	pp, _ := ParamsGenerate()
	pk, sk, _ := KeyGenerate()
	largeData := make([]byte, 1024*1024) // 1MB
	rand.Read(largeData)
	msg := &Message{
		MessageBytes: largeData,
	}
	sig, _ := Sign(sk, msg)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = Verify(pk, msg, sig, pp)
	}
}
