package bls01

import (
	"testing"
)

// TestBLSFlow 测试BLS签名的完整流程：密钥生成、签名、验证。
func TestBLSFlow(t *testing.T) {
	// 1. 密钥生成
	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	// 3. 签名
	message := &Message{
		MessageBytes: []byte("This is a test message for signature signature."),
	}
	signature, err := Sign(sk, message)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 4. 验证 - 预期成功
	isValid, err := Verify(pk, signature)
	if err != nil {
		t.Fatalf("Verify failed unexpectedly: %v", err)
	}
	if !isValid {
		t.Fatal("SigmaSignature was expected to be valid, but Verify returned false")
	}
}

// TestInvalidSignature 测试无效签名的验证。
func TestInvalidSignature(t *testing.T) {
	pk, sk, err := KeyGenerate()
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	// 签名一个消息
	message1 := &Message{
		MessageBytes: []byte("Original message"),
	}
	signature, err := Sign(sk, message1)
	if err != nil {
		t.Fatalf("Sign failed: %v", err)
	}

	// 尝试用不同的消息进行验证
	message2 := []byte("A different message")
	signature.MessageBytes = message2

	// 验证 - 预期失败
	isValid, err := Verify(pk, signature)
	if err != nil {
		t.Fatalf("Verify failed unexpectedly: %v", err)
	}
	if isValid {
		t.Fatal("SigmaSignature was expected to be invalid, but Verify returned true")
	}
}
