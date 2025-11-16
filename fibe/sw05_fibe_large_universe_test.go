package fibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"testing"
)

func TestFIBELargeUniverse1(t *testing.T) {
	var err error

	m, err := new(bn254.GT).SetRandom()
	if err != nil {
		t.Fatal(err)
	}
	message := &SW05FIBELargeUniverseMessage{
		Message: *m,
	}
	fmt.Println("原始消息:", message.Message)

	userAttributes, err := NewFIBELargeUniverseAttributes([]int64{1, 2, 3, 4})
	messageAttributes, err := NewFIBELargeUniverseAttributes([]int64{1, 2, 3, 4})

	fibeInstance := NewSW05FIBELargeUniverseInstance(10, 3)
	publicParams, err := fibeInstance.SetUp()
	if err != nil {
		t.Fatal("系统初始化失败:", err)
	}
	secretKey, err := fibeInstance.KeyGenerate(userAttributes, publicParams)
	if err != nil {
		t.Fatal("密钥生成失败:", err)
	}
	ciphertext, err := fibeInstance.Encrypt(messageAttributes, message, publicParams)
	if err != nil {
		t.Fatal("加密失败:", err)
	}

	decryptedMessage, err := fibeInstance.Decrypt(secretKey, ciphertext, publicParams)
	if err != nil {
		t.Fatal("解密失败:", err)
	}

	fmt.Println("解密消息:", decryptedMessage.Message)

	// 验证解密后的消息与原始消息是否一致
	if decryptedMessage.Message != message.Message {
		t.Fatal("解密消息与原始消息不匹配")
	}
}
