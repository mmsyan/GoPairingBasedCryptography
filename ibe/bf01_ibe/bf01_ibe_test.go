package bf01_ibe

import (
	"fmt"
	"testing"
)

func TestBF01IBE1(t *testing.T) {
	// 1. 生成身份
	identity, err := NewBF01Identity("alice@google.com")
	if err != nil {
		t.Fatalf("NewBF01Identity failed: %v", err)
	}

	// 2. 准备消息（正确构造结构体指针）
	messages := []*BFIBEMessage{
		{Message: []byte("This is Alice's first secret.")},
		{Message: []byte("Meeting scheduled for 3 PM.")},
		{Message: []byte("The IBE scheme is working correctly.")},
	}

	// 3. 初始化切片（关键！）
	ciphertexts := make([]*BFIBECiphertext, len(messages))
	decryptedMessages := make([]*BFIBEMessage, len(messages))

	// 4. 初始化 IBE 实例
	instance, err := NewBFIBEInstance()
	if err != nil {
		t.Fatalf("NewBFIBEInstance failed: %v", err)
	}

	publicParams, err := instance.SetUp()
	if err != nil {
		t.Fatalf("SetUp failed: %v", err)
	}

	secretKey, err := instance.KeyGenerate(identity, publicParams)
	if err != nil {
		t.Fatalf("KeyGenerate failed: %v", err)
	}

	// 5. 加密
	for i := range messages {
		ciphertexts[i], err = instance.Encrypt(identity, messages[i], publicParams)
		if err != nil {
			t.Fatalf("Encrypt failed at index %d: %v", i, err)
		}
	}

	// 6. 解密
	for i := range ciphertexts {
		decryptedMessages[i], err = instance.Decrypt(ciphertexts[i], secretKey, publicParams)
		if err != nil {
			t.Fatalf("Decrypt failed at index %d: %v", i, err)
		}
	}

	// 7. 验证
	for i := 0; i < len(messages); i++ {
		if string(decryptedMessages[i].Message) != string(messages[i].Message) {
			t.Fatalf("decrypted wrong, %s", string(decryptedMessages[i].Message))
		}
		fmt.Printf("message before encrypt: %s \n", string(messages[i].Message))
		fmt.Printf("message after decrypt: %s \n", string(decryptedMessages[i].Message))
	}

	// 可选：用 t.Log 替代 fmt.Printf
	t.Log("All messages encrypted and decrypted correctly.")
}

func TestBF01IBE2(t *testing.T) {
	var err error

	identity, err := NewBF01Identity("alice")

	message := &BFIBEMessage{
		Message: []byte("Hello World"),
	}

	instance, err := NewBFIBEInstance()
	publicParams, err := instance.SetUp()
	secretKey, err := instance.KeyGenerate(identity, publicParams)
	ciphertext, err := instance.Encrypt(identity, message, publicParams)
	decryptedMessage, err := instance.Decrypt(ciphertext, secretKey, publicParams)

	if string(decryptedMessage.Message) != "Hello World" {
		t.Fatalf("decrypted wrong, %s", string(decryptedMessage.Message))
	}

	fmt.Printf("message before encrypt: %s \n", string(message.Message))
	fmt.Printf("message after decrypt: %s \n", string(decryptedMessage.Message))

	if err != nil {
		t.Fatal(err)
	}
}

func TestBF01IBE3(t *testing.T) {
	var err error

	identity, err := NewBF01Identity("alice")

	message := &BFIBEMessage{
		Message: []byte("hajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfghajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhajimilaluomeiduoaxigaaxsajdhfsgbhjnashsdgvbjnhvcfdxrcfg hfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrhfdrxcftvgbhnhbgvfctdrtfvgbhj nhbgvfcdrctfvgbhnjhbgvqswdefrgthyjukhgfdsasdfghhgtfredwaswdfghhgtreasdfr"),
	}
	fmt.Println("测试不通过，因为明文长度太长导致异或步骤失效；建议对一个对称加密密钥进行")
	instance, err := NewBFIBEInstance()
	publicParams, err := instance.SetUp()
	secretKey, err := instance.KeyGenerate(identity, publicParams)
	ciphertext, err := instance.Encrypt(identity, message, publicParams)
	decryptedMessage, err := instance.Decrypt(ciphertext, secretKey, publicParams)

	fmt.Printf("message before encrypt: %s \n", string(message.Message))
	fmt.Printf("message after decrypt: %s \n", string(decryptedMessage.Message))
	if string(decryptedMessage.Message) != string(message.Message) {
		t.Fatalf("decrypted wrong, %s", string(decryptedMessage.Message))

	}

	if err != nil {
		t.Fatal(err)
	}
}
