package hash

import (
	"crypto/sha256"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

// ToField 将字符串映射到 BN254 曲线的标量域 Fr 中的元素。
// 该函数使用 SHA-256 哈希算法将任意长度的字符串确定性地映射到有限域元素。
//
// 参数:
//   - str: 待映射的输入字符串，可以是任意长度
//
// 返回值:
//   - fr.Element: BN254 曲线标量域中的元素，由输入字符串的 SHA-256 哈希值确定性生成
//
// 注意:
//   - 相同的输入字符串总是产生相同的域元素（确定性映射）
//   - 该函数不会返回错误，因为任何哈希值都可以被解释为有限域元素
//   - 如果哈希值超过域的模数，SetBytes 会自动进行模运算
//
// 常用用法:
//
//	// 将属性字符串映射到域元素
//	AElement := ToField("Attribute:A")
//
//	// 用于生成确定性的随机数
//	seed := ToField("my-secret-seed")
func ToField(str string) fr.Element {
	// 创建 SHA-256 哈希器
	sha256 := sha256.New()
	sha256.Write([]byte(str))
	hashBytes := sha256.Sum(nil)

	// 将哈希值转换为有限域元素
	var result fr.Element
	result.SetBytes(hashBytes)
	return result
}
