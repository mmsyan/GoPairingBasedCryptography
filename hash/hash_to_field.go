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

// BytesToField 将字节数组映射到 BN254 曲线的标量域 Fr 中的元素。
// 该函数使用 SHA-256 哈希算法将任意长度的字节数组确定性地映射到有限域元素。
//
// 算法流程:
//  1. 对输入字节数组进行 SHA-256 哈希
//  2. 将 256 位哈希输出解释为大端序整数
//  3. 通过 SetBytes 自动执行模运算，将整数约简到 Fr 的范围内
//
// 参数:
//   - data: 待映射的输入字节数组，可以是任意长度
//
// 返回值:
//   - fr.Element: BN254 曲线标量域中的元素，由输入字节的 SHA-256 哈希值确定性生成
//
// 性能特点:
//   - 在双线性配对中，映射到 Fr（标量域）是最简单、最快速的操作
//   - 复杂度远低于映射到 G1、G2 或 GT 群元素
//   - SHA-256 哈希是该函数的主要性能开销
//
// 注意事项:
//   - 相同的输入字节数组总是产生相同的域元素（确定性映射）
//   - 该函数不会返回错误，因为任何哈希值都可以被解释为有限域元素
//   - 如果哈希值超过域的模数 r，SetBytes 会自动进行模 r 运算
//   - SHA-256 的 256 位输出提供了良好的均匀分布性
//
// 常用场景:
//
//	// 哈希序列化的数据结构
//	serialized := serialize(myStruct)
//	element := BytesToField(serialized)
//
//	// 哈希文件内容
//	fileBytes, _ := ioutil.ReadFile("data.bin")
//	element := BytesToField(fileBytes)
//
//	// 哈希消息摘要
//	msgHash := sha256.Sum256(longMessage)
//	element := BytesToField(msgHash[:])
//
//	// 组合多个哈希值
//	combined := append(hash1[:], hash2[:]...)
//	element := BytesToField(combined)
func BytesToField(data []byte) fr.Element {
	// 创建 SHA-256 哈希器
	sha256 := sha256.New()
	// 写入字节数据
	sha256.Write(data)
	// 获取 256 位哈希输出
	hashBytes := sha256.Sum(nil)

	// 将哈希值转换为有限域元素
	// SetBytes 自动将字节数组解释为大端序整数并执行模运算
	var result fr.Element
	result.SetBytes(hashBytes)
	return result
}
