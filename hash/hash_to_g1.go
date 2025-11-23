package hash

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// ToG1 将字符串映射到 BN254 曲线的 G1 群中的点。
// 该函数使用标准的 hash-to-curve 算法将任意字符串确定性地映射到椭圆曲线点。
//
// 参数:
//   - str: 待映射的输入字符串，可以是任意长度
//
// 返回值:
//   - bn254.G1Affine: BN254 曲线 G1 群中的仿射坐标点，由输入字符串确定性生成
//
// Panic:
//   - 如果底层的 hash-to-curve 算法失败（极少发生），函数会 panic
//
// 注意:
//   - 相同的输入字符串总是产生相同的 G1 点（确定性映射）
//   - 使用域分离标签 "Hash String To Element In G1" 确保与其他用途的哈希独立
//   - 生成的点保证在 G1 群中，可直接用于配对运算
//
// 常用用法:
//
//	// 将用户身份映射到 G1 点（用于基于身份的加密）
//	publicKey := ToG1("user@example.com")
//
//	// 生成承诺的基点
//	commitment := ToG1("commitment-base-2024")
//
//	// 用于签名方案中的消息哈希
//	messagePoint := ToG1("message to be signed")
func ToG1(str string) bn254.G1Affine {
	result, err := bn254.HashToG1([]byte(str), []byte("Hash String To Element In G1"))
	if err != nil {
		panic(fmt.Errorf("failed to hash string to g1: %v", err))
	}
	return result
}
