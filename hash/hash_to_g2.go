package hash

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

// ToG2 将字符串映射到 BN254 曲线的 G2 群中的点。
// 该函数使用标准的 hash-to-curve 算法将任意字符串确定性地映射到椭圆曲线点。
//
// 参数:
//   - str: 待映射的输入字符串，可以是任意长度
//
// 返回值:
//   - bn254.G2Affine: BN254 曲线 G2 群中的仿射坐标点，由输入字符串确定性生成
//
// Panic:
//   - 如果底层的 hash-to-curve 算法失败（极少发生），函数会 panic
//
// 注意:
//   - 相同的输入字符串总是产生相同的 G2 点（确定性映射）
//   - 使用域分离标签 "Hash String To Element In G2" 确保与其他用途的哈希独立
//   - 生成的点保证在 G2 群中，可直接用于配对运算
//
// 常用用法:
//
//	// 将用户身份映射到 G2 点（用于基于身份的加密）
//	publicKey := ToG2("user@example.com")
//
//	// 生成承诺的基点
//	commitment := ToG2("commitment-base-2024")
//
//	// 用于签名方案中的消息哈希
//	messagePoint := ToG2("message to be signed")
func ToG2(str string) bn254.G2Affine {
	result, err := bn254.HashToG2([]byte(str), []byte("Hash String To Element In G2"))
	if err != nil {
		panic(fmt.Errorf("failed to hash string to g2: %v", err))
	}
	return result
}

// BytesToG2 将字节数组映射到 BN254 曲线的 G2 群中的点。
// 该函数使用标准的 hash-to-curve 算法将任意字节数组确定性地映射到椭圆曲线点。
//
// 参数:
//   - b: 待映射的输入字节数组，可以是任意长度
//
// 返回值:
//   - bn254.G2Affine: BN254 曲线 G2 群中的仿射坐标点，由输入字节数组确定性生成
//
// Panic:
//   - 如果底层的 hash-to-curve 算法失败（极少发生），函数会 panic
//
// 性能特点:
//   - ⚠️ 在双线性配对中，映射到 G2 是最复杂、最慢的操作（Fr < G1 < GT < G2）
//   - G2 点定义在扩域 F_{p^2} 上，运算比 G1（基域 F_p）慢约 3-5 倍
//   - 大辅因子乘法开销显著，是主要性能瓶颈
//   - 通常比映射到 G1 慢 3-5 倍，比映射到 Fr 慢 10-20 倍
//
// 技术细节:
//   - 使用域分离标签 "Hash Bytes To Element In G2" 确保与其他哈希用途独立
//   - 生成的点保证在素数阶子群 G2 中，满足配对运算的要求
//   - 实现遵循 RFC 9380 (Hash to Elliptic Curve) 标准
//   - BN254 的 G2 辅因子约为 2^{100}，乘法操作代价高昂
//
// 注意事项:
//   - 相同的输入字节数组总是产生相同的 G2 点（确定性映射）
//   - 域分离标签防止不同协议间的哈希碰撞
//   - 生成的点可直接用于配对运算 e(G1, G2) -> GT
//   - 由于性能原因，应避免在热路径（高频操作）中使用
//
// 设计考虑:
//   - 由于 G2 哈希开销大，许多协议将不常变化的数据放在 G2
//   - 例如：公钥在 G2（固定），消息/签名在 G1（频繁生成）
//   - BLS 签名变体：公钥在 G2，签名在 G1，因为签名操作更频繁
//   - Waters IBE：系统参数在 G2（一次性生成），密文/签名在 G1
//
// 性能优化建议:
//   - 如果可能，预计算并缓存 G2 点
//   - 将高频哈希操作放在 G1 或 Fr
//   - 批量处理多个 G2 哈希以分摊固定开销
//   - 考虑使用确定性预生成的 G2 点而非实时哈希
//
// 常用场景:
//
//	// 生成系统公钥（一次性操作）
//	systemParam := []byte("system-parameter-v1")
//	publicKey := BytesToG2(systemParam)
//
//	// 哈希域标识符
//	domainID := []byte("example.com")
//	domainPoint := BytesToG2(domainID)
//
//	// 用于 BLS 聚合签名的公钥
//	userPK := sha256.Sum256([]byte("user@example.com"))
//	publicKeyPoint := BytesToG2(userPK[:])
//
//	// Waters IBE 系统参数
//	paramSeed := []byte("ibe-param-u-prime")
//	uPrime := BytesToG2(paramSeed)
func BytesToG2(b []byte) bn254.G2Affine {
	result, err := bn254.HashToG2(b, []byte("Hash Bytes To Element In G2"))
	if err != nil {
		panic(fmt.Errorf("failed to hash string to g2: %v", err))
	}
	return result
}
