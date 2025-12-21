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

// BytesToG1 将字节数组映射到 BN254 曲线的 G1 群中的点。
// 该函数使用标准的 hash-to-curve 算法将任意字节数组确定性地映射到椭圆曲线点。
//
// 参数:
//   - b: 待映射的输入字节数组，可以是任意长度
//
// 返回值:
//   - bn254.G1Affine: BN254 曲线 G1 群中的仿射坐标点，由输入字节数组确定性生成
//
// Panic:
//   - 如果底层的 hash-to-curve 算法失败（极少发生），函数会 panic
//
// 技术细节:
//   - 使用域分离标签 "Hash Bytes To Element In G1" 确保与其他哈希用途独立
//   - 生成的点保证在素数阶子群 G1 中，满足配对运算的要求
//   - 实现遵循 RFC 9380 (Hash to Elliptic Curve) 标准
//
// 注意事项:
//   - 相同的输入字节数组总是产生相同的 G1 点（确定性映射）
//   - 域分离标签防止不同协议间的哈希碰撞
//   - 生成的点可直接用于配对运算 e(G1, G2) -> GT
//
// 与 ToG1 的区别:
//   - ToG1: 接受字符串参数，内部转换为字节数组
//   - BytesToG1: 直接接受字节数组，适用于已经是二进制格式的数据
//
// 设计考虑:
//   - 许多密码学协议选择将消息/身份映射到 G1，而将公钥放在 G2
//   - 这是因为 G1 的哈希操作更快，而验证通常只需要固定的 G2 运算
//   - 例如 BLS 签名方案中，签名在 G1，公钥在 G2
//
// 常用场景:
//
//	// 哈希序列化的消息
//	serialized := serialize(message)
//	messagePoint := BytesToG1(serialized)
//
//	// 哈希用户标识符
//	userID := []byte("user123")
//	identityPoint := BytesToG1(userID)
//
//	// 哈希承诺值
//	commitment := sha256.Sum256(secretData)
//	commitPoint := BytesToG1(commitment[:])
//
//	// 用于 BLS 签名
//	msgHash := sha256.Sum256(document)
//	H_m := BytesToG1(msgHash[:])
func BytesToG1(b []byte) bn254.G1Affine {
	result, err := bn254.HashToG1(b, []byte("Hash Bytes To Element In G1"))
	if err != nil {
		panic(fmt.Errorf("failed to hash string to g1: %v", err))
	}
	return result
}
