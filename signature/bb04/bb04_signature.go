// Package bb04 implements the Boneh-Boyen short signature scheme (BB04).
// 作者: mmsyan
// 日期: 2025-12-21
// 参考论文:
// Boneh, D., Boyen, X. (2004). Short Signatures Without Random Oracles.
// In: Cachin, C., Camenisch, J.L. (eds) Advances in Cryptology - EUROCRYPT 2004. EUROCRYPT 2004.
// Lecture Notes in Computer Science, vol 3027. Springer, Berlin, Heidelberg.
// https://doi.org/10.1007/978-3-540-24676-3_4
//
// This package provides a cryptographic signature scheme based on bilinear pairings
// over the BN254 elliptic curve. The scheme offers short signatures and is provably
// secure under the Strong Diffie-Hellman assumption.
//
// The signature scheme consists of three main operations:
//   - KeyGenerate: Generates a public/private key pair
//   - Sign: Creates a signature for a given message
//   - Verify: Verifies that a signature is valid for a message and public key
//
// Security Properties:
//   - Existential unforgeability under chosen message attack (EUF-CMA)
//   - Based on the q-Strong Diffie-Hellman (q-SDH) assumption
//   - Signatures are randomized (different signatures for the same message)
package bb04

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// PrivateKey 表示 BB04 签名方案中的签名密钥(私钥)。
// 它由两个随机域元素(alpha 和 beta)组成,必须严格保密。
// 该方案的安全性依赖于保持这些值的机密性。
//
// 私钥用于生成签名,绝不应该共享或传输。丢失私钥意味着无法签署消息,
// 而私钥泄露则允许攻击者伪造签名。
type PrivateKey struct {
	// Alpha 是私钥的第一个秘密分量。它是 BN254 曲线标量域 Fr 中的一个随机元素。
	Alpha fr.Element

	// Beta 是私钥的第二个秘密分量。 它是 BN254 曲线标量域 Fr 中的一个随机元素。
	Beta fr.Element
}

// PublicKey 表示 BB04 签名方案中的验证密钥(公钥)。
// 它由 BN254 曲线 G2 群上的两个椭圆曲线点组成。
// 公钥可以自由共享,用于验证签名。
//
// 公钥通过私钥分量与生成元点的标量乘法导出。
type PublicKey struct {
	// Y 是公钥的第一个分量,计算为 alpha * G2,
	// 其中 G2 是 BN254 曲线 G2 群的生成元。
	Y bn254.G2Affine

	// Z 是公钥的第二个分量,计算为 beta * G2,
	// 其中 G2 是 BN254 曲线 G2 群的生成元。
	Z bn254.G2Affine
}

// Message 表示 BB04 方案中待签名的消息。
// 消息被表示为 BN254 曲线标量域 Fr 中的域元素。
// 任何要签名的数据必须首先转换或哈希为域元素。
//
// 为了安全性,建议在签名前使用抗碰撞哈希函数将任意长度的消息
// 映射为域元素。
type Message struct {
	// MessageFr 是表示为域元素的消息。
	// 这是将被纳入签名的值。
	MessageFr fr.Element
}

// Signature 表示消息的 BB04 签名。
// 它由一个随机域元素 R 和一个椭圆曲线点 Sigma 组成。
// R 提供的随机化确保同一消息的多次签名是不同的,增强隐私性并防止某些攻击。
//
// 签名可以使用相应的公钥和原始消息进行验证。
type Signature struct {
	// R 是签名过程中选择的随机域元素。
	// 每个签名使用新的随机 R,使签名具有随机性。
	R fr.Element

	// Sigma 是核心签名值,计算为 (1 / (alpha + r * beta + m)) * G1,
	// 其中 G1 是 BN254 曲线 G1 群的生成元,
	// alpha 和 beta 是私钥分量,
	// r 是随机值 R,m 是消息。
	Sigma bn254.G1Affine
}

// KeyGenerate 为 BB04 签名方案生成新的公钥/私钥对。
//
// 该函数生成两个随机域元素(alpha 和 beta)作为私钥,
// 并通过与 G2 生成元的标量乘法计算相应的公钥分量:
//   - Y = alpha * G2
//   - Z = beta * G2
//
// 返回值:
//   - *PublicKey: 生成的公钥(可以公开共享)
//   - *PrivateKey: 生成的私钥(必须保密)
//   - error: 如果随机数生成失败则返回错误
//
// 生成的密钥是密码学安全的,适合立即使用。
// 每次调用 KeyGenerate 都会以压倒性的概率产生唯一的密钥对。
//
// 示例:
//
//	pk, sk, err := KeyGenerate()
//	if err != nil {
//	    return fmt.Errorf("密钥生成失败: %w", err)
//	}
//	// pk 现在可以分发,sk 必须保密
func KeyGenerate() (*PublicKey, *PrivateKey, error) {
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating alpha signature key")
	}
	beta, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating beta signature key")
	}
	y := new(bn254.G2Affine).ScalarMultiplicationBase(alpha.BigInt(new(big.Int)))
	z := new(bn254.G2Affine).ScalarMultiplicationBase(beta.BigInt(new(big.Int)))

	return &PublicKey{
			Y: *y,
			Z: *z,
		}, &PrivateKey{
			Alpha: *alpha,
			Beta:  *beta,
		}, nil
}

// Sign 使用提供的私钥对消息创建 BB04 签名。
//
// 签名算法:
//  1. 生成随机域元素 r
//  2. 计算值 (alpha + r * beta + m)
//  3. 计算签名 sigma = (1 / (alpha + r * beta + m)) * G1
//
// 参数:
//   - sk: 用于签名的私钥(不能为 nil)
//   - m: 要签名的消息(不能为 nil)
//
// 返回值:
//   - *Signature: 生成的签名,包含 R 和 Sigma 分量
//   - error: 如果随机数生成失败则返回错误
//
// 安全注意事项:
//   - 每个签名使用新的随机值 r,使签名非确定性
//   - 同一消息签名两次会产生不同的签名
//   - 私钥必须保密;任何拥有私钥访问权限的人都可以伪造签名
//   - 消息通常应该是要签名数据的哈希值
//
// 示例:
//
//	msg := &Message{}
//	msg.MessageFr.SetUint64(12345)
//	sig, err := Sign(privateKey, msg)
//	if err != nil {
//	    return fmt.Errorf("签名失败: %w", err)
//	}
func Sign(sk *PrivateKey, m *Message) (*Signature, error) {
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	// 计算 (alpha + r * beta + m)
	rMulBeta := new(fr.Element).Mul(r, &sk.Beta)
	alphaAddRMulBeta := new(fr.Element).Add(&sk.Alpha, rMulBeta)
	alphaAddRMulBetaAddM := new(fr.Element).Add(alphaAddRMulBeta, &m.MessageFr)

	// 计算 sigma = (1 / (alpha + r * beta + m)) * G1
	inverseSigma := new(fr.Element).Inverse(alphaAddRMulBetaAddM)
	sigma := new(bn254.G1Affine).ScalarMultiplicationBase(inverseSigma.BigInt(new(big.Int)))

	return &Signature{
		R:     *r,
		Sigma: *sigma,
	}, nil
}

// Verify 检查签名对于给定消息和公钥是否有效。
//
// 验证算法使用双线性配对来检查签名方程:
//
//	e(sigma, Y + r*Z + m*G2) = e(G1, G2)
//
// 其中 e 是 BN254 上的双线性配对函数,为了效率使用配对乘积检查来验证方程。
//
// 参数:
//   - pk: 用于验证的公钥(不能为 nil)
//   - m: 被声称已签名的消息(不能为 nil)
//   - sign: 要验证的签名(不能为 nil)
//
// 返回值:
//   - bool: 如果签名有效则为 true,否则为 false
//   - error: 如果配对计算失败则返回错误
//
// 安全注意事项:
//   - 对于无效签名、被篡改的消息或错误的公钥返回 false
//   - 验证是确定性的 - 相同的输入总是产生相同的结果
//   - 有效的签名证明签名者在签名时拥有私钥
//   - 不验证消息真实性 - 使用安全哈希函数确保消息完整性
//
// 示例:
//
//	valid, err := Verify(publicKey, msg, sig)
//	if err != nil {
//	    return fmt.Errorf("验证失败: %w", err)
//	}
//	if !valid {
//	    return fmt.Errorf("无效签名")
//	}
//	// 签名有效
func Verify(pk *PublicKey, m *Message, sign *Signature) (bool, error) {
	_, _, g1, g2 := bn254.Generators()

	// 计算 -sigma 用于配对检查
	negSigma := new(bn254.G1Affine).Neg(&sign.Sigma)

	// 计算 Y + r*Z + m*G2
	rMulZ := new(bn254.G2Affine).ScalarMultiplication(&pk.Z, sign.R.BigInt(new(big.Int)))
	g2ExpM := new(bn254.G2Affine).ScalarMultiplicationBase(m.MessageFr.BigInt(new(big.Int)))
	temp := new(bn254.G2Affine).Add(rMulZ, g2ExpM)
	temp.Add(&pk.Y, temp)

	// 检查 e(-sigma, Y + r*Z + m*G2) * e(G1, G2) = 1
	// 这等价于检查 e(sigma, Y + r*Z + m*G2) = e(G1, G2)
	isValid, err := bn254.PairingCheck(
		[]bn254.G1Affine{*negSigma, g1},
		[]bn254.G2Affine{*temp, g2},
	)
	if err != nil {
		return false, err
	}
	return isValid, nil
}
