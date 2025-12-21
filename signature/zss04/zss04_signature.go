// Package zss04 implements the Zhang-Safavi-Naini-Susilo short signature scheme (ZSS04).
// 作者: mmsyan
// 日期: 2025-12-21
// 参考论文:
// Zhang, F., Safavi-Naini, R., Susilo, W. (2004). An Efficient Signature Scheme from Bilinear Pairings and Its Applications.
// In: Bao, F., Deng, R., Zhou, J. (eds) Public Key Cryptography – PKC 2004. PKC 2004.
// Lecture Notes in Computer Science, vol 2947. Springer, Berlin, Heidelberg.
// https://doi.org/10.1007/978-3-540-24632-9_20
//
// 该实现基于 BN254 椭圆曲线和双线性配对运算,提供了高效的短签名方案,具有以下特性:
//   - 短签名:签名只包含一个 G1 群元素
//   - 确定性签名:同一消息的多次签名产生相同结果
//   - 高效验证:验证只需要一次配对运算
//   - 强安全性:在 CDH (Computational Diffie-Hellman) 假设下可证明安全
//
// The signature scheme consists of four main operations:
//   - ParamsGenerate: 生成系统公共参数
//   - KeyGenerate: 生成公钥/私钥对
//   - Sign: 对消息创建签名
//   - Verify: 验证签名的有效性
//
// Security Properties:
//   - Existential unforgeability under chosen message attack (EUF-CMA)
//   - Based on the Computational Diffie-Hellman (CDH) assumption
//   - Signatures are deterministic (same message produces same signature)
//
// 与 BB04 签名方案的对比:
//   - ZSS04: 确定性签名,签名更短(仅一个 G1 元素),需要公共参数
//   - BB04: 随机化签名,签名包含随机值和 G1 元素,不需要公共参数
package zss04

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"math/big"
)

// PublicParams 表示 ZSS04 签名方案的系统公共参数。
// 这些参数在系统初始化时生成一次,可以被所有用户共享使用。
//
// 公共参数包含基础生成元的配对值,用于加速签名验证过程。
// 通过预计算 e(G1, G2),验证时只需要计算一次配对运算。
type PublicParams struct {
	// eG1G2 是基础生成元 G1 和 G2 的配对值,即 e(G1, G2)。
	// 这是 GT 群中的一个元素,用于签名验证。
	// 预计算此值可以显著提高验证效率。
	eG1G2 bn254.GT
}

// PrivateKey 表示 ZSS04 签名方案中的签名密钥(私钥)。
// 它由一个随机域元素 x 组成,必须严格保密。
//
// 私钥用于生成签名,绝不应该共享或传输。丢失私钥意味着无法签署消息,
// 而私钥泄露则允许攻击者伪造签名。
type PrivateKey struct {
	// x 是私钥的秘密值,是 BN254 曲线标量域 Fr 中的一个随机元素。
	// 必须严格保密,任何获得 x 的人都可以伪造签名。
	x fr.Element
}

// PublicKey 表示 ZSS04 签名方案中的验证密钥(公钥)。
// 它由 BN254 曲线 G2 群上的一个椭圆曲线点组成。
// 公钥可以自由共享,用于验证签名。
//
// 公钥通过私钥与 G2 生成元的标量乘法导出: P = x * G2
type PublicKey struct {
	// p 是公钥点,计算为 x * G2,
	// 其中 x 是私钥,G2 是 BN254 曲线 G2 群的生成元。
	p bn254.G2Affine
}

// Message 表示 ZSS04 方案中待签名的消息。
// 消息以字节数组形式表示,可以是任意长度的二进制数据。
//
// 在签名过程中,消息会通过哈希函数映射到标量域 Fr,
// 确保不同的消息产生不同的域元素。
type Message struct {
	// MessageBytes 是原始消息的字节表示。
	// 可以是任意长度的数据,在签名时会被哈希到域元素。
	MessageBytes []byte
}

// Signature 表示消息的 ZSS04 签名。
// 签名只包含一个 G1 群上的椭圆曲线点,这使得签名非常短小。
//
// ZSS04 签名是确定性的:对同一消息使用同一私钥签名,
// 总是产生相同的签名值。这与 BB04 的随机化签名不同。
type Signature struct {
	// S 是签名值,是 G1 群中的一个点。
	// 计算为 S = (1 / (H(m) + x)) * G1,
	// 其中 H(m) 是消息的哈希值,x 是私钥,G1 是生成元。
	S bn254.G1Affine
}

// ParamsGenerate 生成 ZSS04 签名方案的系统公共参数。
//
// 该函数计算基础生成元 G1 和 G2 的配对值 e(G1, G2),
// 并将其作为公共参数。这个预计算的配对值可以被所有用户共享,
// 用于加速签名验证过程。
//
// 算法流程:
//  1. 获取 BN254 曲线的标准生成元 G1 和 G2
//  2. 计算配对 e(G1, G2) 得到 GT 群中的元素
//  3. 将配对结果作为公共参数返回
//
// 返回值:
//   - *PublicParams: 生成的公共参数,包含 e(G1, G2)
//   - error: 如果配对计算失败则返回错误
//
// 性能说明:
//   - 该函数通常在系统初始化时调用一次
//   - 配对运算是开销较大的操作,但只需要执行一次
//   - 生成的公共参数可以被持久化存储,避免重复计算
//
// 注意事项:
//   - 公共参数对所有用户是相同的
//   - 参数可以公开发布,不包含任何秘密信息
//   - 验证者必须使用正确的公共参数,否则验证会失败
//
// 示例:
//
//	pp, err := ParamsGenerate()
//	if err != nil {
//	    return fmt.Errorf("生成公共参数失败: %w", err)
//	}
//	// pp 可以被所有用户共享使用
func ParamsGenerate() (*PublicParams, error) {
	// 获取 BN254 曲线的标准生成元
	_, _, g1, g2 := bn254.Generators()

	// 计算基础配对 e(G1, G2)
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, err
	}

	return &PublicParams{
		eG1G2: eG1G2,
	}, nil
}

// KeyGenerate 为 ZSS04 签名方案生成新的公钥/私钥对。
//
// 该函数生成一个随机域元素 x 作为私钥,
// 并通过与 G2 生成元的标量乘法计算相应的公钥:
//   - 私钥: x (随机选择的域元素)
//   - 公钥: P = x * G2
//
// 算法流程:
//  1. 从标量域 Fr 中随机选择私钥 x
//  2. 计算公钥 P = x * G2
//  3. 返回公钥和私钥对
//
// 返回值:
//   - *PublicKey: 生成的公钥(可以公开共享)
//   - *PrivateKey: 生成的私钥(必须保密)
//   - error: 如果随机数生成失败则返回错误
//
// 安全性说明:
//   - 私钥 x 是从密码学安全的随机数生成器中选择的
//   - 每次调用都会产生不同的密钥对
//   - 公钥可以从私钥计算得出,但反向计算(从公钥推导私钥)是困难的
//   - 基于离散对数问题的困难性假设
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
//	// pk 现在可以分发给其他人用于验证签名
//	// sk 必须安全保存,用于签名消息
func KeyGenerate() (*PublicKey, *PrivateKey, error) {
	// 随机选择私钥 x
	x, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, err
	}

	// 计算公钥 P = x * G2
	p := new(bn254.G2Affine).ScalarMultiplicationBase(x.BigInt(new(big.Int)))

	return &PublicKey{
			p: *p,
		}, &PrivateKey{
			x: *x,
		}, nil
}

// Sign 使用提供的私钥对消息创建 ZSS04 签名。
//
// 签名算法:
//  1. 将消息哈希到标量域: h = H(m)
//  2. 计算 h + x (消息哈希值加私钥)
//  3. 计算其逆元: 1 / (h + x)
//  4. 计算签名: S = (1 / (h + x)) * G1
//
// 这是一个确定性签名方案:对同一消息使用同一私钥签名,
// 总是产生完全相同的签名值。这与 BB04 的随机化签名不同。
//
// 参数:
//   - sk: 用于签名的私钥(不能为 nil)
//   - m: 要签名的消息(不能为 nil)
//
// 返回值:
//   - *Signature: 生成的签名,包含一个 G1 群元素
//   - error: 如果签名过程失败则返回错误(通常不会发生)
//
// 性能特点:
//   - 消息首先被哈希到 Fr(标量域),这是所有群操作中最快的
//   - 主要开销是一次 G1 上的标量乘法
//   - 签名生成比验证更快,因为不需要配对运算
//
// 安全注意事项:
//   - 签名是确定性的,相同消息产生相同签名
//   - 私钥必须保密;任何拥有私钥的人都可以伪造签名
//   - 消息通过 SHA-256 哈希到域元素,提供抗碰撞性
//   - 如果 H(m) + x = 0(概率极低),签名会失败
//
// 与其他方案的对比:
//   - ZSS04: 确定性,签名短(仅一个 G1 元素)
//   - BB04: 随机化,签名长(一个 Fr 元素和一个 G1 元素)
//   - ECDSA: 确定性变体需要额外的安全假设
//
// 示例:
//
//	msg := &Message{
//	    MessageBytes: []byte("Hello, World!"),
//	}
//	sig, err := Sign(privateKey, msg)
//	if err != nil {
//	    return fmt.Errorf("签名失败: %w", err)
//	}
//	// sig 现在可以与消息一起发送
func Sign(sk *PrivateKey, m *Message) (*Signature, error) {
	// 将消息哈希到标量域 Fr
	// 使用 SHA-256 确保抗碰撞性和均匀分布
	hm := hash.BytesToField(m.MessageBytes)

	// 计算 H(m) + x
	hmAddS := new(fr.Element).Add(&hm, &sk.x)

	// 计算逆元: 1 / (H(m) + x)
	inverseHmAddS := new(fr.Element).Inverse(hmAddS)

	// 计算签名: S = (1 / (H(m) + x)) * G1
	s := new(bn254.G1Affine).ScalarMultiplicationBase(inverseHmAddS.BigInt(new(big.Int)))

	return &Signature{
		S: *s,
	}, nil
}

// Verify 检查签名对于给定消息和公钥是否有效。
//
// 验证算法使用双线性配对来检查签名方程:
//
//	e(S, H(m)*G2 + P) = e(G1, G2)
//
// 其中:
//   - S 是签名(G1 中的点)
//   - H(m) 是消息的哈希值
//   - P 是公钥(G2 中的点)
//   - e 是双线性配对函数
//
// 验证原理:
//
//	如果签名有效,则 S = (1 / (H(m) + x)) * G1
//	因此:
//	  e(S, H(m)*G2 + P)
//	= e((1/(H(m)+x))*G1, H(m)*G2 + x*G2)
//	= e((1/(H(m)+x))*G1, (H(m)+x)*G2)
//	= e(G1, G2)^((H(m)+x)/(H(m)+x))
//	= e(G1, G2)
//
// 参数:
//   - pk: 用于验证的公钥(不能为 nil)
//   - m: 被声称已签名的消息(不能为 nil)
//   - sigma: 要验证的签名(不能为 nil)
//   - pp: 系统公共参数,包含预计算的 e(G1, G2)(不能为 nil)
//
// 返回值:
//   - bool: 如果签名有效则为 true,否则为 false
//   - error: 如果配对计算失败或签名无效则返回错误
//
// 性能特点:
//   - 验证只需要一次配对运算(因为 e(G1, G2) 已预计算)
//   - 配对运算是开销最大的操作
//   - 还需要一次 G2 上的标量乘法和点加法
//   - 总体上,验证比签名慢,但仍然高效
//
// 安全注意事项:
//   - 验证是确定性的 - 相同的输入总是产生相同的结果
//   - 对于无效签名、被篡改的消息或错误的公钥返回 false
//   - 有效的签名证明签名者在签名时拥有对应的私钥
//   - 必须使用正确的公共参数,否则验证会失败
//   - 不验证消息的来源或完整性,只验证签名的数学正确性
//
// 错误情况:
//   - 配对计算失败(极少发生)
//   - 签名验证失败(消息被篡改或签名无效)
//
// 示例:
//
//	valid, err := Verify(publicKey, msg, sig, publicParams)
//	if err != nil {
//	    return fmt.Errorf("验证失败: %w", err)
//	}
//	if !valid {
//	    return fmt.Errorf("无效签名")
//	}
//	// 签名有效,消息确实由私钥持有者签名
func Verify(pk *PublicKey, m *Message, sigma *Signature, pp *PublicParams) (bool, error) {
	// 将消息哈希到标量域 Fr
	// 必须使用与签名时相同的哈希方式
	hm := hash.BytesToField(m.MessageBytes)

	// 计算 H(m) * G2
	g2ExpHm := new(bn254.G2Affine).ScalarMultiplicationBase(hm.BigInt(new(big.Int)))

	// 计算 H(m)*G2 + P (其中 P 是公钥)
	g2ExpHmAddPk := new(bn254.G2Affine).Add(g2ExpHm, &pk.p)

	// 计算配对 e(S, H(m)*G2 + P)
	pairLeft, err := bn254.Pair([]bn254.G1Affine{sigma.S}, []bn254.G2Affine{*g2ExpHmAddPk})
	if err != nil {
		return false, err
	}

	// 检查 e(S, H(m)*G2 + P) = e(G1, G2)
	// 如果相等,则签名有效
	if pairLeft.Equal(&pp.eG1G2) {
		return true, nil
	} else {
		return false, fmt.Errorf("invalid signature")
	}
}
