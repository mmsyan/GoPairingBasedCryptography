package ibe

// 作者: mmsyan
// 日期: 2025-11-13
// 参考论文:
// Gentry, C. (2006). Practical Identity-Based Encryption Without Random Oracles.
// In: Vaudenay, S. (eds) Advances in Cryptology - EUROCRYPT 2006.
// https://doi.org/10.1007/11761679_27
// 论文链接: https://link.springer.com/chapter/10.1007/11761679_27
//
// 该实现基于BN254椭圆曲线和配对运算,提供了完整的Craig Gentry IBE系统功能,包括:
//   - 系统初始化(SetUp)
//   - 密钥生成(KeyGenerate)
//   - 加密(Encrypt)
//   - 解密(Decrypt)
//
// 该实现基于论文的第三章：Construction I: Chosen-Plaintext Security的第3.1节
// 该实现基于的方案是IND-ID-CPA安全的

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// Gentry06CPAIBEInstance 表示 Gentry IBE (2006) 方案的实例对象。
// 该实例包含了系统的主密钥 alpha。
// 主密钥 alpha 属于 Zp 域，用于生成用户的私钥，必须严格保密。
type Gentry06CPAIBEInstance struct {
	alpha fr.Element // 系统主密钥，alpha 属于 Zp
}

// Gentry06CPAIBEPublicParams 表示 Gentry IBE 方案的公共参数。
// 这些参数在系统初始化时生成，可以公开发布给所有用户。
type Gentry06CPAIBEPublicParams struct {
	g1      bn254.G1Affine // G1 群的生成元
	g2      bn254.G2Affine // G2 群的生成元
	g1Alpha bn254.G1Affine // g1^alpha，主公钥的一部分
	h       bn254.G2Affine // G2 群上的一个随机元素，可表示为 g2^r_h
}

// Gentry06CPAIBEIdentity 表示 IBE 方案中的用户身份。
// 身份 ID 被编码为 Zp 有限域上的一个元素。
// 必须满足 ID != alpha，否则无法生成私钥。
type Gentry06CPAIBEIdentity struct {
	Id fr.Element // 用户的身份 ID 属于 Zp
}

// Gentry06CPAIBESecretKey 表示 Gentry IBE 方案中的用户私钥。
// 私钥 $d_{ID} = (r_{ID}, h_{ID})$ 包含两部分：
//   - $r_{ID}$: Zp 域上的随机元素
//   - $h_{ID}$: G2 群上的元素，计算为 $h_{ID} = (h g_2^{-r_{ID}})^{\frac{1}{\alpha - ID}}$
type Gentry06CPAIBESecretKey struct {
	rid fr.Element     // 随机参数 r_ID 属于 Zp
	hid bn254.G2Affine // 密钥元素 h_ID 属于 G2
}

// Gentry06IBEMessage 表示 IBE 方案中的明文消息。
// 明文 M 被编码为 GT 群（配对运算的目标群）上的一个元素。
type Gentry06CPAIBEMessage struct {
	Message bn254.GT // 明文 M 属于 GT
}

// Gentry06CPAIBECiphertext 表示 IBE 方案中的密文 $C = (u, v, w)$。
// 密文由三个部分组成：
//   - u: G1 群上的元素
//   - v: GT 群上的元素
//   - w: GT 群上的元素，包含加密后的消息
type Gentry06CPAIBECiphertext struct {
	u bn254.G1Affine // u 属于 G1
	v bn254.GT       // v 属于 GT
	w bn254.GT       // w 属于 GT
}

// NewGentry06CPAIBEInstance 创建一个新的 Gentry IBE 方案实例。
// 该函数随机生成主密钥 alpha 属于 Zp。
// 返回的实例对象包含主密钥，应由可信中心持有并妥善保管。
//
// 返回值:
//   - *Gentry06IBEInstance: 包含主密钥的 IBE 实例
//   - error: 如果随机数生成失败，返回错误信息
func NewGentry06CPAIBEInstance() (*Gentry06CPAIBEInstance, error) {
	// 随机选取主密钥 alpha 属于 Zp
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}
	return &Gentry06CPAIBEInstance{
		alpha: *alpha,
	}, nil
}

// SetUp 执行系统初始化操作，生成并返回公共参数。
// 该方法使用 IBE 实例中的主密钥 alpha，计算公开的系统参数。
//
// 步骤:
// 1. 获取群生成元 g1, g2。
// 2. 计算主公钥 $g_1^{\alpha}$。
// 3. 随机选择 h 并计算 $g_2^r$ 作为 $h$。
//
// 返回值:
//   - *Gentry06IBEPublicParams: 系统公共参数
//   - error: 如果初始化失败，返回错误信息
func (instance *Gentry06CPAIBEInstance) SetUp() (*Gentry06CPAIBEPublicParams, error) {
	// 获取 BN254 曲线的生成元 g1 和 g2
	_, _, g1, g2 := bn254.Generators()
	// 计算 g1^alpha
	g1Alpha := new(bn254.G1Affine).ScalarMultiplicationBase(instance.alpha.BigInt(new(big.Int)))
	// 随机选取 h 的指数，并计算 h = g2^r_h
	hRandom, err := new(fr.Element).SetRandom()
	h := new(bn254.G2Affine).ScalarMultiplicationBase(hRandom.BigInt(new(big.Int)))

	if err != nil {
		return nil, fmt.Errorf("failed to set up")
	}
	return &Gentry06CPAIBEPublicParams{
		g1:      g1,
		g2:      g2,
		g1Alpha: *g1Alpha,
		h:       *h,
	}, nil
}

// KeyGenerate 为指定用户身份生成私钥 $d_{ID} = (r_{ID}, h_{ID})$。
// 该方法使用主密钥 alpha 和用户身份 ID，通过密钥生成算法计算用户的私钥。
// 私钥应通过安全信道传递给对应的用户。
//
// 参数:
//   - identity: 用户的身份标识符
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *Gentry06IBESecretKey: 生成的私钥
//   - error: 如果密钥生成失败或 ID = alpha，返回错误信息
func (instance *Gentry06CPAIBEInstance) KeyGenerate(identity *Gentry06CPAIBEIdentity, publicParams *Gentry06CPAIBEPublicParams) (*Gentry06CPAIBESecretKey, error) {
	var err error
	rid, err := new(fr.Element).SetRandom()                                               // 1. 随机选取 r_ID 属于 Zp
	negRid := new(fr.Element).Neg(rid)                                                    // 计算 -r_ID
	g2InvRid := new(bn254.G2Affine).ScalarMultiplicationBase(negRid.BigInt(new(big.Int))) // 计算 $g_2^{-r_{ID}}$

	hAddG2InvRid := new(bn254.G2Affine).Add(&publicParams.h, g2InvRid) // 2. 计算 $h g_2^{-r_{ID}}$

	alphaMinusId := new(fr.Element).Sub(&instance.alpha, &identity.Id) // 3. 计算 $\alpha - ID$
	invAlphaMinusId := new(fr.Element).Inverse(alphaMinusId)           // 计算 $1 / (\alpha - ID)$
	if invAlphaMinusId.IsZero() {
		return nil, fmt.Errorf("your identity is invalid (ID equals alpha)") // ID = alpha 时无逆元
	}

	// 4. 计算 $h_{ID} = (h g_2^{-r_{ID}})^{\frac{1}{\alpha - ID}}$
	hid := new(bn254.G2Affine).ScalarMultiplication(hAddG2InvRid, invAlphaMinusId.BigInt(new(big.Int)))
	if err != nil {
		return nil, fmt.Errorf("failed to generate key")
	}
	return &Gentry06CPAIBESecretKey{
		rid: *rid,
		hid: *hid,
	}, nil
}

// Encrypt 使用指定用户身份对 GT 群上的消息 M 进行加密，生成密文 $C=(u, v, w)$。
// 该方法实现了基于身份的加密算法。
//
// 参数:
//   - identity: 接收者的身份标识符
//   - message: 要加密的明文消息(字节数组)
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *Gentry06IBECiphertext: 加密后的密文
//   - error: 如果加密失败，返回错误信息
func (instance *Gentry06CPAIBEInstance) Encrypt(message *Gentry06CPAIBEMessage, identity *Gentry06CPAIBEIdentity, publicParams *Gentry06CPAIBEPublicParams) (*Gentry06CPAIBECiphertext, error) {
	var err error
	s, err := new(fr.Element).SetRandom() // 1. 随机选取 s 属于 Zp

	// 计算 $g_1^{\alpha s}$
	g1AlphaS := new(bn254.G1Affine).ScalarMultiplication(&publicParams.g1Alpha, s.BigInt(new(big.Int)))

	// 计算 $g_1^{-s \cdot ID}$
	sId := new(fr.Element).Mul(s, &identity.Id) // s * ID
	negSId := new(fr.Element).Neg(sId)          // -s * ID
	g1NegSId := new(bn254.G1Affine).ScalarMultiplicationBase(negSId.BigInt(new(big.Int)))

	// 2. 计算 $u = g_1^{\alpha s} \cdot g_1^{-s \cdot ID}$
	u := new(bn254.G1Affine).Add(g1AlphaS, g1NegSId)

	// 3. 计算 $v = e(g_1, g_2)^s$
	eG1G2, err := bn254.Pair([]bn254.G1Affine{publicParams.g1}, []bn254.G2Affine{publicParams.g2})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	v := new(bn254.GT).Exp(eG1G2, s.BigInt(new(big.Int)))

	// 4. 计算 $w = M \cdot e(g_1, h)^{-s}$
	eG1H, err := bn254.Pair([]bn254.G1Affine{publicParams.g1}, []bn254.G2Affine{publicParams.h})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	negS := new(fr.Element).Neg(s)
	// 计算 $e(g_1, h)^{-s}$
	w := new(bn254.GT).Exp(eG1H, negS.BigInt(new(big.Int)))
	// 计算 $w = M \cdot e(g_1, h)^{-s}$
	w = new(bn254.GT).Mul(w, &message.Message)

	return &Gentry06CPAIBECiphertext{
		u: *u,
		v: *v,
		w: *w,
	}, nil
}

// Decrypt 使用私钥 $d_{ID} = (r_{ID}, h_{ID})$ 对密文 $C=(u, v, w)$ 进行解密。
// 解密恢复原始明文消息 $M$。
//
// 参数:
//   - ciphertext: 要解密的密文
//   - secretKey: 用户的私钥
//   - publicParams: 系统公共参数
//
// 步骤:
// 1. 计算 $e(u, h_{ID})$。
// 2. 计算 $v^{r_{ID}}$。
// 3. 计算 $M = w \cdot e(u, h_{ID}) \cdot v^{r_{ID}}$。
//
// 返回值:
//   - *Gentry06IBEMessage: 解密后的明文消息
//   - error: 如果解密失败，返回错误信息
func (instance *Gentry06CPAIBEInstance) Decrypt(ciphertext *Gentry06CPAIBECiphertext, secretKey *Gentry06CPAIBESecretKey, publicParams *Gentry06CPAIBEPublicParams) (*Gentry06CPAIBEMessage, error) {
	var err error
	// 1. 计算 $e(u, h_{ID})$
	eUHid, err := bn254.Pair([]bn254.G1Affine{ciphertext.u}, []bn254.G2Affine{secretKey.hid})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext")
	}
	// 2. 计算 $v^{r_{ID}}$
	vRid := new(bn254.GT).Exp(ciphertext.v, secretKey.rid.BigInt(new(big.Int)))

	// 3. 计算 $M = w \cdot e(u, h_{ID}) \cdot v^{r_{ID}}$
	// m = w * e(u, h_ID)
	m := new(bn254.GT).Mul(&ciphertext.w, &eUHid)
	// m = (w * e(u, h_ID)) * v^r_ID
	m.Mul(m, vRid)

	return &Gentry06CPAIBEMessage{
		Message: *m,
	}, nil
}

// NewGentry06CPAIBEIdentity 将大整数类型的 ID 转换为 IBE 方案使用的 fr.Element 身份结构体。
func NewGentry06CPAIBEIdentity(identity *big.Int) (*Gentry06CPAIBEIdentity, error) {
	return &Gentry06CPAIBEIdentity{
		Id: *new(fr.Element).SetBigInt(identity), // 将 big.Int 映射到 Zp 域元素
	}, nil
}
