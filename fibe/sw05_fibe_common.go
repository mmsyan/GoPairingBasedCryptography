package fibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GoPairingBasedCryptography/utils"
	"math/big"
)

// 作者: mmsyan
// 日期: 2025-11-16
// 参考论文:
// Sahai, A., Waters, B. (2005). Fuzzy Identity-Based Encryption. In: Cramer, R. (eds) Advances in Cryptology – EUROCRYPT 2005.
// EUROCRYPT 2005. Lecture Notes in Computer Science, vol 3494. Springer, Berlin, Heidelberg.
// https://doi.org/10.1007/11426639_27
//
// 论文链接: https://link.springer.com/chapter/10.1007/11426639_27
//
// 该实现基于BN254椭圆曲线和配对运算，是一个容错的基于属性的加密方案。
// 它可以容忍用户属性集与密文属性集之间的“模糊”匹配（即存在一定数量的交集），
// 只有当两个集合的交集大小达到或超过预设的容错距离时，解密才能成功。
//
// 主要功能包括:
//   - 系统初始化 (SetUp)
//   - 用户私钥生成 (KeyGenerate)
//   - 加密 (Encrypt)
//   - 解密 (Decrypt)
//
// 方案特性:
//   - **容错性 (Fuzzy)**: 解密成功依赖于属性集交集大小（匹配度）。
//   - **基于拉格朗日插值**: 利用拉格朗日插值多项式和门限加密技术实现容错逻辑。

// SW05FIBEInstance 表示模糊身份基加密 (FIBE) 方案的实例对象。
// 包含了方案运行所需的系统参数和主密钥。
type SW05FIBEInstance struct {
	universe map[fr.Element]struct{}   // 属性宇宙 U（所有合法属性）
	distance int                       // 容错距离 d（最小匹配属性数量）
	msk_ti   map[fr.Element]fr.Element // 主密钥组件：t_i（每个属性对应一个随机数）
	msk_y    fr.Element                // 主密钥组件：y（共享秘密）
}

// SW05FIBEPublicParams 表示 FIBE 方案的公共参数。
// 这些参数在系统初始化时生成并公开发布，用于密钥生成、加密和解密操作。
type SW05FIBEPublicParams struct {
	g1    bn254.G1Affine                // G1 群的生成元 g1。
	g2    bn254.G2Affine                // G2 群的生成元 g2。
	pk_Ti map[fr.Element]bn254.G2Affine // 公钥组件 T_i = g2^t_i，对应第 i 个属性。
	pk_Y  bn254.GT                      // 公钥组件 Y = e(g1, g2)^y，GT 群上的元素。
}

// SW05FIBESecretKey 表示用户的私钥。
// 私钥与用户的属性集相关联，用于对匹配的密文进行解密。
type SW05FIBESecretKey struct {
	userAttributes []fr.Element                  // 用户拥有的属性集 S_user。
	di             map[fr.Element]bn254.G1Affine // 私钥组件 D_i，Di = g1^(q(i)/t_i)，对应 S_user 中的每个属性 i。
}

// SW05FIBEMessage 表示要加密或解密的消息。
// 消息是一个 GT 群上的元素。
type SW05FIBEMessage struct {
	Message bn254.GT // GT 群上的消息 M。
}

// SW05FIBECiphertext 表示加密后的密文。
// 密文与一个属性集相关联，只有属性集匹配的用户才能解密。
type SW05FIBECiphertext struct {
	messageAttributes []fr.Element                  // 密文关联的属性集 S_msg。
	ePrime            bn254.GT                      // 密文组件 e' = M * Y^s，其中 s 是加密随机数。
	ei                map[fr.Element]bn254.G2Affine // 密文组件 E_i = (T_i)^s，对应 S_msg 中的每个属性 i。
}

// NewSW05FIBEInstanceByElements 创建一个新的 FIBE 方案实例。
//
// Parameters:
// - universe: 属性宇宙U，直接以 []fr.Element 形式传入。
// - distance: 容错距离 d（解密所需的最小属性匹配数量）。
//
// Returns:
// - *SW05FIBEInstance: 初始化后的 FIBE 实例指针。
func NewSW05FIBEInstanceByElements(universe []fr.Element, distance int) *SW05FIBEInstance {
	// 使用 &SW05FIBEInstance{} 语法创建一个结构体实例并返回其指针。
	attributesUniverse := make(map[fr.Element]struct{}, len(universe))
	for _, u := range universe {
		attributesUniverse[u] = struct{}{}
	}
	return &SW05FIBEInstance{
		universe: attributesUniverse,
		distance: distance,
		msk_ti:   make(map[fr.Element]fr.Element),
	}
}

// NewSW05FIBEInstanceByInt64Slice 创建一个新的 FIBE 方案实例。
//
// Parameters:
// - universe: 属性宇宙U，以 []int64 切片形式传入，每个 int64 会被转换为 fr.Element。
// - distance: 容错距离 d（解密所需的最小属性匹配数量）。
//
// Returns:
// - *SW05FIBEInstance: 初始化后的 FIBE 实例指针。
func NewSW05FIBEInstanceByInt64Slice(universe []int64, distance int) *SW05FIBEInstance {
	attributesUniverse := make(map[fr.Element]struct{}, len(universe))
	for _, u := range universe {
		uElement := *new(fr.Element).SetInt64(u)
		attributesUniverse[uElement] = struct{}{}
	}
	return &SW05FIBEInstance{
		universe: attributesUniverse,
		distance: distance,
		msk_ti:   make(map[fr.Element]fr.Element),
	}
}

// NewSW05FIBEInstanceByInt64Pair 创建一个新的 FIBE 方案实例（连续整数区间）。
//
// Parameters:
// - start: 属性宇宙的起始整数（包含）。
// - end:   属性宇宙的结束整数（不包含），即生成 [start, end) 区间内的所有整数属性。
// - distance: 容错距离 d（解密所需的最小属性匹配数量）。
//
// Returns:
// - *SW05FIBEInstance: 初始化后的 FIBE 实例指针。
//
// Example:
//
//	NewSW05FIBEInstanceByInt64Pair(1, 101, 10)  // 生成属性宇宙 {1,2,...,100}
func NewSW05FIBEInstanceByInt64Pair(start int64, end int64, distance int) *SW05FIBEInstance {
	attributesUniverse := make(map[fr.Element]struct{}, end-start)
	for i := start; i < end; i++ {
		u := *new(fr.Element).SetInt64(i)
		attributesUniverse[u] = struct{}{}
	}
	return &SW05FIBEInstance{
		universe: attributesUniverse,
		distance: distance,
		msk_ti:   make(map[fr.Element]fr.Element),
	}
}

// SetUp 执行系统初始化操作，生成主密钥和公共参数。
// 主密钥 (msk_ti, msk_y) 必须保密，公共参数 (g1, g2, pk_Ti, pk_Y) 公开发布。
//
// 返回值:
//   - *SW05FIBEPublicParams: 系统公共参数指针。
//   - error: 如果初始化失败（如随机数生成失败），返回错误信息。
func (instance *SW05FIBEInstance) SetUp() (*SW05FIBEPublicParams, error) {
	// 获取 G1 和 G2 群的生成元。
	_, _, g1, g2 := bn254.Generators()

	// 随机生成属性主密钥 t_i，并计算公钥组件 T_i = g2^t_i。
	pk_Ti := make(map[fr.Element]bn254.G2Affine)
	for i := range instance.universe {
		temp, err := new(fr.Element).SetRandom() // t_i <- Zq
		if err != nil {
			return nil, fmt.Errorf("fibe instance setup failure")
		}
		instance.msk_ti[i] = *temp
		pk_Ti[i] = *new(bn254.G2Affine).ScalarMultiplicationBase(temp.BigInt(new(big.Int))) // T_i = g2^t_i
	}

	// 随机生成主密钥 y，并计算公钥组件 Y = e(g1, g2)^y。
	temp, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("fibe instance setup failure")
	}
	instance.msk_y = *temp                                               // y <- Zq
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2}) // e(g1, g2)
	// Y = e(g1, g2)^y
	pk_Y := *new(bn254.GT).Exp(eG1G2, instance.msk_y.BigInt(new(big.Int)))

	if err != nil {
		return nil, err
	}

	// 返回公共参数。
	return &SW05FIBEPublicParams{
		g1:    g1,
		g2:    g2,
		pk_Ti: pk_Ti,
		pk_Y:  pk_Y,
	}, nil

}

// KeyGenerate 为具有指定属性集的用户生成私钥。
// 该过程由密钥生成中心 (PKG) 使用主密钥完成。
//
// 参数:
//   - userAttributes: 用户的属性集 S_user。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *SW05FIBESecretKey: 生成的用户私钥指针。
//   - error: 如果属性集无效或密钥生成失败，返回错误信息。
func (instance *SW05FIBEInstance) KeyGenerate(userAttributes *SW05FIBEAttributes, publicParams *SW05FIBEPublicParams) (*SW05FIBESecretKey, error) {
	// 检查属性集是否有效
	if !instance.isValidAttributes(userAttributes.attributes) {
		return nil, fmt.Errorf("invalid user attributes")
	}

	di := make(map[fr.Element]bn254.G1Affine)

	// 生成一个 d-1 阶的随机多项式 q(x)，满足 q(0) = y = msk_y。
	polynomial := utils.GenerateRandomPolynomial(instance.distance, instance.msk_y)

	// 为用户属性集 S_user 中的每个属性 i 计算私钥组件 D_i。
	for _, i := range userAttributes.attributes {
		// 计算 q(i)。
		qi := utils.ComputePolynomialValue(polynomial, i)

		// 在有限域 F_q 内计算除法：qiDivTi = q(i) * (t_i)^{-1} mod q。
		ti := instance.msk_ti[i]
		tiInverse := new(fr.Element).Inverse(&ti)
		qiDivTi := new(fr.Element).Mul(&qi, tiInverse)

		// 计算私钥组件 D_i = g1^(q(i)/t_i)。
		di[i] = *new(bn254.G1Affine).ScalarMultiplicationBase(qiDivTi.BigInt(new(big.Int)))
	}

	return &SW05FIBESecretKey{
		userAttributes: userAttributes.attributes,
		di:             di,
	}, nil
}

// Encrypt 使用指定的属性集对消息进行加密。
//
// 参数:
//   - messageAttributes: 密文关联的属性集 S_msg。
//   - message: 要加密的明文消息 M。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *SW05FIBECiphertext: 生成的密文指针。
//   - error: 如果属性集无效或加密失败，返回错误信息。
func (instance *SW05FIBEInstance) Encrypt(messageAttributes *SW05FIBEAttributes, message *SW05FIBEMessage, publicParams *SW05FIBEPublicParams) (*SW05FIBECiphertext, error) {
	// 检查属性集是否有效。
	if !instance.isValidAttributes(messageAttributes.attributes) {
		return nil, fmt.Errorf("invalid message attributes")
	}

	// 选择一个随机数 s <- Zq。
	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt MessageBytes")
	}

	// 计算 Y^s = (e(g1, g2)^y)^s。
	egg_ys := *(new(bn254.GT)).Exp(publicParams.pk_Y, s.BigInt(new(big.Int)))

	// 计算密文组件 e' = M * Y^s。
	ePrime := *new(bn254.GT).Mul(&message.Message, &egg_ys)

	// 为密文属性集 S_msg 中的每个属性 i 计算密文组件 E_i。
	// E_i = (T_i)^s = (g2^t_i)^s。
	ei := map[fr.Element]bn254.G2Affine{}
	for _, i := range messageAttributes.attributes {
		// E_i = (pk_Ti[i])^s。
		ti := publicParams.pk_Ti[i]
		ei[i] = *(&bn254.G2Affine{}).ScalarMultiplication(&ti, s.BigInt(new(big.Int)))
	}

	return &SW05FIBECiphertext{
		messageAttributes: messageAttributes.attributes,
		ePrime:            ePrime,
		ei:                ei,
	}, nil

}

// Decrypt 使用用户的私钥对密文进行解密。
// 解密成功的条件是：用户属性集 S_user 与密文属性集 S_msg 的交集大小至少为容错距离 d。
// 即：|S_user ∩ S_msg| >= d。
//
// 参数:
//   - userSecretKey: 用户的私钥。
//   - ciphertext: 要解密的密文。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *SW05FIBEMessage: 解密后的明文消息指针。
//   - error: 如果属性集无效或交集数量不足 d，返回错误信息。
func (instance *SW05FIBEInstance) Decrypt(userSecretKey *SW05FIBESecretKey, ciphertext *SW05FIBECiphertext, publicParams *SW05FIBEPublicParams) (*SW05FIBEMessage, error) {
	// 检查属性集是否有效。
	if !instance.isValidAttributes(userSecretKey.userAttributes) {
		return nil, fmt.Errorf("invalid user attributes")
	}
	if !instance.isValidAttributes(ciphertext.messageAttributes) {
		return nil, fmt.Errorf("invalid cipher text")
	}

	// 查找用户属性集和密文属性集之间的公共属性集 S = S_user ∩ S_msg。
	// 如果 |S| < d，则返回 nil，表示匹配失败。
	s := utils.FindCommonAttributes(userSecretKey.userAttributes, ciphertext.messageAttributes, instance.distance)
	if s == nil {
		return nil, fmt.Errorf("failed to find enough common attributes")
	}

	// 初始化分母 Denominator = ∏_{i ∈ S} e(D_i, E_i)^(Δ_{0, S}(i))。
	denominator := bn254.GT{}
	denominator.SetOne()

	// 遍历公共属性集 S 中的每个属性 i。
	for _, i := range s {
		di := userSecretKey.di[i] // 私钥组件 D_i = g1^(q(i)/t_i)
		ei := ciphertext.ei[i]    // 密文组件 E_i = g2^(t_i * s)

		// 计算配对 e(D_i, E_i) = e(g1^(q(i)/t_i), g2^(t_i * s)) = e(g1, g2)^(q(i) * s)。
		eDiEi, err := bn254.Pair([]bn254.G1Affine{di}, []bn254.G2Affine{ei})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt MessageBytes")
		}

		// 计算拉格朗日基多项式 Δ_{0, S}(i) = ∏_{j ∈ S, j ≠ i} (0 - j) / (i - j)。
		delta := utils.ComputeLagrangeBasis(i, s, *new(fr.Element).SetZero())

		// 计算 e(D_i, E_i)^(Δ_{0, S}(i))。
		eDiEiDelta := new(bn254.GT).Exp(eDiEi, delta.BigInt(new(big.Int)))

		// 累乘到分母中。
		denominator.Mul(&denominator, eDiEiDelta)
	}

	// 解密恢复 M = e' / Denominator。
	// 由于 |S| >= d，拉格朗日插值多项式的性质保证：
	// Denominator = e(g1, g2)^(q(0) * s) = e(g1, g2)^(y * s) = Y^s。
	// 因此 M = (M * Y^s) / Y^s = M。
	decryptedMessage := new(bn254.GT).Div(&ciphertext.ePrime, &denominator)
	return &SW05FIBEMessage{Message: *decryptedMessage}, nil
}
