package fibe

// 作者: mmsyan
// 日期: 2025-11-16
// 参考论文:
// Amit Sahai and Brent Waters. "Fuzzy Identity-Based Encryption."
// In Advances in Cryptology - EUROCRYPT 2005, pp. 457-473. Springer, 2005.
//
// 论文链接: https://link.springer.com/chapter/10.1007/11424793_27
// 预印本: https://eprint.iacr.org/2004/086.pdf
//
// 该实现基于BN254椭圆曲线和配对运算,实现了Sahai-Waters (SW05) 提出的
// "Large Universe" 模糊身份基加密(FIBE)方案。
//
// 主要特点:
//   - **容错性/门限解密:** 密文和私钥各关联一个属性集,只要这两个集合的交集大小
//     超过预设的门限距离 d,即可成功解密。
//   - **大域支持:** 属性集可以从一个较大的域(整数集)中选取。
//   - **配对基加密:** 利用双线性对的性质实现密文和私钥的匹配。
//
// 系统功能包括:
//   - 系统初始化(SetUp)
//   - 密钥生成(KeyGenerate)
//   - 加密(Encrypt)
//   - 解密(Decrypt)

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/utils"
	"math/big"
)

// SW05FIBELargeUniverseInstance 表示Sahai-Waters 2005大域模糊身份基加密(FIBE)方案的实例对象。
// 该实例主要由密钥生成中心(PKG)维护。
type SW05FIBELargeUniverseInstance struct {
	distance int // **容错距离 d (门限值):** 只有当用户属性集和密文属性集的交集大小
	// 大于等于 d 时,解密才能成功。
	msk_y fr.Element // **主密钥组件 y:** PKG持有的主密钥,是 Zq 域上的一个随机元素。
	// 用于在 SetUp 阶段计算公开参数 pk_Y,并在 KeyGenerate 阶段
	// 秘密地用于构造私钥。
}

// SW05FIBELargeUniversePublicParams 表示SW05 FIBE方案的公共参数。
// 这些参数在系统初始化时生成,可以公开发布。
type SW05FIBELargeUniversePublicParams struct {
	n  int64                    // **最大属性集大小/域上限:** 方案中使用的最大属性值范围,即属性集 I = {1, ..., n} 的大小。
	g1 bn254.G1Affine           // **G1 生成元 g1。**
	g2 bn254.G2Affine           // **G2 生成元 g2。**
	ti map[int64]bn254.G2Affine // **G2 群上的随机点 T_i':** 一组随机的 G2 群元素,i 属于 {1, ..., n+1}。
	// 用于在 SetUp 阶段定义 T_i 函数 (computeT)。
	pk_Y bn254.GT // **公开参数 pk_Y:** GT 群上的元素 Y = e(g1, g2)^y,由主密钥 y 派生。
}

// SW05FIBELargeUniverseSecretKey 表示SW05 FIBE方案中的用户私钥。
// 该私钥由 PKG 为用户的特定属性集 S_user 生成。
type SW05FIBELargeUniverseSecretKey struct {
	userAttributes []fr.Element                  // **用户拥有的属性集 S_user。**
	_di            map[fr.Element]bn254.G1Affine // **私钥组件 d_i:** 对应 S_user 中每个属性 i 的 G1 群元素,
	// 形式为 $d_i = g_1^{r_i}$, $r_i$ 是密钥生成时的随机数。
	_Di map[fr.Element]bn254.G2Affine // **私钥组件 D_i:** 对应 S_user 中每个属性 i 的 G2 群元素,
	// 形式为 $D_i = g_2^{q(i)} \cdot T_i^{r_i}$。
	// 其中 $q(x)$ 是一个度为 $d-1$ 且 $q(0)=y$ 的多项式。
}

// SW05FIBELargeUniverseMessage 表示SW05 FIBE方案中的明文消息。
// 明文必须是 GT 群上的元素。
type SW05FIBELargeUniverseMessage struct {
	Message bn254.GT // **GT 群上的消息 M。**
}

// SW05FIBELargeUniverseCiphertext 表示SW05 FIBE方案中的密文。
// 密文是针对一个属性集 S_msg 加密的。
type SW05FIBELargeUniverseCiphertext struct {
	messageAttributes []fr.Element                  // **密文关联的属性集 S_msg。**
	ePrime            bn254.GT                      // **密文组件 e':** $e' = M \cdot Y^s$, 其中 $s$ 是加密随机数。
	ePrimePrime       bn254.G1Affine                // **密文组件 E'':** $E'' = g_1^s$。
	ei                map[fr.Element]bn254.G2Affine // **密文组件 E_i:** 对应 S_msg 中每个属性 i 的 G2 群元素,
	// 形式为 $E_i = T_i^s$。
}

// NewSW05FIBELargeUniverseInstance 创建一个新的Sahai-Waters FIBE方案实例。
// 该函数会初始化容错距离 d,并随机生成主密钥组件 y。
//
// 参数:
//   - distance: 容错门限 d。
//
// 返回值:
//   - *SW05FIBELargeUniverseInstance: 包含容错距离和主密钥 y 的 FIBE 实例。
func NewSW05FIBELargeUniverseInstance(distance int) *SW05FIBELargeUniverseInstance {
	var msk_y fr.Element
	// 忽略错误检查,假设SetRandom成功
	_, _ = msk_y.SetRandom()
	// 使用 &SW05FIBEInstance{} 语法创建一个结构体实例并返回其指针。
	return &SW05FIBELargeUniverseInstance{
		distance: distance,
		msk_y:    msk_y,
	}
}

// SetUp 执行系统初始化操作,生成并返回公共参数。
// 该方法设置属性域大小 n,并基于主密钥 y 生成公开参数 Y 和辅助参数 T_i'。
//
// 参数:
//   - n: 属性集 I = {1, ..., n} 的上限。
//
// 返回值:
//   - *SW05FIBELargeUniversePublicParams: 系统公共参数。
//   - error: 如果初始化失败,返回错误信息。
func (instance *SW05FIBELargeUniverseInstance) SetUp(n int64) (*SW05FIBELargeUniversePublicParams, error) {
	// 获取 G1 和 G2 群的生成元 g1, g2。
	_, _, g1, g2 := bn254.Generators()
	ti := make(map[int64]bn254.G2Affine)

	// 生成 n+1 个 G2 群上的随机点 T_i'。
	for i := int64(1); i <= n+1; i++ {
		temp, err := new(fr.Element).SetRandom() // t_i' <- Zq
		if err != nil {
			return nil, fmt.Errorf("fibe instance setup failure")
		}
		ti[i] = *new(bn254.G2Affine).ScalarMultiplicationBase(temp.BigInt(new(big.Int)))
	}

	// 计算 Y = e(g1, g2)^y。
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2}) // e(g1, g2)
	if err != nil {
		return nil, fmt.Errorf("fibe instance setup failure")
	}
	pk_Y := *new(bn254.GT).Exp(eG1G2, instance.msk_y.BigInt(new(big.Int)))

	return &SW05FIBELargeUniversePublicParams{
		n:    n,
		g1:   g1,
		g2:   g2,
		ti:   ti,
		pk_Y: pk_Y,
	}, nil
}

// KeyGenerate 为指定的属性集 S_user 生成私钥。
// PKG 使用主密钥 y 和拉格朗日插值技术来构造私钥。
//
// 参数:
//   - userAttributes: 用户的属性集 S_user。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *SW05FIBELargeUniverseSecretKey: 生成的私钥。
//   - error: 如果密钥生成失败,返回错误信息。
func (instance *SW05FIBELargeUniverseInstance) KeyGenerate(userAttributes *SW05FIBEAttributes, publicParams *SW05FIBELargeUniversePublicParams) (*SW05FIBELargeUniverseSecretKey, error) {
	di := make(map[fr.Element]bn254.G1Affine)
	Di := make(map[fr.Element]bn254.G2Affine)

	// 1. 生成一个 d-1 次的多项式 q(x), 满足 q(0) = y。
	// q(x) = y + \sum_{j=1}^{d-1} a_j x^j
	polynomial := utils.GenerateRandomPolynomial(instance.distance, instance.msk_y)

	// 2. 为 S_user 中的每个属性 i 计算私钥组件。
	for _, i := range userAttributes.attributes {
		// 随机数 r_i <- Zq。
		ri, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("fibe instance setup failure")
		}

		// 计算 d_i = g1^{r_i}。
		di[i] = *new(bn254.G1Affine).ScalarMultiplicationBase(ri.BigInt(new(big.Int)))

		// 计算 q(i)。
		qi := utils.ComputePolynomialValue(polynomial, i)

		// 计算 g2^{q(i)}。
		g2ExpQi := new(bn254.G2Affine).ScalarMultiplicationBase(qi.BigInt(new(big.Int)))

		// 计算 T_i = g2^t(i), 其中 t(i) 是一个复杂的拉格朗日插值多项式。
		ti := publicParams.computeT(i)

		// 计算 T_i^{r_i}。
		tiExpRi := new(bn254.G2Affine).ScalarMultiplication(&ti, ri.BigInt(new(big.Int)))

		// 计算 D_i = g2^{q(i)} \cdot T_i^{r_i}。
		Di[i] = *new(bn254.G2Affine).Add(g2ExpQi, tiExpRi)
	}

	return &SW05FIBELargeUniverseSecretKey{
		userAttributes: userAttributes.attributes,
		_di:            di,
		_Di:            Di,
	}, nil
}

// Encrypt 使用指定的属性集 S_msg 对消息 M 进行加密。
//
// 参数:
//   - messageAttributes: 密文关联的属性集 S_msg。
//   - message: 要加密的明文 M。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *SW05FIBELargeUniverseCiphertext: 加密后的密文。
//   - error: 如果加密失败,返回错误信息。
func (instance *SW05FIBELargeUniverseInstance) Encrypt(messageAttributes *SW05FIBEAttributes, message *SW05FIBELargeUniverseMessage, publicParams *SW05FIBELargeUniversePublicParams) (*SW05FIBELargeUniverseCiphertext, error) {
	// 1. 选择一个随机数 s <- Zq。
	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt Message")
	}

	// 2. 计算 Y^s。
	egg_ys := *(new(bn254.GT)).Exp(publicParams.pk_Y, s.BigInt(new(big.Int)))

	// 3. 计算密文组件 e' = M * Y^s。
	ePrime := *new(bn254.GT).Mul(&message.Message, &egg_ys)

	// 4. 计算密文组件 E'' = g1^s。
	ePrimePrime := *new(bn254.G1Affine).ScalarMultiplicationBase(s.BigInt(new(big.Int)))

	// 5. 为 S_msg 中的每个属性 i 计算密文组件 E_i。
	ei := make(map[fr.Element]bn254.G2Affine)
	for _, i := range messageAttributes.attributes {
		// 计算 T_i = g2^t(i)。
		ti := publicParams.computeT(i)
		// 计算 E_i = T_i^s。
		ei[i] = *new(bn254.G2Affine).ScalarMultiplication(&ti, s.BigInt(new(big.Int)))
	}

	return &SW05FIBELargeUniverseCiphertext{
		messageAttributes: messageAttributes.attributes,
		ePrime:            ePrime,
		ePrimePrime:       ePrimePrime,
		ei:                ei,
	}, nil
}

// Decrypt 使用私钥对密文进行解密。
// 只有当用户属性集 S_user 和密文属性集 S_msg 的交集大小 $\ge d$ 时,解密才能成功。
// 解密核心是利用拉格朗日插值恢复 $Y^s = e(g_1, g_2)^{ys}$ 并计算 $M = e' / Y^s$。
//
// 参数:
//   - userSecretKey: 用户的私钥。
//   - ciphertext: 要解密的密文。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *SW05FIBELargeUniverseMessage: 解密后的明文消息 M。
//   - error: 如果解密失败(如交集属性不足 d 个),返回错误信息。
func (instance *SW05FIBELargeUniverseInstance) Decrypt(userSecretKey *SW05FIBELargeUniverseSecretKey, ciphertext *SW05FIBELargeUniverseCiphertext, publicParams *SW05FIBELargeUniversePublicParams) (*SW05FIBELargeUniverseMessage, error) {
	// 1. 找到 S_user 和 S_msg 之间的公共属性子集 S, 且 |S| \ge d。
	s := utils.FindCommonAttributes(userSecretKey.userAttributes, ciphertext.messageAttributes, instance.distance)
	if s == nil {
		return nil, fmt.Errorf("failed to find enough common attributes")
	}

	// 2. 初始化分母 D = e(g_1, g_2)^{-ys} (在配对运算后计算)。
	denominator := new(bn254.GT).SetOne()

	// 3. 遍历公共属性集 S 中的每个属性 i, 利用拉格朗日插值计算 Y^s 的逆。
	for _, i := range s {
		di := userSecretKey._di[i]            // $d_i = g_1^{r_i}$
		Di := userSecretKey._Di[i]            // $D_i = g_2^{q(i)} \cdot T_i^{r_i}$
		ei := ciphertext.ei[i]                // $E_i = T_i^s$
		ePrimePrime := ciphertext.ePrimePrime // $E'' = g_1^s$

		// 计算配对项 1: $e(d_i, E_i) = e(g_1^{r_i}, T_i^s) = e(g_1, T_i)^{r_i s}$。
		ediEi, err := bn254.Pair([]bn254.G1Affine{di}, []bn254.G2Affine{ei})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt Message")
		}

		// 计算配对项 2: $e(E'', D_i) = e(g_1^s, g_2^{q(i)} \cdot T_i^{r_i}) = e(g_1, g_2)^{s q(i)} \cdot e(g_1, T_i)^{s r_i}$。
		eDiEPrimePrime, err := bn254.Pair([]bn254.G1Affine{ePrimePrime}, []bn254.G2Affine{Di})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt Message")
		}

		// 计算 $P_i = \frac{e(d_i, E_i)}{e(E'', D_i)} = \frac{e(g_1, T_i)^{r_i s}}{e(g_1, g_2)^{s q(i)} \cdot e(g_1, T_i)^{s r_i}} = e(g_1, g_2)^{-s q(i)}$。
		pairDiv := new(bn254.GT).Div(&ediEi, &eDiEPrimePrime)

		// 计算拉格朗日基多项式 $\Delta_{0, S}(i) = \prod_{j \in S, j \neq i} \frac{0 - j}{i - j}$。
		delta := utils.ComputeLagrangeBasis(i, s, *new(fr.Element).SetZero())

		// 计算 $P_i^{\Delta_{0, S}(i)} = e(g_1, g_2)^{-s q(i) \cdot \Delta_{0, S}(i)}$。
		pairExpDelta := new(bn254.GT).Exp(*pairDiv, delta.BigInt(new(big.Int)))

		// 累乘到分母中。根据拉格朗日插值性质, $\prod_{i \in S} e(g_1, g_2)^{-s q(i) \cdot \Delta_{0, S}(i)} = e(g_1, g_2)^{-s q(0)} = e(g_1, g_2)^{-s y} = Y^{-s}$。
		denominator.Mul(denominator, pairExpDelta)
	}

	// 4. 计算 $M = e' \cdot Y^{-s} = (M \cdot Y^s) \cdot Y^{-s}$。
	m := new(bn254.GT).Mul(&ciphertext.ePrime, denominator)
	return &SW05FIBELargeUniverseMessage{
		Message: *m,
	}, nil
}

// computeT 是一个辅助函数,用于计算 G2 群元素 $T_x = g_2^{t(x)}$。
// 其中 $t(x)$ 是一个与 n 个随机点 $T_i'$ 相关的拉格朗日插值多项式。
// $T_x = g_2^{x^n} \cdot \prod_{i=1}^{n+1} (T_i')^{\Delta_{x, N}(i)}$, 其中 $N=\{1, \dots, n+1\}$。
//
// 参数:
//   - x: 属性值 x。
//
// 返回值:
//   - bn254.G2Affine: G2 群上的元素 $T_x$。
func (publicParams *SW05FIBELargeUniversePublicParams) computeT(x fr.Element) bn254.G2Affine {
	// 1. 计算 $g_2^{x^n}$。
	xElement := new(fr.Element).Set(&x)
	nElement := new(fr.Element).SetInt64(int64(publicParams.n))
	xExpN := new(fr.Element).Exp(*xElement, nElement.BigInt(new(big.Int)))
	g2ExpXExpN := new(bn254.G2Affine).ScalarMultiplicationBase(xExpN.BigInt(new(big.Int)))

	// 构造集合 N = {1, ..., n+1}。
	N := make([]fr.Element, publicParams.n+1)
	for i := 0; i < len(N); i++ {
		N[i] = *new(fr.Element).SetInt64(int64(i + 1))
	}

	// 2. 计算 $\prod_{i=1}^{n+1} (T_i')^{\Delta_{x, N}(i)}$ 并累加到 $g_2^{x^n}$ 上。
	// 注意: 代码中的循环索引从 0 开始,与论文中的 $i \in \{1, \dots, n+1\}$ 可能不完全对应,
	// 假定 utils2.ComputeLagrangeBasis 和 publicParams.ti 的索引处理是正确的。
	for i := int64(0); i < int64(len(publicParams.ti)); i++ {
		// 计算 $\Delta_{x, N}(i) = \prod_{j \in N, j \neq i} \frac{x - j}{i - j}$。
		// 这里的 i 应该代表 N 中的元素。
		delta := utils.ComputeLagrangeBasis(*new(fr.Element).SetInt64(i), N, x)
		ti := publicParams.ti[i] // $T_i'$
		tiExpDelta := new(bn254.G2Affine).ScalarMultiplication(&ti, delta.BigInt(new(big.Int)))
		g2ExpXExpN.Add(g2ExpXExpN, tiExpDelta)
	}

	return *g2ExpXExpN
}
