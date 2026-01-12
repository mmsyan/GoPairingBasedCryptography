// Package afp25_bibe
// implements the Amit Agarwal, Rex Fernando, Benny Pinkas's Batch scheme (AFP25).
// 作者: mmsyan
// 日期: 2025-12-30
// 参考论文:
// eprint: https://eprint.iacr.org/2024/1575
// Agarwal, A., Fernando, R., Pinkas, B. (2025).
// Efficiently-Thresholdizable Batched Identity Based Encryption, with Applications.
// In: Tauman Kalai, Y., Kamara, S.F. (eds) Advances in Cryptology – CRYPTO 2025. CRYPTO 2025.
// Lecture Notes in Computer Science, vol 16002. Springer, Cham.
// https://doi.org/10.1007/978-3-032-01881-6_3
//
// 本包实现了一个高效的批量身份加密(Batched Identity-Based Encryption, BIBE)方案。
// BIBE允许使用单个密钥对一批身份进行解密,相比传统IBE方案可以显著减少密钥管理开销。
//
// 方案包含以下主要操作:
//   - Setup: 初始化系统参数,设置批量大小
//   - KeyGen: 生成主公钥和主密钥
//   - Encrypt: 使用身份和批量标签加密消息
//   - Digest: 为一批身份生成批量摘要
//   - ComputeKey: 基于批量摘要计算解密密钥
//   - Decrypt: 使用解密密钥恢复明文消息
package afp25_bibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// BatchIBEParams 表示批量身份加密方案的系统参数。
// 这些参数在系统初始化时设置,定义了批量操作的规模限制。
type BatchIBEParams struct {
	B int
}

// MasterSecretKey 表示系统的主密钥(Master Secret Key)。
// 主密钥由可信的密钥生成中心(Key Generation Center, KGC)持有,
// 用于为用户身份生成解密密钥。主密钥必须严格保密。
type MasterSecretKey struct {
	Msk fr.Element
}

// MasterPublicKey 表示系统的主公钥(Master Public Key)。
// 主公钥可以公开发布,供所有用户用于加密操作和验证。
// 公钥包含预计算的幂次值,用于支持多项式运算和批量操作。
type MasterPublicKey struct {
	G1ExpTauPowers []bn254.G1Affine
	G2ExpTau       bn254.G2Affine
	G2ExpMsk       bn254.G2Affine
}

// Identity 表示用户的身份标识。
// 在身份加密方案中,身份可以是任意字符串(如邮箱地址、用户名等),
// 这里将身份映射为有限域元素以便进行代数运算。
type Identity struct {
	Id fr.Element
}

// BatchLabel 表示批量操作的标签。
// 标签用于将多个密文关联到同一个批量上下文,使得可以使用单个密钥解密。
// 标签可以是时间戳、会话ID或其他上下文信息。
type BatchLabel struct {
	T []byte
}

// BatchDigest 表示一批身份的批量摘要。
// 摘要是对身份集合的密码学承诺,用于生成批量解密密钥。
// 摘要的计算涉及多项式运算,确保只有正确的身份集合才能解密。
type BatchDigest struct {
	D bn254.G1Affine
}

// Message 表示待加密的明文消息。
// 消息被表示为GT群(目标群)中的元素,这是配对运算的输出群。
type Message struct {
	M bn254.GT
}

// Ciphertext 表示加密后的密文。
// 密文由两部分组成:C1提供密钥封装,C2是加密的消息。
// 解密需要正确的身份密钥和批量上下文信息。
type Ciphertext struct {
	C1 [3]bn254.G2Affine
	C2 bn254.GT
}

// SecretKey 表示用户的解密密钥(Secret Key)。
// 解密密钥由密钥生成中心(KGC)基于批量摘要和批量标签计算生成。
// 一个解密密钥可以解密发送给批量中任意身份的密文。
type SecretKey struct {
	Sk bn254.G1Affine
}

// Setup 初始化批量身份加密方案的系统参数。
//
// 该函数设置批量大小B,定义系统可以支持的最大批量身份数量。
// 批量大小影响主公钥的大小和系统的计算效率。
//
// 参数:
//   - B: 批量大小,必须至少为1。更大的B支持更大的批量,但会增加存储开销。
//
// 返回值:
//   - *BatchIBEParams: 初始化的系统参数
//   - error: 如果B无效(小于1)则返回错误
//
// 示例:
//
//	params, err := Setup(100) // 支持最多100个身份的批量
//	if err != nil {
//	    return fmt.Errorf("系统初始化失败: %w", err)
//	}
func Setup(B int) (*BatchIBEParams, error) {
	if B < 1 {
		return nil, fmt.Errorf("invalid B: %d", B)
	}
	return &BatchIBEParams{
		B: B,
	}, nil
}

// KeyGen 生成批量身份加密方案的主公钥和主密钥。
//
// 该函数是系统初始化的核心步骤,由可信的密钥生成中心(KGC)执行。
// 生成过程包括:
//  1. 随机选择主密钥msk和陷门值τ
//  2. 计算G1群中τ的幂次:[g1^τ, g1^τ², ..., g1^τ^B]
//  3. 计算G2群中的公钥分量:g2^τ和g2^msk
//
// 参数:
//   - params: 系统参数,包含批量大小B
//
// 返回值:
//   - *MasterPublicKey: 生成的主公钥(可以公开发布)
//   - *MasterSecretKey: 生成的主密钥(必须严格保密)
//   - error: 如果随机数生成失败则返回错误
//
// 示例:
//
//	mpk, msk, err := KeyGen(params)
//	if err != nil {
//	    return fmt.Errorf("密钥生成失败: %w", err)
//	}
//	// mpk可以公开,msk必须保密存储
func KeyGen(params *BatchIBEParams) (*MasterPublicKey, *MasterSecretKey, error) {
	msk, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate master secret key: %s", err)
	}
	tau, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate tau value: %s", err)
	}

	// [τ]1, [τ^2]1, ..., [τ^B]1
	tauPower := new(fr.Element).Set(tau)
	g1ExpTauPower := make([]bn254.G1Affine, params.B)
	for i := 0; i < params.B; i++ {
		g1ExpTauPower[i] = *new(bn254.G1Affine).ScalarMultiplicationBase(tauPower.BigInt(new(big.Int)))
		tauPower.Mul(tauPower, tau)
	}

	g2ExpTau := *new(bn254.G2Affine).ScalarMultiplicationBase(tau.BigInt(new(big.Int))) // [τ]2
	g2ExpMsk := *new(bn254.G2Affine).ScalarMultiplicationBase(msk.BigInt(new(big.Int))) // [msk]2
	return &MasterPublicKey{
			G1ExpTauPowers: g1ExpTauPower,
			G2ExpTau:       g2ExpTau,
			G2ExpMsk:       g2ExpMsk,
		}, &MasterSecretKey{
			Msk: *msk,
		}, nil
}

// Encrypt 使用主公钥对消息进行加密,生成可由指定身份解密的密文。
//
// 加密算法基于双线性配对构造密文,包含以下步骤:
//  1. 构造矩阵A,编码身份信息和公钥分量
//  2. 构造向量b,包含配对值e(h(t), g2^msk)
//  3. 随机选择向量r = (r₁, r₂)
//  4. 计算C1 = r^T · A,包含三个G2群元素
//  5. 计算C2 = r^T · b · M,在GT群中掩码消息
//
// 参数:
//   - pk: 主公钥,用于加密操作
//   - m: 待加密的明文消息,必须是GT群元素
//   - id: 接收者的身份标识
//   - t: 批量标签,用于关联批量上下文
//
// 返回值:
//   - *Ciphertext: 生成的密文,包含C1和C2两部分
//   - error: 如果配对计算失败则返回错误
//
// 密文结构:
//   - C1[0] = r₁·g2 + r₂·(g2^msk)
//   - C1[1] = r₁·(g2^id - g2^τ)
//   - C1[2] = -r₂·g2
//   - C2 = M · e(h(t), g2^msk)^r₂ · e(g1, g2)^r₁
//
// 安全性质:
//   - 每次加密使用新的随机数r₁和r₂,确保密文的随机性
//   - 只有拥有正确身份密钥的用户才能解密
//   - 批量标签t将密文绑定到特定批量上下文
//
// 示例:
//
//	ct, err := Encrypt(mpk, msg, userID, batchLabel)
//	if err != nil {
//	    return fmt.Errorf("加密失败: %w", err)
//	}
func Encrypt(pk *MasterPublicKey, m *Message, id *Identity, t *BatchLabel) (*Ciphertext, error) {
	var a [2][3]bn254.G2Affine
	_, _, _, g2 := bn254.Generators()
	a[0][0] = g2 // [1]2
	g2ExpId := new(bn254.G2Affine).ScalarMultiplicationBase(id.Id.BigInt(new(big.Int)))
	g2ExpIdDivTau := new(bn254.G2Affine).Sub(g2ExpId, &pk.G2ExpTau)
	a[0][1] = *g2ExpIdDivTau // [id]2-[τ]2
	a[0][2].SetInfinity()    // 0
	a[1][0] = pk.G2ExpMsk    //[msk]2
	a[1][1].SetInfinity()    // 0
	negG2 := new(bn254.G2Affine).Neg(&g2)
	a[1][2] = *negG2 // -[1]2

	var b [2]bn254.GT
	b[0] = *new(bn254.GT).SetOne() // [0]T

	eHtG2ExpMsk, err := bn254.Pair(
		[]bn254.G1Affine{h(t)},
		[]bn254.G2Affine{pk.G2ExpMsk},
	)
	if err != nil {
		return nil, err
	}
	b[1] = *new(bn254.GT).Inverse(&eHtG2ExpMsk) // -e(H(t), [msk]2)

	// (r1, r2) <- (Zp)^2
	randomFr := make([]*fr.Element, 2)
	for i := 0; i < len(randomFr); i++ {
		randomFr[i], err = new(fr.Element).SetRandom()
		if err != nil {
			return nil, err
		}
	}
	r1, r2 := randomFr[0], randomFr[1]

	// c1 = r^T * A
	var c1 [3]bn254.G2Affine
	for j := 0; j < 3; j++ {
		var temp1, temp2 bn254.G2Affine
		temp1.ScalarMultiplication(&a[0][j], r1.BigInt(new(big.Int)))
		temp2.ScalarMultiplication(&a[1][j], r2.BigInt(new(big.Int)))
		c1[j].Add(&temp1, &temp2)
	}

	// c2 = r^T · b + m
	var c2 bn254.GT
	var bPart1, bPart2 bn254.GT // r^T · b = b[0]^r1 * b[1]^r2
	bPart1.Exp(b[0], r1.BigInt(new(big.Int)))
	bPart2.Exp(b[1], r2.BigInt(new(big.Int)))

	c2.Mul(&bPart1, &bPart2)
	c2.Mul(&c2, &m.M)

	return &Ciphertext{
		C1: c1,
		C2: c2,
	}, nil

}

// Digest 为一批身份生成批量摘要。
//
// 批量摘要是身份集合的密码学承诺,用于生成批量解密密钥。
// 计算过程包括:
//  1. 构造以所有身份为根的多项式f(X) = ∏(X - id_i)
//  2. 展开多项式得到系数[c₀, c₁, ..., c_n]
//  3. 使用公钥中的τ幂次计算D = g1^f(τ) = g1^c₀ · (g1^τ)^c₁ · ... · (g1^τⁿ)^c_n
//
// 参数:
//   - pk: 主公钥,包含τ幂次用于多项式求值
//   - identities: 身份列表,表示批量中包含的所有身份
//
// 返回值:
//   - *BatchDigest: 生成的批量摘要
//   - error: 如果身份列表为空或超过批量大小则返回错误
//
// 示例:
//
//	digest, err := Digest(mpk, []Identity{id1, id2, id3})
//	if err != nil {
//	    return fmt.Errorf("摘要生成失败: %w", err)
//	}
func Digest(pk *MasterPublicKey, identities []*Identity) (*BatchDigest, error) {
	if len(identities) == 0 {
		return nil, fmt.Errorf("identities is empty")
	}
	if len(identities) > len(pk.G1ExpTauPowers) {
		return nil, fmt.Errorf("too many identities for batch size")
	}
	coefficients := computePolynomialCoeffs(identities)
	var d bn254.G1Affine
	_, _, g1, _ := bn254.Generators()

	d.ScalarMultiplication(&g1, coefficients[0].BigInt(new(big.Int)))

	for i := 1; i < len(coefficients); i++ {
		var temp bn254.G1Affine
		temp.ScalarMultiplication(&pk.G1ExpTauPowers[i-1], coefficients[i].BigInt(new(big.Int)))
		d.Add(&d, &temp)
	}

	return &BatchDigest{
		D: d,
	}, nil
}

// ComputeKey 基于批量摘要和批量标签计算用户的解密密钥。
//
// 该函数由密钥生成中心(KGC)执行,为用户生成批量解密密钥。
// 密钥计算公式为:sk = msk · (D + h(t))
// 其中:
//   - D是批量摘要,承诺了身份集合
//   - h(t)是批量标签的哈希值,映射到G1群
//   - msk是主密钥,确保只有KGC能生成有效密钥
//
// 参数:
//   - msk: 主密钥,必须保密
//   - d: 批量摘要,对应特定的身份集合
//   - t: 批量标签,定义批量上下文
//
// 返回值:
//   - *SecretKey: 生成的解密密钥
//   - error: 理论上不会失败,保留用于一致性
//
// 示例:
//
//	sk, err := ComputeKey(msk, digest, batchLabel)
//	if err != nil {
//	    return fmt.Errorf("密钥计算失败: %w", err)
//	}
func ComputeKey(msk *MasterSecretKey, d *BatchDigest, t *BatchLabel) (*SecretKey, error) {
	ht := h(t)
	dMulHt := new(bn254.G1Affine).Add(&d.D, &ht)
	sk := *new(bn254.G1Affine).ScalarMultiplication(dMulHt, msk.Msk.BigInt(new(big.Int)))
	return &SecretKey{
		Sk: sk,
	}, nil
}

// Decrypt 使用解密密钥从密文中恢复明文消息。
//
// 解密算法基于多项式插值和双线性配对验证。主要步骤包括:
//  1. 构造商多项式q(X) = f(X) / (X - id),其中f(X)是完整批量的身份多项式
//  2. 计算π = g1^q(τ),使用公钥中的τ幂次
//  3. 构造向量w = (D, π, sk),其中D是批量摘要,sk是解密密钥
//  4. 计算配对乘积c1 ∘ w = e(D, C1[0]) · e(π, C1[1]) · e(sk, C1[2])
//  5. 恢复明文m = C2 / (c1 ∘ w)
//
// 参数:
//   - c: 待解密的密文
//   - sk: 解密密钥,对应批量和标签
//   - d: 批量摘要,必须与密钥匹配
//   - identities: 完整的身份列表,包含解密者身份
//   - id: 解密者的身份,必须在identities中
//   - t: 批量标签,必须与加密时使用的标签一致
//   - pk: 主公钥,用于计算商多项式
//
// 返回值:
//   - *Message: 解密得到的明文消息
//   - error: 如果身份不在列表中或配对计算失败则返回错误
//
// 商多项式构造原理:
//   - 完整多项式f(X) = (X-id₁)(X-id₂)...(X-id_n)在所有身份处为零
//   - 商多项式q(X) = f(X)/(X-id)在除id外的所有身份处为零
//   - q(τ)可以用公钥中的τ幂次高效计算
//
// 示例:
//
//	msg, err := Decrypt(ct, sk, digest, allIDs, myID, label, mpk)
//	if err != nil {
//	    return fmt.Errorf("解密失败: %w", err)
//	}
func Decrypt(c *Ciphertext, sk *SecretKey, d *BatchDigest, identities []*Identity, id *Identity, t *BatchLabel, pk *MasterPublicKey) (*Message, error) {
	// 1. 构造商多项式 q(X) = f(X) / (X - id)
	// q(X) 的根为 identities \ {id}
	var rootsWithoutId []*Identity
	for _, identity := range identities {
		if !identity.Id.Equal(&id.Id) {
			rootsWithoutId = append(rootsWithoutId, identity)
		}
	}
	fmt.Println("decrypt rootsWithoutId", rootsWithoutId)
	if len(rootsWithoutId) != len(identities)-1 {
		return nil, fmt.Errorf("identity not found in identity list")
	}
	qx := computePolynomialCoeffs(rootsWithoutId)
	fmt.Println("decrypt qx", qx)

	// 2. 计算 π = g1^q(τ)
	var pi bn254.G1Affine
	_, _, g1, _ := bn254.Generators()
	pi.ScalarMultiplication(&g1, qx[0].BigInt(new(big.Int)))
	for i := 1; i < len(qx); i++ {
		var term bn254.G1Affine
		term.ScalarMultiplication(&pk.G1ExpTauPowers[i-1], qx[i].BigInt(new(big.Int)))
		pi.Add(&pi, &term)
	}

	// 3. 构造向量 w = (d, π, sk) ∈ (G1)^3
	w := [3]bn254.G1Affine{
		d.D,
		pi,
		sk.Sk,
	}

	// 4. 计算 c1 ∘ w = e(c1[0], w[0]) * e(c1[1], w[1]) * e(c1[2], w[2])
	pairing1, err := bn254.Pair([]bn254.G1Affine{w[0]}, []bn254.G2Affine{c.C1[0]})
	if err != nil {
		return nil, err
	}
	pairing2, err := bn254.Pair([]bn254.G1Affine{w[1]}, []bn254.G2Affine{c.C1[1]})
	if err != nil {
		return nil, err
	}
	pairing3, err := bn254.Pair([]bn254.G1Affine{w[2]}, []bn254.G2Affine{c.C1[2]})
	if err != nil {
		return nil, err
	}
	var c1DotW bn254.GT
	c1DotW.Mul(&pairing1, &pairing2)
	c1DotW.Mul(&c1DotW, &pairing3)

	// 5. 计算 m = c2 / (c1 ∘ w)
	var m bn254.GT
	m.Div(&c.C2, &c1DotW)

	return &Message{
		M: m,
	}, nil
}
