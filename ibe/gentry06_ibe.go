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
// 该实现基于论文的第四章：Construction II: Chosen-Ciphertext Security (CCA安全方案)
// 该方案通过使用额外的密钥组件 h2, h3 和密文组件 y, 以及哈希函数 h() 实现了 CCA 安全性。
import (
	"crypto/sha256"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// Gentry06IBEInstance 表示 Gentry IBE (2006) 方案的实例对象。
// 该实例包含了系统的主密钥 $\alpha$。
// 主密钥 $\alpha$ 属于 $\mathbb{Z}_p$ 域，用于生成用户的私钥，必须严格保密。
type Gentry06IBEInstance struct {
	alpha fr.Element // 系统主密钥，$\alpha \in \mathbb{Z}_p$
}

// Gentry06IBEPublicParams 表示 Gentry IBE 方案的公共参数。
// 这些参数在系统初始化时生成，可以公开发布给所有用户。
type Gentry06IBEPublicParams struct {
	g1      bn254.G1Affine    // $g_1 \in G_1$ 群的生成元
	g2      bn254.G2Affine    // $g_2 \in G_2$ 群的生成元
	g1Alpha bn254.G1Affine    // $g_1^\alpha \in G_1$，主公钥的一部分
	hs      [3]bn254.G2Affine // $h_1, h_2, h_3 \in G_2$ (CCA安全所需的随机元素)
}

// Gentry06IBEIdentity 表示 IBE 方案中的用户身份。
// 身份 ID 被编码为 $\mathbb{Z}_p$ 有限域上的一个元素。
// 必须满足 $ID \neq \alpha$，否则无法生成私钥。
type Gentry06IBEIdentity struct {
	Id fr.Element // 用户的身份 $ID \in \mathbb{Z}_p$
}

// Gentry06IBESecretKey 表示 Gentry IBE 方案中的用户私钥。
// 私钥 $d_{ID} = \{ (r_{(ID,1)}, h_{(ID,1)}), (r_{(ID,2)}, h_{(ID,2)}), (r_{(ID,3)}, h_{(ID,3)}) \}$
// 包含三组用于抵抗 CCA 攻击的组件：
//   - $r_{(ID,i)}$: $\mathbb{Z}_p$ 域上的随机元素。
//   - $h_{(ID,i)}$: $G_2$ 群上的元素，计算为 $h_{(ID,i)} = (h_i g_2^{-r_{(ID,i)}})^{\frac{1}{\alpha - ID}}$。
type Gentry06IBESecretKey struct {
	rids [3]fr.Element     // 随机参数 $r_{(ID,i)} \in \mathbb{Z}_p$
	hids [3]bn254.G2Affine // 密钥元素 $h_{(ID,i)} \in G_2$
}

// Gentry06IBEMessage 表示 IBE 方案中的明文消息。
// 明文 $M$ 被编码为 $G_T$ 群（配对运算的目标群）上的一个元素。
type Gentry06IBEMessage struct {
	Message bn254.GT // 明文 $M \in G_T$
}

// Gentry06IBECiphertext 表示 IBE 方案中的密文 $C = (u, v, w, y)$ (CCA安全版本)。
// 密文由四个部分组成：
//   - $u$: $G_1$ 群上的元素。
//   - $v$: $G_T$ 群上的元素。
//   - $w$: $G_T$ 群上的元素，包含加密后的消息 $M$。
//   - $y$: $G_T$ 群上的元素，用于 CCA 安全性检查。
type Gentry06IBECiphertext struct {
	u bn254.G1Affine // $u \in G_1$
	v bn254.GT       // $v \in G_T$
	w bn254.GT       // $w \in G_T$
	y bn254.GT       // $y \in G_T$
}

// NewGentry06IBEInstance 创建一个新的 Gentry IBE 方案实例。
// 该函数随机生成主密钥 $\alpha \in \mathbb{Z}_p$。
// 返回的实例对象包含主密钥，应由可信中心持有并妥善保管。
//
// 返回值:
//   - *Gentry06IBEInstance: 包含主密钥的 IBE 实例
//   - error: 如果随机数生成失败，返回错误信息
func NewGentry06IBEInstance() (*Gentry06IBEInstance, error) {
	// 随机选取主密钥 $\alpha \in \mathbb{Z}_p$
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}
	return &Gentry06IBEInstance{
		alpha: *alpha,
	}, nil
}

// SetUp 执行 IBE 方案的系统初始化，生成公共参数。
// 步骤:
// 1. 选取群生成元 $g_1, g_2$。
// 2. 计算主公钥 $g_1^\alpha$。
// 3. 随机选取 $h_1, h_2, h_3 \in G_2$。
// 4. 返回公共参数 $\{g_1, g_2, g_1^\alpha, h_1, h_2, h_3\}$。
//
// 返回值:
//   - *Gentry06IBEPublicParams: 生成的公共参数
//   - error: 如果初始化失败，返回错误信息
func (instance *Gentry06IBEInstance) SetUp() (*Gentry06IBEPublicParams, error) {
	var err error
	// 获取 BN254 曲线的生成元 $g_1$ 和 $g_2$
	_, _, g1, g2 := bn254.Generators()
	// 计算 $g_1^\alpha$
	g1Alpha := new(bn254.G1Affine).ScalarMultiplicationBase(instance.alpha.BigInt(new(big.Int)))
	var hs [3]bn254.G2Affine
	for i := 0; i < 3; i++ {
		// 随机选取 $h_i$
		hRandom, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("failed to set up")
		}
		h := new(bn254.G2Affine).ScalarMultiplicationBase(hRandom.BigInt(new(big.Int)))
		hs[i] = *h
	}

	if err != nil {
		return nil, fmt.Errorf("failed to set up")
	}
	return &Gentry06IBEPublicParams{
		g1:      g1,
		g2:      g2,
		g1Alpha: *g1Alpha,
		hs:      hs,
	}, nil
}

// KeyGenerate 为指定用户身份生成私钥 $d_{ID}$。
// 该方法使用主密钥 $\alpha$ 和用户身份 $ID$，计算三组私钥组件。
//
// 参数:
//   - identity: 用户的身份标识符
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *Gentry06IBESecretKey: 生成的私钥
//   - error: 如果密钥生成失败或 $ID = \alpha$，返回错误信息
func (instance *Gentry06IBEInstance) KeyGenerate(identity *Gentry06IBEIdentity, publicParams *Gentry06IBEPublicParams) (*Gentry06IBESecretKey, error) {
	var err error
	rids := [3]fr.Element{}
	hids := [3]bn254.G2Affine{}

	alphaMinusId := new(fr.Element).Sub(&instance.alpha, &identity.Id) // 1. 计算 $\alpha - ID$
	invAlphaMinusId := new(fr.Element).Inverse(alphaMinusId)           // 计算 $\frac{1}{\alpha - ID}$
	if invAlphaMinusId.IsZero() {
		return nil, fmt.Errorf("your identity is invalid (ID equals alpha)") // $ID = \alpha$ 时无逆元
	}

	for i := 0; i < 3; i++ {
		rid, err := new(fr.Element).SetRandom()                                               // 1. 随机选取 $r_{(ID,i)} \in \mathbb{Z}_p$
		negRid := new(fr.Element).Neg(rid)                                                    // 计算 $-r_{(ID,i)}$
		g2InvRid := new(bn254.G2Affine).ScalarMultiplicationBase(negRid.BigInt(new(big.Int))) // 计算 $g_2^{-r_{(ID,i)}}$

		hAddG2InvRid := new(bn254.G2Affine).Add(&publicParams.hs[i], g2InvRid) // 3. 计算 $h_i g_2^{-r_{(ID,i)}}$
		// 4. 计算 $h_{(ID,i)} = (h_i g_2^{-r_{(ID,i)}})^{\frac{1}{\alpha - ID}}$
		hid := new(bn254.G2Affine).ScalarMultiplication(hAddG2InvRid, invAlphaMinusId.BigInt(new(big.Int)))
		if err != nil {
			return nil, fmt.Errorf("failed to generate key")
		}

		rids[i] = *rid
		hids[i] = *hid
	}

	if err != nil {
		return nil, fmt.Errorf("failed to generate key")
	}

	return &Gentry06IBESecretKey{
		rids: rids,
		hids: hids,
	}, nil
}

// Encrypt 使用指定用户身份对 $G_T$ 群上的消息 $M$ 进行加密，生成密文 $C=(u, v, w, y)$。
//
// 参数:
//   - identity: 接收者的身份标识符
//   - message: 要加密的明文消息(字节数组)
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *Gentry06IBECiphertext: 加密后的密文 $C=(u, v, w, y)$
//   - error: 如果加密失败，返回错误信息
func (instance *Gentry06IBEInstance) Encrypt(message *Gentry06IBEMessage, identity *Gentry06IBEIdentity, publicParams *Gentry06IBEPublicParams) (*Gentry06IBECiphertext, error) {
	var err error
	s, err := new(fr.Element).SetRandom() // 1. 随机选取 $s \in \mathbb{Z}_p$

	// 计算 $g_1^{\alpha s}$
	g1AlphaS := new(bn254.G1Affine).ScalarMultiplication(&publicParams.g1Alpha, s.BigInt(new(big.Int)))

	// 计算 $g_1^{-s \cdot ID}$
	sId := new(fr.Element).Mul(s, &identity.Id) // $s \cdot ID$
	negSId := new(fr.Element).Neg(sId)          // $-s \cdot ID$
	g1NegSId := new(bn254.G1Affine).ScalarMultiplicationBase(negSId.BigInt(new(big.Int)))

	// 2. 计算 $u = g_1^{\alpha s} \cdot g_1^{-s \cdot ID} = g_1^{s(\alpha - ID)}$
	u := *new(bn254.G1Affine).Add(g1AlphaS, g1NegSId)

	// 3. 计算 $v = e(g_1, g_2)^s$
	eG1G2, err := bn254.Pair([]bn254.G1Affine{publicParams.g1}, []bn254.G2Affine{publicParams.g2})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	v := *new(bn254.GT).Exp(eG1G2, s.BigInt(new(big.Int)))

	// 4. 计算 $w = M \cdot e(g_1, h_1)^{-s}$
	eG1H, err := bn254.Pair([]bn254.G1Affine{publicParams.g1}, []bn254.G2Affine{publicParams.hs[0]})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	negS := new(fr.Element).Neg(s)
	// 计算 $e(g_1, h_1)^{-s}$
	w := *new(bn254.GT).Exp(eG1H, negS.BigInt(new(big.Int)))
	// 计算 $w = M \cdot e(g_1, h_1)^{-s}$
	w = *new(bn254.GT).Mul(&w, &message.Message)

	// 5. 计算 $\beta = H(u, v, w)$
	beta := h(u, v, w)

	// 6. 计算 $y = e(g_1, h_2)^s e(g_1, h_3)^{s\beta}$
	// 计算 $e(g_1, h_2)^s$
	eG1H2, err := bn254.Pair([]bn254.G1Affine{publicParams.g1}, []bn254.G2Affine{publicParams.hs[1]})
	eG1H2S := new(bn254.GT).Exp(eG1H2, s.BigInt(new(big.Int)))
	// 计算 $e(g_1, h_3)^{s\beta}$
	eG1H3, err := bn254.Pair([]bn254.G1Affine{publicParams.g1}, []bn254.G2Affine{publicParams.hs[2]})
	sMulBeta := new(fr.Element).Mul(s, &beta)
	eGH3SBeta := new(bn254.GT).Exp(eG1H3, sMulBeta.BigInt(new(big.Int)))
	// 计算 $y$
	y := *new(bn254.GT).Mul(eG1H2S, eGH3SBeta)

	return &Gentry06IBECiphertext{
		u: u,
		v: v,
		w: w,
		y: y,
	}, nil
}

// Decrypt 使用私钥 $d_{ID}$ 对密文 $C=(u, v, w, y)$ 进行解密。
// 首先进行 CCA 安全性检查，检查通过后恢复原始明文消息 $M$。
//
// 参数:
//   - ciphertext: 要解密的密文
//   - secretKey: 用户的私钥
//   - publicParams: 系统公共参数
//
// 步骤:
//  1. 计算 $\beta = H(u, v, w)$。
//  2. **检查**: 验证密文是否有效，需要 $y \stackrel{?}{=} e(u, h_{(ID,2)}h_{(ID,3)}^\beta)^{r_{(ID,2)}+r_{(ID,3)}{\beta}} \cdot v^{r_{(ID,2)}+r_{(ID,3)}{\beta}}$
//     注：此处代码中的检查公式与论文略有不同，但仍用于密文有效性判断。
//  3. **恢复**: 计算 $M = w \cdot e(u, h_{(ID,1)}) \cdot v^{r_{(ID,1)}}$。
//
// 返回值:
//   - *Gentry06IBEMessage: 解密后的明文消息
//   - error: 如果解密检查失败或解密操作失败，返回错误信息
func (instance *Gentry06IBEInstance) Decrypt(ciphertext *Gentry06IBECiphertext, secretKey *Gentry06IBESecretKey, publicParams *Gentry06IBEPublicParams) (*Gentry06IBEMessage, error) {
	var err error
	beta := h(ciphertext.u, ciphertext.v, ciphertext.w)

	// --- CCA 安全性检查 (Check) ---

	// 计算指数 $r_{(ID,2)}+r_{(ID,3)}\beta$
	rid3MulBeta := new(fr.Element).Mul(&secretKey.rids[2], &beta)
	rid3MulBetaAddRid2 := new(fr.Element).Add(&secretKey.rids[1], rid3MulBeta)

	// 计算 $v^{r_{(ID,2)}+r_{(ID,3)}\beta}$
	vExpRid3MulBetaAddRid2 := new(bn254.GT).Exp(ciphertext.v, rid3MulBetaAddRid2.BigInt(new(big.Int)))

	// 计算 $h_{(ID,2)} \cdot h_{(ID,3)}^\beta$
	hId3ExpBeta := new(bn254.G2Affine).ScalarMultiplication(&secretKey.hids[2], beta.BigInt(new(big.Int)))
	hId2AddHId3ExpBeta := new(bn254.G2Affine).Add(&secretKey.hids[1], hId3ExpBeta)

	// 计算 $p = e(u, h_{(ID,2)} \cdot h_{(ID,3)}^\beta)$
	p, err := bn254.Pair([]bn254.G1Affine{ciphertext.u}, []bn254.G2Affine{*hId2AddHId3ExpBeta})
	if err != nil {
		return nil, fmt.Errorf("failed to perform check pairing")
	}

	// 计算 $y' = e(u, h_{(ID,2)} \cdot h_{(ID,3)}^\beta) \cdot v^{r_{(ID,2)}+r_{(ID,3)}\beta}$
	// 注：代码中的 $y'$ 计算似乎与原始方案的 Check 步骤有出入，但用于有效性检查
	yPrime := new(bn254.GT).Mul(vExpRid3MulBetaAddRid2, &p)

	if !yPrime.Equal(&ciphertext.y) {
		return nil, fmt.Errorf("failed to pass decrypt check")
	}

	// --- 明文恢复 (Recovery) ---

	// 1. 计算 $e(u, h_{(ID,1)})$
	eUHid, err := bn254.Pair([]bn254.G1Affine{ciphertext.u}, []bn254.G2Affine{secretKey.hids[0]})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt ciphertext")
	}
	// 2. 计算 $v^{r_{(ID,1)}}$
	vRid := new(bn254.GT).Exp(ciphertext.v, secretKey.rids[0].BigInt(new(big.Int)))

	// 3. 计算 $M = w \cdot e(u, h_{(ID,1)}) \cdot v^{r_{(ID,1)}}$
	// m = w * e(u, h_ID)
	m := new(bn254.GT).Mul(&ciphertext.w, &eUHid)
	// m = (w * e(u, h_ID)) * v^r_ID
	m.Mul(m, vRid)

	return &Gentry06IBEMessage{
		Message: *m,
	}, nil
}

// h 实现了 Gentry IBE 方案中用于 CCA 安全性的哈希函数 $H: G_1 \times G_T \times G_T \to \mathbb{Z}_p$。
// 在标准模型下的安全证明要求 $H$ 是一个普通的哈希函数，但在实现中，我们可以使用一个实际安全的、
// 具有良好均匀性的哈希算法（如 SHA-256）来实例化它。
func h(u bn254.G1Affine, v bn254.GT, w bn254.GT) fr.Element {
	// 1. 获取输入元素的标准字节表示
	// 确保使用的 Bytes() 方法是规范且确定的。
	uBytes := u.Bytes()
	vBytes := v.Bytes()
	wBytes := w.Bytes()

	// 2. 拼接所有输入字节，作为哈希函数的输入
	inputBytes := make([]byte, 0, len(uBytes)+len(vBytes)+len(wBytes))
	inputBytes = append(inputBytes, uBytes[:]...)
	inputBytes = append(inputBytes, vBytes[:]...)
	inputBytes = append(inputBytes, wBytes[:]...)

	// 3. 使用 SHA-256 计算哈希值
	hasher := sha256.New()
	hasher.Write(inputBytes)
	hash := hasher.Sum(nil) // 得到 32 字节 (256 比特) 的哈希值

	// 4. 将哈希输出映射到 $\mathbb{Z}_p$ 域元素 $\beta$
	// $fr.Element.SetBytes$ 方法会负责将 32 字节的哈希值截断或处理，以确保它正确地落入 $\mathbb{Z}_p$ 域。
	var beta fr.Element
	beta.SetBytes(hash)

	return beta
}

// NewGentry06Identity 将大整数类型的 ID 转换为 IBE 方案使用的 fr.Element 身份结构体。
//
// 输入:
//   - identity: 大整数形式的用户 ID
//
// 返回值:
//   - *Gentry06IBEIdentity: 包含 $\mathbb{Z}_p$ 元素的身份结构体
func NewGentry06Identity(identity *big.Int) (*Gentry06IBEIdentity, error) {
	return &Gentry06IBEIdentity{
		Id: *new(fr.Element).SetBigInt(identity), // 将 big.Int 映射到 $\mathbb{Z}_p$ 域元素
	}, nil
}
