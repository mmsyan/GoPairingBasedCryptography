package bb04_ibe

// 作者: mmsyan
// 日期: 2025-11-14
// 参考论文:
// Boneh, D., Boyen, X. (2004). Secure Identity Based Encryption Without Random Oracles.
// In: Franklin, M. (eds) Advances in Cryptology – CRYPTO 2004. CRYPTO 2004. Lecture Notes in Computer Science, vol 3152. Springer, Berlin, Heidelberg.
// https://doi.org/10.1007/978-3-540-28628-8_27
//
// 该实现基于BN254椭圆曲线和配对运算,提供了完整的Brent Waters IBE系统功能,包括:
//   - 系统初始化(SetUp)
//   - 密钥生成(KeyGenerate)
//   - 加密(Encrypt)
//   - 解密(Decrypt)
//
// 该实现基于论文的第四章：Construction
// 考虑到同期还有一篇《Efficient Selective-ID Secure Identity-Based Encryption Without Random Oracles》
// https://link.springer.com/chapter/10.1007/978-3-540-24676-3_14
// 这篇我们命名为BB04IBE (表示它是full secure)
// 另外一篇命名为BB04sIBE (表示它是selective-id secure)

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// n 是身份向量的长度，此处设为 256 位，对应 SHA-256 的输出长度。
const n = 256

// s 是身份向量每个位置的维度，此处为 2 (0 或 1)。
const s = 2

// BB04IBEInstance 代表 IBE 方案的秘密参数实例（可信中心）。
type BB04IBEInstance struct {
	// alpha 是系统的主私钥（msk），用于生成私钥。
	alpha fr.Element
	// g2ExpAlpha 是 g2^alpha，作为主密钥的一部分，在密钥生成中用于 d0 的计算。
	g2ExpAlpha bn254.G2Affine
}

// BB04IBEPublicParams 代表 IBE 方案的公开参数（mpk）。
type BB04IBEPublicParams struct {
	// g1 是 G1 群的生成元。
	g1 bn254.G1Affine
	// g2 是 G2 群的生成元。
	g2 bn254.G2Affine
	// g1ExpAlpha 是 g1^alpha，作为公钥的一部分，用于加密中的密钥封装。
	g1ExpAlpha bn254.G1Affine
	// uij 是用于身份编码的矩阵 (n x s)，uij[i][j] 位于 G2 群。
	uij [n][s]bn254.G2Affine
}

// BB04IBEIdentity 代表哈希后的用户身份。
type BB04IBEIdentity struct {
	// Id 是哈希后的身份字符串对应的 n 维二进制向量 (0 或 1)。
	Id [n]int
}

// BB04IBESecretKey 代表用户的私钥。
type BB04IBESecretKey struct {
	// d0 是私钥的第一部分，位于 G2 群。
	// d0 = g2^alpha * Product(u_{i, a_i}^{r_i})
	d0 bn254.G2Affine
	// dj 是私钥的第二部分，是一个 G1 群元素的向量。
	// dj[i] = g1^{r_i}
	dj [n]bn254.G1Affine
}

// BB04IBEMessage 代表待加密的明文消息。
// 明文 M 必须是目标群 GT 上的元素。
type BB04IBEMessage struct {
	Message bn254.GT
}

// BB04IBECiphertext 代表密文。
type BB04IBECiphertext struct {
	// a 是密文的第一部分，位于 GT 群。
	// a = M * e(g1^alpha, g2)^t
	a bn254.GT
	// b 是密文的第二部分，位于 G1 群。
	// b = g1^t
	b bn254.G1Affine
	// c 是密文的第三部分，是一个 G2 群元素的向量。
	// c[i] = u_{i, a_i}^t
	c [n]bn254.G2Affine
}

// NewBB04IBEInstance 创建一个新的 IBE 实例（可信中心）。
// 该函数随机生成主私钥 alpha，并计算 g2^alpha。
func NewBB04IBEInstance() (*BB04IBEInstance, error) {
	// 随机选择 alpha
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}
	// 计算 g2^alpha，用于私钥生成（d0）。
	g2ExpAlpha := new(bn254.G2Affine).ScalarMultiplicationBase(alpha.BigInt(new(big.Int)))
	return &BB04IBEInstance{
		alpha:      *alpha,
		g2ExpAlpha: *g2ExpAlpha,
	}, nil
}

// SetUp 执行系统初始化操作，生成并返回公共参数。
func (instance *BB04IBEInstance) SetUp() (*BB04IBEPublicParams, error) {
	// 获取 BN254 曲线的生成元 g1 和 g2
	_, _, g1, g2 := bn254.Generators()
	// 计算 g1^alpha，用于加密（密钥封装）。
	g1ExpAlpha := *new(bn254.G1Affine).ScalarMultiplicationBase(instance.alpha.BigInt(new(big.Int)))

	// 随机生成身份编码矩阵 uij
	var uij [n][s]bn254.G2Affine
	for i := 0; i < n; i++ {
		for j := 0; j < s; j++ {
			uRandom, err := new(fr.Element).SetRandom()
			if err != nil {
				return nil, fmt.Errorf("failed to set up")
			}
			// 计算 uij[i][j] = g2^{随机数}
			uij[i][j] = *new(bn254.G2Affine).ScalarMultiplicationBase(uRandom.BigInt(new(big.Int)))
		}
	}

	return &BB04IBEPublicParams{
		g1:         g1,
		g2:         g2,
		g1ExpAlpha: g1ExpAlpha,
		uij:        uij,
	}, nil
}

// KeyGenerate 为指定身份生成私钥 (d0, {dj})。
// 注意: 此处代码存在一个数学上的错误，ScalarMultiplicationBase 默认是以 g1/g2 为基，但上一个回复中指出应修正为 ScalarMultiplication(&publicParams.g1, ...)
func (instance *BB04IBEInstance) KeyGenerate(identity *BB04IBEIdentity, publicParams *BB04IBEPublicParams) (*BB04IBESecretKey, error) {
	r := [n]fr.Element{}
	dj := [n]bn254.G1Affine{}
	for i := 0; i < n; i++ {
		// 随机选取 r_i
		temp, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("failed to generate key")
		}
		r[i] = *temp
		// 计算 d_i = g1^{r_i} (这里使用 ScalarMultiplicationBase 隐含以 G1 的基点进行运算)
		dj[i] = *new(bn254.G1Affine).ScalarMultiplicationBase(temp.BigInt(new(big.Int)))
	}

	// 计算 Prod = Product(u_{i, a_i}^{r_i})
	prod := new(bn254.G2Affine).SetInfinity() // G2 上的单位元
	for i := 0; i < n; i++ {
		// 计算 u_{i, a_i}^{r_i}
		uIAiR := new(bn254.G2Affine).ScalarMultiplication(&publicParams.uij[i][identity.Id[i]], r[i].BigInt(new(big.Int)))
		// 累乘 (在 G2 椭圆曲线上是点加)
		prod.Add(prod, uIAiR)
	}

	// 计算 d0 = g2^alpha * Prod
	// (在 G2 椭圆曲线上是点加)
	d0 := *new(bn254.G2Affine).Add(&instance.g2ExpAlpha, prod)

	return &BB04IBESecretKey{
		d0: d0,
		dj: dj,
	}, nil

}

// Encrypt 使用指定身份 V 对明文 M 进行加密，生成密文 (a, b, {c_i})。
func (instance *BB04IBEInstance) Encrypt(identity *BB04IBEIdentity, message *BB04IBEMessage, publicParams *BB04IBEPublicParams) (*BB04IBECiphertext, error) {
	// 随机选取 t (临时会话密钥)
	t, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}

	// 计算 K_t = e(g1^alpha, g2)^t = e(g1, g2)^{alpha*t} (密钥封装的基元)
	eG1AlphaG2, err := bn254.Pair([]bn254.G1Affine{publicParams.g1ExpAlpha}, []bn254.G2Affine{publicParams.g2})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	// 得到 K = e(g1, g2)^{alpha*t}
	eG1AlphaG2ExpT := new(bn254.GT).Exp(eG1AlphaG2, t.BigInt(new(big.Int)))

	// 密文 a (密钥封装) = Message * K
	a := *new(bn254.GT).Mul(eG1AlphaG2ExpT, &message.Message)

	// 密文 b = g1^t
	b := *new(bn254.G1Affine).ScalarMultiplicationBase(t.BigInt(new(big.Int)))

	// 密文 {c_i}
	var c [n]bn254.G2Affine
	for i := 0; i < n; i++ {
		// 计算 c_i = u_{i, a_i}^t
		c[i] = *new(bn254.G2Affine).ScalarMultiplication(&publicParams.uij[i][identity.Id[i]], t.BigInt(new(big.Int)))
	}

	return &BB04IBECiphertext{
		a: a,
		b: b,
		c: c,
	}, nil
}

// Decrypt 使用私钥 (d0, {dj}) 对密文 (a, b, {c_i}) 进行解密。
// 解密公式: M = a * Product(e(dj, cj)) / e(b, d0)
func (instance *BB04IBEInstance) Decrypt(ciphertext *BB04IBECiphertext, secretKey *BB04IBESecretKey, publicParams *BB04IBEPublicParams) (*BB04IBEMessage, error) {
	// 1. 计算分子中的 Prod_pair = Product(e(dj, cj))
	// e(dj, cj) = e(g1^{r_j}, u_{j, a_j}^t) = Product(e(g1, u_{j, a_j})^{r_j t})
	prod := new(bn254.GT).SetOne()
	for j := 0; j < n; j++ {
		eDjCj, err := bn254.Pair([]bn254.G1Affine{secretKey.dj[j]}, []bn254.G2Affine{ciphertext.c[j]})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt message")
		}
		prod.Mul(prod, &eDjCj)
	}

	// 2. 计算分母 e(b, d0)
	// e(b, d0) = e(g1^t, g2^alpha * Product(u_{i, a_i}^{r_i}))
	//          = e(g1, g2)^{alpha t} * Product(e(g1, u_{i, a_i})^{t r_i})
	eBD0, err := bn254.Pair([]bn254.G1Affine{ciphertext.b}, []bn254.G2Affine{secretKey.d0})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message")
	}

	// 3. 计算 M = a * Prod_pair
	m := new(bn254.GT).Mul(&ciphertext.a, prod)

	// 4. M = (a * Prod_pair) / e(b, d0)
	// 根据配对性质，Prod_pair 将与 e(b, d0) 中的身份部分抵消，只剩下 M / e(g1, g2)^{alpha t} 的倒数，
	// 最终得到 M。
	m = new(bn254.GT).Div(m, &eBD0)

	return &BB04IBEMessage{
		Message: *m,
	}, nil
}

// NewBB04IBEIdentity 将一个字符串身份转换为 n=256 位的二进制身份向量。
// 使用 SHA-256 哈希身份字符串。
func NewBB04IBEIdentity(identity string) (*BB04IBEIdentity, error) {
	if len(identity) == 0 {
		return nil, errors.New("identity string cannot be empty")
	}

	// 1. 哈希身份字符串 (SHA-256 输出 256 比特，即 32 字节)
	hasher := sha256.New()
	hasher.Write([]byte(identity))
	hashBytes := hasher.Sum(nil)

	wId := &BB04IBEIdentity{}

	// 2. 将 32 字节的哈希值转换为 256 位的二进制向量
	for byteIndex := 0; byteIndex < 32; byteIndex++ {
		b := hashBytes[byteIndex]

		for bitIndex := 0; bitIndex < 8; bitIndex++ {
			vectorIndex := byteIndex*8 + bitIndex

			// 提取比特值 (0 或 1)。从高位 (7) 到低位 (0) 提取。
			bitValue := (b >> (7 - bitIndex)) & 0x01

			wId.Id[vectorIndex] = int(bitValue)
		}
	}
	return wId, nil
}
