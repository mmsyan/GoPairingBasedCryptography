package ibe

// 作者: mmsyan
// 日期: 2025-11-01
// 参考论文:
// Dan Boneh and Xavier Boyen. "Efficient Selective-ID Secure Identity-Based
// Encryption Without Random Oracles." In Advances in Cryptology - EUROCRYPT 2004,
// pp. 223-238. Springer, 2004.
//
// 论文链接: https://link.springer.com/chapter/10.1007/978-3-540-24676-3_14
// 预印本: https://crypto.stanford.edu/~dabo/pubs/papers/bbibe.pdf
//
// 该实现基于BN254椭圆曲线和配对运算，提供了完整的IBE系统功能，包括：
//   - 系统初始化(SetUp)
//   - 密钥生成(KeyGenerate)
//   - 加密(Encrypt)
//   - 解密(Decrypt)

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// BBIBEInstance 表示Boneh-Boyen身份基加密(IBE)方案的实例对象。
// 该实例包含了系统的主密钥对(x, y)，其中x和y都是Zp域上的随机元素。
// 主密钥用于生成用户的私钥，必须严格保密。
type BBIBEInstance struct {
	x fr.Element
	y fr.Element
}

// BBIBEPublicParams 表示Boneh-Boyen IBE方案的公共参数。
// 这些参数在系统初始化时生成，可以公开发布给所有用户。
// 包含基础生成元g1和g2，以及由主密钥派生的公开元素x=g1^x和y=g1^y。
type BBIBEPublicParams struct {
	g1 bn254.G1Affine
	g2 bn254.G2Affine
	x  bn254.G1Affine
	y  bn254.G1Affine
}

// BBIBEIdentity 表示Boneh-Boyen IBE方案中的用户身份。
// 身份被编码为Zp有限域上的一个元素。
// 在实际应用中，可以通过哈希函数将任意字符串(如邮箱地址)映射到Zp域元素。
type BBIBEIdentity struct {
	Id fr.Element
}

// BBIBESecretKey 表示Boneh-Boyen IBE方案中的用户私钥。
// 私钥包含两个部分：
//   - r: Zp域上的随机元素
//   - k: G2群上的元素，计算为k=g2^{1/(Id+x+ry)}
//
// 私钥由密钥生成中心(PKG)使用主密钥和用户身份生成，必须安全地传递给用户。
type BBIBESecretKey struct {
	r fr.Element
	k bn254.G2Affine
}

// BBIBEMessage 表示Boneh-Boyen IBE方案中的明文消息。
// 明文被编码为GT群(配对运算的目标群)上的一个元素。
// 在实际应用中，通常需要将原始消息映射到GT群元素。
type BBIBEMessage struct {
	Message bn254.GT
}

// BBIBECiphertext 表示Boneh-Boyen IBE方案中的密文。
// 密文由三个部分组成：
//   - a: G1群上的元素，编码了身份和随机性
//   - b: G1群上的元素，编码了随机掩码
//   - c: GT群上的元素，包含加密后的消息
type BBIBECiphertext struct {
	a bn254.G1Affine
	b bn254.G1Affine
	c bn254.GT
}

// NewBBIBEInstance 创建一个新的Boneh-Boyen IBE方案实例。
// 该函数随机生成主密钥对(x, y)，两者都是从Zp域中均匀随机采样的元素。
// 返回的实例对象包含主密钥，应该由可信的密钥生成中心(PKG)持有并妥善保管。
//
// 返回值:
//   - *BBIBEInstance: 包含主密钥的IBE实例
//   - error: 如果随机数生成失败，返回错误信息
func NewBBIBEInstance() (*BBIBEInstance, error) {
	var err error
	var x, y fr.Element
	_, err = x.SetRandom()
	_, err = y.SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity based encryption instance: %s", err)
	}
	return &BBIBEInstance{x, y}, nil
}

// SetUp 执行系统初始化操作，生成并返回公共参数。
// 该方法使用IBE实例中的主密钥，计算公开的系统参数。
// 生成的公共参数可以安全地发布给所有系统用户，用于加密操作。
//
// 返回值:
//   - *BBIBEPublicParams: 系统公共参数，包含g1, g2, g1^x, g1^y
//   - error: 如果初始化失败，返回错误信息
func (instance *BBIBEInstance) SetUp() (*BBIBEPublicParams, error) {
	_, _, g1, g2 := bn254.Generators()
	// x = g1^x, y = g1^y
	g1x := *new(bn254.G1Affine).ScalarMultiplicationBase(instance.x.BigInt(new(big.Int)))
	g1y := *new(bn254.G1Affine).ScalarMultiplicationBase(instance.y.BigInt(new(big.Int)))
	return &BBIBEPublicParams{
		g1: g1,
		g2: g2,
		x:  g1x,
		y:  g1y,
	}, nil
}

// KeyGenerate 为指定用户身份生成私钥。
// 该方法使用主密钥和用户身份，通过密钥生成算法计算用户的私钥。
// 私钥应通过安全信道传递给对应的用户，并由用户妥善保管。
//
// 参数:
//   - identity: 用户的身份标识符
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *BBIBESecretKey: 生成的私钥，包含随机参数r和密钥元素k
//   - error: 如果密钥生成失败，返回错误信息
func (instance *BBIBEInstance) KeyGenerate(identity *BBIBEIdentity, publicParams *BBIBEPublicParams) (*BBIBESecretKey, error) {
	var err error
	var r fr.Element
	_, err = r.SetRandom()

	// 计算 1 / (ID + x + r*y) mod q
	denominator := new(fr.Element)
	denominator.Mul(&r, &instance.y)
	denominator.Add(denominator, &instance.x)
	denominator.Add(denominator, &identity.Id)
	denominator.Inverse(denominator)

	//denominator := new(big.Int).Mul(r, instance.y) // denominator = r*y
	//denominator.Add(denominator, identity.Id)      // denominator = r*y + ID
	//denominator.Add(denominator, instance.x)       // denominator = r*y + ID + x
	//denominator.Mod(denominator, q)                // denominator = (r*y + ID + x) mod q
	//denominator.ModInverse(denominator, q)

	// k = g2 ^ {1 / (ID + x + r*y)}
	k := *new(bn254.G2Affine).ScalarMultiplicationBase(denominator.BigInt(new(big.Int)))

	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %s", err)
	}

	// r, k = g2^{\frac{1}{Id+x+ry}}
	return &BBIBESecretKey{
		r: r,
		k: k,
	}, nil
}

// Encrypt 使用指定用户身份对消息进行加密。
// 该方法实现了基于身份的加密算法，任何知道公共参数的用户都可以使用接收者的身份进行加密，
// 而无需事先获取接收者的公钥证书。
//
// 参数:
//   - message: 要加密的明文消息
//   - identity: 接收者的身份标识符
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *BBIBECiphertext: 加密后的密文，包含a, b, c三个组件
//   - error: 如果加密失败，返回错误信息
func (instance *BBIBEInstance) Encrypt(message *BBIBEMessage, identity *BBIBEIdentity, publicParams *BBIBEPublicParams) (*BBIBECiphertext, error) {
	var err error
	var s fr.Element
	_, err = s.SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt: %s", err)
	}

	// a = g1^{s * Id} * X^s
	s_id := new(fr.Element).Mul(&s, &identity.Id)
	a := new(bn254.G1Affine).ScalarMultiplicationBase(s_id.BigInt(new(big.Int)))
	x_s := new(bn254.G1Affine).ScalarMultiplication(&publicParams.x, s.BigInt(new(big.Int)))
	a.Add(a, x_s)

	// b = Y^s
	b := *new(bn254.G1Affine).ScalarMultiplication(&publicParams.y, s.BigInt(new(big.Int)))

	// c = e(g1, g2)^s * message
	c, err := bn254.Pair([]bn254.G1Affine{publicParams.g1}, []bn254.G2Affine{publicParams.g2})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	c.Exp(c, s.BigInt(new(big.Int)))
	c.Mul(&c, &message.Message)

	return &BBIBECiphertext{*a, b, c}, nil
}

// Decrypt 使用私钥对密文进行解密。
// 该方法使用用户的私钥恢复原始明文消息。
// 只有持有与密文中身份对应的正确私钥的用户才能成功解密。
//
// 参数:
//   - ciphertext: 要解密的密文
//   - secretKey: 用户的私钥
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *BBIBEMessage: 解密后的明文消息
//   - error: 如果解密失败，返回错误信息
func (instance *BBIBEInstance) Decrypt(ciphertext *BBIBECiphertext, secretKey *BBIBESecretKey, publicParams *BBIBEPublicParams) (*BBIBEMessage, error) {
	// A*B^r
	a_br := new(bn254.G1Affine).ScalarMultiplication(&ciphertext.b, secretKey.r.BigInt(new(big.Int))) // B^r
	a_br.Add(&ciphertext.a, a_br)                                                                     // A*B^r(注意gnark)是加法群

	// e(A*B^r, K)
	denominator, err := bn254.Pair([]bn254.G1Affine{*a_br}, []bn254.G2Affine{secretKey.k})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt")
	}

	// m = C / e(A*B^r, K)
	decryptedMessage := *(new(bn254.GT)).Div(&ciphertext.c, &denominator)
	return &BBIBEMessage{Message: decryptedMessage}, nil
}

func NewBB04Identity(identity *big.Int) (*BBIBEIdentity, error) {
	return &BBIBEIdentity{
		Id: *new(fr.Element).SetBigInt(identity),
	}, nil
}
