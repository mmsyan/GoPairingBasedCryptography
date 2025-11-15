package ibe

// 作者: mmsyan
// 日期: 2025-11-14
// 参考论文:
// Waters, B. (2005). Efficient Identity-Based Encryption Without Random Oracles. In: Cramer, R. (eds) Advances in Cryptology
// – EUROCRYPT 2005. EUROCRYPT 2005. Lecture Notes in Computer Science, vol 3494. Springer, Berlin, Heidelberg.
// https://doi.org/10.1007/11426639_7
//
// 该实现基于BN254椭圆曲线和配对运算,提供了完整的Brent Waters IBE系统功能,包括:
//   - 系统初始化(SetUp)
//   - 密钥生成(KeyGenerate)
//   - 加密(Encrypt)
//   - 解密(Decrypt)
//
// 该实现基于论文的第四章：Construction

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

// Waters05IBEInstance 表示 Waters-05 身份基加密 (IBE) 方案的实例对象。
// 它包含主密钥和由主密钥导出的公开参数的一部分。
type Waters05IBEInstance struct {
	// alpha 是系统的主密钥，是一个随机选取的 Zp 域元素。
	// 必须严格保密。
	alpha fr.Element
	// g2ExpAlpha 是 g2^alpha，作为主密钥的一部分，用于密钥生成。
	g2ExpAlpha bn254.G2Affine
}

// Waters05IBEPublicParams 表示 Waters-05 IBE 方案的公共参数。
// 这些参数在系统初始化时生成，可以公开发布。
type Waters05IBEPublicParams struct {
	// g1 是 BN254 曲线 G1 群的生成元。
	g1 bn254.G1Affine
	// g2 是 BN254 曲线 G2 群的生成元。
	g2 bn254.G2Affine
	// g1ExpAlpha 是 g1^alpha，用于加密。
	g1ExpAlpha bn254.G1Affine
	// uPrime 是 G2 群上的一个随机元素 U'。
	uPrime bn254.G2Affine
	// ui 是 G2 群上的一组随机元素 U_i，用于身份向量的编码。
	// 这里的长度 256 与 SHA-256 的输出位数对应。
	ui [256]bn254.G2Affine
}

// Waters05IBEIdentity 表示 Waters-05 IBE 方案中的用户身份。
// 身份被编码为一个 256 位的二进制向量。
type Waters05IBEIdentity struct {
	// Id 是哈希后的身份字符串对应的 256 位二进制向量，其中每个元素是 0 或 1。
	Id [256]int
}

// Waters05IBESecretKey 表示 Waters-05 IBE 方案中的用户私钥。
type Waters05IBESecretKey struct {
	// d1 是私钥的第一部分，位于 G2 群。
	// d1 = g2^alpha * (U' * Product(U_i^(Id[i]=1)))^r
	d1 bn254.G2Affine
	// d2 是私钥的第二部分，位于 G1 群。
	// d2 = g1^r
	d2 bn254.G1Affine
}

// Waters05IBEMessage 表示 Waters-05 IBE 方案中的明文消息。
// 明文被编码为 GT 群（配对运算的目标群）上的一个元素。
type Waters05IBEMessage struct {
	// Message 是 GT 群上的明文元素。
	Message bn254.GT
}

// Waters05IBECiphertext 表示 Waters-05 IBE 方案中的密文。
// 密文由三个部分组成。
type Waters05IBECiphertext struct {
	// c1 是密文的第一部分，位于 GT 群。
	// c1 = Message * e(g1^alpha, g2)^t
	c1 bn254.GT
	// c2 是密文的第二部分，位于 G1 群。
	// c2 = g1^t
	c2 bn254.G1Affine
	// c3 是密文的第三部分，位于 G2 群。
	// c3 = (U' * Product(U_i^(Id[i]=1)))^t
	c3 bn254.G2Affine
}

// NewWaters05IBEInstance 创建一个新的 Waters-05 IBE 方案实例。
// 该函数随机生成主密钥 alpha，并计算 g2^alpha。
//
// 返回值:
//   - *Waters05IBEInstance: 包含主密钥的 IBE 实例。
//   - error: 如果随机数生成失败，返回错误信息。
func NewWaters05IBEInstance() (*Waters05IBEInstance, error) {
	// 随机选择 alpha
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}
	// 计算 g2^alpha
	g2ExpAlpha := new(bn254.G2Affine).ScalarMultiplicationBase(alpha.BigInt(new(big.Int)))
	return &Waters05IBEInstance{
		alpha:      *alpha,
		g2ExpAlpha: *g2ExpAlpha,
	}, nil
}

// SetUp 执行系统初始化操作，生成并返回公共参数。
// 该方法使用实例中的主密钥 alpha，计算 g1^alpha 和其他随机参数 U', U_i。
//
// 返回值:
//   - *Waters05IBEPublicParams: 系统公共参数。
//   - error: 如果初始化失败，返回错误信息。
func (instance *Waters05IBEInstance) SetUp() (*Waters05IBEPublicParams, error) {
	// 获取 BN254 曲线的生成元 g1 和 g2
	_, _, g1, g2 := bn254.Generators()
	// 计算 g1^alpha
	g1Alpha := new(bn254.G1Affine).ScalarMultiplicationBase(instance.alpha.BigInt(new(big.Int)))

	// 随机选取 U' 的指数
	uPrimeRandom, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to set up")
	}

	// 计算 U' = g2^{随机数}
	uPrime := new(bn254.G2Affine).ScalarMultiplicationBase(uPrimeRandom.BigInt(new(big.Int)))

	// 计算 U_i 数组
	var ui [256]bn254.G2Affine
	for i := 0; i < len(ui); i++ {
		// 随机选取 U_i 的指数
		uRandom, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("failed to set up")
		}
		// 计算 U_i = g2^{随机数}
		ui[i] = *new(bn254.G2Affine).ScalarMultiplicationBase(uRandom.BigInt(new(big.Int)))
	}

	return &Waters05IBEPublicParams{
		g1:         g1,
		g2:         g2,
		g1ExpAlpha: *g1Alpha,
		uPrime:     *uPrime,
		ui:         ui,
	}, nil
}

// KeyGenerate 为指定用户身份生成私钥。
// 该方法使用主密钥 alpha、用户的身份向量以及随机数 r，计算用户的私钥 (d1, d2)。
//
// 参数:
//   - identity: 用户的身份向量。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *Waters05IBESecretKey: 生成的私钥。
//   - error: 如果密钥生成失败，返回错误信息。
func (instance *Waters05IBEInstance) KeyGenerate(identity *Waters05IBEIdentity, publicParams *Waters05IBEPublicParams) (*Waters05IBESecretKey, error) {
	// 随机选取 r
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate key")
	}
	// d2 = g1^r
	d2 := new(bn254.G1Affine).ScalarMultiplicationBase(r.BigInt(new(big.Int)))

	// 计算 Product = U' * Product(U_i^(Id[i]=1))
	product := publicParams.uPrime
	for i := 0; i < len(identity.Id); i++ {
		if identity.Id[i] == 1 {
			// 在 G2 群中执行加法 (对应于指数上的乘法)
			product.Add(&product, &publicParams.ui[i])
		}
	}
	// Product = (U' * Product(U_i^(Id[i]=1)))^r
	// 在 G2 群中执行标量乘法
	product = *(new(bn254.G2Affine)).ScalarMultiplication(&product, r.BigInt(new(big.Int)))

	// d1 = g2^alpha + Product
	// d1 = g2^alpha * (U' * Product(U_i^(Id[i]=1)))^r (乘法群表示)
	// 在 G2 群中执行加法 (对应于指数上的乘法)
	d1 := new(bn254.G2Affine).Add(&instance.g2ExpAlpha, &product)

	return &Waters05IBESecretKey{
		d1: *d1,
		d2: *d2,
	}, nil
}

// Encrypt 使用指定用户身份对消息进行加密。
// 该方法使用接收者的身份向量和随机数 t 进行加密。
//
// 参数:
//   - message: 要加密的明文消息。
//   - identity: 接收者的身份向量。
//   - publicParams: 系统公共参数。
//
// 返回值:
//   - *Waters05IBECiphertext: 加密后的密文 (c1, c2, c3)。
//   - error: 如果加密失败，返回错误信息。
func (instance *Waters05IBEInstance) Encrypt(message *Waters05IBEMessage, identity *Waters05IBEIdentity, publicParams *Waters05IBEPublicParams) (*Waters05IBECiphertext, error) {
	// 随机选取 t
	t, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}

	// 计算 e(g1^alpha, g2)
	eG1AlphaG2, err := bn254.Pair([]bn254.G1Affine{publicParams.g1ExpAlpha}, []bn254.G2Affine{publicParams.g2})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	// 计算 e(g1^alpha, g2)^t
	eG1AlphaG2ExpT := new(bn254.GT).Exp(eG1AlphaG2, t.BigInt(new(big.Int)))
	// c1 = Message * e(g1^alpha, g2)^t
	c1 := *new(bn254.GT).Mul(eG1AlphaG2ExpT, &message.Message)

	// c2 = g1^t
	c2 := *new(bn254.G1Affine).ScalarMultiplicationBase(t.BigInt(new(big.Int)))

	// 计算 Product = U' * Product(U_i^(Id[i]=1))
	c3 := publicParams.uPrime
	for i := 0; i < len(identity.Id); i++ {
		if identity.Id[i] == 1 {
			// 在 G2 群中执行加法 (对应于指数上的乘法)
			c3.Add(&c3, &publicParams.ui[i])
		}
	}
	// c3 = Product^t
	// c3 = (U' * Product(U_i^(Id[i]=1)))^t
	// 在 G2 群中执行标量乘法
	c3 = *new(bn254.G2Affine).ScalarMultiplication(&c3, t.BigInt(new(big.Int)))

	return &Waters05IBECiphertext{
		c1: c1,
		c2: c2,
		c3: c3,
	}, nil
}

// Decrypt 使用私钥对密文进行解密。
// 解密基于配对性质: Message = c1 * e(d2, c3) / e(c2, d1)
//
// 参数:
//   - ciphertext: 要解密的密文 (c1, c2, c3)。
//   - secretkey: 用户的私钥 (d1, d2)。
//   - publicParams: 系统公共参数 (未使用，但作为标准接口参数保留)。
//
// 返回值:
//   - *Waters05IBEMessage: 解密后的明文消息。
//   - error: 如果解密失败，返回错误信息。
func (instance *Waters05IBEInstance) Decrypt(ciphertext *Waters05IBECiphertext, secretKey *Waters05IBESecretKey, publicParams *Waters05IBEPublicParams) (*Waters05IBEMessage, error) {
	// eD2C3 = e(d2, c3) = e(g1^r, (Product)^t) = e(g1, Product)^{rt}
	eD2C3, err := bn254.Pair([]bn254.G1Affine{secretKey.d2}, []bn254.G2Affine{ciphertext.c3})

	// eC2D1 = e(c2, d1) = e(g1^t, g2^alpha * Product^r) = e(g1, g2)^{t*alpha} * e(g1, Product)^{tr}
	eC2D1, err := bn254.Pair([]bn254.G1Affine{ciphertext.c2}, []bn254.G2Affine{secretKey.d1})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message")
	}

	// 分子: c1 * e(d2, c3)
	// 分子 = (Message * e(g1, g2)^{t*alpha}) * e(g1, Product)^{rt}
	m := new(bn254.GT).Mul(&ciphertext.c1, &eD2C3)

	// m = 分子 / e(c2, d1)
	// m = (Message * e(g1, g2)^{t*alpha} * e(g1, Product)^{rt}) / (e(g1, g2)^{t*alpha} * e(g1, Product)^{tr})
	// m = Message
	m = new(bn254.GT).Div(m, &eC2D1)

	return &Waters05IBEMessage{
		Message: *m,
	}, nil
}

// NewWaters05IBEIdentity 将一个字符串身份转换为 Waters-05 IBE 所需的 256 位二进制身份向量。
// 它通过 SHA-256 哈希身份字符串来实现。
//
// 参数:
//   - identity: 用户的身份字符串（例如邮箱地址）。
//
// 返回值:
//   - *Waters05IBEIdentity: 对应的 256 位身份向量。
//   - error: 如果身份字符串为空或哈希失败，返回错误信息。
func NewWaters05IBEIdentity(identity string) (*Waters05IBEIdentity, error) {
	if len(identity) == 0 {
		return nil, errors.New("identity string cannot be empty")
	}

	// 1. 哈希身份字符串 (SHA-256 输出 256 比特，即 32 字节)
	hasher := sha256.New()
	hasher.Write([]byte(identity))
	hashBytes := hasher.Sum(nil)

	wId := &Waters05IBEIdentity{}

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
