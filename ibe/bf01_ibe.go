package ibe

// 作者: mmsyan
// 日期: 2025-11-01
// 参考论文:
// Dan Boneh and Matthew Franklin. "Identity-Based Encryption from the Weil Pairing."
// In Advances in Cryptology - CRYPTO 2001, pp. 213-229. Springer, 2001.
//
// 论文链接: https://link.springer.com/chapter/10.1007/3-540-44647-8_13
// 预印本: https://crypto.stanford.edu/~dabo/pubs/papers/bfibe.pdf
//
// 该实现基于BN254椭圆曲线和配对运算,提供了完整的Boneh-Franklin IBE系统功能,包括:
//   - 系统初始化(SetUp)
//   - 密钥生成(KeyGenerate)
//   - 加密(Encrypt)
//   - 解密(Decrypt)
//
// 与Boneh-Boyen方案的主要区别:
//   - 使用Hash-to-Curve将身份映射到G2群元素
//   - 采用混合加密方式,使用XOR掩码保护实际消息
//   - 密文更加紧凑,适合加密任意长度的字节消息

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"github.com/mmsyan/GnarkPairingProject/utils"
	"math/big"
)

// BFIBEInstance 表示Boneh-Franklin身份基加密(IBE)方案的实例对象。
// 该实例包含了系统的主密钥x,它是Zp域上的一个随机元素。
// 主密钥用于生成用户的私钥,必须严格保密。
// DST(Domain Separation Tag)用于Hash-to-Curve操作,确保哈希的域分离。
type BFIBEInstance struct {
	x   fr.Element
	DST []byte
}

// BFIBEPublicParams 表示Boneh-Franklin IBE方案的公共参数。
// 这些参数在系统初始化时生成,可以公开发布给所有用户。
// 包含基础生成元g1和由主密钥派生的公开元素g1x=g1^x。
type BFIBEPublicParams struct {
	g1  bn254.G1Affine
	g1x bn254.G1Affine
}

// BFIBEIdentity 表示Boneh-Franklin IBE方案中的用户身份。
// 身份使用字符串表示(如邮箱地址),在加密和密钥生成时会通过Hash-to-Curve
// 函数映射到G2群上的一个点。
type BFIBEIdentity struct {
	Id string
}

// BFIBESecretKey 表示Boneh-Franklin IBE方案中的用户私钥。
// 私钥是G2群上的一个元素,计算为sk=h(Id)^x,其中H是Hash-to-Curve函数。
// 私钥由密钥生成中心(PKG)使用主密钥和用户身份生成,必须安全地传递给用户。
type BFIBESecretKey struct {
	sk bn254.G2Affine
}

// BFIBEMessage 表示Boneh-Franklin IBE方案中的明文消息。
// 明文是任意长度的字节数组,可以直接表示实际的消息内容。
// 该方案使用混合加密,通过XOR操作保护消息。
type BFIBEMessage struct {
	Message []byte
}

// BFIBECiphertext 表示Boneh-Franklin IBE方案中的密文。
// 密文由两个部分组成:
//   - C1: G1群上的元素,为g^r,其中r是随机数
//   - C2: 字节数组,为M ⊕ H2(e(g1x, h(Id))^r),包含加密后的消息
type BFIBECiphertext struct {
	C1 bn254.G1Affine
	C2 []byte
}

// NewBFIBEInstance 创建一个新的Boneh-Franklin IBE方案实例。
// 该函数随机生成主密钥x,它是从Zp域中均匀随机采样的元素。
// 同时初始化域分离标签DST为"ibe Encryption",用于Hash-to-Curve操作。
// 返回的实例对象包含主密钥,应该由可信的密钥生成中心(PKG)持有并妥善保管。
//
// 返回值:
//   - *BFIBEInstance: 包含主密钥和DST的IBE实例
//   - error: 如果创建实例失败,返回错误信息
func NewBFIBEInstance() (*BFIBEInstance, error) {
	var x fr.Element
	var err error
	_, err = x.SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate identity based encryption instance")
	}
	return &BFIBEInstance{x, []byte("ibe Encryption")}, nil
}

// SetUp 执行系统初始化操作,生成并返回公共参数。
// 该方法使用IBE实例中的主密钥,计算公开的系统参数。
// 生成的公共参数可以安全地发布给所有系统用户,用于加密操作。
//
// 返回值:
//   - *BFIBEPublicParams: 系统公共参数,包含g1和g1^x
//   - error: 如果初始化失败,返回错误信息
func (instance *BFIBEInstance) SetUp() (*BFIBEPublicParams, error) {
	// g <- G1
	// g^x in G1
	_, _, g, _ := bn254.Generators()
	gx := *new(bn254.G1Affine).ScalarMultiplicationBase(instance.x.BigInt(new(big.Int)))
	return &BFIBEPublicParams{
		g1:  g,
		g1x: gx,
	}, nil
}

// KeyGenerate 为指定用户身份生成私钥。
// 该方法首先将用户身份通过Hash-to-Curve函数映射到G2群上的点Qid,
// 然后计算私钥sk=Qid^x。私钥应通过安全信道传递给对应的用户,并由用户妥善保管。
//
// 参数:
//   - identity: 用户的身份标识符(字符串形式)
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *BFIBESecretKey: 生成的私钥,为G2群上的元素
//   - error: 如果Hash-to-Curve或密钥生成失败,返回错误信息
func (instance *BFIBEInstance) KeyGenerate(identity *BFIBEIdentity, publicParams *BFIBEPublicParams) (*BFIBESecretKey, error) {
	// qid = hashToCurve(id) in G2
	qid := hash.ToG2(identity.Id)
	// sk = qid^x
	sk := *new(bn254.G2Affine).ScalarMultiplication(&qid, instance.x.BigInt(new(big.Int)))
	return &BFIBESecretKey{
		sk: sk,
	}, nil
}

// Encrypt 使用指定用户身份对消息进行加密。
// 该方法实现了Boneh-Franklin基于身份的加密算法,采用混合加密方式:
// 1. 将身份哈希到G2群得到Qid
// 2. 选择随机数r,计算C1=g^r
// 3. 计算gid=e(g1x, Qid)^r,这是共享密钥
// 4. 将消息与H2(gid)进行XOR操作得到C2
//
// 任何知道公共参数的用户都可以使用接收者的身份进行加密,
// 而无需事先获取接收者的公钥证书。
//
// 参数:
//   - identity: 接收者的身份标识符
//   - message: 要加密的明文消息(字节数组)
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *BFIBECiphertext: 加密后的密文,包含C1(G1元素)和C2(字节数组)
//   - error: 如果加密过程失败,返回错误信息
func (instance *BFIBEInstance) Encrypt(identity *BFIBEIdentity, message *BFIBEMessage, publicParams *BFIBEPublicParams) (*BFIBECiphertext, error) {
	// qid = hashToCurve(id) in G2
	qid := hash.ToG2(identity.Id)

	// r <- Zq
	r, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	// c1 = g^r
	c1 := *new(bn254.G1Affine).ScalarMultiplicationBase(r)

	// c2 = m xor H2(gid)
	// gid = e(g^x, qid)^r
	eGxQid, err := bn254.Pair([]bn254.G1Affine{publicParams.g1x}, []bn254.G2Affine{qid})
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	gid := *(new(bn254.GT).Exp(eGxQid, r))
	gidBytes := hash.FromGT(gid)
	c2 := utils.Xor(message.Message, gidBytes)

	return &BFIBECiphertext{
		C1: c1,
		C2: c2,
	}, nil
}

// Decrypt 使用私钥对密文进行解密。
// 该方法通过配对运算恢复共享密钥gid=e(C1, sk)=e(g^r, Qid^x),
// 然后使用H2(gid)与C2进行XOR操作恢复原始明文。
// 只有持有与密文中身份对应的正确私钥的用户才能成功解密。
//
// 解密正确性:
// e(C1, sk) = e(g^r, Qid^x) = e(g, Qid)^(rx) = e(g^x, Qid)^r = gid
//
// 参数:
//   - ciphertext: 要解密的密文
//   - secretKey: 用户的私钥
//   - publicParams: 系统公共参数
//
// 返回值:
//   - *BFIBEMessage: 解密后的明文消息(字节数组)
//   - error: 如果解密失败,返回错误信息
func (instance *BFIBEInstance) Decrypt(ciphertext *BFIBECiphertext, secretKey *BFIBESecretKey, publicParams *BFIBEPublicParams) (*BFIBEMessage, error) {
	// gid = e(c1, sk) = e(g^r, qid^x)
	gid, err := bn254.Pair([]bn254.G1Affine{ciphertext.C1}, []bn254.G2Affine{secretKey.sk})
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt message")
	}
	gidBytes := hash.FromGT(gid)
	return &BFIBEMessage{
		Message: utils.Xor(ciphertext.C2, gidBytes),
	}, nil
}

func NewBF01Identity(identity string) (*BFIBEIdentity, error) {
	return &BFIBEIdentity{
		Id: identity,
	}, nil
}
