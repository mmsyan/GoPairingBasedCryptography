package fibe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	utils2 "github.com/mmsyan/GnarkPairingProject/fibe/utils"
	"github.com/mmsyan/GnarkPairingProject/utils"
	"math/big"
)

type SW05FIBELargeUniverseInstance struct {
	universe int64      // 属性宇宙的大小 U。属性被预定义为 [1, 2, ..., U]。
	distance int        // 加密方案的容错距离 d (也称为门限值)。
	msk_y    fr.Element // 另一个主密钥组件 y，是 Zq 域上的随机元素。
}

type SW05FIBELargeUniversePublicParams struct {
	n    int64
	g1   bn254.G1Affine // G1 群的生成元 g1。
	g2   bn254.G2Affine // G2 群的生成元 g2。
	ti   []bn254.G2Affine
	pk_Y bn254.GT
}

type SW05FIBELargeUniverseAttributes struct {
	attributes []int64 // 属性集合 S，一个整数数组。

}

type SW05FIBELargeUniverseSecretKey struct {
	userAttributes []int64                   // 用户拥有的属性集 S_user。
	_di            map[int64]*bn254.G1Affine // 私钥组件 d_i，对应 S_user 中的每个属性 i。
	_Di            map[int64]*bn254.G2Affine
}

type SW05FIBELargeUniverseMessage struct {
	Message bn254.GT // GT 群上的消息 M。
}

type SW05FIBELargeUniverseCiphertext struct {
	messageAttributes []int64  // 密文关联的属性集 S_msg。
	ePrime            bn254.GT // 密文组件 e' = M * Y^s，其中 s 是加密随机数。
	ePrimePrime       bn254.G1Affine
	ei                map[int64]*bn254.G2Affine // 密文组件 E_i = (T_i)^s，对应 S_msg 中的每个属性 i。
}

func NewSW05FIBELargeUniverseInstance(universe int64, distance int) *SW05FIBELargeUniverseInstance {
	// 使用 &SW05FIBEInstance{} 语法创建一个结构体实例并返回其指针。
	return &SW05FIBELargeUniverseInstance{
		universe: universe,
		distance: distance,
	}
}

func (instance *SW05FIBELargeUniverseInstance) SetUp() (*SW05FIBELargeUniversePublicParams, error) {
	_, _, g1, g2 := bn254.Generators()
	ti := make([]bn254.G2Affine, instance.universe+2)

	for i := int64(1); i <= instance.universe; i++ {
		temp, err := new(fr.Element).SetRandom() // t_i <- Zq
		if err != nil {
			return nil, fmt.Errorf("fibe instance setup failure")
		}
		ti[i] = *new(bn254.G2Affine).ScalarMultiplicationBase(temp.BigInt(new(big.Int)))
	}

	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2}) // e(g1, g2)
	if err != nil {
		return nil, fmt.Errorf("fibe instance setup failure")
	}
	// Y = e(g1, g2)^y
	pk_Y := *new(bn254.GT).Exp(eG1G2, instance.msk_y.BigInt(new(big.Int)))

	return &SW05FIBELargeUniversePublicParams{
		n:    instance.universe,
		g1:   g1,
		g2:   g2,
		ti:   ti,
		pk_Y: pk_Y,
	}, nil
}

func (instance *SW05FIBELargeUniverseInstance) KeyGenerate(userAttributes *SW05FIBELargeUniverseAttributes, publicParams *SW05FIBELargeUniversePublicParams) (*SW05FIBELargeUniverseSecretKey, error) {
	di := make(map[int64]*bn254.G1Affine)
	Di := make(map[int64]*bn254.G2Affine)
	polynomial := utils.GenerateRandomPolynomial(instance.distance, instance.msk_y)
	for _, i := range userAttributes.attributes {
		ri, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("fibe instance setup failure")
		}
		di[i] = new(bn254.G1Affine).ScalarMultiplicationBase(ri.BigInt(new(big.Int)))
		qi := utils.ComputePolynomialValue(polynomial, *new(fr.Element).SetInt64(int64(i)))
		g2ExpQi := new(bn254.G2Affine).ScalarMultiplicationBase(qi.BigInt(new(big.Int)))
		ti := publicParams.computeT(i)
		tiExpRi := new(bn254.G2Affine).ScalarMultiplication(&ti, ri.BigInt(new(big.Int)))
		Di[i] = new(bn254.G2Affine).Add(g2ExpQi, tiExpRi)
	}

	return &SW05FIBELargeUniverseSecretKey{
		userAttributes: userAttributes.attributes,
		_di:            di,
		_Di:            Di,
	}, nil
}

func (instance *SW05FIBELargeUniverseInstance) Encrypt(messageAttributes *SW05FIBELargeUniverseAttributes, message *SW05FIBELargeUniverseMessage, publicParams *SW05FIBELargeUniversePublicParams) (*SW05FIBELargeUniverseCiphertext, error) {
	// 选择一个随机数 s <- Zq。
	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt Message")
	}
	// 计算 Y^s = (e(g1, g2)^y)^s。
	egg_ys := *(new(bn254.GT)).Exp(publicParams.pk_Y, s.BigInt(new(big.Int)))

	// 计算密文组件 e' = M * Y^s。
	ePrime := *new(bn254.GT).Mul(&message.Message, &egg_ys)

	ePrimePrime := *new(bn254.G1Affine).ScalarMultiplicationBase(s.BigInt(new(big.Int)))

	ei := make(map[int64]*bn254.G2Affine)
	for _, i := range messageAttributes.attributes {
		ti := publicParams.computeT(i)
		ei[i] = new(bn254.G2Affine).ScalarMultiplication(&ti, s.BigInt(new(big.Int)))
	}

	return &SW05FIBELargeUniverseCiphertext{
		messageAttributes: messageAttributes.attributes,
		ePrime:            ePrime,
		ePrimePrime:       ePrimePrime,
		ei:                ei,
	}, nil
}

func (instance *SW05FIBELargeUniverseInstance) Decrypt(userSecretKey *SW05FIBELargeUniverseSecretKey, ciphertext *SW05FIBELargeUniverseCiphertext, publicParams *SW05FIBELargeUniversePublicParams) (*SW05FIBELargeUniverseMessage, error) {
	s := utils2.FindCommonAttributes(userSecretKey.userAttributes, ciphertext.messageAttributes, instance.distance)
	if s == nil {
		return nil, fmt.Errorf("failed to find enough common attributes")
	}

	denominator := new(bn254.GT).SetOne()

	// 遍历公共属性集 S 中的每个属性 i。
	for _, i := range s {
		di := *userSecretKey._di[i] // 私钥组件 d_i = g1^(q(i)/t_i)
		Di := *userSecretKey._Di[i]
		ei := *ciphertext.ei[i] // 密文组件 e_i = g2^(t_i * s)

		// 计算配对 e(d_i, E_i) = e(g1^(q(i)/t_i), g2^(t_i * s)) = e(g1, g2)^(q(i) * s)。
		ediEi, err := bn254.Pair([]bn254.G1Affine{di}, []bn254.G2Affine{ei})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt Message")
		}
		eDiEPrimePrime, err := bn254.Pair([]bn254.G1Affine{ciphertext.ePrimePrime}, []bn254.G2Affine{Di})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt Message")
		}

		pairDiv := new(bn254.GT).Div(&ediEi, &eDiEPrimePrime)

		// 计算拉格朗日基多项式 Δ_{0, S}(i) = ∏_{j ∈ S, j ≠ i} (0 - j) / (i - j)。
		delta := utils2.ComputeLagrangeBasis(i, s, 0)

		pairExpDelta := new(bn254.GT).Exp(*pairDiv, delta.BigInt(new(big.Int)))

		// 累乘到分母中。
		denominator.Mul(denominator, pairExpDelta)
	}
	m := new(bn254.GT).Mul(&ciphertext.ePrime, denominator)
	return &SW05FIBELargeUniverseMessage{
		Message: *m,
	}, nil
}

func (publicParams *SW05FIBELargeUniversePublicParams) computeT(x int64) bn254.G2Affine {
	xElement := new(fr.Element).SetInt64(int64(x))
	nElement := new(fr.Element).SetInt64(int64(publicParams.n))
	xExpN := new(fr.Element).Exp(*xElement, nElement.BigInt(new(big.Int)))
	g2ExpXExpN := new(bn254.G2Affine).ScalarMultiplicationBase(xExpN.BigInt(new(big.Int)))

	N := make([]int64, publicParams.n+1)
	for i := 0; i < len(N); i++ {
		N[i] = int64(i + 1)
	}
	for i := int64(0); i < int64(len(publicParams.ti)); i++ {
		delta := utils2.ComputeLagrangeBasis(i, N, int(x))
		tiExpDelta := new(bn254.G2Affine).ScalarMultiplication(&publicParams.ti[i], delta.BigInt(new(big.Int)))
		g2ExpXExpN.Add(g2ExpXExpN, tiExpDelta)
	}

	return *g2ExpXExpN
}

func NewFIBELargeUniverseAttributes(attributes []int64) (*SW05FIBELargeUniverseAttributes, error) {
	return &SW05FIBELargeUniverseAttributes{
		attributes: attributes,
	}, nil
}
