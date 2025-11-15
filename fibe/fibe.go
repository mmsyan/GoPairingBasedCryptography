package fibe

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/utils"
	"math/big"
)

type FIBEInstance struct {
	universe int // 属性宇宙的大小，属性被预定义好为[1, 2, …… , Universe]
	distance int // 加密方案的容错距离，控制解密时要求的最小匹配度
	msk_ti   []fr.Element
	msk_y    fr.Element
}

type FIBEPublicParams struct {
	g1    bn254.G1Affine
	g2    bn254.G2Affine
	pk_Ti []*bn254.G2Affine
	pk_Y  bn254.GT
}

type FIBEAttributes struct {
	attributes []int
}

type FIBESecretKey struct {
	userAttributes []int
	di             map[int]*bn254.G1Affine
}

type FIBEMessage struct {
	Message bn254.GT
}

type FIBECiphertext struct {
	messageAttributes []int
	ePrime            bn254.GT
	ei                map[int]*bn254.G2Affine
}

func NewFIBEInstance(universe int, distance int) *FIBEInstance {
	// 使用 &FIBEInstance{} 语法创建一个结构体实例并返回其指针。
	return &FIBEInstance{
		universe: universe,
		distance: distance,
		// Zp类型元素数组。为了与论文适配，我们选择让属性从1开始到U结束，因此msk_ti刚好表示第i个主密钥
		msk_ti: make([]fr.Element, universe+1),
	}
}

func (instance *FIBEInstance) SetUp() (*FIBEPublicParams, error) {
	_, _, g1, g2 := bn254.Generators()
	pk_Ti := make([]*bn254.G2Affine, instance.universe+1)

	for i := 1; i <= instance.universe; i++ {
		temp, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("fibe instance setup failure")
		}
		instance.msk_ti[i] = *temp                                                         // ti <- Zq
		pk_Ti[i] = new(bn254.G2Affine).ScalarMultiplicationBase(temp.BigInt(new(big.Int))) // Ti = g2^ti
	}
	temp, err := new(fr.Element).SetRandom()
	instance.msk_y = *temp // y <- Zq
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	pk_Y := *new(bn254.GT).Exp(eG1G2, instance.msk_y.BigInt(new(big.Int))) // Y = e(g1, g2)^y
	if err != nil {
		return nil, err
	}
	return &FIBEPublicParams{
		g1:    g1,
		g2:    g2,
		pk_Ti: pk_Ti,
		pk_Y:  pk_Y,
	}, nil

}

func (instance *FIBEInstance) KeyGenerate(userAttributes *FIBEAttributes, publicParams *FIBEPublicParams) (*FIBESecretKey, error) {
	if !utils.CheckAttributesArray(userAttributes.attributes, instance.universe) {
		return nil, fmt.Errorf("invalid user attributes")
	}
	di := make(map[int]*bn254.G1Affine)
	polynomial := utils.GenerateRandomPolynomial(instance.distance, instance.msk_y)
	for _, i := range userAttributes.attributes {
		qi := utils.ComputePolynomialValue(polynomial, *new(fr.Element).SetInt64(int64(i)))
		// 在有限域 F_q 内计算除法：qiDivTi = qi * (msk_ti[i])^{-1} mod q
		tiInverse := new(fr.Element).Inverse(&instance.msk_ti[i])
		qiDivTi := new(fr.Element).Mul(&qi, tiInverse)
		// Di = g1^(q(i)/ti)
		Di := new(bn254.G1Affine).ScalarMultiplicationBase(qiDivTi.BigInt(new(big.Int)))
		di[i] = Di
	}
	return &FIBESecretKey{
		userAttributes: userAttributes.attributes,
		di:             di,
	}, nil
}

func (instance *FIBEInstance) Encrypt(messageAttributes *FIBEAttributes, message *FIBEMessage, publicParams *FIBEPublicParams) (*FIBECiphertext, error) {
	if !utils.CheckAttributesArray(messageAttributes.attributes, instance.universe) {
		return nil, fmt.Errorf("invalid cipher text")
	}
	s, err := rand.Int(rand.Reader, ecc.BN254.ScalarField())
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt Message")
	}
	egg_ys := *(new(bn254.GT)).Exp(publicParams.pk_Y, s)

	// e' = Message * Y^s = Message * (e(g1, g2)^y)^s
	ePrime := *new(bn254.GT).Mul(&message.Message, &egg_ys)

	// ei = Ti^s = (g2^ti)^s
	ei := map[int]*bn254.G2Affine{}
	for _, i := range messageAttributes.attributes {
		//ei[i] = instance.pk_Ti[i].ScalarMultiplicationBase(s)
		ei[i] = (&bn254.G2Affine{}).ScalarMultiplication(publicParams.pk_Ti[i], s)
	}

	return &FIBECiphertext{
		messageAttributes: messageAttributes.attributes,
		ePrime:            ePrime,
		ei:                ei,
	}, nil

}

func (instance *FIBEInstance) Decrypt(userSecretKey *FIBESecretKey, ciphertext *FIBECiphertext, publicParams *FIBEPublicParams) (*FIBEMessage, error) {
	if !utils.CheckAttributesArray(userSecretKey.userAttributes, instance.universe) {
		return nil, fmt.Errorf("invalid user attributes")
	}
	if !utils.CheckAttributesArray(ciphertext.messageAttributes, instance.universe) {
		return nil, fmt.Errorf("invalid cipher text")
	}

	s := utils.FindCommonAttributes(userSecretKey.userAttributes, ciphertext.messageAttributes, instance.distance)
	if s == nil {
		return nil, fmt.Errorf("failed to find enough common attributes")
	}
	denominator := bn254.GT{}
	denominator.SetOne()
	for _, i := range s {
		di := *userSecretKey.di[i]
		ei := *ciphertext.ei[i]
		// e(Di, Ei)
		eDiEi, err := bn254.Pair([]bn254.G1Affine{di}, []bn254.G2Affine{ei})
		if err != nil {
			return nil, fmt.Errorf("failed to decrypt Message")
		}
		delta := utils.ComputeLagrangeBasis(i, s, 0)
		eDiEiDelta := new(bn254.GT).Exp(eDiEi, delta.BigInt(new(big.Int)))
		denominator.Mul(&denominator, eDiEiDelta)
	}

	decryptedMessage := new(bn254.GT).Div(&ciphertext.ePrime, &denominator)
	return &FIBEMessage{Message: *decryptedMessage}, nil
}

func NewFIBEAttributes(attributes []int) (*FIBEAttributes, error) {
	return &FIBEAttributes{
		attributes: attributes,
	}, nil
}
