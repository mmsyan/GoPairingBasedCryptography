package kpabe

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
)

type KPABEInstance struct {
	universe int
	g1       bn254.G1Affine
	g2       bn254.G2Affine
	q        *big.Int
	msk_ti   []*big.Int
	msk_y    *big.Int
}

type KPABEPublicParams struct {
	pk_Ti []*bn254.G2Affine
	pk_Y  bn254.GT
}

type KPABEMessage struct {
	Message bn254.GT
}

type KPABECiphertext struct {
	messageAttributes []int
	ePrime            bn254.GT
	ei                map[int]*bn254.G2Affine
}

func NewKPABEInstance(universe int, distance int) *KPABEInstance {
	return &KPABEInstance{
		universe: universe,
		msk_ti:   make([]*big.Int, universe+1),
	}
}

func (instance *KPABEInstance) SetUp() (*KPABEPublicParams, error) {
	instance.q = ecc.BN254.ScalarField()
	_, _, instance.g1, instance.g2 = bn254.Generators()
	pk_Ti := make([]*bn254.G2Affine, instance.universe+1)

	var err error
	for i := 1; i <= instance.universe; i++ {
		instance.msk_ti[i], err = rand.Int(rand.Reader, instance.q)
		pk_Ti[i] = (&bn254.G2Affine{}).ScalarMultiplicationBase(instance.msk_ti[i])
	}
	instance.msk_y, err = rand.Int(rand.Reader, instance.q)
	eG1G2, err := bn254.Pair([]bn254.G1Affine{instance.g1}, []bn254.G2Affine{instance.g2})
	pk_Y := *new(bn254.GT).Exp(eG1G2, instance.msk_y)
	if err != nil {
		return nil, err
	}
	return &KPABEPublicParams{
		pk_Ti: pk_Ti,
		pk_Y:  pk_Y,
	}, nil
}

func (instance *KPABEInstance) Encrypt(messageAttributes []int, message *KPABEMessage, publicParams *KPABEPublicParams) (*KPABECiphertext, error) {
	s, err := rand.Int(rand.Reader, instance.q)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	egg_ys := *(new(bn254.GT)).Exp(publicParams.pk_Y, s)

	// e' = Message * Y^s = Message * (e(g1, g2)^y)^s
	ePrime := *new(bn254.GT).Mul(&message.Message, &egg_ys)

	// ei = Ti^s = (g2^ti)^s
	ei := map[int]*bn254.G2Affine{}
	for _, i := range messageAttributes {
		//ei[i] = instance.pk_Ti[i].ScalarMultiplicationBase(s)
		ei[i] = (&bn254.G2Affine{}).ScalarMultiplication(publicParams.pk_Ti[i], s)
	}
	return &KPABECiphertext{
		messageAttributes: messageAttributes,
		ePrime:            ePrime,
		ei:                ei,
	}, nil
}

func (instance *KPABEInstance) KeyGenerate() {

}
