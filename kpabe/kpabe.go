package kpabe

import (
	"crypto/rand"
	"fmt"
	"github.com/consensys/gnark-crypto/ecc"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"math/big"
)

type KPABE struct {
	universe int
	distance int
	g1       bn254.G1Affine
	g2       bn254.G2Affine
	q        *big.Int
	msk_ti   []*big.Int
	msk_y    *big.Int
	pk_Ti    []*bn254.G2Affine
	pk_Y     bn254.GT
}

type KPABECiphertext struct {
	messageAttributes []int
	ePrime            bn254.GT
	ei                map[int]*bn254.G2Affine
}

func NewKPABE(universe int, distance int) *KPABE {
	return &KPABE{
		universe: universe,
		distance: distance,
		msk_ti:   make([]*big.Int, universe+1),
		pk_Ti:    make([]*bn254.G2Affine, universe+1),
	}
}

func (kpabe *KPABE) SetUp() {
	kpabe.q = ecc.BN254.ScalarField()
	_, _, kpabe.g1, kpabe.g2 = bn254.Generators()
	var err error
	for i := 1; i <= kpabe.universe; i++ {
		kpabe.msk_ti[i], err = rand.Int(rand.Reader, kpabe.q)
		kpabe.pk_Ti[i] = (&bn254.G2Affine{}).ScalarMultiplicationBase(kpabe.msk_ti[i])
	}
	kpabe.msk_y, err = rand.Int(rand.Reader, kpabe.q)
	eG1G2, err := bn254.Pair([]bn254.G1Affine{kpabe.g1}, []bn254.G2Affine{kpabe.g2})
	kpabe.pk_Y = *((new(bn254.GT)).Exp(eG1G2, kpabe.msk_y))
	if err != nil {
		panic(err)
	}
}

func (kpabe *KPABE) Encrypt(messageAttributes []int, message bn254.GT) (*KPABECiphertext, error) {
	s, err := rand.Int(rand.Reader, kpabe.q)
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt message")
	}
	egg_ys := *(new(bn254.GT)).Exp(kpabe.pk_Y, s)

	ePrime := *(message.Mul(&message, &egg_ys))
	ei := map[int]*bn254.G2Affine{}
	for _, i := range messageAttributes {
		ei[i].ScalarMultiplication(kpabe.pk_Ti[i], s)
	}

	return &KPABECiphertext{
		messageAttributes: messageAttributes,
		ePrime:            ePrime,
		ei:                ei,
	}, nil
}

func (kpabe *KPABE) KeyGenerate() {

}
