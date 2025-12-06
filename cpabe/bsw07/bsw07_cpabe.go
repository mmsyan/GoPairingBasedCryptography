package bsw07

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

type CPABEInstance struct {
}

type CPABEPublicParameters struct {
	g1            bn254.G1Affine
	g2            bn254.G2Affine
	h             bn254.G1Affine
	f             bn254.G2Affine
	eG1G2ExpAlpha bn254.GT
}

type CPABEMasterSecretKey struct {
	beta       fr.Element
	g2ExpAlpha bn254.G2Affine
}

type CPABEUserAttributes struct {
	Attributes []fr.Element
}

type CPABEUserSecretKey struct {
	d       bn254.G2Affine
	dj      map[fr.Element]bn254.G2Affine
	djPrime map[fr.Element]bn254.G2Affine
}

type CPABEMessage struct {
	Message bn254.GT
}

type CPABEAccessPolicy struct{}

type CPABECiphertext struct{}

func (instance *CPABEInstance) SetUp() (*CPABEPublicParameters, *CPABEMasterSecretKey, error) {
	_, _, g1, g2 := bn254.Generators()
	// alpha, beta <- Zq
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("error setting alpha generator: %v", err)
	}
	beta, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("error setting beta generator: %v", err)
	}

	// g2^alpha
	g2ExpAlpha := new(bn254.G2Affine).ScalarMultiplicationBase(alpha.BigInt(new(big.Int)))

	// h = g1^beta
	h := new(bn254.G1Affine).ScalarMultiplicationBase(beta.BigInt(new(big.Int)))

	// f = g2^(1/beta)
	inverseBeta := new(fr.Element).Inverse(beta)
	f := new(bn254.G2Affine).ScalarMultiplicationBase(inverseBeta.BigInt(new(big.Int)))

	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, nil, fmt.Errorf("error pairing : %v", err)
	}
	// e(g1, g2)^alpha
	eG1G2ExpAlpha := new(bn254.GT).Exp(eG1G2, alpha.BigInt(new(big.Int)))

	return &CPABEPublicParameters{
			g1:            g1,
			g2:            g2,
			h:             *h,
			f:             *f,
			eG1G2ExpAlpha: *eG1G2ExpAlpha,
		}, &CPABEMasterSecretKey{
			beta:       *beta,
			g2ExpAlpha: *g2ExpAlpha,
		}, nil
}

func (instance *CPABEInstance) KeyGenerate(attr *CPABEUserAttributes, msk *CPABEMasterSecretKey, pp *CPABEPublicParameters) (*CPABEUserSecretKey, error) {
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("error setting random: %v", err)
	}
	// d = g^((alpha+r)/beta)
	g2ExpR := new(bn254.G2Affine).ScalarMultiplicationBase(r.BigInt(new(big.Int)))
	g2ExpAlphaPlusR := new(bn254.G2Affine).Add(&msk.g2ExpAlpha, g2ExpR)
	inverseBeta := new(fr.Element).Inverse(&msk.beta)
	d := new(bn254.G2Affine).ScalarMultiplication(g2ExpAlphaPlusR, inverseBeta.BigInt(new(big.Int)))

	dj := make(map[fr.Element]bn254.G2Affine, len(attr.Attributes))
	djPrime := make(map[fr.Element]bn254.G2Affine, len(attr.Attributes))
	for _, j := range attr.Attributes {
		rj, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("error setting random: %v", err)
		}
		g2ExpR := new(bn254.G2Affine).ScalarMultiplicationBase(r.BigInt(new(big.Int)))
		hj := HashBSw07(j)
		hjExpRj := new(bn254.G2Affine).ScalarMultiplication(&hj, rj.BigInt(new(big.Int)))
		dj[j] = *new(bn254.G2Affine).Add(g2ExpR, hjExpRj)
		djPrime[j] = *new(bn254.G2Affine).ScalarMultiplicationBase(rj.BigInt(new(big.Int)))
	}

	return &CPABEUserSecretKey{
		d:       *d,
		dj:      dj,
		djPrime: djPrime,
	}, nil
}

func (instance *CPABEInstance) Encrypt(message *CPABEMessage, accessPolicy *CPABEAccessPolicy, pp *CPABEPublicParameters) (*CPABECiphertext, error) {
	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("error setting random: %v", err)
	}
	// e(g,g)^(alpha*s)
	eG1G2ExpAlphaS := new(bn254.GT).Exp(pp.eG1G2ExpAlpha, s.BigInt(new(big.Int)))
	cTilde := new(bn254.GT).Mul(eG1G2ExpAlphaS, &message.Message)
	c := new(bn254.G1Affine).ScalarMultiplication(&pp.h, s.BigInt(new(big.Int)))
}

func (instance *CPABEInstance) Decrypt(ciphertext *CPABECiphertext, usk *CPABEUserSecretKey) (*CPABEMessage, error) {
}

func (instance *CPABEInstance) Delegate(usk *CPABEUserSecretKey, subsetAttr *CPABEUserAttributes) (*CPABEUserSecretKey, error) {
}
