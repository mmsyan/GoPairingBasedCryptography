// Package agka09
// implements the Qianhong Wu, Yi Mu, Willy Susilo, Bo Qin & Josep Domingo-Ferrer's Aggregatable Signature-Based Broadcast
// 作者: mmsyan
// 日期: 2026-01-13
// 参考论文:
// Wu, Q., Mu, Y., Susilo, W., Qin, B., Domingo-Ferrer, J. (2009).
// Asymmetric Group Key Agreement.
// In: Joux, A. (eds) Advances in Cryptology - EUROCRYPT 2009. EUROCRYPT 2009.
// Lecture Notes in Computer Science, vol 5479. Springer, Berlin, Heidelberg.
// https://doi.org/10.1007/978-3-642-01001-9_9
// eprint link: https://eprint.iacr.org/2010/209.pdf
//
// Algorithms:
// publicParameters := ParaGen()
// (pk, sk) <- KeyGen(π)
// σ <- Sign(str, sk)
// 0/1 := Verify(str, σ, pk)
// ciphertext <- Encrypt(plaintext, pk)
// plaintext := Decrypt(ciphertext, str, σ)
//
// Key Homomorphism:
// if:
//
//	(1) (pk1, sk1) <- KeyGen(π) and (pk2, sk2) <- KeyGen(π)
//	(2) σ1 = Sign(str, pk1, sk1) && σ2 = Sign(str, pk2, sk2)
//
// then:
//
//	(1) Verify(str, σ1*σ2, pk1*pk2) = 1
//	(2) Encrypt(plaintext, pk1*pk2) = c => Decrypt(c, str, σ1*σ2) = m
package agka09

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GoPairingBasedCryptography/hash"
	"math/big"
)

type PublicParameters struct {
	G1 bn254.G1Affine
	G2 bn254.G2Affine
}

type PublicKey struct {
	R bn254.G2Affine
	A bn254.GT
}

type PrivateKey struct {
	R fr.Element
	X bn254.G1Affine
}

type SignMessage struct {
	S []byte
}

type Signature struct {
	Sigma bn254.G1Affine
}

type PlainText struct {
	M bn254.GT
}

type CipherText struct {
	C1 bn254.G2Affine
	C2 bn254.G2Affine
	C3 bn254.GT
}

func ParaGen() (*PublicParameters, error) {
	_, _, g1, g2 := bn254.Generators()
	return &PublicParameters{
		G1: g1,
		G2: g2,
	}, nil
}

func KeyGen(pp *PublicParameters) (*PublicKey, *PrivateKey, error) {
	// r <- Zp*
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate random key: %v", err)
	}

	// X <- G1
	xElement, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("unable to generate random key: %v", err)
	}
	x := *new(bn254.G1Affine).ScalarMultiplicationBase(xElement.BigInt(new(big.Int)))

	// R = g2^{-r}
	negR := new(fr.Element).Neg(r)
	g2ExpNegR := new(bn254.G2Affine).ScalarMultiplicationBase(negR.BigInt(new(big.Int)))

	// A = e(X, g2)
	pairXG2, err := bn254.Pair([]bn254.G1Affine{x}, []bn254.G2Affine{pp.G2})
	if err != nil {
		return nil, nil, err
	}

	return &PublicKey{
			R: *g2ExpNegR,
			A: pairXG2,
		}, &PrivateKey{
			R: *r,
			X: x,
		}, nil
}

func Sign(s *SignMessage, sk *PrivateKey) (*Signature, error) {
	hs := hash.BytesToG1(s.S)
	hsExpR := new(bn254.G1Affine).ScalarMultiplication(&hs, sk.R.BigInt(new(big.Int)))
	// σ = X·H(s)^r
	sigma := new(bn254.G1Affine).Add(&sk.X, hsExpR)
	return &Signature{Sigma: *sigma}, nil
}

func Verify(s *SignMessage, sigma *Signature, pk *PublicKey) (bool, error) {
	_, _, _, g2 := bn254.Generators()

	// e(σ, g2)
	pairSigmaG2, err := bn254.Pair([]bn254.G1Affine{sigma.Sigma}, []bn254.G2Affine{g2})
	if err != nil {
		return false, fmt.Errorf("unable to verify signature: %v", err)
	}

	// e(H(s), R)
	pairHsR, err := bn254.Pair([]bn254.G1Affine{hash.BytesToG1(s.S)}, []bn254.G2Affine{pk.R})
	if err != nil {
		return false, fmt.Errorf("unable to verify signature: %v", err)
	}

	// e(σ, g2) * e(H(s), R) ==?== A
	pairLeft := new(bn254.GT).Mul(&pairSigmaG2, &pairHsR)
	if pairLeft.Equal(&pk.A) {
		return true, nil
	} else {
		return false, fmt.Errorf("sigma is a not valid signature!")
	}

}

func Encrypt(plaintext *PlainText, pk *PublicKey) (*CipherText, error) {
	// t <- Zp*
	t, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("unable to generate random ciphertext: %v", err)
	}

	// c1 = g2^t
	c1 := new(bn254.G2Affine).ScalarMultiplicationBase(t.BigInt(new(big.Int)))

	// c2 = R^t
	c2 := new(bn254.G2Affine).ScalarMultiplication(&pk.R, t.BigInt(new(big.Int)))

	// c3 = m·A^t
	aExpT := new(bn254.GT).Exp(pk.A, t.BigInt(new(big.Int)))
	c3 := new(bn254.GT).Mul(&plaintext.M, aExpT)

	return &CipherText{
		C1: *c1,
		C2: *c2,
		C3: *c3,
	}, nil

}

func Decrypt(c CipherText, s *SignMessage, sigma *Signature) (*PlainText, error) {
	// e(σ, c1)
	pairSigmaC1, err := bn254.Pair([]bn254.G1Affine{sigma.Sigma}, []bn254.G2Affine{c.C1})
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt ciphertext: %v", err)
	}

	// e(H(s), c2)
	pairHsC2, err := bn254.Pair([]bn254.G1Affine{hash.BytesToG1(s.S)}, []bn254.G2Affine{c.C2})
	if err != nil {
		return nil, fmt.Errorf("unable to decrypt ciphertext: %v", err)
	}

	// c3 / [e(σ, c1)*e(H(s), c2)]
	temp := new(bn254.GT).Mul(&pairSigmaC1, &pairHsC2)
	plainText := new(bn254.GT).Div(&c.C3, temp)

	return &PlainText{M: *plainText}, nil
}

func AggregatePublicKeys(pks []*PublicKey) (*PublicKey, error) {
	if len(pks) == 0 {
		return nil, fmt.Errorf("no public keys provided")
	}
	aggregateR := *new(bn254.G2Affine).SetInfinity()
	aggregateA := *new(bn254.GT).SetOne()
	for _, pk := range pks {
		aggregateR.Add(&aggregateR, &pk.R)
		aggregateA.Mul(&aggregateA, &pk.A)
	}
	return &PublicKey{
		R: aggregateR,
		A: aggregateA,
	}, nil
}

func AggregateSignatures(sigmas []*Signature) (*Signature, error) {
	if len(sigmas) == 0 {
		return nil, fmt.Errorf("no signatures provided")
	}
	aggregateSigma := *new(bn254.G1Affine).SetInfinity()
	for _, s := range sigmas {
		aggregateSigma.Add(&aggregateSigma, &s.Sigma)
	}
	return &Signature{
		Sigma: aggregateSigma,
	}, nil
}
