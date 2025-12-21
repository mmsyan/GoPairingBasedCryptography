package bb04

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

type PrivateKey struct {
	Alpha fr.Element
	Beta  fr.Element
}

type PublicKey struct {
	Y bn254.G2Affine // Y = alpha*G2
	Z bn254.G2Affine // Z = beta*G2
}

type Message struct {
	MessageFr fr.Element
}

type Signature struct {
	R     fr.Element
	Sigma bn254.G1Affine // sigma = (1 / (alpha + r * beta + m)) * G1
}

func KeyGenerate() (*PublicKey, *PrivateKey, error) {
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating alpha signature key")
	}
	beta, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("error generating beta signature key")
	}
	y := new(bn254.G2Affine).ScalarMultiplicationBase(alpha.BigInt(new(big.Int)))
	z := new(bn254.G2Affine).ScalarMultiplicationBase(beta.BigInt(new(big.Int)))

	return &PublicKey{
			Y: *y,
			Z: *z,
		}, &PrivateKey{
			Alpha: *alpha,
			Beta:  *beta,
		}, nil
}

func Sign(sk *PrivateKey, m *Message) (*Signature, error) {
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, err
	}

	rMulBeta := new(fr.Element).Mul(r, &sk.Beta)
	alphaAddRMulBeta := new(fr.Element).Add(&sk.Alpha, rMulBeta)
	alphaAddRMulBetaAddM := new(fr.Element).Add(alphaAddRMulBeta, &m.MessageFr)
	inverseSigma := new(fr.Element).Inverse(alphaAddRMulBetaAddM)
	sigma := new(bn254.G1Affine).ScalarMultiplicationBase(inverseSigma.BigInt(new(big.Int)))
	return &Signature{
		R:     *r,
		Sigma: *sigma,
	}, nil
}

func Verify(pk *PublicKey, m *Message, sign *Signature) (bool, error) {
	_, _, g1, g2 := bn254.Generators()

	negSigma := new(bn254.G1Affine).Neg(&sign.Sigma)

	rMulZ := new(bn254.G2Affine).ScalarMultiplication(&pk.Z, sign.R.BigInt(new(big.Int)))
	g2ExpM := new(bn254.G2Affine).ScalarMultiplicationBase(m.MessageFr.BigInt(new(big.Int)))
	temp := new(bn254.G2Affine).Add(rMulZ, g2ExpM)
	temp.Add(&pk.Y, temp)

	isValid, err := bn254.PairingCheck(
		[]bn254.G1Affine{*negSigma, g1},
		[]bn254.G2Affine{*temp, g2},
	)
	if err != nil {
		return false, err
	}
	return isValid, nil
}
