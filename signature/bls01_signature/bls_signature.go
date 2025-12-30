package bls01_signature

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GoPairingBasedCryptography/hash"
	"math/big"
)

type PublicParams struct {
	G1 bn254.G1Affine
}

type PrivateKey struct {
	PrivateKey fr.Element
}

type PublicKey struct {
	PublicKey bn254.G1Affine
}

type Message struct {
	MessageBytes []byte
}

type Signature struct {
	SigmaSignature bn254.G2Affine
}

func ParamsGenerate() (*PublicParams, error) {
	_, _, g1, _ := bn254.Generators()
	return &PublicParams{
		G1: g1,
	}, nil
}

func KeyGenerate() (*PublicKey, *PrivateKey, error) {
	// x <- Zq
	x, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate key pair: %v", err)
	}
	// g1^x
	g1ExpX := *new(bn254.G1Affine).ScalarMultiplicationBase(x.BigInt(new(big.Int)))

	// private key: x <- Zq
	// public key: g1^x
	return &PublicKey{
			PublicKey: g1ExpX,
		},
		&PrivateKey{
			PrivateKey: *x,
		},
		nil
}

func Sign(sk *PrivateKey, m *Message) (*Signature, error) {
	// compute h(m): m to point
	hm := hash.BytesToG2(m.MessageBytes)

	// compute h(m)^x
	hmx := *new(bn254.G2Affine).ScalarMultiplication(&hm, sk.PrivateKey.BigInt(new(big.Int)))

	// signature format: (m, h(m)^x)
	return &Signature{
		SigmaSignature: hmx,
	}, nil
}

func Verify(pk *PublicKey, m *Message, sigma *Signature, pp *PublicParams) (bool, error) {
	// compute h(m): m to point
	hm := hash.BytesToG2(m.MessageBytes)

	// -sigma = inverse of sigma (bn254.G2 is add-group)
	inverseSigma := *new(bn254.G2Affine).Neg(&sigma.SigmaSignature)

	// e(g1^x, h(m)) =?= e(g1, h(m)^x)
	// e(pk, hm) =?= e(g1, sigma)
	// e(pk, hm) * e(g1, inverseSigma) =?= 1
	isValid, err := bn254.PairingCheck(
		[]bn254.G1Affine{pk.PublicKey, pp.G1},
		[]bn254.G2Affine{hm, inverseSigma},
	)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %v", err)
	}
	return isValid, nil
}
