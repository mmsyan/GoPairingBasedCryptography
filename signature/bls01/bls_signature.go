package bls01

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"math/big"
)

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
	MessageBytes   []byte
	SigmaSignature bn254.G2Affine
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
		MessageBytes:   m.MessageBytes,
		SigmaSignature: hmx,
	}, nil
}

func Verify(pk *PublicKey, sigma *Signature) (bool, error) {
	// compute h(m): m to point
	hm := hash.BytesToG2(sigma.MessageBytes)
	_, _, g1, _ := bn254.Generators()
	// -sigma = inverse of sigma (bn254.G2 is add-group)
	inverseSigma := *new(bn254.G2Affine).Neg(&sigma.SigmaSignature)

	// e(g1^x, h(m)) =?= e(g1, h(m)^x)
	// e(pk, hm) =?= e(g1, sigma)
	// e(pk, hm) * e(g1, inverseSigma) =?= 1
	isValid, err := bn254.PairingCheck(
		[]bn254.G1Affine{pk.PublicKey, g1},
		[]bn254.G2Affine{hm, inverseSigma},
	)
	if err != nil {
		return false, fmt.Errorf("failed to verify signature: %v", err)
	}
	return isValid, nil
}
