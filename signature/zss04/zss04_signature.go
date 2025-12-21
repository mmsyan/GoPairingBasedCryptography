package zss04

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"math/big"
)

type PublicParams struct {
	eG1G2 bn254.GT
}

type PrivateKey struct {
	x fr.Element
}

type PublicKey struct {
	p bn254.G2Affine
}

type Message struct {
	MessageBytes []byte
}

type Signature struct {
	S bn254.G1Affine
}

func ParamsGenerate() (*PublicParams, error) {
	_, _, g1, g2 := bn254.Generators()
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, err
	}
	return &PublicParams{
		eG1G2: eG1G2,
	}, nil
}

func KeyGenerate() (*PublicKey, *PrivateKey, error) {
	x, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, err
	}
	p := new(bn254.G2Affine).ScalarMultiplicationBase(x.BigInt(new(big.Int)))
	return &PublicKey{
			p: *p,
		}, &PrivateKey{
			x: *x,
		}, nil
}

func Sign(sk *PrivateKey, m *Message) (*Signature, error) {
	hm := hash.BytesToField(m.MessageBytes)
	hmAddS := new(fr.Element).Add(&hm, &sk.x)
	inverseHmAddS := new(fr.Element).Inverse(hmAddS)
	s := new(bn254.G1Affine).ScalarMultiplicationBase(inverseHmAddS.BigInt(new(big.Int)))
	return &Signature{
		S: *s,
	}, nil
}

func Verify(pk *PublicKey, m *Message, sigma *Signature, pp *PublicParams) (bool, error) {
	hm := hash.BytesToField(m.MessageBytes)
	g2ExpHm := new(bn254.G2Affine).ScalarMultiplicationBase(hm.BigInt(new(big.Int)))
	g2ExpHmAddPk := new(bn254.G2Affine).Add(g2ExpHm, &pk.p)
	pairLeft, err := bn254.Pair([]bn254.G1Affine{sigma.S}, []bn254.G2Affine{*g2ExpHmAddPk})
	if err != nil {
		return false, err
	}
	if pairLeft.Equal(&pp.eG1G2) {
		return true, nil
	} else {
		return false, fmt.Errorf("invalid signature")
	}
}
