package cpabe

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"math/big"
)

type LW11DABEGlobalParams struct {
	g1 bn254.G1Affine
	g2 bn254.G2Affine
}

type LW11DabeAttributePK struct {
	eggExpAlphai bn254.GT
	gExpYi       bn254.G1Affine
}

type LW11DabeAttributeSK struct {
	alphai fr.Element
	yi     fr.Element
}

type LW11DabeUserKey struct {
	keyIGid bn254.G1Affine
}

func GlobalSetup() (*LW11DABEGlobalParams, error) {
	_, _, g1, g2 := bn254.Generators()
	return &LW11DABEGlobalParams{
		g1: g1,
		g2: g2,
	}, nil
}

func AuthoritySetup(attribute fr.Element, gp *LW11DABEGlobalParams) (*LW11DabeAttributePK, *LW11DabeAttributeSK, error) {
	var err error
	alphai, err := new(fr.Element).SetRandom()
	yi, err := new(fr.Element).SetRandom()
	gExpYi := new(bn254.G1Affine).ScalarMultiplicationBase(yi.BigInt(new(big.Int)))
	egg, err := bn254.Pair([]bn254.G1Affine{gp.g1}, []bn254.G2Affine{gp.g2})
	eggExpAlphai := new(bn254.GT).Exp(egg, alphai.BigInt(new(big.Int)))
	if err != nil {
		return nil, nil, err
	}
	return &LW11DabeAttributePK{eggExpAlphai: *eggExpAlphai, gExpYi: *gExpYi}, &LW11DabeAttributeSK{alphai: *alphai, yi: *yi}, nil
}

func KeyGenerate(attribute fr.Element, gid string, attributeSK *LW11DabeAttributeSK) (*LW11DabeUserKey, error) {
	gExpAlphai := new(bn254.G1Affine).ScalarMultiplicationBase(attributeSK.alphai.BigInt(new(big.Int)))
	hGid, err := bn254.HashToG1([]byte(gid), []byte("<Decentralizing Attribute-Based Encryption>"))
	if err != nil {
		return nil, err
	}
	hGidExpY1 := new(bn254.G1Affine).ScalarMultiplication(&hGid, attributeSK.yi.BigInt(new(big.Int)))
	result := new(bn254.G1Affine).Add(gExpAlphai, hGidExpY1)
	return &LW11DabeUserKey{keyIGid: *result}, nil
}
