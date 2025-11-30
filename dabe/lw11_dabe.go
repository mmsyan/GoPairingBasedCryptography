package dabe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"github.com/mmsyan/GnarkPairingProject/lsss"
	"math/big"
)

type LW11DABEGlobalParams struct {
	g1    bn254.G1Affine
	g2    bn254.G2Affine
	eG1G2 bn254.GT
}

type LW11DABEAttributes struct {
	attributes []fr.Element
}

type LW11DABEAttributePK struct {
	eG1G2ExpAlphaI map[fr.Element]bn254.GT
	g2ExpYi        map[fr.Element]bn254.G2Affine
}

type LW11DABEAttributeSK struct {
	alphaI map[fr.Element]fr.Element
	yi     map[fr.Element]fr.Element
}

type LW11DABEUserKey struct {
	UserGid        string
	UserAttributes *LW11DABEAttributes
	KIGID          map[fr.Element]bn254.G1Affine
}

type LW11DABEMessage struct {
	Message bn254.GT
}

type LW11DABECiphertext struct {
	matrix *lsss.LewkoWatersLsssMatrix
	c0     bn254.GT
	c1x    []bn254.GT
	c2x    []bn254.G2Affine
	c3x    []bn254.G2Affine
}

func GlobalSetup() (*LW11DABEGlobalParams, error) {
	_, _, g1, g2 := bn254.Generators()
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, fmt.Errorf("failed to global setup")
	}
	return &LW11DABEGlobalParams{
		g1:    g1,
		g2:    g2,
		eG1G2: eG1G2,
	}, nil
}

func AuthoritySetup(authorityAttributes *LW11DABEAttributes, gp *LW11DABEGlobalParams) (*LW11DABEAttributePK, *LW11DABEAttributeSK, error) {
	// SK = { αi, yi }
	skAlphaI := make(map[fr.Element]fr.Element)
	skYi := make(map[fr.Element]fr.Element)
	// PK = { e(g1,g2)^αi, g2^yi }
	pkEggAlphaI := make(map[fr.Element]bn254.GT)
	pkG2Yi := make(map[fr.Element]bn254.G2Affine)

	for _, i := range authorityAttributes.attributes {
		alphaI, err := new(fr.Element).SetRandom()
		yi, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, nil, fmt.Errorf("failed to authority setup")
		}
		eggExpAlphaI := new(bn254.GT).Exp(gp.eG1G2, alphaI.BigInt(new(big.Int)))
		g2ExpYi := new(bn254.G2Affine).ScalarMultiplicationBase(yi.BigInt(new(big.Int)))
		pkEggAlphaI[i] = *eggExpAlphaI
		pkG2Yi[i] = *g2ExpYi
		skAlphaI[i] = *alphaI
		skYi[i] = *yi
	}
	return &LW11DABEAttributePK{eG1G2ExpAlphaI: pkEggAlphaI, g2ExpYi: pkG2Yi},
		&LW11DABEAttributeSK{alphaI: skAlphaI, yi: skYi},
		nil
}

func KeyGenerate(grantedAttribute *LW11DABEAttributes, userGid string, attributeSK *LW11DABEAttributeSK) (*LW11DABEUserKey, error) {
	KIGID := make(map[fr.Element]bn254.G1Affine)
	// K_{i,GID} = g1^αi*H(GID)^yi
	for _, i := range grantedAttribute.attributes {
		alphaI := attributeSK.alphaI[i]
		// g1^αi
		gExpAlphaI := new(bn254.G1Affine).ScalarMultiplicationBase(alphaI.BigInt(new(big.Int)))
		hGid := hash.ToG1(userGid)
		yi := attributeSK.yi[i]
		// H(GID)^yi
		hGidExpY1 := new(bn254.G1Affine).ScalarMultiplication(&hGid, yi.BigInt(new(big.Int)))
		KIGID[i] = *new(bn254.G1Affine).Add(gExpAlphaI, hGidExpY1)
	}
	return &LW11DABEUserKey{
		UserGid:        userGid,
		UserAttributes: grantedAttribute,
		KIGID:          KIGID,
	}, nil
}

func Encrypt(message *LW11DABEMessage, matrix *lsss.LewkoWatersLsssMatrix, gp *LW11DABEGlobalParams, pk *LW11DABEAttributePK) (*LW11DABECiphertext, error) {
	var err error
	n := matrix.ColumnNumber()
	c1xSlice := make([]bn254.GT, n)
	c2xSlice := make([]bn254.G2Affine, n)
	c3xSlice := make([]bn254.G2Affine, n)

	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %vectorV", err)
	}

	vectorV := make([]fr.Element, n)
	vectorW := make([]fr.Element, n)
	vectorV[0] = *s
	vectorW[0] = *new(fr.Element).SetZero()

	for i := 1; i < n; i++ {
		vi, err := new(fr.Element).SetRandom()
		wi, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("encrypt failed: %v", err)
		}
		vectorV[i] = *vi
		vectorW[i] = *wi
	}

	eG1G2ExpS := new(bn254.GT).Exp(gp.eG1G2, s.BigInt(new(big.Int)))
	c0 := new(bn254.GT).Mul(&message.Message, eG1G2ExpS)

	for x := 0; x < n; x++ {
		rx, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("encrypt failed: %v", err)
		}
		lambdaX := matrix.ComputeVector(x, vectorV)
		omegaX := matrix.ComputeVector(x, vectorW)
		rhoX := matrix.Rho(x)

		eG1G2LambdaX := new(bn254.GT).Exp(gp.eG1G2, lambdaX.BigInt(new(big.Int)))
		eG1G2AlphaRhoX := pk.eG1G2ExpAlphaI[rhoX]
		eG1G2AlphaRhoXRx := new(bn254.GT).Exp(eG1G2AlphaRhoX, rx.BigInt(new(big.Int)))
		c1x := new(bn254.GT).Mul(eG1G2LambdaX, eG1G2AlphaRhoXRx)
		c2x := new(bn254.G2Affine).ScalarMultiplicationBase(rx.BigInt(new(big.Int)))

		g2ExpYRhoX := pk.g2ExpYi[rhoX]
		g2ExpYRhoXRx := new(bn254.G2Affine).ScalarMultiplication(&g2ExpYRhoX, rx.BigInt(new(big.Int)))
		g2ExpOmegaX := new(bn254.G2Affine).ScalarMultiplicationBase(omegaX.BigInt(new(big.Int)))
		c3x := new(bn254.G2Affine).Add(g2ExpYRhoXRx, g2ExpOmegaX)

		c1xSlice[x] = *c1x
		c2xSlice[x] = *c2x
		c3xSlice[x] = *c3x

	}

	var accessMatrix = *matrix

	return &LW11DABECiphertext{
		c0:     *c0,
		matrix: &accessMatrix,
		c1x:    c1xSlice,
		c2x:    c2xSlice,
		c3x:    c3xSlice,
	}, nil
}

func Decrypt(ciphertext *LW11DABECiphertext, userKey *LW11DABEUserKey, gp *LW11DABEGlobalParams) (*LW11DABEMessage, error) {
	hGid := hash.ToG1(userKey.UserGid)
	xSlice, wSlice := ciphertext.matrix.GetSatisfiedLinearCombination(userKey.UserAttributes.attributes)
	denominator := new(bn254.GT).SetOne()
	for _, x := range xSlice {
		c1x := ciphertext.c1x[x]
		eHGidC3x, err := bn254.Pair([]bn254.G1Affine{hGid}, []bn254.G2Affine{ciphertext.c3x[x]})
		if err != nil {
			return nil, err
		}

		rhoX := ciphertext.matrix.Rho(x)
		kRho := userKey.KIGID[rhoX]
		eKRhoC2x, err := bn254.Pair([]bn254.G1Affine{kRho}, []bn254.G2Affine{ciphertext.c2x[x]})

		denominator.Mul(denominator, &c1x)
		denominator.Mul(denominator, &eHGidC3x)
		denominator.Div(denominator, &eKRhoC2x)

		denominator.Exp(*denominator, wSlice[x].BigInt(new(big.Int)))
	}

	message := *new(bn254.GT).Div(&ciphertext.c0, denominator)

	return &LW11DABEMessage{
		Message: message,
	}, nil
}
