package cpabe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/lsss"
	"math/big"
)

type LW11DABEGlobalParams struct {
	g1 bn254.G1Affine
	g2 bn254.G2Affine
}

type lw11DabeAttributePK struct {
	eggExpAlphai bn254.GT
	gExpYi       bn254.G2Affine
}

type LW11DabeAttributePK struct {
	Pk map[fr.Element]lw11DabeAttributePK
}

type lw11DabeAttributeSK struct {
	alphai fr.Element
	yi     fr.Element
}

type LW11DabeAttributeSK struct {
	Sk map[fr.Element]lw11DabeAttributeSK
}

type LW11DabeUserKey struct {
	Gid            string
	UserAttributes []fr.Element
	Key            map[fr.Element]bn254.G1Affine
}

type Lw11DabeMessage struct {
	Message bn254.GT
}

type lw11DabeCiphertext struct {
	c1x bn254.GT
	c2x bn254.G2Affine
	c3x bn254.G2Affine
}

type LW11DabeCiphertext struct {
	matrix *lsss.LewkoWatersLsssMatrix
	c0     bn254.GT
	cx     []lw11DabeCiphertext
}

func GlobalSetup() (*LW11DABEGlobalParams, error) {
	_, _, g1, g2 := bn254.Generators()
	return &LW11DABEGlobalParams{
		g1: g1,
		g2: g2,
	}, nil
}

func AuthoritySetup(attribute []fr.Element, gp *LW11DABEGlobalParams) (*LW11DabeAttributePK, *LW11DabeAttributeSK, error) {
	pk := make(map[fr.Element]lw11DabeAttributePK)
	sk := make(map[fr.Element]lw11DabeAttributeSK)

	for _, a := range attribute {
		alphai, err := new(fr.Element).SetRandom()
		yi, err := new(fr.Element).SetRandom()
		gExpYi := new(bn254.G2Affine).ScalarMultiplicationBase(yi.BigInt(new(big.Int)))
		egg, err := bn254.Pair([]bn254.G1Affine{gp.g1}, []bn254.G2Affine{gp.g2})
		eggExpAlphai := new(bn254.GT).Exp(egg, alphai.BigInt(new(big.Int)))
		if err != nil {
			return nil, nil, err
		}
		pk[a] = lw11DabeAttributePK{
			eggExpAlphai: *eggExpAlphai,
			gExpYi:       *gExpYi,
		}
		sk[a] = lw11DabeAttributeSK{
			alphai: *alphai,
			yi:     *yi,
		}
	}
	return &LW11DabeAttributePK{Pk: pk}, &LW11DabeAttributeSK{Sk: sk}, nil
}

func KeyGenerate(attribute []fr.Element, gid string, attributeSK *LW11DabeAttributeSK) (*LW11DabeUserKey, error) {
	Key := make(map[fr.Element]bn254.G1Affine)
	for _, a := range attribute {
		alphai := attributeSK.Sk[a].alphai
		gExpAlphai := new(bn254.G1Affine).ScalarMultiplicationBase(alphai.BigInt(new(big.Int)))
		hGid, err := bn254.HashToG1([]byte(gid), []byte("<Decentralizing Attribute-Based Encryption>"))
		if err != nil {
			return nil, err
		}
		yi := attributeSK.Sk[a].yi
		hGidExpY1 := new(bn254.G1Affine).ScalarMultiplication(&hGid, yi.BigInt(new(big.Int)))
		Key[a] = *new(bn254.G1Affine).Add(gExpAlphai, hGidExpY1)
	}
	return &LW11DabeUserKey{
		Gid:            gid,
		UserAttributes: attribute,
		Key:            Key,
	}, nil
}

func Encrypt(message *Lw11DabeMessage, matrix *lsss.LewkoWatersLsssMatrix, gp *LW11DABEGlobalParams, pk *LW11DabeAttributePK) (*LW11DabeCiphertext, error) {

	l := matrix.GetL()
	cx := make([]lw11DabeCiphertext, l)

	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed: %v", err)
	}

	v := make([]fr.Element, l)
	w := make([]fr.Element, l)
	v[0] = *s
	w[0] = *new(fr.Element).SetZero()
	for i := 1; i < l; i++ {
		vi, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("Encrypt failed: %v", err)
		}
		wi, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("Encrypt failed: %v", err)
		}
		v[i] = *vi
		w[i] = *wi
	}

	eG1G2, err := bn254.Pair([]bn254.G1Affine{gp.g1}, []bn254.G2Affine{gp.g2})
	if err != nil {
		return nil, fmt.Errorf("Encrypt failed: %v", err)
	}

	eG1G2ExpS := new(bn254.GT).Exp(eG1G2, s.BigInt(new(big.Int)))
	c0 := new(bn254.GT).Mul(&message.Message, eG1G2ExpS)

	for x := 0; x < l; x++ {
		rx, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("Encrypt failed: %v", err)
		}
		lambdaX := matrix.ComputeVector(x, v)
		omegaX := matrix.ComputeVector(x, w)
		rhoX := matrix.RhoX(x)

		eG1G2LambdaX := new(bn254.GT).Exp(eG1G2, lambdaX.BigInt(new(big.Int)))
		eG1G2AlphaRhoX := pk.Pk[rhoX].eggExpAlphai
		eG1G2AlphaRhoXRx := new(bn254.GT).Exp(eG1G2AlphaRhoX, rx.BigInt(new(big.Int)))
		c1x := new(bn254.GT).Mul(eG1G2LambdaX, eG1G2AlphaRhoXRx)
		c2x := new(bn254.G2Affine).ScalarMultiplicationBase(rx.BigInt(new(big.Int)))

		g2ExpYRhoX := pk.Pk[rhoX].gExpYi
		g2ExpYRhoXRx := new(bn254.G2Affine).ScalarMultiplication(&g2ExpYRhoX, rx.BigInt(new(big.Int)))
		g2ExpOmegaX := new(bn254.G2Affine).ScalarMultiplicationBase(omegaX.BigInt(new(big.Int)))
		c3x := new(bn254.G2Affine).Add(g2ExpYRhoXRx, g2ExpOmegaX)

		cx[x] = lw11DabeCiphertext{
			c1x: *c1x,
			c2x: *c2x,
			c3x: *c3x,
		}
	}

	var accessMatrix = *matrix

	return &LW11DabeCiphertext{
		c0:     *c0,
		matrix: &accessMatrix,
		cx:     cx,
	}, nil
}

func Decrypt(ciphertext *LW11DabeCiphertext, userKey *LW11DabeUserKey, gp *LW11DABEGlobalParams) (*Lw11DabeMessage, error) {
	hGid, err := bn254.HashToG1([]byte(userKey.Gid), []byte("<Decentralizing Attribute-Based Encryption>"))
	if err != nil {
		return nil, err
	}
	xSlice, wSlice := ciphertext.matrix.GetSatisfiedLinearCombination(userKey.UserAttributes)
	denominator := new(bn254.GT).SetOne()
	for _, x := range xSlice {
		c1x := ciphertext.cx[x].c1x
		eHGidC3x, err := bn254.Pair([]bn254.G1Affine{hGid}, []bn254.G2Affine{ciphertext.cx[x].c3x})
		if err != nil {
			return nil, err
		}

		rhoX := ciphertext.matrix.RhoX(x)
		kRho := userKey.Key[rhoX]
		eKRhoC2x, err := bn254.Pair([]bn254.G1Affine{kRho}, []bn254.G2Affine{ciphertext.cx[x].c2x})

		denominator.Mul(denominator, &c1x)
		denominator.Mul(denominator, &eHGidC3x)
		denominator.Div(denominator, &eKRhoC2x)

		denominator.Exp(*denominator, wSlice[x].BigInt(new(big.Int)))
	}

	message := *new(bn254.GT).Div(&ciphertext.c0, denominator)

	return &Lw11DabeMessage{
		Message: message,
	}, nil
}
