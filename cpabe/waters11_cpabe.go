package cpabe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/lsss"
	"math/big"
)

type Waters11CPABEInstance struct {
	universe map[fr.Element]struct{}
}

type Waters11CPABEPublicParameters struct {
	g1            bn254.G1Affine
	g2            bn254.G2Affine
	g1ExpA        bn254.G1Affine // g1^a
	eG1G2ExpAlpha bn254.GT       // e(g1, g2)^alpha
	h             map[fr.Element]bn254.G1Affine
}

type Waters11CPABEMasterSecretKey struct {
	g1ExpAlpha bn254.G1Affine // g1^alpha
}

type Waters11CPABEAttributes struct {
	Attributes []fr.Element
}

type Waters11CPABEUserSecretKey struct {
	userAttributes []fr.Element
	k              bn254.G1Affine
	l              bn254.G2Affine
	kx             map[fr.Element]bn254.G1Affine
}

type Waters11CPABEAccessPolicy struct {
	matrix *lsss.LewkoWatersLsssMatrix
}

type Waters11CPABEMessage struct {
	Message bn254.GT
}

type Waters11CPABECiphertext struct {
	accessMatrix *lsss.LewkoWatersLsssMatrix
	c            bn254.GT
	cPrime       bn254.G2Affine
	cx           []bn254.G1Affine
	dx           []bn254.G2Affine
}

func NewWaters11CPABEInstance(universe []fr.Element) (*Waters11CPABEInstance, error) {
	attributesUniverse := make(map[fr.Element]struct{}, len(universe))
	for _, u := range universe {
		attributesUniverse[u] = struct{}{}
	}
	return &Waters11CPABEInstance{
		universe: attributesUniverse,
	}, nil
}

func (instance *Waters11CPABEInstance) SetUp() (*Waters11CPABEPublicParameters, *Waters11CPABEMasterSecretKey, error) {
	_, _, g1, g2 := bn254.Generators()
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("could not set up alpha Waters11CPABEPublicParameters")
	}
	a, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("could not set up alpha Waters11CPABEPublicParameters")
	}
	g1ExpA := new(bn254.G1Affine).ScalarMultiplicationBase(a.BigInt(new(big.Int)))
	g1ExpAlpha := new(bn254.G1Affine).ScalarMultiplicationBase(alpha.BigInt(new(big.Int)))
	eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
	if err != nil {
		return nil, nil, fmt.Errorf("could not set up alpha Waters11CPABEPublicParameters")
	}
	eG1G2ExpAlpha := new(bn254.GT).Exp(eG1G2, alpha.BigInt(new(big.Int)))

	h := make(map[fr.Element]bn254.G1Affine, len(instance.universe))
	for u := range instance.universe {
		temp, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, nil, fmt.Errorf("could not set up alpha Waters11CPABEPublicParameters")
		}
		h[u] = *new(bn254.G1Affine).ScalarMultiplicationBase(temp.BigInt(new(big.Int)))
	}

	return &Waters11CPABEPublicParameters{
			g1:            g1,
			g2:            g2,
			g1ExpA:        *g1ExpA,
			eG1G2ExpAlpha: *eG1G2ExpAlpha,
			h:             h,
		}, &Waters11CPABEMasterSecretKey{
			g1ExpAlpha: *g1ExpAlpha,
		}, nil
}

func (instance *Waters11CPABEInstance) KeyGenerate(userAttributes *Waters11CPABEAttributes, msk *Waters11CPABEMasterSecretKey, pp *Waters11CPABEPublicParameters) (*Waters11CPABEUserSecretKey, error) {
	t, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("could not set up alpha Waters11CPABEPublicParameters")
	}
	// g1^(at)
	g1ExpAT := new(bn254.G1Affine).ScalarMultiplication(&pp.g1ExpA, t.BigInt(new(big.Int)))
	// k = g1^alpha * g1^(at)
	k := *new(bn254.G1Affine).Add(&msk.g1ExpAlpha, g1ExpAT)
	// l = g2^t
	l := *new(bn254.G2Affine).ScalarMultiplicationBase(t.BigInt(new(big.Int)))
	// kx = hx^t
	kx := make(map[fr.Element]bn254.G1Affine, len(instance.universe))
	for _, x := range userAttributes.Attributes {
		hx := pp.h[x]
		kx[x] = *new(bn254.G1Affine).ScalarMultiplication(&hx, t.BigInt(new(big.Int)))
	}

	return &Waters11CPABEUserSecretKey{
		userAttributes: userAttributes.Attributes,
		k:              k,
		l:              l,
		kx:             kx,
	}, nil
}

func (instance *Waters11CPABEInstance) Encrypt(message *Waters11CPABEMessage, accessPolicy *Waters11CPABEAccessPolicy, pp *Waters11CPABEPublicParameters) (*Waters11CPABECiphertext, error) {
	n := accessPolicy.matrix.ColumnNumber()

	cx := make([]bn254.G1Affine, n)
	dx := make([]bn254.G2Affine, n)

	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %vectorV", err)
	}

	vectorV := make([]fr.Element, n)
	vectorV[0] = *s
	for i := 1; i < n; i++ {
		vi, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("encrypt failed: %v", err)
		}
		vectorV[i] = *vi
	}

	// e(g1, g2)^(alpha*s)
	eG1G2ExpAlphaS := new(bn254.GT).Exp(pp.eG1G2ExpAlpha, s.BigInt(new(big.Int)))

	// c = message * e(g1, g2)^(alpha*s)
	c := new(bn254.GT).Mul(eG1G2ExpAlphaS, &message.Message)
	// c' = g2^s
	cPrime := new(bn254.G2Affine).ScalarMultiplicationBase(s.BigInt(new(big.Int)))

	for i := 0; i < n; i++ {
		ri, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("encrypt failed: %v", err)
		}
		lambdaI := accessPolicy.matrix.ComputeVector(i, vectorV)
		rhoI := accessPolicy.matrix.Rho(i)

		// (g1^a)^lambdaI
		g1ExpALambdaI := new(bn254.G1Affine).ScalarMultiplication(&pp.g1ExpA, lambdaI.BigInt(new(big.Int)))
		hRhoI := pp.h[rhoI]
		negRi := new(fr.Element).Neg(ri)
		// h_rho(i)^(-ri)
		hRhoIExpNegRi := new(bn254.G1Affine).ScalarMultiplication(&hRhoI, negRi.BigInt(new(big.Int)))

		cx[i] = *new(bn254.G1Affine).Add(g1ExpALambdaI, hRhoIExpNegRi)
		dx[i] = *new(bn254.G2Affine).ScalarMultiplicationBase(ri.BigInt(new(big.Int)))
	}

	return &Waters11CPABECiphertext{
		c:            *c,
		cPrime:       *cPrime,
		cx:           cx,
		dx:           dx,
		accessMatrix: accessPolicy.matrix,
	}, nil
}

func (instance *Waters11CPABEInstance) Decrypt(ciphertext *Waters11CPABECiphertext, usk *Waters11CPABEUserSecretKey, gp *Waters11CPABEPublicParameters) (*Waters11CPABEMessage, error) {
	// e(K, C')
	eCPrimeK, err := bn254.Pair([]bn254.G1Affine{usk.k}, []bn254.G2Affine{ciphertext.cPrime})
	if err != nil {
		return nil, fmt.Errorf("decrypt failed: %v", err)
	}
	iSlice, wSlice := ciphertext.accessMatrix.GetSatisfiedLinearCombination(usk.userAttributes)
	if iSlice == nil || wSlice == nil {
		return nil, fmt.Errorf("decrypt failed: access policy is not satisfied")
	}
	denominator := new(bn254.GT).SetOne()
	for _, i := range iSlice {
		ci := ciphertext.cx[i]
		di := ciphertext.dx[i]
		rhoI := ciphertext.accessMatrix.Rho(i)
		kRhoI := usk.kx[rhoI]

		// e(Ci, L)
		eCiL, err := bn254.Pair([]bn254.G1Affine{ci}, []bn254.G2Affine{usk.l})
		if err != nil {
			return nil, fmt.Errorf("decrypt failed: %v", err)
		}

		// e(Di, Krho(i))
		eDiKRhoI, err := bn254.Pair([]bn254.G1Affine{kRhoI}, []bn254.G2Affine{di})
		if err != nil {
			return nil, fmt.Errorf("decrypt failed: %v", err)
		}

		// e(Ci, L)*e(Di, Krho(i))
		eCiLEDiKRhoI := new(bn254.GT).Mul(&eCiL, &eDiKRhoI)
		// (e(Ci, L)*e(Di, Krho(i)))^wi
		eCiLEDiKRhoIExpWi := eCiLEDiKRhoI.Exp(*eCiLEDiKRhoI, wSlice[i].BigInt(new(big.Int)))

		denominator.Mul(denominator, eCiLEDiKRhoIExpWi)

	}

	eG1G2ExpAlphaS := new(bn254.GT).Div(&eCPrimeK, denominator)
	message := *new(bn254.GT).Div(&ciphertext.c, eG1G2ExpAlphaS)

	return &Waters11CPABEMessage{Message: message}, nil
}
