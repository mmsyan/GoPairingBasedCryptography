package bsw07

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/access/tree"
	"github.com/mmsyan/GnarkPairingProject/utils"
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
	r          fr.Element
	attributes []fr.Element
	d          bn254.G2Affine
	dj         map[fr.Element]bn254.G2Affine
	djPrime    map[fr.Element]bn254.G2Affine
}

type CPABEMessage struct {
	Message bn254.GT
}

type CPABEAccessPolicy struct {
	accessTree *tree.AccessTreeNode
}

type CPABECiphertext struct {
	accessPolicy *CPABEAccessPolicy
	cTilde       bn254.GT
	c            bn254.G1Affine
	cy           map[int]bn254.G1Affine
	cyPrime      map[int]bn254.G1Affine
}

func (instance *CPABEInstance) SetUp() (*CPABEPublicParameters, *CPABEMasterSecretKey, error) {
	_, _, g1, g2 := bn254.Generators()
	// alpha, beta <- Zq
	alpha, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set up: %v", err)
	}
	beta, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to set up: %v", err)
	}

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

	// g2^alpha
	g2ExpAlpha := new(bn254.G2Affine).ScalarMultiplicationBase(alpha.BigInt(new(big.Int)))

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

func (instance *CPABEInstance) KeyGenerate(attr *CPABEUserAttributes, msk *CPABEMasterSecretKey) (*CPABEUserSecretKey, error) {
	r, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("failed to generate user key: %v", err)
	}
	// D = g2^((alpha+r)/beta)
	g2ExpR := new(bn254.G2Affine).ScalarMultiplicationBase(r.BigInt(new(big.Int)))                   // g2^r
	g2ExpAlphaPlusR := new(bn254.G2Affine).Add(&msk.g2ExpAlpha, g2ExpR)                              // (g2^alpha)(g2^r)=g2^(alpha+r)
	inverseBeta := new(fr.Element).Inverse(&msk.beta)                                                // 1/beta
	d := new(bn254.G2Affine).ScalarMultiplication(g2ExpAlphaPlusR, inverseBeta.BigInt(new(big.Int))) // g2^((alpha+r)/beta)

	dj := make(map[fr.Element]bn254.G2Affine, len(attr.Attributes))
	djPrime := make(map[fr.Element]bn254.G2Affine, len(attr.Attributes))

	for _, j := range attr.Attributes {
		rj, err := new(fr.Element).SetRandom()
		if err != nil {
			return nil, fmt.Errorf("error setting random: %v", err)
		}
		hj := Hash2BSw07(j)
		hjExpRj := new(bn254.G2Affine).ScalarMultiplication(&hj, rj.BigInt(new(big.Int)))
		// Dj = g2^r H2(j)^rj
		dj[j] = *new(bn254.G2Affine).Add(g2ExpR, hjExpRj)
		// Dj' = g2^rj
		djPrime[j] = *new(bn254.G2Affine).ScalarMultiplicationBase(rj.BigInt(new(big.Int)))
	}

	return &CPABEUserSecretKey{
		r:          *r,
		attributes: attr.Attributes,
		d:          *d,
		dj:         dj,
		djPrime:    djPrime,
	}, nil
}

func (instance *CPABEInstance) Encrypt(message *CPABEMessage, accessPolicy *CPABEAccessPolicy, pp *CPABEPublicParameters) (*CPABECiphertext, error) {
	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("error setting random: %v", err)
	}

	// 🔧 修复1：生成叶子节点ID（必须在 ShareSecret 之前调用）
	accessPolicy.accessTree.GenerateLeafID()

	// 🔧 修复2：调用 ShareSecret 来分发秘密值到所有节点
	accessPolicy.accessTree.ShareSecret(*s)

	// e(g,g)^(alpha*s)
	eG1G2ExpAlphaS := new(bn254.GT).Exp(pp.eG1G2ExpAlpha, s.BigInt(new(big.Int)))
	cTilde := new(bn254.GT).Mul(eG1G2ExpAlphaS, &message.Message)
	// C = h^s
	c := new(bn254.G1Affine).ScalarMultiplication(&pp.h, s.BigInt(new(big.Int)))

	leafNodes := accessPolicy.accessTree.GetLeafNodes()
	cy := make(map[int]bn254.G1Affine)
	cyPrime := make(map[int]bn254.G1Affine)
	for _, n := range leafNodes {
		qy0 := utils.ComputePolynomialValue(n.Poly, fr.NewElement(0))
		// Cy = g1^qy(0)
		cy[n.LeafId] = *new(bn254.G1Affine).ScalarMultiplicationBase(qy0.BigInt(new(big.Int)))
		h_attr_y := Hash1BSw07(n.Attribute)
		// Cy' = H1(attr)^qy(0)
		cyPrime[n.LeafId] = *new(bn254.G1Affine).ScalarMultiplication(&h_attr_y, qy0.BigInt(new(big.Int)))
	}

	return &CPABECiphertext{
		accessPolicy: accessPolicy,
		cTilde:       *cTilde,
		c:            *c,
		cy:           cy,
		cyPrime:      cyPrime,
	}, nil
}

func (instance *CPABEInstance) Decrypt(ciphertext *CPABECiphertext, usk *CPABEUserSecretKey) (*CPABEMessage, error) {
	attributes := usk.attributes
	attributesMap := make(map[fr.Element]struct{}, len(attributes))
	for _, j := range attributes {
		attributesMap[j] = struct{}{}
	}
	A := ciphertext.accessPolicy.accessTree.DecryptNode(attributesMap, usk.dj, usk.djPrime, ciphertext.cy, ciphertext.cyPrime, usk.r)
	if A == nil {
		return nil, fmt.Errorf("error decrypting message")
	}

	// e(C, D)
	eCD, err := bn254.Pair([]bn254.G1Affine{ciphertext.c}, []bn254.G2Affine{usk.d})
	if err != nil {
		return nil, err
	}
	// e(C, D) / A
	eCDDivA := new(bn254.GT).Div(&eCD, A)
	M := *new(bn254.GT).Div(&ciphertext.cTilde, eCDDivA)
	return &CPABEMessage{
		Message: M,
	}, nil

}
