package cpabe

// 作者: mmsyan
// 日期: 2025-12-04
// 参考论文:
// Waters, B. (2011). Ciphertext-Policy Attribute-Based Encryption: An Expressive, Efficient, and Provably Secure Realization.
// In: Catalano, D., Fazio, N., Gennaro, R., Nicolosi, A. (eds) Public Key Cryptography – PKC 2011. PKC 2011.
// Lecture Notes in Computer Science, vol 6571. Springer, Berlin, Heidelberg.
// https://doi.org/10.1007/978-3-642-19379-8_4
//
// section 3 Our Most Efficient Construction
//
// full version: https://eprint.iacr.org/2008/290.pdf
//
// 该实现基于BN254椭圆曲线和配对运算,提供了完整的 Waters 2011 CP-ABE 系统功能,包括:
//   - 系统初始化 (SetUp)
//   - 密钥生成 (KeyGenerate)
//   - 加密 (Encrypt)
//   - 解密 (Decrypt)

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

// SetUp 执行 CP-ABE 方案的系统初始化，生成公共参数 (PP) 和主密钥 (MSK)。
// 步骤:
// 1. 选取随机指数 $\alpha, a \in \mathbb{Z}_p$。
// 2. 计算 $g_1^a, g_1^\alpha, e(g_1, g_2)^\alpha$。
// 3. 对属性宇宙中的每个属性 $u$，随机选取 $\tau_u \in \mathbb{Z}_p$，计算 $h_u = g_1^{\tau_u}$。
//
// 返回值:
//   - *Waters11CPABEPublicParameters: 生成的公共参数 PP
//   - *Waters11CPABEMasterSecretKey: 生成的主密钥 MSK
//   - error: 如果随机数生成或配对操作失败，返回错误信息
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

// KeyGenerate 根据用户属性集 $S$ 为用户生成私钥 (SK)。
// 步骤:
// 1. 选取随机值 $t \in \mathbb{Z}_p$。
// 2. 计算 $K = g_1^\alpha \cdot (g_1^a)^t = g_1^{\alpha + at}$。
// 3. 计算 $L = g_2^t$。
// 4. 对每个属性 $x \in S$，计算 $K_x = h_x^t$。
//
// 参数:
//   - userAttributes: 用户的属性集合 $S$
//   - msk: 系统主密钥 MSK
//   - pp: 系统公共参数 PP
//
// 返回值:
//   - *Waters11CPABEUserSecretKey: 生成的用户私钥
//   - error: 如果属性不在宇宙中或随机数生成失败，返回错误信息
func (instance *Waters11CPABEInstance) KeyGenerate(userAttributes *Waters11CPABEAttributes, msk *Waters11CPABEMasterSecretKey, pp *Waters11CPABEPublicParameters) (*Waters11CPABEUserSecretKey, error) {
	check := instance.checkAttributes(userAttributes.Attributes)
	if !check {
		return nil, fmt.Errorf("failed to pass attribute check")
	}

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

// Encrypt 使用访问策略A=(M, \rho)对消息M进行加密。
//
// 参数:
//   - message: 要加密的明文消息M
//   - accessPolicy: 访问策略A=(M, \rho)
//   - pp: 系统公共参数 PP
//
// 返回值:
//   - *Waters11CPABECiphertext: 生成的密文
//   - error: 如果加密失败，返回错误信息
func (instance *Waters11CPABEInstance) Encrypt(message *Waters11CPABEMessage, accessPolicy *Waters11CPABEAccessPolicy, pp *Waters11CPABEPublicParameters) (*Waters11CPABECiphertext, error) {
	check := instance.checkAttributes(accessPolicy.matrix.Attributes())
	if !check {
		return nil, fmt.Errorf("failed to pass attribute check. contains invalid ciphertext attributes")
	}

	n := accessPolicy.matrix.ColumnNumber()

	cx := make([]bn254.G1Affine, n)
	dx := make([]bn254.G2Affine, n)

	s, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("encrypt failed: %vectorV", err)
	}

	// v = [s, r2, r3, ..., rn]
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

// Decrypt 使用用户私钥对密文进行解密。
// 仅当用户属性集S满足密文的访问策略时才能成功解密。
// 参数:
//   - ciphertext: 要解密的密文
//   - usk: 用户的私钥
//
// 返回值:
//   - *Waters11CPABEMessage: 解密后的明文消息
//   - error: 如果解密失败或属性不满足策略，返回错误信息
func (instance *Waters11CPABEInstance) Decrypt(ciphertext *Waters11CPABECiphertext, usk *Waters11CPABEUserSecretKey) (*Waters11CPABEMessage, error) {
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
