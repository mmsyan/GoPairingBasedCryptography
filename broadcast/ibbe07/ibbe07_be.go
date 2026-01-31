package ibbe07

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GoPairingBasedCryptography/hash"
	"math/big"
)

type MasterSecretKey struct {
	G     bn254.G1Affine
	Gamma fr.Element
}

type PublicKey struct {
	W            bn254.G1Affine
	V            bn254.GT
	H            bn254.G2Affine
	HGammaPowers []bn254.G2Affine
}

type Identity struct {
	Id []byte
}

type UserSecretKey struct {
	Sk bn254.G1Affine
}

type BroadcastHeader struct {
	C1 bn254.G1Affine
	C2 bn254.G2Affine
}

type MessageEncyptionKey struct {
	K bn254.GT
}

func Setup(m int) (*PublicKey, *MasterSecretKey, error) {
	// 修复：正确初始化随机元素
	elements := make([]*fr.Element, 3)
	for i := 0; i < len(elements); i++ {
		elements[i] = new(fr.Element)
		_, err := elements[i].SetRandom()
		if err != nil {
			return nil, nil, err
		}
	}
	gElement, hElement, gamma := elements[0], elements[1], elements[2]

	// g ∈ G1
	g := new(bn254.G1Affine).ScalarMultiplicationBase(gElement.BigInt(new(big.Int)))
	// h ∈ G2
	h := new(bn254.G2Affine).ScalarMultiplicationBase(hElement.BigInt(new(big.Int)))
	// w = g^γ
	w := new(bn254.G1Affine).ScalarMultiplication(g, gamma.BigInt(new(big.Int)))
	// v = e(g, h)
	v, err := bn254.Pair([]bn254.G1Affine{*g}, []bn254.G2Affine{*h})
	if err != nil {
		return nil, nil, err
	}

	// h^γ, h^γ^2, ..., h^γ^m
	hGammaPowers := make([]bn254.G2Affine, m)
	gammaPower := new(fr.Element).SetOne()
	for i := 0; i < m; i++ {
		gammaPower.Mul(gammaPower, gamma) // γ^(i+1)
		hGammaPowers[i] = *new(bn254.G2Affine).ScalarMultiplication(h, gammaPower.BigInt(new(big.Int)))
	}

	return &PublicKey{
			W:            *w,
			V:            v,
			H:            *h,
			HGammaPowers: hGammaPowers,
		}, &MasterSecretKey{
			G:     *g,
			Gamma: *gamma,
		}, nil
}

func Extract(msk *MasterSecretKey, id *Identity) (*UserSecretKey, error) {
	hid := hash.BytesToField(id.Id)
	gammaAddHid := new(fr.Element).Add(&msk.Gamma, &hid)
	inverseGammaAddHid := new(fr.Element).Inverse(gammaAddHid)
	// sk_{id} = g^{1/(γ+H(id))}
	sk := new(bn254.G1Affine).ScalarMultiplication(&msk.G, inverseGammaAddHid.BigInt(new(big.Int)))
	return &UserSecretKey{
		Sk: *sk,
	}, nil
}

func Encrypt(s []Identity, pk *PublicKey) (*BroadcastHeader, *MessageEncyptionKey, error) {
	k, err := new(fr.Element).SetRandom()
	if err != nil {
		return nil, nil, err
	}

	negK := new(fr.Element).Neg(k)
	// C1 = w^{-k} = g^{-kγ}
	C1 := new(bn254.G1Affine).ScalarMultiplication(&pk.W, negK.BigInt(new(big.Int)))

	// 计算 C2 = h^{k·∏(γ+H(ID_i))}
	// 先计算多项式系数
	elements := make([]fr.Element, len(s))
	for i := 0; i < len(elements); i++ {
		elements[i] = hash.BytesToField(s[i].Id)
	}
	coeffs := ComputePolyCoefficients(elements)

	// coeffs[i] 对应 γ^i 的系数
	// 计算 h^{c0} · (h^γ)^{c1} · (h^γ^2)^{c2} · ...
	var result bn254.G2Affine
	result.ScalarMultiplication(&pk.H, coeffs[0].BigInt(new(big.Int)))
	for i := 1; i < len(coeffs); i++ {
		var tmp bn254.G2Affine
		tmp.ScalarMultiplication(&pk.HGammaPowers[i-1], coeffs[i].BigInt(new(big.Int)))
		result.Add(&result, &tmp)
	}

	// 最后乘以 k
	C2 := new(bn254.G2Affine).ScalarMultiplication(&result, k.BigInt(new(big.Int)))

	// K = v^k = e(g,h)^k
	K := new(bn254.GT).Exp(pk.V, k.BigInt(new(big.Int)))

	return &BroadcastHeader{
			C1: *C1,
			C2: *C2,
		}, &MessageEncyptionKey{
			K: *K,
		}, nil
}

func Decrypt(s []Identity, id *Identity, sk *UserSecretKey, hdr *BroadcastHeader, pk *PublicKey) (*MessageEncyptionKey, error) {
	// 根据论文公式:
	// K = [e(C1, h^{p_{i,S}(γ)}) · e(sk_{ID_i}, C2)]^{∏_{j≠i} 1/H(ID_j)}
	// 其中 p_{i,S}(γ) = (1/γ) · [∏_{j≠i}(γ+H(ID_j)) - ∏_{j≠i}H(ID_j)]

	// 1. 找到当前用户在集合中的索引
	userIndex := -1
	for i, identity := range s {
		if string(identity.Id) == string(id.Id) {
			userIndex = i
			break
		}
	}
	if userIndex == -1 {
		return nil, fmt.Errorf("user not in recipient set")
	}

	// 2. 计算 p_{i,S}(γ)
	// 首先计算 ∏_{j≠i}(x + H(ID_j))
	elementsWithoutI := make([]fr.Element, 0, len(s)-1)
	for j := 0; j < len(s); j++ {
		if j != userIndex {
			elementsWithoutI = append(elementsWithoutI, hash.BytesToField(s[j].Id))
		}
	}

	// 计算多项式系数
	coeffsWithoutI := ComputePolyCoefficients(elementsWithoutI)

	// 计算 ∏_{j≠i} H(ID_j)
	prodHidWithoutI := new(fr.Element).SetOne()
	for j := 0; j < len(s); j++ {
		if j != userIndex {
			hid := hash.BytesToField(s[j].Id)
			prodHidWithoutI.Mul(prodHidWithoutI, &hid)
		}
	}

	// 计算 p_{i,S}(γ) 的系数：(coeffsWithoutI - [0, 0, ..., prodHidWithoutI]) / γ
	// 注意：coeffsWithoutI[0] 需要减去 prodHidWithoutI
	// 除以 γ 意味着系数整体向右移动一位
	pCoeffs := make([]fr.Element, len(coeffsWithoutI))
	pCoeffs[0].Sub(&coeffsWithoutI[1], prodHidWithoutI) // 实际上 coeffsWithoutI 没有常数项对应的 prodHid

	// 重新计算：p_{i,S}(γ) = (1/γ) · [∏_{j≠i}(γ+H(ID_j)) - ∏_{j≠i}H(ID_j)]
	// 多项式 ∏(x+H(ID_j)) = c0 + c1·x + c2·x^2 + ...
	// 在 x=γ 时减去常数 ∏H(ID_j)，然后除以 γ
	// 结果的系数为: [(c1 + c2·γ + c3·γ^2 + ... + (c0 - ∏H(ID_j))/γ]
	// 等价于: c1 + c2·γ + c3·γ^2 + ... (因为 c0 = ∏H(ID_j))

	// 简化：直接使用 coeffsWithoutI[1:] 因为 coeffsWithoutI[0] = ∏H(ID_j)

	// 计算 h^{p_{i,S}(γ)}
	var hPower bn254.G2Affine
	if len(coeffsWithoutI) > 1 {
		hPower.ScalarMultiplication(&pk.H, coeffsWithoutI[1].BigInt(new(big.Int)))
		for i := 2; i < len(coeffsWithoutI); i++ {
			var tmp bn254.G2Affine
			tmp.ScalarMultiplication(&pk.HGammaPowers[i-2], coeffsWithoutI[i].BigInt(new(big.Int)))
			hPower.Add(&hPower, &tmp)
		}
	} else {
		// 如果只有一个用户，p_{i,S}(γ) = 0
		hPower.ScalarMultiplication(&pk.H, new(fr.Element).SetZero().BigInt(new(big.Int)))
	}

	// 3. 计算 e(C1, h^{p_{i,S}(γ)})
	pairing1, err := bn254.Pair([]bn254.G1Affine{hdr.C1}, []bn254.G2Affine{hPower})
	if err != nil {
		return nil, err
	}

	// 4. 计算 e(sk_{ID_i}, C2)
	pairing2, err := bn254.Pair([]bn254.G1Affine{sk.Sk}, []bn254.G2Affine{hdr.C2})
	if err != nil {
		return nil, err
	}

	// 5. 计算 pairing1 · pairing2
	K := new(bn254.GT).Mul(&pairing1, &pairing2)

	// 6. 计算指数 ∏_{j≠i} 1/H(ID_j)
	expInverse := new(fr.Element).Inverse(prodHidWithoutI)

	// 7. K = K^{∏_{j≠i} 1/H(ID_j)}
	K.Exp(*K, expInverse.BigInt(new(big.Int)))

	return &MessageEncyptionKey{
		K: *K,
	}, nil
}
