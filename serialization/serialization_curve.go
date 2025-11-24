package serialization

import "github.com/consensys/gnark-crypto/ecc/bn254"

func MarshalG1(element bn254.G1Affine) []byte {
	return element.Marshal()
}

func MarshalG2(element bn254.G2Affine) []byte {
	return element.Marshal()
}

func MarshalGT(element bn254.GT) []byte {
	return element.Marshal()
}

func UnmarshalG1(data []byte) bn254.G1Affine {
	var g1 bn254.G1Affine
	g1.Unmarshal(data)
	return g1
}

func UnmarshalG2(data []byte) bn254.G2Affine {
	var g2 bn254.G2Affine
	g2.Unmarshal(data)
	return g2
}

func UnmarshalGT(data []byte) bn254.GT {
	var gt bn254.GT
	gt.Unmarshal(data)
	return gt
}
