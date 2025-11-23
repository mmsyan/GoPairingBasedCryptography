package hash

import "github.com/consensys/gnark-crypto/ecc/bn254"

func FromGT(gt bn254.GT) []byte {
	gtBytes := gt.Bytes()
	return gtBytes[:]
}
