package hash

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
)

func HashStringToG1(str string) bn254.G1Affine {
	result, err := bn254.HashToG1([]byte(str), []byte("Hash String To Element In G1"))
	if err != nil {
		panic(fmt.Errorf("failed to hash string to g1: %v", err))
	}
	return result
}
