package lsss

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

type LewkoWatersLsssMatrix struct {
	l            int
	n            int
	lsssMatrix   [][]int
	attributeRho []fr.Element
}

func isTargetVector(v []int) bool {
	if v[0] != 1 {
		return false
	}
	for i := 1; i < len(v); i++ {
		if v[i] != 0 {
			return false
		}
	}
	return true
}
