package waters11

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

func NewWaters11CPABEInstance(universe []fr.Element) (*Waters11CPABEInstance, error) {
	attributesUniverse := make(map[fr.Element]struct{}, len(universe))
	for _, u := range universe {
		attributesUniverse[u] = struct{}{}
	}
	return &Waters11CPABEInstance{
		universe: attributesUniverse,
	}, nil
}

func NewWaters11CPABEInstanceByInt64Slice(universe []int64) (*Waters11CPABEInstance, error) {
	attributesUniverse := make(map[fr.Element]struct{}, len(universe))
	for _, u := range universe {
		uElement := *new(fr.Element).SetInt64(u)
		attributesUniverse[uElement] = struct{}{}
	}
	return &Waters11CPABEInstance{
		universe: attributesUniverse,
	}, nil
}

func NewWaters11CPABEInstanceByInt64Pair(start, end int64) (*Waters11CPABEInstance, error) {
	if end < start {
		return nil, fmt.Errorf("end must be greater than start")
	}
	attributesUniverse := make(map[fr.Element]struct{}, end-start)
	for i := start; i < end; i++ {
		iElement := *new(fr.Element).SetInt64(i)
		attributesUniverse[iElement] = struct{}{}
	}
	return &Waters11CPABEInstance{
		universe: attributesUniverse,
	}, nil
}

func (instance *Waters11CPABEInstance) checkAttributes(attributes []fr.Element) bool {
	for _, a := range attributes {
		if _, ok := instance.universe[a]; !ok {
			return false
		}
	}
	return true
}
