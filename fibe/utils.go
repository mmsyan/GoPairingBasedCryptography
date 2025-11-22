package fibe

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

func (instance *SW05FIBEInstance) isValidAttributes(attributes []fr.Element) bool {
	for _, i := range attributes {
		_, ok := instance.universe[i]
		if !ok {
			return false
		}
	}
	return true
}
