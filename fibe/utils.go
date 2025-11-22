package fibe

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// isValidAttributes checks whether all given attributes belong to the universe
// defined in the SW05FIBEInstance.
//
// Parameters:
//
//	attributes - slice of field elements representing the attribute set to validate
//
// Returns:
//
//	true if all attributes are in the instance's universe, false otherwise
func (instance *SW05FIBEInstance) isValidAttributes(attributes []fr.Element) bool {
	for _, i := range attributes {
		if _, ok := instance.universe[i]; !ok {
			return false
		}
	}
	return true
}
