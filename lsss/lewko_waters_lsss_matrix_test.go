package lsss

import (
	"fmt"
	"testing"
)

func TestLSSSMatrix(t *testing.T) {
	exampleTrees, formulas := GetExamples()

	for i := range exampleTrees {
		m := NewLSSSMatrixFromTree(exampleTrees[i])
		fmt.Printf("Access formula: %s\n", formulas[i])
		fmt.Println("ρ(i)  Matrix")
		for j := range m.lsssMatrix {
			fmt.Printf("%-4s   %v\n", m.attributeRho[j], m.lsssMatrix[j])
		}
		fmt.Println()
	}

}
