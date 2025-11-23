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
		fmt.Printf("matrix l: %d, n: %d\n", m.l, m.n)
		fmt.Println("ρ(i)  Matrix")
		for j := range m.lsssMatrix {
			fmt.Printf("index %d, %s   %v\n", j, m.attributeRho[j].String()[:4], m.lsssMatrix[j])
		}

		fmt.Println()
	}

}
