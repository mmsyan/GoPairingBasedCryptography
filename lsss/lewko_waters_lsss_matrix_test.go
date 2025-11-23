package lsss

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
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
			fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.attributeRho[j].String()[:4], m.lsssMatrix[j])
		}
		fmt.Println()
	}
}

func TestLewkoWatersLsssMatrix_ComputeVector1(t *testing.T) {
	exampleTree, formula := GetExample1()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	attributes := []fr.Element{AElement}

	rows, wis := m.GetSatisfiedLinearCombination(attributes)
	for j := range m.lsssMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.attributeRho[j].String()[:4], m.lsssMatrix[j])
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_ComputeVector14(t *testing.T) {
	exampleTree, formula := GetExample14()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	CElement := hash.ToField("C")
	attributes := []fr.Element{AElement, CElement}

	rows, wis := m.GetSatisfiedLinearCombination(attributes)
	for j := range m.lsssMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.attributeRho[j].String()[:4], m.lsssMatrix[j])
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}
