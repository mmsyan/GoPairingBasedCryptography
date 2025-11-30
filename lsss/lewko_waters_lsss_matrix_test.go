package lsss

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"github.com/mmsyan/GnarkPairingProject/lsss/backend"
	"testing"
)

func TestLSSSMatrix(t *testing.T) {
	exampleTrees, formulas := backend.GetExamples()

	for i := range exampleTrees {
		m := NewLSSSMatrixFromTree(exampleTrees[i])
		fmt.Printf("Access formula: %s\n", formulas[i])
		fmt.Printf("matrix rowNumber: %d, columnNumber: %d\columnNumber", m.rowNumber, m.columnNumber)
		fmt.Println("ρ(i)  Matrix")
		for j := range m.accessMatrix {
			fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.rhoRowToAttribute[j].String()[:4], m.accessMatrix[j])
		}
		fmt.Println()
	}
}

func TestTreeDSL(t *testing.T) {
	tree1, formulas := backend.GetExample15()
	tree2 := backend.And(
		backend.Leaf("E"),
		backend.Or(
			backend.Or(
				backend.And(backend.Leaf("A"), backend.Leaf("B")),
				backend.And(backend.Leaf("C"), backend.Leaf("D")),
			),
			backend.And(
				backend.Or(backend.Leaf("A"), backend.Leaf("B")),
				backend.Or(backend.Leaf("C"), backend.Leaf("D")),
			),
		),
	)
	m1 := NewLSSSMatrixFromTree(tree1)
	m2 := NewLSSSMatrixFromTree(tree2)

	fmt.Printf("Access formula: %s\n", formulas)
	fmt.Printf("matrix from tree1 \n")
	fmt.Println("ρ(i)  Matrix")
	for j := range m1.accessMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m1.rhoRowToAttribute[j].String()[:4], m1.accessMatrix[j])
	}
	fmt.Println()
	fmt.Printf("matrix from tree2 \n")
	fmt.Println("ρ(i)  Matrix")
	for j := range m2.accessMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m2.rhoRowToAttribute[j].String()[:4], m2.accessMatrix[j])
	}
}

func TestLewkoWatersLsssMatrix_ComputeVector1(t *testing.T) {
	exampleTree, formula := backend.GetExample1()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	attributes := []fr.Element{AElement}

	rows, wis := m.GetSatisfiedLinearCombination(attributes)
	for j := range m.accessMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.rhoRowToAttribute[j].String()[:4], m.accessMatrix[j])
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_ComputeVector14(t *testing.T) {
	exampleTree, formula := backend.GetExample14()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	CElement := hash.ToField("C")
	attributes := []fr.Element{AElement, CElement}

	rows, wis := m.GetSatisfiedLinearCombination(attributes)
	for j := range m.accessMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.rhoRowToAttribute[j].String()[:4], m.accessMatrix[j])
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}
