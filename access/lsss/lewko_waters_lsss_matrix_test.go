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
		m.Print()
		//fmt.Printf("matrix rowNumber: %d, columnNumber: %d", m.rowNumber, m.columnNumber)
		//fmt.Println("ρ(i)  Matrix")
		//for j := range m.accessMatrix {
		//	fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.rhoRowToAttribute[j].String()[:4], m.accessMatrix[j])
		//}
		//fmt.Println()
	}
}

func TestTreeDSL(t *testing.T) {
	tree1, formulas := GetExample15()
	tree2 := And(
		LeafFromString("E"),
		Or(
			Or(
				And(LeafFromString("A"), LeafFromString("B")),
				And(LeafFromString("C"), LeafFromString("D")),
			),
			And(
				Or(LeafFromString("A"), LeafFromString("B")),
				Or(LeafFromString("C"), LeafFromString("D")),
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

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight1(t *testing.T) {
	exampleTree, formula := GetExample1()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	attributes := []fr.Element{AElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight2(t *testing.T) {
	exampleTree, formula := GetExample2()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	attributes := []fr.Element{AElement, BElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight3(t *testing.T) {
	exampleTree, formula := GetExample3()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	attributes := []fr.Element{AElement, BElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	if rows != nil || wis != nil {
		t.Fatal("rows and wis should be nil")
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight4(t *testing.T) {
	exampleTree, formula := GetExample4()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	attributes := []fr.Element{AElement, BElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight5(t *testing.T) {
	exampleTree, formula := GetExample5()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	attributes := []fr.Element{AElement, BElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	if rows != nil || wis != nil {
		t.Fatal("rows and wis should be nil")
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight6(t *testing.T) {
	exampleTree, formula := GetExample6()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	DElement := hash.ToField("D")
	attributes := []fr.Element{DElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	if rows != nil || wis != nil {
		t.Fatal("rows and wis should be nil")
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight7(t *testing.T) {
	exampleTree, formula := GetExample7()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	attributes := []fr.Element{CElement, BElement, AElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight8(t *testing.T) {
	exampleTree, formula := GetExample8()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	attributes := []fr.Element{AElement, BElement, CElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight9(t *testing.T) {
	exampleTree, formula := GetExample9()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	BElement := hash.ToField("B")
	attributes := []fr.Element{BElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	if rows != nil || wis != nil {
		t.Fatal("rows and wis should be nil")
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight10(t *testing.T) {
	exampleTree, formula := GetExample10()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	attributes := []fr.Element{BElement, CElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight11(t *testing.T) {
	exampleTree, formula := GetExample11()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	CElement := hash.ToField("C")
	attributes := []fr.Element{CElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	if rows != nil || wis != nil {
		t.Fatal("rows and wis should be nil")
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight12(t *testing.T) {
	exampleTree, formula := GetExample12()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	CElement := hash.ToField("C")
	attributes := []fr.Element{AElement, CElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	if rows != nil || wis != nil {
		t.Fatal("rows and wis should be nil")
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight13(t *testing.T) {
	exampleTree, formula := GetExample13()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	DElement := hash.ToField("D")
	attributes := []fr.Element{AElement, DElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight14(t *testing.T) {
	exampleTree, formula := GetExample14()
	m := NewLSSSMatrixFromTree(exampleTree)
	fmt.Printf("Access formula: %s\n", formula)

	AElement := hash.ToField("A")
	CElement := hash.ToField("C")
	attributes := []fr.Element{AElement, CElement}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeightSpecial1(t *testing.T) {
	m := [][]fr.Element{
		{fr.NewElement(1), fr.NewElement(1)},
		{fr.NewElement(1), fr.NewElement(2)},
		{fr.NewElement(1), fr.NewElement(3)},
		{fr.NewElement(1), fr.NewElement(4)},
	}
	attr := []fr.Element{hash.ToField("A"), hash.ToField("B"), hash.ToField("C"), hash.ToField("D")}
	lsss := &LewkoWatersLsssMatrix{
		rowNumber:         len(m),
		columnNumber:      len(m[0]),
		accessMatrix:      m,
		rhoRowToAttribute: attr,
	}

	userAttributes := []fr.Element{hash.ToField("B"), hash.ToField("D")}

	lsss.Print()

	for _, a := range userAttributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := lsss.FindLinearCombinationWeight(userAttributes)
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeightSpecial2(t *testing.T) {
	m := [][]fr.Element{
		{fr.NewElement(1), fr.NewElement(1), fr.NewElement(0)},
		{fr.NewElement(1), fr.NewElement(2), fr.NewElement(1)},
		{fr.NewElement(1), fr.NewElement(2), fr.NewElement(2)},
		{fr.NewElement(1), fr.NewElement(2), fr.NewElement(3)},
		{fr.NewElement(1), fr.NewElement(2), fr.NewElement(4)},
	}
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	DElement := hash.ToField("D")
	EElement := hash.ToField("E")
	attr := []fr.Element{EElement, AElement, BElement, CElement, DElement}
	lsss := &LewkoWatersLsssMatrix{
		rowNumber:         len(m),
		columnNumber:      len(m[0]),
		accessMatrix:      m,
		rhoRowToAttribute: attr,
	}

	userAttributes := []fr.Element{EElement, CElement, DElement}

	lsss.Print()

	for _, a := range userAttributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := lsss.FindLinearCombinationWeight(userAttributes)
	if rows != nil || wis != nil {
		for i := range rows {
			fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
		}
	} else {
		fmt.Println("rows and wis are nil")
	}
}
