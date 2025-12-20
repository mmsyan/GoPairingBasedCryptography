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
		m := NewLSSSMatrixFromBinaryTree(exampleTrees[i])
		fmt.Printf("Access formula: %s\n", formulas[i])
		m.Print()
		//fmt.Printf("matrix rowNumber: %d, columnNumber: %d", m.rowNumber, m.columnNumber)
		//fmt.Println("ρ(i)  Matrix")
		//for j := range m.accessMatrix {
		//	fmt.Printf("index %d || attribute: %s ||  %v\n", j, m.rho[j].String()[:4], m.accessMatrix[j])
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
	m1 := NewLSSSMatrixFromBinaryTree(tree1)
	m2 := NewLSSSMatrixFromBinaryTree(tree2)

	fmt.Printf("Access formula: %s\n", formulas)
	fmt.Printf("matrix from tree1 \n")
	fmt.Println("ρ(i)  Matrix")
	for j := range m1.accessMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m1.rho[j].String()[:4], m1.accessMatrix[j])
	}
	fmt.Println()
	fmt.Printf("matrix from tree2 \n")
	fmt.Println("ρ(i)  Matrix")
	for j := range m2.accessMatrix {
		fmt.Printf("index %d || attribute: %s ||  %v\n", j, m2.rho[j].String()[:4], m2.accessMatrix[j])
	}
}

func TestLewkoWatersLsssMatrix_FindLinearCombinationWeight1(t *testing.T) {
	exampleTree, formula := GetExample1()
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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
	m := NewLSSSMatrixFromBinaryTree(exampleTree)
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

// <Efficient Generation of Linear Secret Sharing Scheme Matrices from Threshold Access Trees> Page 7
func TestLewkoWatersLsssMatrix_FindLinearCombinationWeightSpecial1(t *testing.T) {
	m := [][]fr.Element{
		{fr.NewElement(1), fr.NewElement(1)},
		{fr.NewElement(1), fr.NewElement(2)},
		{fr.NewElement(1), fr.NewElement(3)},
		{fr.NewElement(1), fr.NewElement(4)},
	}
	attr := []fr.Element{hash.ToField("A"), hash.ToField("B"), hash.ToField("C"), hash.ToField("D")}
	lsss := &LewkoWatersLsssMatrix{
		rowNumber:    len(m),
		columnNumber: len(m[0]),
		accessMatrix: m,
		rho:          attr,
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

// <Efficient Generation of Linear Secret Sharing Scheme Matrices from Threshold Access Trees> Page 3
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
		rowNumber:    len(m),
		columnNumber: len(m[0]),
		accessMatrix: m,
		rho:          attr,
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

func TestNewLSSSMatrixFromBinaryTree(t *testing.T) {

	// === 铁塔基础属性（10个）===
	attr1 := hash.ToField("TowerID:SH-2025-0731")
	attr2 := hash.ToField("Province:Shanghai")
	attr3 := hash.ToField("City:Pudong")
	attr4 := hash.ToField("District:Xinqu")
	attr5 := hash.ToField("TowerType:5G_BaseStation")
	attr6 := hash.ToField("Height:45m")
	attr7 := hash.ToField("Owner:ChinaMobile")
	attr8 := hash.ToField("VoltageLevel:220kV")
	attr9 := hash.ToField("BuildYear:2023")
	attr10 := hash.ToField("MaintenanceCompany:Huaxin")

	// === 无人机权限属性（10个）===
	attr11 := hash.ToField("DroneID:DJI-M300-2025X")
	attr12 := hash.ToField("DroneLicense:SH-UAV-951")
	attr13 := hash.ToField("Pilot:ZhangSan")
	attr14 := hash.ToField("FlightPermission:Level_A")
	attr15 := hash.ToField("MaxAltitude:120m")
	attr16 := hash.ToField("Camera:Zenmuse_H20T")
	attr17 := hash.ToField("MissionType:TowerInspection")
	attr18 := hash.ToField("FlightDate:2025-12-11")
	attr19 := hash.ToField("TimeWindow:08:00-18:00")
	attr20 := hash.ToField("Company:PowerGrid_DroneTeam")

	policyTree := And(
		//And(
		//	Leaf(attr3),
		//	Leaf(attr4),
		//	Leaf(attr3),
		//	Leaf(attr4),
		//	Leaf(attr5),
		//	Leaf(attr6),
		//	And(
		//		Leaf(attr17),
		//		Leaf(attr18),
		//	),
		//),
		//Leaf(attr9),
		And(
			Leaf(attr1),
			Leaf(attr2),
			Or(
				Leaf(attr3),
				Leaf(attr5),
			),
		),
		And(
			Leaf(attr16),
			Leaf(attr11),
		),
	)
	m := NewLSSSMatrixFromBinaryTree(policyTree)

	attributes := []fr.Element{attr1, attr2, attr3, attr4, attr5, attr6, attr7, attr8, attr9, attr10,
		attr11, attr12, attr13, attr14, attr15, attr16, attr17, attr18, attr19, attr20}

	m.Print()

	for _, a := range attributes {
		fmt.Printf("attributes: %s", a.String())
		fmt.Println()
	}
	rows, wis := m.FindLinearCombinationWeight(attributes)
	if rows == nil || wis == nil {
		t.Fatal("rows and wis shouldn't be nil")
	}
	for i := range rows {
		fmt.Printf("row: %d || wi: %s \n", rows[i], wis[i].String())
	}
}
