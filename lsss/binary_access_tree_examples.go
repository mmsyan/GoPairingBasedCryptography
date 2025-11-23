package lsss

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
)

// GetExamples 返回示例树和布尔公式
func GetExamples() ([]*BinaryAccessTree, []string) {
	var booleanFormulas []string
	exampleTrees := make([]*BinaryAccessTree, 0, 16)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	DElement := hash.ToField("D")
	EElement := hash.ToField("E")

	// 0: (A or B)
	booleanFormulas = append(booleanFormulas, "(A or B)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, AElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, BElement, nil, nil)))

	// 1: (A and B)
	booleanFormulas = append(booleanFormulas, "(A and B)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, AElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, BElement, nil, nil)))

	// 2: (B or C)
	booleanFormulas = append(booleanFormulas, "(B or C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, BElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil)))

	// 3: (B and C)
	booleanFormulas = append(booleanFormulas, "(B and C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, BElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil)))

	// 4: ((A or B) or C)
	booleanFormulas = append(booleanFormulas, "((A or B) or C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		exampleTrees[0].Copy(),
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil)))

	// 5: ((A and B) and C)
	booleanFormulas = append(booleanFormulas, "((A and B) and C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		exampleTrees[1].Copy(),
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil)))

	// 6: (A or (B or C))
	booleanFormulas = append(booleanFormulas, "(A or (B or C))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, AElement, nil, nil),
		exampleTrees[2].Copy()))

	// 7: (A and (B and C))
	booleanFormulas = append(booleanFormulas, "(A and (B and C))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, AElement, nil, nil),
		exampleTrees[3].Copy()))

	// 8: ((A or B) and C)
	booleanFormulas = append(booleanFormulas, "((A or B) and C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		exampleTrees[0].Copy(),
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil)))

	// 9: (A or (B and C))
	booleanFormulas = append(booleanFormulas, "(A or (B and C))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, AElement, nil, nil),
		exampleTrees[3].Copy()))

	// 10: (C or D)
	booleanFormulas = append(booleanFormulas, "(C or D)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, DElement, nil, nil)))

	// 11: (C and D)
	booleanFormulas = append(booleanFormulas, "(C and D)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, DElement, nil, nil)))

	// 12: ((A and B) or (C and D))
	booleanFormulas = append(booleanFormulas, "((A and B) or (C and D))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		exampleTrees[1].Copy(),
		exampleTrees[11].Copy()))

	// 13: ((A or B) and (C or D))
	booleanFormulas = append(booleanFormulas, "((A or B) and (C or D))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		exampleTrees[0].Copy(),
		exampleTrees[10].Copy()))

	// 14: (((A and B) or (C and D)) or ((A or B) and (C or D)))
	booleanFormulas = append(booleanFormulas, "(((A and B) or (C and D)) or ((A or B) and (C or D)))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		exampleTrees[12].Copy(),
		exampleTrees[13].Copy()))

	// 15: (E and (((A and B) or (C and D)) or ((A or B) and (C or D))))
	booleanFormulas = append(booleanFormulas, "(E and (((A and B) or (C and D)) or ((A or B) and (C or D))))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, EElement, nil, nil),
		exampleTrees[14].Copy()))

	return exampleTrees, booleanFormulas
}

func GetExample1() (*BinaryAccessTree, string) {
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	booleanFormulas := "(A or B)"
	exampleTrees := NewBinaryAccessTree(NodeTypeOr, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, AElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, BElement, nil, nil))
	return exampleTrees, booleanFormulas
}

func GetExample2() (*BinaryAccessTree, string) {
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	booleanFormulas := "(A and B)"
	exampleTrees := NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, AElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, BElement, nil, nil))
	return exampleTrees, booleanFormulas
}

func GetExample3() (*BinaryAccessTree, string) {
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	booleanFormulas := "(B and C)"
	exampleTrees := NewBinaryAccessTree(NodeTypeAnd, fr.Element{},
		NewBinaryAccessTree(NodeTypeLeave, BElement, nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, CElement, nil, nil))
	return exampleTrees, booleanFormulas
}

func GetExample4() (*BinaryAccessTree, string) {
	// ((A or B) or C)
	tree, _ := GetExamples()
	return tree[4].Copy(), "((A or B) or C)"
}

func GetExample5() (*BinaryAccessTree, string) {
	// ((A and B) and C)
	tree, _ := GetExamples()
	return tree[5].Copy(), "((A and B) and C)"
}

func GetExample6() (*BinaryAccessTree, string) {
	// (A or (B or C))
	tree, _ := GetExamples()
	return tree[6].Copy(), "(A or (B or C))"
}

func GetExample7() (*BinaryAccessTree, string) {
	// (A and (B and C))
	tree, _ := GetExamples()
	return tree[7].Copy(), "(A and (B and C))"
}

func GetExample8() (*BinaryAccessTree, string) {
	// ((A or B) and C)
	tree, _ := GetExamples()
	return tree[8].Copy(), "((A or B) and C)"
}

func GetExample9() (*BinaryAccessTree, string) {
	// (A or (B and C))
	tree, _ := GetExamples()
	return tree[9].Copy(), "(A or (B and C))"
}

func GetExample10() (*BinaryAccessTree, string) {
	// (C or D)
	tree, _ := GetExamples()
	return tree[10].Copy(), "(C or D)"
}

func GetExample11() (*BinaryAccessTree, string) {
	// (C and D)
	tree, _ := GetExamples()
	return tree[11].Copy(), "(C and D)"
}

func GetExample12() (*BinaryAccessTree, string) {
	// ((A and B) or (C and D))
	tree, _ := GetExamples()
	return tree[12].Copy(), "((A and B) or (C and D))"
}

func GetExample13() (*BinaryAccessTree, string) {
	// ((A or B) and (C or D))
	tree, _ := GetExamples()
	return tree[13].Copy(), "((A or B) and (C or D))"
}

func GetExample14() (*BinaryAccessTree, string) {
	// (((A and B) or (C and D)) or ((A or B) and (C or D)))
	tree, _ := GetExamples()
	return tree[14].Copy(), "(((A and B) or (C and D)) or ((A or B) and (C or D)))"
}

func GetExample15() (*BinaryAccessTree, string) {
	// (E and (((A and B) or (C and D)) or ((A or B) and (C or D))))
	tree, _ := GetExamples()
	return tree[15].Copy(), "(E and (((A and B) or (C and D)) or ((A or B) and (C or D))))"
}
