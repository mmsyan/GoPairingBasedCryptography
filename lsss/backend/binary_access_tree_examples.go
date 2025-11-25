package backend

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"github.com/mmsyan/GnarkPairingProject/lsss"
)

// GetExamples 返回示例树和布尔公式
func GetExamples() ([]*lsss.BinaryAccessTree, []string) {
	var booleanFormulas []string
	exampleTrees := make([]*lsss.BinaryAccessTree, 0, 16)

	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	DElement := hash.ToField("D")
	EElement := hash.ToField("E")

	// 0: (A or B)
	booleanFormulas = append(booleanFormulas, "(A or B)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, AElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, BElement, nil, nil)))

	// 1: (A and B)
	booleanFormulas = append(booleanFormulas, "(A and B)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, AElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, BElement, nil, nil)))

	// 2: (B or C)
	booleanFormulas = append(booleanFormulas, "(B or C)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, BElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil)))

	// 3: (B and C)
	booleanFormulas = append(booleanFormulas, "(B and C)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, BElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil)))

	// 4: ((A or B) or C)
	booleanFormulas = append(booleanFormulas, "((A or B) or C)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		exampleTrees[0].Copy(),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil)))

	// 5: ((A and B) and C)
	booleanFormulas = append(booleanFormulas, "((A and B) and C)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		exampleTrees[1].Copy(),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil)))

	// 6: (A or (B or C))
	booleanFormulas = append(booleanFormulas, "(A or (B or C))")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, AElement, nil, nil),
		exampleTrees[2].Copy()))

	// 7: (A and (B and C))
	booleanFormulas = append(booleanFormulas, "(A and (B and C))")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, AElement, nil, nil),
		exampleTrees[3].Copy()))

	// 8: ((A or B) and C)
	booleanFormulas = append(booleanFormulas, "((A or B) and C)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		exampleTrees[0].Copy(),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil)))

	// 9: (A or (B and C))
	booleanFormulas = append(booleanFormulas, "(A or (B and C))")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, AElement, nil, nil),
		exampleTrees[3].Copy()))

	// 10: (C or D)
	booleanFormulas = append(booleanFormulas, "(C or D)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, DElement, nil, nil)))

	// 11: (C and D)
	booleanFormulas = append(booleanFormulas, "(C and D)")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, DElement, nil, nil)))

	// 12: ((A and B) or (C and D))
	booleanFormulas = append(booleanFormulas, "((A and B) or (C and D))")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		exampleTrees[1].Copy(),
		exampleTrees[11].Copy()))

	// 13: ((A or B) and (C or D))
	booleanFormulas = append(booleanFormulas, "((A or B) and (C or D))")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		exampleTrees[0].Copy(),
		exampleTrees[10].Copy()))

	// 14: (((A and B) or (C and D)) or ((A or B) and (C or D)))
	booleanFormulas = append(booleanFormulas, "(((A and B) or (C and D)) or ((A or B) and (C or D)))")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		exampleTrees[12].Copy(),
		exampleTrees[13].Copy()))

	// 15: (E and (((A and B) or (C and D)) or ((A or B) and (C or D))))
	booleanFormulas = append(booleanFormulas, "(E and (((A and B) or (C and D)) or ((A or B) and (C or D))))")
	exampleTrees = append(exampleTrees, lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, EElement, nil, nil),
		exampleTrees[14].Copy()))

	return exampleTrees, booleanFormulas
}

func GetExample1() (*lsss.BinaryAccessTree, string) {
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	booleanFormulas := "(A or B)"
	exampleTrees := lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, AElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, BElement, nil, nil))
	return exampleTrees, booleanFormulas
}

func GetExample2() (*lsss.BinaryAccessTree, string) {
	AElement := hash.ToField("A")
	BElement := hash.ToField("B")
	booleanFormulas := "(A and B)"
	exampleTrees := lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, AElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, BElement, nil, nil))
	return exampleTrees, booleanFormulas
}

func GetExample3() (*lsss.BinaryAccessTree, string) {
	BElement := hash.ToField("B")
	CElement := hash.ToField("C")
	booleanFormulas := "(B and C)"
	exampleTrees := lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{},
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, BElement, nil, nil),
		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, CElement, nil, nil))
	return exampleTrees, booleanFormulas
}

func GetExample4() (*lsss.BinaryAccessTree, string) {
	// ((A or B) or C)
	tree, _ := GetExamples()
	return tree[4].Copy(), "((A or B) or C)"
}

func GetExample5() (*lsss.BinaryAccessTree, string) {
	// ((A and B) and C)
	tree, _ := GetExamples()
	return tree[5].Copy(), "((A and B) and C)"
}

func GetExample6() (*lsss.BinaryAccessTree, string) {
	// (A or (B or C))
	tree, _ := GetExamples()
	return tree[6].Copy(), "(A or (B or C))"
}

func GetExample7() (*lsss.BinaryAccessTree, string) {
	// (A and (B and C))
	tree, _ := GetExamples()
	return tree[7].Copy(), "(A and (B and C))"
}

func GetExample8() (*lsss.BinaryAccessTree, string) {
	// ((A or B) and C)
	tree, _ := GetExamples()
	return tree[8].Copy(), "((A or B) and C)"
}

func GetExample9() (*lsss.BinaryAccessTree, string) {
	// (A or (B and C))
	tree, _ := GetExamples()
	return tree[9].Copy(), "(A or (B and C))"
}

func GetExample10() (*lsss.BinaryAccessTree, string) {
	// (C or D)
	tree, _ := GetExamples()
	return tree[10].Copy(), "(C or D)"
}

func GetExample11() (*lsss.BinaryAccessTree, string) {
	// (C and D)
	tree, _ := GetExamples()
	return tree[11].Copy(), "(C and D)"
}

func GetExample12() (*lsss.BinaryAccessTree, string) {
	// ((A and B) or (C and D))
	tree, _ := GetExamples()
	return tree[12].Copy(), "((A and B) or (C and D))"
}

func GetExample13() (*lsss.BinaryAccessTree, string) {
	// ((A or B) and (C or D))
	tree, _ := GetExamples()
	return tree[13].Copy(), "((A or B) and (C or D))"
}

func GetExample14() (*lsss.BinaryAccessTree, string) {
	// (((A and B) or (C and D)) or ((A or B) and (C or D)))
	tree, _ := GetExamples()
	return tree[14].Copy(), "(((A and B) or (C and D)) or ((A or B) and (C or D)))"
}

func GetExample15() (*lsss.BinaryAccessTree, string) {
	// (E and (((A and B) or (C and D)) or ((A or B) and (C or D))))
	tree, _ := GetExamples()
	return tree[15].Copy(), "(E and (((A and B) or (C and D)) or ((A or B) and (C or D))))"
}
