package lsss

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
)

type NodeType string

const (
	NodeTypeOr    NodeType = "or"
	NodeTypeAnd   NodeType = "and"
	NodeTypeLeave NodeType = "leave"
)

type BinaryAccessTree struct {
	Type   NodeType
	Value  fr.Element
	Left   *BinaryAccessTree
	Right  *BinaryAccessTree
	Vector []int
}

func NewBinaryAccessTree(t NodeType, value fr.Element, left, right *BinaryAccessTree) *BinaryAccessTree {
	return &BinaryAccessTree{
		Type:   t,
		Value:  value,
		Left:   left,
		Right:  right,
		Vector: []int{},
	}
}

func (t *BinaryAccessTree) VectorPadZero(counter int) {
	for i := len(t.Vector); i < counter; i++ {
		t.Vector = append(t.Vector, 0)
	}
}

func (t *BinaryAccessTree) Copy() *BinaryAccessTree {
	if t == nil {
		return nil
	}

	newTree := &BinaryAccessTree{
		Type:   t.Type,
		Value:  t.Value,
		Vector: make([]int, len(t.Vector)),
	}
	copy(newTree.Vector, t.Vector)

	if t.Left != nil {
		newTree.Left = t.Left.Copy()
	}
	if t.Right != nil {
		newTree.Right = t.Right.Copy()
	}

	return newTree
}

// GetExamples 返回示例树和布尔公式
func GetExamples() ([]*BinaryAccessTree, []string) {
	var booleanFormulas []string
	exampleTrees := make([]*BinaryAccessTree, 0, 16)

	AElement := hash.HashStringToFidld("A")
	BElement := hash.HashStringToFidld("B")
	CElement := hash.HashStringToFidld("C")
	DElement := hash.HashStringToFidld("D")
	EElement := hash.HashStringToFidld("E")

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
