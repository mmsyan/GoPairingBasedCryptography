package lsss

type NodeType string

const (
	NodeTypeOr    NodeType = "or"
	NodeTypeAnd   NodeType = "and"
	NodeTypeLeave NodeType = "leave"
)

type BinaryAccessTree struct {
	Type   NodeType
	Value  string
	Left   *BinaryAccessTree
	Right  *BinaryAccessTree
	Vector []int
}

func NewBinaryAccessTree(t NodeType, value string, left, right *BinaryAccessTree) *BinaryAccessTree {
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
	booleanFormulas := []string{}
	exampleTrees := make([]*BinaryAccessTree, 0, 16)

	// 0: (A or B)
	booleanFormulas = append(booleanFormulas, "(A or B)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		NewBinaryAccessTree(NodeTypeLeave, "A", nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, "B", nil, nil)))

	// 1: (A and B)
	booleanFormulas = append(booleanFormulas, "(A and B)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		NewBinaryAccessTree(NodeTypeLeave, "A", nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, "B", nil, nil)))

	// 2: (B or C)
	booleanFormulas = append(booleanFormulas, "(B or C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		NewBinaryAccessTree(NodeTypeLeave, "B", nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, "C", nil, nil)))

	// 3: (B and C)
	booleanFormulas = append(booleanFormulas, "(B and C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		NewBinaryAccessTree(NodeTypeLeave, "B", nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, "C", nil, nil)))

	// 4: ((A or B) or C)
	booleanFormulas = append(booleanFormulas, "((A or B) or C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		exampleTrees[0].Copy(),
		NewBinaryAccessTree(NodeTypeLeave, "C", nil, nil)))

	// 5: ((A and B) and C)
	booleanFormulas = append(booleanFormulas, "((A and B) and C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		exampleTrees[1].Copy(),
		NewBinaryAccessTree(NodeTypeLeave, "C", nil, nil)))

	// 6: (A or (B or C))
	booleanFormulas = append(booleanFormulas, "(A or (B or C))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		NewBinaryAccessTree(NodeTypeLeave, "A", nil, nil),
		exampleTrees[2].Copy()))

	// 7: (A and (B and C))
	booleanFormulas = append(booleanFormulas, "(A and (B and C))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		NewBinaryAccessTree(NodeTypeLeave, "A", nil, nil),
		exampleTrees[3].Copy()))

	// 8: ((A or B) and C)
	booleanFormulas = append(booleanFormulas, "((A or B) and C)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		exampleTrees[0].Copy(),
		NewBinaryAccessTree(NodeTypeLeave, "C", nil, nil)))

	// 9: (A or (B and C))
	booleanFormulas = append(booleanFormulas, "(A or (B and C))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		NewBinaryAccessTree(NodeTypeLeave, "A", nil, nil),
		exampleTrees[3].Copy()))

	// 10: (C or D)
	booleanFormulas = append(booleanFormulas, "(C or D)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		NewBinaryAccessTree(NodeTypeLeave, "C", nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, "D", nil, nil)))

	// 11: (C and D)
	booleanFormulas = append(booleanFormulas, "(C and D)")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		NewBinaryAccessTree(NodeTypeLeave, "C", nil, nil),
		NewBinaryAccessTree(NodeTypeLeave, "D", nil, nil)))

	// 12: ((A and B) or (C and D))
	booleanFormulas = append(booleanFormulas, "((A and B) or (C and D))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		exampleTrees[1].Copy(),
		exampleTrees[11].Copy()))

	// 13: ((A or B) and (C or D))
	booleanFormulas = append(booleanFormulas, "((A or B) and (C or D))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		exampleTrees[0].Copy(),
		exampleTrees[10].Copy()))

	// 14: (((A and B) or (C and D)) or ((A or B) and (C or D)))
	booleanFormulas = append(booleanFormulas, "(((A and B) or (C and D)) or ((A or B) and (C or D)))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeOr, "",
		exampleTrees[12].Copy(),
		exampleTrees[13].Copy()))

	// 15: (E and (((A and B) or (C and D)) or ((A or B) and (C or D))))
	booleanFormulas = append(booleanFormulas, "(E and (((A and B) or (C and D)) or ((A or B) and (C or D))))")
	exampleTrees = append(exampleTrees, NewBinaryAccessTree(NodeTypeAnd, "",
		NewBinaryAccessTree(NodeTypeLeave, "E", nil, nil),
		exampleTrees[14].Copy()))

	return exampleTrees, booleanFormulas
}
