package lsss

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type NodeType string

const (
	NodeTypeOr    NodeType = "or"
	NodeTypeAnd   NodeType = "and"
	NodeTypeLeave NodeType = "leave"
)

type BinaryAccessTree struct {
	Type      NodeType
	Attribute fr.Element
	Left      *BinaryAccessTree
	Right     *BinaryAccessTree
	Vector    []int
}

func NewBinaryAccessTree(nodeType NodeType, attr fr.Element, left, right *BinaryAccessTree) *BinaryAccessTree {
	return &BinaryAccessTree{
		Type:      nodeType,
		Attribute: attr,
		Left:      left,
		Right:     right,
		Vector:    []int{},
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
		Type:      t.Type,
		Attribute: t.Attribute,
		Vector:    make([]int, len(t.Vector)),
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
