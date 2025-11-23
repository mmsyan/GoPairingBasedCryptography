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
