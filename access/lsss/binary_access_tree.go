package lsss

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
)

type nodeType string

const (
	NodeTypeOr    nodeType = "or"
	NodeTypeAnd   nodeType = "and"
	NodeTypeLeave nodeType = "leave"
)

type BinaryAccessTree struct {
	Type      nodeType
	Attribute fr.Element
	Left      *BinaryAccessTree
	Right     *BinaryAccessTree
	Vector    []fr.Element
}

func NewBinaryAccessTree(nodeType nodeType, attr fr.Element, left, right *BinaryAccessTree) *BinaryAccessTree {
	return &BinaryAccessTree{
		Type:      nodeType,
		Attribute: attr,
		Left:      left,
		Right:     right,
		Vector:    []fr.Element{},
	}
}

func (t *BinaryAccessTree) VectorPadZero(counter int) {
	for i := len(t.Vector); i < counter; i++ {
		t.Vector = append(t.Vector, fr.NewElement(0))
	}
}

func (t *BinaryAccessTree) Copy() *BinaryAccessTree {
	if t == nil {
		return nil
	}

	newTree := &BinaryAccessTree{
		Type:      t.Type,
		Attribute: t.Attribute,
		Vector:    make([]fr.Element, len(t.Vector)),
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
