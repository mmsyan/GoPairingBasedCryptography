package kpabe

import "math/big"

type KpabeNode struct {
	poly      []*big.Int
	threshold int
	attribute int
	children  []*KpabeNode
	leaveId   int
}

func NewKpabeLeaveNode(attribute int) *KpabeNode {
	poly := make([]*big.Int, 1)
	poly[0] = big.NewInt(1)
	return &KpabeNode{
		poly:      poly,
		threshold: -1,
		attribute: attribute,
		children:  nil,
	}
}

func NewKpabeInternalNode(threshold int, children []*KpabeNode) *KpabeNode {
	var finalChildren []*KpabeNode
	if children == nil {
		finalChildren = children
	} else {
		finalChildren = make([]*KpabeNode, 0)
	}
	return &KpabeNode{
		poly:      make([]*big.Int, threshold),
		threshold: threshold,
		attribute: -1,
		children:  finalChildren,
	}
}

func isKpabeLeaveNode(node *KpabeNode) bool {
	return len(node.children) == 0
}
