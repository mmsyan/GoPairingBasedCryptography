package kpabe

import "math/big"

// NodeType 定义节点类型
type NodeType int

const (
	LeafNode      NodeType = iota // 叶子节点（属性节点）
	AndNode                       // AND门节点
	OrNode                        // OR门节点
	ThresholdNode                 // 门限节点（t-of-n）
)

type KpabeNode struct {
	NodeType  NodeType // 节点类型
	Threshold int      // 节点的阈值：只有非叶子节点才有
	Attribute int      // 节点的属性：只有叶子节点才有

	Children []*KpabeNode
	Parent   *KpabeNode
	Index    int

	Poly   []*big.Int
	Secret *big.Int
}

func NewKpabeLeaveNode(attribute int) *KpabeNode {
	poly := make([]*big.Int, 1)
	poly[0] = big.NewInt(1)
	return &KpabeNode{
		poly:      poly,
		threshold: -1,
		Attribute: attribute,
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
		Attribute: -1,
		children:  finalChildren,
	}
}

func isKpabeLeaveNode(node *KpabeNode) bool {
	return len(node.children) == 0
}
