package tree

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

type nodeType string

const (
	NodeTypeLeave     nodeType = "leave"
	NodeTypeThreshold nodeType = "threshold"
)

type AccessTreeNode struct {
	nodeType   nodeType
	attribute  fr.Element
	threshold  int
	leafId     int
	children   []*AccessTreeNode
	parent     *AccessTreeNode
	childIndex int

	secret fr.Element
	poly   []fr.Element
}

func NewLeafNode(attr fr.Element) *AccessTreeNode {
	return &AccessTreeNode{
		nodeType:  NodeTypeLeave,
		attribute: attr,
		children:  nil,
	}
}

func NewThresholdNode(threshold int, children ...*AccessTreeNode) *AccessTreeNode {
	if threshold < 1 || threshold > len(children) {
		panic("threshold must be between 1 and len(children)")
	}
	node := &AccessTreeNode{
		nodeType:  NodeTypeThreshold,
		threshold: threshold,
		children:  children,
	}
	for i, c := range children {
		c.childIndex = i + 1
	}
	return node
}

//func (node *AccessTreeNode) shareSecret(secret fr.Element) {
//	if
//}

func (node *AccessTreeNode) isLeaf() bool {
	return node.nodeType == NodeTypeLeave
}

func (node *AccessTreeNode) getLeafNodes() []*AccessTreeNode {
	if node.isLeaf() {
		return []*AccessTreeNode{node}
	}
	var leafNodes []*AccessTreeNode
	for _, child := range node.children {
		leafNodes = append(leafNodes, child.getLeafNodes()...)
	}
	return leafNodes
}
