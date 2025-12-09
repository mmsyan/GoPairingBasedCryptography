package tree

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/utils"
	"math/big"
)

type nodeType string

const (
	NodeTypeLeave     nodeType = "leave"
	NodeTypeThreshold nodeType = "threshold"
)

type AccessTreeNode struct {
	nodeType   nodeType
	Attribute  fr.Element
	threshold  int
	LeafId     int
	children   []*AccessTreeNode
	parent     *AccessTreeNode
	childIndex int

	secret fr.Element
	Poly   []fr.Element
}

func NewLeafNode(attr fr.Element) *AccessTreeNode {
	return &AccessTreeNode{
		nodeType:  NodeTypeLeave,
		Attribute: attr,
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

func (node *AccessTreeNode) isLeaf() bool {
	return node.nodeType == NodeTypeLeave
}

func (node *AccessTreeNode) ShareSecret(secret fr.Element) {
	if node.isLeaf() {
		return
	}
	node.Poly = utils.GenerateRandomPolynomial(node.threshold, secret)
	for i := 0; i < len(node.children); i++ {
		childSecret := utils.ComputePolynomialValue(node.Poly, *new(fr.Element).SetInt64(int64(i + 1)))
		node.children[i].ShareSecret(childSecret)
	}
}

// GenerateLeafID 为所有叶子节点生成唯一的编号
// 这个方法必须在使用访问树进行加密之前调用
func (node *AccessTreeNode) GenerateLeafID() {
	sequenceNumber := 1
	node.generateLeafIDHelper(&sequenceNumber)
}

// generateLeafIDHelper 递归辅助方法，使用层序遍历为叶子节点分配ID
func (node *AccessTreeNode) generateLeafIDHelper(counter *int) {
	if node.isLeaf() {
		node.LeafId = *counter
		*counter++
		return
	}
	for _, child := range node.children {
		child.generateLeafIDHelper(counter)
	}
}

func (node *AccessTreeNode) DecryptNode(attributes map[fr.Element]struct{}, dj map[fr.Element]bn254.G2Affine, djPrime map[fr.Element]bn254.G2Affine, cy map[int]bn254.G1Affine, cyPrime map[int]bn254.G1Affine) bn254.GT {
	if node.isLeaf() {
		if _, ok := attributes[node.Attribute]; ok {
			eDiCx, err := bn254.Pair([]bn254.G1Affine{cy[node.LeafId]}, []bn254.G2Affine{dj[node.Attribute]})
			if err != nil {
				panic(err)
			}
			eDiPrimeCxPrime, err := bn254.Pair([]bn254.G1Affine{cyPrime[node.LeafId]}, []bn254.G2Affine{djPrime[node.Attribute]})
			if err != nil {
				panic(err)
			}
			return *new(bn254.GT).Div(&eDiCx, &eDiPrimeCxPrime)
		}
		return bn254.GT{}
	}

	indexToChild := make(map[int]*AccessTreeNode)
	indexToSecret := make(map[int]bn254.GT)

	for i, c := range node.children {
		childSecret := c.DecryptNode(attributes, dj, djPrime, cy, cyPrime)
		// 修复：只有当子节点解密成功（不等于零元素）时才添加
		if !childSecret.Equal(&bn254.GT{}) {
			indexToChild[i+1] = c
			indexToSecret[i+1] = childSecret
			if len(indexToChild) == node.threshold {
				break
			}
		}
	}

	if len(indexToChild) == node.threshold {
		result := new(bn254.GT).SetOne()
		s := []fr.Element{}
		for index := range indexToChild {
			s = append(s, fr.NewElement(uint64(index)))
		}
		for index := range indexToChild {
			delta := utils.ComputeLagrangeBasis(fr.NewElement(uint64(index)), s, fr.NewElement(0))
			fz := new(bn254.GT).Exp(indexToSecret[index], delta.BigInt(new(big.Int)))
			result = new(bn254.GT).Mul(result, fz)
		}
		return *result
	}

	return bn254.GT{}
}

func (node *AccessTreeNode) GetLeafNodes() []*AccessTreeNode {
	if node.isLeaf() {
		return []*AccessTreeNode{node}
	}
	var leafNodes []*AccessTreeNode
	for _, child := range node.children {
		leafNodes = append(leafNodes, child.GetLeafNodes()...)
	}
	return leafNodes
}
