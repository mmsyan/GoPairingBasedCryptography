package tree

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GoPairingBasedCryptography/utils"
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
	node.secret = secret // 保存当前节点的秘密值

	if node.isLeaf() {
		// 🔧 叶子节点生成常数多项式 q(x) = secret
		node.Poly = []fr.Element{secret}
		return
	}

	// 非叶子节点：生成度为 threshold-1 的随机多项式
	node.Poly = utils.GenerateRandomPolynomial(node.threshold, secret)

	// 递归分配秘密给子节点
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

func (node *AccessTreeNode) DecryptNode(attributes map[fr.Element]struct{}, dj map[fr.Element]bn254.G2Affine, djPrime map[fr.Element]bn254.G2Affine, cy map[int]bn254.G1Affine, cyPrime map[int]bn254.G1Affine, r fr.Element) *bn254.GT {
	if node.isLeaf() {
		if _, ok := attributes[node.Attribute]; ok {
			fmt.Println("node attribute:", node.Attribute)
			fmt.Println("node poly:", node.Poly)
			cx := cy[node.LeafId]
			di := dj[node.Attribute]
			cxPrime := cyPrime[node.LeafId]
			diPrime := djPrime[node.Attribute]
			fmt.Println(cx, cxPrime, di, diPrime)
			eDiCx, err := bn254.Pair([]bn254.G1Affine{cx}, []bn254.G2Affine{di})
			if err != nil {
				panic(err)
			}
			eDiPrimeCxPrime, err := bn254.Pair([]bn254.G1Affine{cxPrime}, []bn254.G2Affine{diPrime})
			if err != nil {
				panic(err)
			}
			result := new(bn254.GT).Div(&eDiCx, &eDiPrimeCxPrime)

			qx0 := utils.ComputePolynomialValue(node.Poly, fr.NewElement(0))
			qx0MulR := new(fr.Element).Mul(&qx0, &r)
			_, _, g1, g2 := bn254.Generators()
			eG1G2, err := bn254.Pair([]bn254.G1Affine{g1}, []bn254.G2Affine{g2})
			if err != nil {
				panic(err)
			}
			eG1G2ExpQ0MulR := new(bn254.GT).Exp(eG1G2, qx0MulR.BigInt(new(big.Int)))

			fmt.Println("eG1G2ExpQ0MulR: ", *eG1G2ExpQ0MulR)
			fmt.Println("compute result: ", *result)
			fmt.Println()
			return result
		}
		return nil
	}

	indexToChild := make(map[int]*AccessTreeNode)
	indexToSecret := make(map[int]bn254.GT)

	for i, c := range node.children {
		childSecret := c.DecryptNode(attributes, dj, djPrime, cy, cyPrime, r)
		// 修复：只有当子节点解密成功（不等于零元素）时才添加
		if childSecret != nil {
			indexToChild[i+1] = c
			indexToSecret[i+1] = *childSecret
			if len(indexToChild) == node.threshold {
				break
			}
		}
	}

	if len(indexToChild) == node.threshold {
		result := new(bn254.GT).SetOne()
		var s []fr.Element
		for index := range indexToChild {
			s = append(s, fr.NewElement(uint64(index)))
		}
		for index := range indexToChild {
			delta := utils.ComputeLagrangeBasis(fr.NewElement(uint64(index)), s, fr.NewElement(0))
			fz := new(bn254.GT).Exp(indexToSecret[index], delta.BigInt(new(big.Int)))
			result = new(bn254.GT).Mul(result, fz)
		}
		fmt.Println("e(g,g)^rs result:", *result)
		return result
	}

	return nil
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
