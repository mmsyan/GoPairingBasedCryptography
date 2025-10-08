package kpabe

import (
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/mmsyan/GnarkPairingProject/utils"
	"math/big"
)

type KpabeTree struct {
	root *KpabeNode
}

func NewKpabeTree(root *KpabeNode) *KpabeTree {
	return &KpabeTree{
		root: root,
	}
}

func (t *KpabeTree) generatePolySecret(rootSecret big.Int) {
	t.root.poly[0] = &rootSecret
	generatePolySecretHelper(t.root)
}

func generatePolySecretHelper(node *KpabeNode) {
	if isKpabeLeaveNode(node) {
		return
	}
	node.poly = utils.GenerateRandomPolynomial(node.threshold, node.poly[0])
	for i := 0; i < len(node.children); i++ {
		childNode := node.children[i]
		childNode.poly[0] = utils.ComputePolynomialValue(node.poly, big.NewInt(int64(i+1)))
		generatePolySecretHelper(childNode)
	}
}

func decryptNode(messageAttributes []int, dx map[int]*bn254.G1Affine, ei map[int]*bn254.G2Affine) bn254.GT {

}

func decryptNodeCommonUniverseHelper(node *KpabeNode, messageAttributes []int, dx map[int]*bn254.G1Affine, ei map[int]*bn254.G2Affine) bn254.GT {

}
