package backend

import (
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
	"github.com/mmsyan/GnarkPairingProject/lsss"
)

// Leaf 创建一个叶子节点（属性节点）
// 参数 attr 是属性名称，如 "A", "B", "UserRole" 等
func Leaf(attr string) *lsss.BinaryAccessTree {
	attrValue := hash.ToField(attr)
	return lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, attrValue, nil, nil)
}

// Or 创建一个 OR 节点
// 接受任意数量的子节点，会自动构建成左结合的二叉树
func Or(nodes ...*lsss.BinaryAccessTree) *lsss.BinaryAccessTree {
	if len(nodes) == 0 {
		panic("Or() requires at least one node")
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	// 左结合：((A or B) or C) or D
	result := lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{}, nodes[0], nodes[1])
	for i := 2; i < len(nodes); i++ {
		result = lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{}, result, nodes[i])
	}
	return result
}

// And 创建一个 AND 节点
// 接受任意数量的子节点，会自动构建成左结合的二叉树
func And(nodes ...*lsss.BinaryAccessTree) *lsss.BinaryAccessTree {
	if len(nodes) == 0 {
		panic("And() requires at least one node")
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	// 左结合：((A and B) and C) and D
	result := lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{}, nodes[0], nodes[1])
	for i := 2; i < len(nodes); i++ {
		result = lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{}, result, nodes[i])
	}
	return result
}

// OrRight 创建一个右结合的 OR 节点
// 用于构建 (A or (B or C)) 这样的结构
func OrRight(nodes ...*lsss.BinaryAccessTree) *lsss.BinaryAccessTree {
	if len(nodes) == 0 {
		panic("OrRight() requires at least one node")
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	// 右结合：A or (B or (C or D))
	result := nodes[len(nodes)-1]
	for i := len(nodes) - 2; i >= 0; i-- {
		result = lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{}, nodes[i], result)
	}
	return result
}

// AndRight 创建一个右结合的 AND 节点
// 用于构建 (A and (B and C)) 这样的结构
func AndRight(nodes ...*lsss.BinaryAccessTree) *lsss.BinaryAccessTree {
	if len(nodes) == 0 {
		panic("AndRight() requires at least one node")
	}
	if len(nodes) == 1 {
		return nodes[0]
	}

	// 右结合：A and (B and (C and D))
	result := nodes[len(nodes)-1]
	for i := len(nodes) - 2; i >= 0; i-- {
		result = lsss.NewBinaryAccessTree(lsss.NodeTypeAnd, fr.Element{}, nodes[i], result)
	}
	return result
}

// Attrs 快捷方式：创建多个叶子节点
// 方便批量创建属性节点
func Attrs(names ...string) []*lsss.BinaryAccessTree {
	nodes := make([]*lsss.BinaryAccessTree, len(names))
	for i, name := range names {
		nodes[i] = Leaf(name)
	}
	return nodes
}

// 预定义的别名，提供更短的函数名
var (
	// L 是 Leaf 的简写
	L = Leaf
	// A 是 And 的简写
	A = And
	// O 是 Or 的简写
	O = Or
	// AR 是 AndRight 的简写
	AR = AndRight
	// OR 是 OrRight 的简写
	OR = OrRight
)
