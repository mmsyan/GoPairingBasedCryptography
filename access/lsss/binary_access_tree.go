package lsss

import (
	"fmt"
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

// Print 打印整棵访问控制树，可读性极高
func (t *BinaryAccessTree) Print() {
	if t == nil {
		fmt.Println("<nil tree>")
		return
	}
	t.printRecursive("", true, true) // 从根开始打印
}

// 可选：如果你只想打印属性字符串而不是 fr.Element 原始值，可以加个映射表
// var attrNameMap = map[string]string{ ... } // 可自行填充

func (t *BinaryAccessTree) printRecursive(prefix string, isLast bool, isRoot bool) {
	if t == nil {
		return
	}

	// 根节点不打印连接线
	if !isRoot {
		if isLast {
			fmt.Printf("%s└── ", prefix)
		} else {
			fmt.Printf("%s├── ", prefix)
		}
	}

	// 打印当前节点类型和内容
	switch t.Type {
	case NodeTypeAnd:
		fmt.Print("AND")
	case NodeTypeOr:
		fmt.Print("OR")
	case NodeTypeLeave:
		fmt.Print("LEAF")
		// 尝试友好显示属性（推荐你在这里加映射）
		attrStr := t.Attribute.String()
		// 十进制大整数
		// 如果你有属性名映射，可以这样：
		// if name, ok := attrNameMap[t.Attribute.String()]; ok {
		//     attrStr = name
		// }
		fmt.Printf("(%s)", attrStr)
	default:
		fmt.Print("UNKNOWN")
	}
	
	fmt.Println()

	// 准备子节点前缀
	childPrefix := prefix
	if !isRoot {
		if isLast {
			childPrefix += "    "
		} else {
			childPrefix += "│   "
		}
	}

	// 递归打印左右子树（先左后右，和逻辑顺序一致）
	children := make([]*BinaryAccessTree, 0, 2)
	if t.Left != nil {
		children = append(children, t.Left)
	}
	if t.Right != nil {
		children = append(children, t.Right)
	}

	for i, child := range children {
		isLastChild := i == len(children)-1
		child.printRecursive(childPrefix, isLastChild, false)
	}
}
