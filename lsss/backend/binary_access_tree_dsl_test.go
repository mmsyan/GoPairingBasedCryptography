package backend

import (
	"github.com/mmsyan/GnarkPairingProject/lsss"
	"testing"

	"github.com/mmsyan/GnarkPairingProject/hash"
)

// TestLeaf 测试叶子节点创建
func TestLeaf(t *testing.T) {
	node := Leaf("Attribute::A")

	if node.Type != lsss.NodeTypeLeave {
		t.Errorf("Leaf() Type = %v, want %v", node.Type, lsss.NodeTypeLeave)
	}

	expectedValue := hash.ToField("Attribute::A")
	if node.Value != expectedValue {
		t.Errorf("Leaf() Value mismatch")
	}

	if node.Left != nil || node.Right != nil {
		t.Errorf("Leaf() should have no children")
	}
}

// TestOr_TwoNodes 测试两节点 OR
func TestOr_TwoNodes(t *testing.T) {
	tree := Or(Leaf("A"), Leaf("B"))

	if tree.Type != lsss.NodeTypeOr {
		t.Errorf("Or() Type = %v, want %v", tree.Type, lsss.NodeTypeOr)
	}

	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeLeave {
		t.Error("Or() left child should be a leaf")
	}

	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeLeave {
		t.Error("Or() right child should be a leaf")
	}
}

// TestAnd_TwoNodes 测试两节点 AND
func TestAnd_TwoNodes(t *testing.T) {
	tree := And(Leaf("A"), Leaf("B"))

	if tree.Type != lsss.NodeTypeAnd {
		t.Errorf("And() Type = %v, want %v", tree.Type, lsss.NodeTypeAnd)
	}

	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeLeave {
		t.Error("And() left child should be a leaf")
	}

	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeLeave {
		t.Error("And() right child should be a leaf")
	}
}

// TestOr_MultipleNodes 测试多节点 OR（左结合）
func TestOr_MultipleNodes(t *testing.T) {
	// ((A or B) or C)
	tree := Or(Leaf("A"), Leaf("B"), Leaf("C"))

	if tree.Type != lsss.NodeTypeOr {
		t.Errorf("Or() Type = %v, want %v", tree.Type, lsss.NodeTypeOr)
	}

	// 根节点的右子节点应该是 C
	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeLeave {
		t.Error("Or() right child should be C")
	}

	// 根节点的左子节点应该是 (A or B)
	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeOr {
		t.Error("Or() left child should be (A or B)")
	}

	// (A or B) 的子节点应该都是叶子
	if tree.Left.Left == nil || tree.Left.Left.Type != lsss.NodeTypeLeave {
		t.Error("Or() nested left should be A")
	}
	if tree.Left.Right == nil || tree.Left.Right.Type != lsss.NodeTypeLeave {
		t.Error("Or() nested right should be B")
	}
}

// TestAnd_MultipleNodes 测试多节点 AND（左结合）
func TestAnd_MultipleNodes(t *testing.T) {
	// ((A and B) and C)
	tree := And(Leaf("A"), Leaf("B"), Leaf("C"))

	if tree.Type != lsss.NodeTypeAnd {
		t.Errorf("And() Type = %v, want %v", tree.Type, lsss.NodeTypeAnd)
	}

	// 检查是左结合
	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeAnd {
		t.Error("And() should be left-associative")
	}
}

// TestOrRight 测试右结合 OR
func TestOrRight(t *testing.T) {
	// (A or (B or C))
	tree := OrRight(Leaf("A"), Leaf("B"), Leaf("C"))

	if tree.Type != lsss.NodeTypeOr {
		t.Errorf("OrRight() Type = %v, want %v", tree.Type, lsss.NodeTypeOr)
	}

	// 根节点的左子节点应该是 A
	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeLeave {
		t.Error("OrRight() left child should be A")
	}

	// 根节点的右子节点应该是 (B or C)
	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeOr {
		t.Error("OrRight() right child should be (B or C)")
	}
}

// TestAndRight 测试右结合 AND
func TestAndRight(t *testing.T) {
	// (A and (B and C))
	tree := AndRight(Leaf("A"), Leaf("B"), Leaf("C"))

	if tree.Type != lsss.NodeTypeAnd {
		t.Errorf("AndRight() Type = %v, want %v", tree.Type, lsss.NodeTypeAnd)
	}

	// 检查是右结合
	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeAnd {
		t.Error("AndRight() should be right-associative")
	}
}

// TestNestedExpressions 测试嵌套表达式
func TestNestedExpressions(t *testing.T) {
	// ((A or B) and C)
	tree := And(
		Or(Leaf("A"), Leaf("B")),
		Leaf("C"),
	)

	if tree.Type != lsss.NodeTypeAnd {
		t.Error("Root should be AND")
	}

	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeOr {
		t.Error("Left child should be OR")
	}

	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeLeave {
		t.Error("Right child should be leaf C")
	}
}

// TestComplexExpression 测试复杂表达式
func TestComplexExpression(t *testing.T) {
	// ((A and B) or (C and D))
	tree := Or(
		And(Leaf("A"), Leaf("B")),
		And(Leaf("C"), Leaf("D")),
	)

	if tree.Type != lsss.NodeTypeOr {
		t.Error("Root should be OR")
	}

	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeAnd {
		t.Error("Left child should be AND")
	}

	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeAnd {
		t.Error("Right child should be AND")
	}
}

// TestAttrs 测试批量创建属性节点
func TestAttrs(t *testing.T) {
	nodes := Attrs("A", "B", "C")

	if len(nodes) != 3 {
		t.Errorf("Attrs() returned %d nodes, want 3", len(nodes))
	}

	for i, node := range nodes {
		if node.Type != lsss.NodeTypeLeave {
			t.Errorf("Attrs()[%d] Type = %v, want %v", i, node.Type, lsss.NodeTypeLeave)
		}
	}
}

// TestAttrsWithOr 测试 Attrs 与 Or 配合使用
func TestAttrsWithOr(t *testing.T) {
	// ((A or B) or C)
	tree := Or(Attrs("A", "B", "C")...)

	if tree.Type != lsss.NodeTypeOr {
		t.Error("Root should be OR")
	}
}

//// TestShortAliases 测试短别名
//func TestShortAliases(t *testing.T) {
//	// 使用短别名构建：(A or B)
//	tree := O(L("A"), L("B"))
//
//	if tree.Type != lsss.NodeTypeOr {
//		t.Error("O() should create OR node")
//	}
//
//	// 使用 A 别名：(A and B)
//	tree2 := A(L("A"), L("B"))
//
//	if tree2.Type != lsss.NodeTypeAnd {
//		t.Error("A() should create AND node")
//	}
//}
//
//// TestBuilderVsManual 比较构建器和手动构建
//func TestBuilderVsManual(t *testing.T) {
//	// 手动构建
//	manual := lsss.NewBinaryAccessTree(lsss.NodeTypeOr, fr.Element{},
//		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, hash.ToField("A"), nil, nil),
//		lsss.NewBinaryAccessTree(lsss.NodeTypeLeave, hash.ToField("B"), nil, nil))
//
//	// 使用构建器
//	builder := Or(Leaf("A"), Leaf("B"))
//
//	// 比较结构
//	if !compareTreeStructure(manual, builder) {
//		t.Error("Builder and manual construction should produce identical trees")
//	}
//}

//// TestBuilderExamples 使用构建器重建所有示例
//func TestBuilderExamples(t *testing.T) {
//	tests := []struct {
//		name    string
//		builder func() *lsss.BinaryAccessTree
//		example func() (*lsss.BinaryAccessTree, string)
//	}{
//		{
//			name:    "Example 1: (A or B)",
//			builder: func() *lsss.BinaryAccessTree { return Or(Leaf("A"), Leaf("B")) },
//			example: GetExample1,
//		},
//		{
//			name:    "Example 2: (A and B)",
//			builder: func() *lsss.BinaryAccessTree { return And(Leaf("A"), Leaf("B")) },
//			example: GetExample2,
//		},
//		{
//			name:    "Example 8: ((A or B) and C)",
//			builder: func() *lsss.BinaryAccessTree { return And(Or(Leaf("A"), Leaf("B")), Leaf("C")) },
//			example: GetExample8,
//		},
//		{
//			name: "Example 12: ((A and B) or (C and D))",
//			builder: func() *lsss.BinaryAccessTree {
//				return Or(
//					And(Leaf("A"), Leaf("B")),
//					And(Leaf("C"), Leaf("D")),
//				)
//			},
//			example: GetExample12,
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			builderTree := tt.builder()
//			exampleTree, _ := tt.example()
//
//			if !compareTreeStructure(builderTree, exampleTree) {
//				t.Errorf("Builder tree doesn't match example tree")
//			}
//		})
//	}
//}
//
//// TestBuilderCompactSyntax 展示紧凑语法
//func TestBuilderCompactSyntax(t *testing.T) {
//	// 使用短别名的紧凑语法
//	tree := O(
//		A(L("A"), L("B")),
//		A(L("C"), L("D")),
//	)
//
//	if tree.Type != lsss.NodeTypeOr {
//		t.Error("Compact syntax should work correctly")
//	}
//}

// TestBuilderReadability 可读性示例
func TestBuilderReadability(t *testing.T) {
	// 示例：复杂的访问控制策略
	// (Admin or (Manager and Department_Head)) and Active_User

	tree := And(
		Or(
			Leaf("Admin"),
			And(
				Leaf("Manager"),
				Leaf("Department_Head"),
			),
		),
		Leaf("Active_User"),
	)

	if tree.Type != lsss.NodeTypeAnd {
		t.Error("Root should be AND")
	}

	// 验证结构
	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeOr {
		t.Error("Left should be OR node")
	}
}

// ExampleOr 示例：创建 OR 表达式
func ExampleOr() {
	tree := Or(Leaf("A"), Leaf("B"))
	_ = tree // (A or B)
}

// ExampleAnd 示例：创建 AND 表达式
func ExampleAnd() {
	tree := And(Leaf("A"), Leaf("B"))
	_ = tree // (A and B)
}

//// ExampleNestedExpression 示例：嵌套表达式
//func ExampleNestedExpression() {
//	tree := And(
//		Or(Leaf("A"), Leaf("B")),
//		Leaf("C"),
//	)
//	_ = tree // ((A or B) and C)
//}

//// ExampleCompactSyntax 示例：紧凑语法
//func ExampleCompactSyntax() {
//	tree := O(
//		A(L("A"), L("B")),
//		A(L("C"), L("D")),
//	)
//	_ = tree // ((A and B) or (C and D))
//}

// ExampleAttrs 示例：批量创建属性
func ExampleAttrs() {
	tree := Or(Attrs("A", "B", "C")...)
	_ = tree // ((A or B) or C)
}

// BenchmarkBuilder_Simple 简单表达式性能测试
func BenchmarkBuilder_Simple(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Or(Leaf("A"), Leaf("B"))
	}
}

// BenchmarkBuilder_Complex 复杂表达式性能测试
func BenchmarkBuilder_Complex(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_ = Or(
			And(Leaf("A"), Leaf("B")),
			And(Leaf("C"), Leaf("D")),
		)
	}
}
