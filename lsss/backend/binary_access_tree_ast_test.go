package backend

//
//import (
//	"github.com/mmsyan/GnarkPairingProject/lsss"
//	"testing"
//
//	"github.com/mmsyan/GnarkPairingProject/hash"
//)
//
//// TestParseBooleanFormula_SimpleExpressions 测试简单表达式
//func TestParseBooleanFormula_SimpleExpressions(t *testing.T) {
//	tests := []struct {
//		name     string
//		formula  string
//		wantType lsss.NodeType
//	}{
//		{
//			name:     "Simple OR",
//			formula:  "A or B",
//			wantType: lsss.NodeTypeOr,
//		},
//		{
//			name:     "Simple AND",
//			formula:  "A and B",
//			wantType: lsss.NodeTypeAnd,
//		},
//		{
//			name:     "Single attribute",
//			formula:  "A",
//			wantType: lsss.NodeTypeLeave,
//		},
//		{
//			name:     "OR with parentheses",
//			formula:  "(A or B)",
//			wantType: lsss.NodeTypeOr,
//		},
//		{
//			name:     "AND with parentheses",
//			formula:  "(A and B)",
//			wantType: lsss.NodeTypeAnd,
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tree, err := ParseBooleanFormula(tt.formula)
//			if err != nil {
//				t.Fatalf("ParseBooleanFormula() error = %v", err)
//			}
//			if tree.Type != tt.wantType {
//				t.Errorf("ParseBooleanFormula() Type = %v, want %v", tree.Type, tt.wantType)
//			}
//		})
//	}
//}
//
//// TestParseBooleanFormula_OperatorPrecedence 测试运算符优先级
//func TestParseBooleanFormula_OperatorPrecedence(t *testing.T) {
//	tests := []struct {
//		name         string
//		formula      string
//		wantRootType lsss.NodeType
//		wantLeftType lsss.NodeType
//	}{
//		{
//			name:         "AND has higher precedence than OR",
//			formula:      "A or B and C",
//			wantRootType: lsss.NodeTypeOr,
//			wantLeftType: lsss.NodeTypeLeave, // A should be left child
//		},
//		{
//			name:         "Parentheses override precedence",
//			formula:      "(A or B) and C",
//			wantRootType: lsss.NodeTypeAnd,
//			wantLeftType: lsss.NodeTypeOr,
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tree, err := ParseBooleanFormula(tt.formula)
//			if err != nil {
//				t.Fatalf("ParseBooleanFormula() error = %v", err)
//			}
//			if tree.Type != tt.wantRootType {
//				t.Errorf("Root Type = %v, want %v", tree.Type, tt.wantRootType)
//			}
//			if tree.Left != nil && tree.Left.Type != tt.wantLeftType {
//				t.Errorf("Left Type = %v, want %v", tree.Left.Type, tt.wantLeftType)
//			}
//		})
//	}
//}
//
//// TestParseBooleanFormula_ComplexExpressions 测试复杂表达式
//func TestParseBooleanFormula_ComplexExpressions(t *testing.T) {
//	tests := []struct {
//		name    string
//		formula string
//	}{
//		{
//			name:    "Nested OR",
//			formula: "((A or B) or C)",
//		},
//		{
//			name:    "Nested AND",
//			formula: "((A and B) and C)",
//		},
//		{
//			name:    "Mixed operators",
//			formula: "(A or B) and (C or D)",
//		},
//		{
//			name:    "Deep nesting",
//			formula: "(((A and B) or (C and D)) or ((A or B) and (C or D)))",
//		},
//		{
//			name:    "Complex formula from examples",
//			formula: "(E and (((A and B) or (C and D)) or ((A or B) and (C or D))))",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tree, err := ParseBooleanFormula(tt.formula)
//			if err != nil {
//				t.Fatalf("ParseBooleanFormula() error = %v", err)
//			}
//			if tree == nil {
//				t.Fatal("ParseBooleanFormula() returned nil tree")
//			}
//		})
//	}
//}
//
//// TestParseBooleanFormula_AttributeValues 测试属性值是否正确设置
//func TestParseBooleanFormula_AttributeValues(t *testing.T) {
//	formula := "A or B"
//	tree, err := ParseBooleanFormula(formula)
//	if err != nil {
//		t.Fatalf("ParseBooleanFormula() error = %v", err)
//	}
//
//	// 检查左子节点（A）
//	if tree.Left == nil || tree.Left.Type != lsss.NodeTypeLeave {
//		t.Fatal("Left child should be a leaf node")
//	}
//	expectedA := hash.ToField("A")
//	if tree.Left.Value != expectedA {
//		t.Errorf("Left child value mismatch")
//	}
//
//	// 检查右子节点（B）
//	if tree.Right == nil || tree.Right.Type != lsss.NodeTypeLeave {
//		t.Fatal("Right child should be a leaf node")
//	}
//	expectedB := hash.ToField("B")
//	if tree.Right.Value != expectedB {
//		t.Errorf("Right child value mismatch")
//	}
//}
//
//// TestParseBooleanFormula_CaseInsensitive 测试操作符大小写不敏感
//func TestParseBooleanFormula_CaseInsensitive(t *testing.T) {
//	tests := []struct {
//		name    string
//		formula string
//	}{
//		{
//			name:    "Lowercase operators",
//			formula: "a or b and c",
//		},
//		{
//			name:    "Uppercase operators",
//			formula: "A OR B AND C",
//		},
//		{
//			name:    "Mixed case operators",
//			formula: "A Or B AnD C",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tree, err := ParseBooleanFormula(tt.formula)
//			if err != nil {
//				t.Fatalf("ParseBooleanFormula() error = %v", err)
//			}
//			if tree == nil {
//				t.Fatal("ParseBooleanFormula() returned nil tree")
//			}
//		})
//	}
//}
//
//// TestParseBooleanFormula_Whitespace 测试空白字符处理
//func TestParseBooleanFormula_Whitespace(t *testing.T) {
//	tests := []struct {
//		name    string
//		formula string
//	}{
//		{
//			name:    "No spaces",
//			formula: "(A or B)and C",
//		},
//		{
//			name:    "Extra spaces",
//			formula: "  ( A   or   B )  and  C  ",
//		},
//		{
//			name:    "Tabs and newlines",
//			formula: "A\tor\nB",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tree, err := ParseBooleanFormula(tt.formula)
//			if err != nil {
//				t.Fatalf("ParseBooleanFormula() error = %v", err)
//			}
//			if tree == nil {
//				t.Fatal("ParseBooleanFormula() returned nil tree")
//			}
//		})
//	}
//}
//
//// TestParseBooleanFormula_Errors 测试错误情况
//func TestParseBooleanFormula_Errors(t *testing.T) {
//	tests := []struct {
//		name    string
//		formula string
//	}{
//		{
//			name:    "Missing closing parenthesis",
//			formula: "(A or B",
//		},
//		{
//			name:    "Missing opening parenthesis",
//			formula: "A or B)",
//		},
//		{
//			name:    "Empty expression",
//			formula: "",
//		},
//		{
//			name:    "Only operator",
//			formula: "and",
//		},
//		{
//			name:    "Missing operand",
//			formula: "A or",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			_, err := ParseBooleanFormula(tt.formula)
//			if err == nil {
//				t.Errorf("ParseBooleanFormula() expected error for formula '%s', got nil", tt.formula)
//			}
//		})
//	}
//}
//
//// TestMustParseBooleanFormula_Panic 测试 MustParse 在错误时会 panic
//func TestMustParseBooleanFormula_Panic(t *testing.T) {
//	defer func() {
//		if r := recover(); r == nil {
//			t.Errorf("MustParseBooleanFormula() should panic on invalid formula")
//		}
//	}()
//
//	MustParseBooleanFormula("(A or B")
//}
//
//// TestMustParseBooleanFormula_Success 测试 MustParse 成功情况
//func TestMustParseBooleanFormula_Success(t *testing.T) {
//	tree := MustParseBooleanFormula("A or B")
//	if tree == nil {
//		t.Fatal("MustParseBooleanFormula() returned nil")
//	}
//	if tree.Type != lsss.NodeTypeOr {
//		t.Errorf("MustParseBooleanFormula() Type = %v, want %v", tree.Type, lsss.NodeTypeOr)
//	}
//}
//
//// TestParseBooleanFormula_CompareWithExamples 测试与预定义示例的兼容性
//func TestParseBooleanFormula_CompareWithExamples(t *testing.T) {
//	exampleTrees, formulas := GetExamples()
//
//	for i, formula := range formulas {
//		t.Run(formula, func(t *testing.T) {
//			parsed, err := ParseBooleanFormula(formula)
//			if err != nil {
//				t.Fatalf("ParseBooleanFormula() error = %v", err)
//			}
//
//			// 比较根节点类型
//			if parsed.Type != exampleTrees[i].Type {
//				t.Errorf("Root type mismatch: got %v, want %v", parsed.Type, exampleTrees[i].Type)
//			}
//
//			// 递归比较树结构
//			if !compareTreeStructure(parsed, exampleTrees[i]) {
//				t.Errorf("Tree structure mismatch for formula: %s", formula)
//			}
//		})
//	}
//}
//
//// compareTreeStructure 递归比较两棵树的结构是否相同
//func compareTreeStructure(t1, t2 *lsss.BinaryAccessTree) bool {
//	if t1 == nil && t2 == nil {
//		return true
//	}
//	if t1 == nil || t2 == nil {
//		return false
//	}
//	if t1.Type != t2.Type {
//		return false
//	}
//	if t1.Type == lsss.NodeTypeLeave {
//		return t1.Value == t2.Value
//	}
//	return compareTreeStructure(t1.Left, t2.Left) && compareTreeStructure(t1.Right, t2.Right)
//}
//
//// TestParseBooleanFormula_LongAttributeNames 测试长属性名
//func TestParseBooleanFormula_LongAttributeNames(t *testing.T) {
//	tests := []struct {
//		name    string
//		formula string
//	}{
//		{
//			name:    "Long attribute names",
//			formula: "UserRole or AdminPrivilege",
//		},
//		{
//			name:    "Attribute with numbers",
//			formula: "User123 and Role456",
//		},
//		{
//			name:    "Attribute with underscores",
//			formula: "User_Role or Admin_Privilege",
//		},
//	}
//
//	for _, tt := range tests {
//		t.Run(tt.name, func(t *testing.T) {
//			tree, err := ParseBooleanFormula(tt.formula)
//			if err != nil {
//				t.Fatalf("ParseBooleanFormula() error = %v", err)
//			}
//			if tree == nil {
//				t.Fatal("ParseBooleanFormula() returned nil tree")
//			}
//		})
//	}
//}
//
//// BenchmarkParseBooleanFormula_Simple 简单表达式性能测试
//func BenchmarkParseBooleanFormula_Simple(b *testing.B) {
//	formula := "A or B"
//	for i := 0; i < b.N; i++ {
//		_, _ = ParseBooleanFormula(formula)
//	}
//}
//
//// BenchmarkParseBooleanFormula_Complex 复杂表达式性能测试
//func BenchmarkParseBooleanFormula_Complex(b *testing.B) {
//	formula := "(((A and B) or (C and D)) or ((A or B) and (C or D)))"
//	for i := 0; i < b.N; i++ {
//		_, _ = ParseBooleanFormula(formula)
//	}
//}
