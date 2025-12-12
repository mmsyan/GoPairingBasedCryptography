package lsss

import (
	"fmt"
	"testing"
)

func TestNewBinaryAccessTree(t *testing.T) {
	trees, formulas := GetExamples()

	// 示例：打印所有布尔公式
	fmt.Println("Boolean Formulas:")
	for i, formula := range formulas {
		fmt.Printf("%d: %s\n", i, formula)
	}

	// 示例：使用 VectorPadTo
	trees[0].VectorPadZero(5)
	fmt.Printf("\nTree 0 vector after padding: %v\n", trees[0].Vector)
}

func TestBinaryAccessTree_Print(t *testing.T) {
	tree15, formulas := GetExample15()
	fmt.Println("Boolean Formulas:", formulas)
	tree15.Print()
}
