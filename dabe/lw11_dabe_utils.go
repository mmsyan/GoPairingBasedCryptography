package dabe

import "github.com/consensys/gnark-crypto/ecc/bn254/fr"

// NewLW11DABEAttributes 创建一个新的属性集合
// 返回指针，方便链式调用和避免大结构体拷贝
func NewLW11DABEAttributes(attrs ...fr.Element) *LW11DABEAttributes {
	copied := make([]fr.Element, len(attrs))
	copy(copied, attrs)
	return &LW11DABEAttributes{
		attributes: copied,
	}
}

// Append 追加属性，返回新的结构体指针（不可变风格，推荐）
func (a *LW11DABEAttributes) Append(extra ...fr.Element) *LW11DABEAttributes {
	if a == nil {
		// 防御性编程：支持 nil 调用，等价于 NewLW11DABEAttributes(extra...)
		copied := make([]fr.Element, len(extra))
		copy(copied, extra)
		return &LW11DABEAttributes{attributes: copied}
	}

	newLen := len(a.attributes) + len(extra)
	newAttrs := make([]fr.Element, newLen)
	copy(newAttrs, a.attributes)
	copy(newAttrs[len(a.attributes):], extra)

	return &LW11DABEAttributes{
		attributes: newAttrs,
	}
}
