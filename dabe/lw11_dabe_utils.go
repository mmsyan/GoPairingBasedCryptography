package dabe

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"github.com/mmsyan/GnarkPairingProject/hash"
)

// NewLW11DABEAttributes 从 fr.Element 值创建新的属性集合。
//
// 参数：
//   - attrs: 可变数量的 fr.Element 值，用于初始化属性集合。
//
// 返回值：
//   - *LW11DABEAttributes: 指向新创建的属性集合的指针。
//     该函数会创建输入切片的深拷贝，以防止外部修改。
//
// 示例：
//
//	var attr1, attr2, attr3 fr.Element
//	attr1 = hash.ToField("1")
//	attr1 = hash.ToField("2")
//	attr1 = hash.ToField("3")
//
//	// 创建属性集合
//	attrs := NewLW11DABEAttributes(attr1, attr2, attr3)
//
//	// 或创建空集合
//	emptyAttrs := NewLW11DABEAttributes()
func NewLW11DABEAttributes(attrs ...fr.Element) *LW11DABEAttributes {
	copied := make([]fr.Element, len(attrs))
	copy(copied, attrs)
	return &LW11DABEAttributes{
		attributes: copied,
	}
}

// NewLW11DABEAttributesFromStrings 从字符串值创建新的属性集合。
//
// 每个字符串通过 hash.ToField 方法转换为 fr.Element，该方法对字符串应用
// SHA-256 哈希，并将结果转换为有限域元素。
//
// 参数：
//   - attrs: 可变数量的字符串值，将被转换并存储为属性。
//
// 返回值：
//   - *LW11DABEAttributes: 指向新创建的属性集合的指针。
//
// 示例：
//
//	// 从字符串创建属性
//	attrs := NewLW11DABEAttributesFromStrings("role:admin", "department:IT", "level:5")
//
//	// 为访问控制创建属性
//	accessAttrs := NewLW11DABEAttributesFromStrings(
//	    "country:USA",
//	    "clearance:top-secret",
//	    "project:quantum",
//	)
func NewLW11DABEAttributesFromStrings(attrs ...string) *LW11DABEAttributes {
	copied := make([]fr.Element, len(attrs))
	for i, attr := range attrs {
		copied[i] = hash.ToField(attr)
	}
	return &LW11DABEAttributes{
		attributes: copied,
	}
}

// Append 追加额外的属性并返回新的 LW11DABEAttributes 实例。
//
// 此方法遵循不可变设计模式，创建新集合而不是修改现有集合。原始集合保持不变。
//
// 参数：
//   - extra: 可变数量的 fr.Element 值，将追加到当前属性中。
//
// 返回值：
//   - *LW11DABEAttributes: 指向新属性集合的指针，包含原始属性和新添加的属性。
//
// 注意事项：
//   - 如果在 nil 接收者上调用，其行为等同于 NewLW11DABEAttributes(extra...)。
//   - 原始属性集合不会被修改（不可变操作）。
//
// 示例：
//
//	// 创建初始属性
//	attrs := NewLW11DABEAttributesFromStrings("role:user", "department:HR")
//
//	// 追加更多属性（创建新实例）
//	var newAttr fr.Element
//	newAttr.SetString("12345")
//	extendedAttrs := attrs.Append(newAttr)
//
//	// 链式追加多个属性
//	var attr1, attr2 fr.Element
//	attr1.SetUint64(100)
//	attr2.SetUint64(200)
//	finalAttrs := attrs.Append(attr1).Append(attr2)
//
//	// nil 安全用法
//	var nilAttrs *LW11DABEAttributes
//	safeAttrs := nilAttrs.Append(attr1, attr2) // 不会 panic
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

func NewRandomLW11DABEMessage() (*LW11DABEMessage, error) {
	element, err := new(bn254.GT).SetRandom()
	if err != nil {
		return nil, fmt.Errorf("unable to generate random lw11 dabe message, %v", err)
	}
	return &LW11DABEMessage{
		Message: *element,
	}, nil
}

func (message *LW11DABEMessage) ToBytes() ([]byte, error) {
	result := message.Message.Bytes()
	return result[:], nil
}

//// NewLW11DABEMessage 使用一个[]byte构造 LW11DABEMessage。
////
//// 输入的 key 的长度必须严格为 384 字节。该函数会将这 384 字节直接解释为 bn254.GT 群元素的
//// 规范压缩表示）。若长度不正确或字节串不是合法的规范编码，则返回错误。
////
//// 参数：
////   - key: 长度必须为 384 字节的数组
////
//// 返回值：
////   - *LW11DABEMessage: 成功时返回封装了该 GT 元素的 DABE 消息
////   - error: 成功时为 nil；密钥长度错误或编码非法时返回具体错误
//func NewLW11DABEMessage(key []byte) (*LW11DABEMessage, error) {
//	if len(key) != 384 {
//		return nil, errors.New("message must be exactly 384 bytes")
//	}
//	var element bn254.GT
//	err := element.SetBytes(key) // 严格检查：必须 < r，且是规范 32 字节表示
//	if err != nil {
//		return nil, err
//	}
//	return &LW11DABEMessage{
//		MessageBytes: element,
//	}, nil
//}
//
//// ExtractLW11DABEMessage 从 LW11DABEMessage 中提取 384 字节 AES-256 对称密钥。
////
//// 返回的字节串是 bn254.GT.Marshal() 生成的规范 384 字节表示，
//// 如果解密成功，提取的结果应该与当初调用 NewLW11DABEFromAESKey 传入的密钥完全一致。
////
//// 参数：
////   - msg: 待提取密钥的消息对象，不能为 nil
////
//// 返回值：
////   - []byte: 长度为 384 字节的原始 AES-256 密钥
////   - error: 成功时为 nil；msg 为 nil 或内部实现异常时返回错误
//func ExtractLW11DABEMessage(message *LW11DABEMessage) ([]byte, error) {
//	key := message.MessageBytes.Marshal()
//	if len(key) != 384 {
//		return nil, errors.New("AES-256 key must be exactly 32 bytes")
//	}
//	return key, nil
//}
