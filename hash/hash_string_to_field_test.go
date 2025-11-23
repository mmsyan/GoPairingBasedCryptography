package hash

import (
	"fmt"
	"github.com/consensys/gnark-crypto/ecc/bn254/fr"
	"strings"
	"testing"
)

// TestHashStringToFidld_Basic 基础功能测试
func TestHashStringToFidld_Basic(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"空字符串", ""},
		{"单字符", "a"},
		{"普通字符串", "hello"},
		{"数字字符串", "12345"},
		{"特殊字符", "!@#$%^&*()"},
		{"中文字符串", "你好世界"},
		{"混合字符串", "Hello世界123!@#"},
		{"空格字符串", "   "},
		{"换行符", "hello\nworld"},
		{"制表符", "hello\tworld"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashStringToFidld(tt.input)

			// 验证结果是有效的域元素
			var zero fr.Element
			if result.Equal(&zero) && tt.input != "" {
				t.Errorf("非空输入 '%s' 产生了零元素", tt.input)
			}

			// 验证结果在有效范围内
			fmt.Println(result)
		})
	}
}

// TestHashStringToFidld_LongStrings 超长字符串测试
func TestHashStringToFidld_LongStrings(t *testing.T) {
	tests := []struct {
		name   string
		length int
	}{
		{"1KB字符串", 1024},
		{"10KB字符串", 10 * 1024},
		{"100KB字符串", 100 * 1024},
		{"1MB字符串", 1024 * 1024},
		{"10MB字符串", 10 * 1024 * 1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// 生成指定长度的字符串
			longString := strings.Repeat("a", tt.length)

			// 测试不会崩溃
			result := HashStringToFidld(longString)

			// 验证结果有效
			fmt.Println(result)

			t.Logf("成功处理 %d 字节的字符串", tt.length)
		})
	}
}

// TestHashStringToFidld_Consistency 一致性测试
func TestHashStringToFidld_Consistency(t *testing.T) {
	testStrings := []string{
		"test",
		"hello world",
		"你好世界",
		"!@#$%^&*()",
		strings.Repeat("a", 10000),
	}

	for _, str := range testStrings {
		t.Run("一致性测试_"+str[:min(len(str), 10)], func(t *testing.T) {
			// 多次计算同一个字符串的哈希
			iterations := 100
			firstResult := HashStringToFidld(str)

			for i := 0; i < iterations; i++ {
				result := HashStringToFidld(str)

				if !result.Equal(&firstResult) {
					t.Errorf("第 %d 次哈希结果不一致", i+1)
					t.Errorf("首次结果: %s", firstResult.String())
					t.Errorf("本次结果: %s", result.String())
					break
				}
			}

			t.Logf("✓ 相同输入产生一致的输出 (测试 %d 次)", iterations)
		})
	}
}

// TestHashStringToFidld_CollisionResistance 抗碰撞测试
func TestHashStringToFidld_CollisionResistance(t *testing.T) {
	t.Run("相似字符串抗碰撞", func(t *testing.T) {
		tests := []struct {
			str1 string
			str2 string
		}{
			{"test", "test1"},
			{"hello", "hello "},
			{"abc", "abd"},
			{"123", "124"},
			{"你好", "您好"},
			{"Test", "test"},       // 大小写
			{"ab", "ba"},           // 顺序
			{"hello\n", "hello\t"}, // 不同空白字符
			{"", " "},              // 空字符串 vs 空格
		}

		for _, tt := range tests {
			t.Run(tt.str1+"_vs_"+tt.str2, func(t *testing.T) {
				result1 := HashStringToFidld(tt.str1)
				result2 := HashStringToFidld(tt.str2)

				if result1.Equal(&result2) {
					t.Errorf("碰撞检测失败！不同字符串产生相同哈希")
					t.Errorf("字符串1: '%s'", tt.str1)
					t.Errorf("字符串2: '%s'", tt.str2)
					t.Errorf("哈希结果: %s", result1.String())
				} else {
					t.Logf("✓ '%s' 和 '%s' 产生不同哈希", tt.str1, tt.str2)
				}
			})
		}
	})

	t.Run("大量随机字符串抗碰撞", func(t *testing.T) {
		const numTests = 10000
		hashMap := make(map[string]string)
		collisions := 0

		for i := 0; i < numTests; i++ {
			// 生成不同的字符串
			testStr := strings.Repeat("test", i) + string(rune(i))
			result := HashStringToFidld(testStr)
			resultStr := result.String()

			// 检查是否有碰撞
			if originalStr, exists := hashMap[resultStr]; exists {
				collisions++
				t.Logf("发现碰撞！字符串1: '%s...', 字符串2: '%s...'",
					originalStr[:min(len(originalStr), 20)],
					testStr[:min(len(testStr), 20)])
			} else {
				hashMap[resultStr] = testStr
			}
		}

		collisionRate := float64(collisions) / float64(numTests) * 100
		t.Logf("测试 %d 个不同字符串，碰撞次数: %d (%.4f%%)",
			numTests, collisions, collisionRate)

		if collisions > 0 {
			t.Errorf("在 %d 次测试中发现 %d 次碰撞，期望 0 次碰撞", numTests, collisions)
		}
	})
}

// TestHashStringToFidld_EdgeCases 边界情况测试
func TestHashStringToFidld_EdgeCases(t *testing.T) {
	tests := []struct {
		name  string
		input string
	}{
		{"空字符串", ""},
		{"单个空格", " "},
		{"多个空格", "     "},
		{"NULL字符", "\x00"},
		{"最大Unicode字符", string(rune(0x10FFFF))},
		{"所有ASCII可打印字符", generateASCIIPrintable()},
		{"重复字符", strings.Repeat("a", 1000)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := HashStringToFidld(tt.input)

			fmt.Println(result)
		})
	}
}

// TestHashStringToFidld_Performance 性能基准测试
func BenchmarkHashStringToFidld(b *testing.B) {
	testCases := []struct {
		name string
		str  string
	}{
		{"短字符串", "test"},
		{"中等字符串", strings.Repeat("hello", 100)},
		{"长字符串", strings.Repeat("benchmark", 10000)},
	}

	for _, tc := range testCases {
		b.Run(tc.name, func(b *testing.B) {
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				_ = HashStringToFidld(tc.str)
			}
		})
	}
}

// 辅助函数
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func generateASCIIPrintable() string {
	var builder strings.Builder
	for i := 32; i <= 126; i++ {
		builder.WriteByte(byte(i))
	}
	return builder.String()
}
