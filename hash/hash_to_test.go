package hash

import (
	"crypto/rand"
	"testing"
)

// 准备测试数据，避免在循环内生成随机数影响测试准确性
func prepareTestData(n int) []byte {
	data := make([]byte, n)
	_, _ = rand.Read(data)
	return data
}

// BenchmarkBytesToField 测试映射到标量域 Fr 的性能
func BenchmarkBytesToField(b *testing.B) {
	data := prepareTestData(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BytesToField(data)
	}
}

// BenchmarkBytesToG1 测试映射到 G1 群的性能
func BenchmarkBytesToG1(b *testing.B) {
	data := prepareTestData(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BytesToG1(data)
	}
}

// BenchmarkBytesToG2 测试映射到 G2 群的性能
func BenchmarkBytesToG2(b *testing.B) {
	data := prepareTestData(32)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BytesToG2(data)
	}
}
