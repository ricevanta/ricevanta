package tiny

import (
	"fmt"
	"testing"
)

func TestAlpha(t *testing.T)   { t.Run("sub", func(t *testing.T) {}) }
func TestBeta(t *testing.T)    { t.Log("beta runs") }
func TestSkipped(t *testing.T) { t.Skip("helper only") }
func BenchmarkThing(b *testing.B) {
	for _, size := range []int{16, 4096} {
		b.Run(fmt.Sprintf("size-%d", size), func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				_ = make([]byte, size)
			}
		})
	}
}
func FuzzThing(f *testing.F) {
	f.Add([]byte("a"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = len(b) })
}
func ExampleHello() {
	fmt.Println(Hello())
	// Output: hi
}
