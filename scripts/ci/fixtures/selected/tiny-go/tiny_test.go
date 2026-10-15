package tiny

import "testing"

func TestAlpha(t *testing.T) { t.Run("sub", func(t *testing.T) {}) }
func TestBeta(t *testing.T)  { t.Log("beta runs") }
func TestSkipped(t *testing.T) { t.Skip("helper only") }
func BenchmarkThing(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		_ = make([]byte, 16)
	}
}
func FuzzThing(f *testing.F) {
	f.Add([]byte("a"))
	f.Fuzz(func(t *testing.T, b []byte) { _ = len(b) })
}
