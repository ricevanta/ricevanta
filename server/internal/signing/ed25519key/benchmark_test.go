package ed25519key

import "testing"

// BenchmarkValidate reports admission cost without imposing a consumer budget.
func BenchmarkValidate(b *testing.B) {
	cases := map[string]string{"accepted": "base-1", "off-curve": "off-curve-y-2-sign-0", "small-order": "torsion-0", "mixed-order": "mixed-base-1-torsion-1"}
	vectors := loadVectors(b)
	for name, vectorName := range cases {
		var key []byte
		var want error
		for _, v := range vectors {
			if v.Name == vectorName {
				key = strictHex(b, v.Public)
				want = outcomes()[v.Expected]
			}
		}
		if key == nil {
			b.Fatal("missing benchmark vector")
		}
		b.Run(name, func(b *testing.B) {
			checkOutcome(b, Validate(key), want)
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := Validate(key); err != want {
					b.Fatal(err)
				}
			}
		})
	}
}
