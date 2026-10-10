package ed25519key

import (
	"bytes"
	"errors"
	"testing"
)

func FuzzValidate(f *testing.F) {
	for _, v := range loadVectors(f) {
		f.Add(strictHex(f, v.Public))
	}
	f.Fuzz(func(t *testing.T, key []byte) {
		saved := bytes.Clone(key)
		err := Validate(key)
		again := Validate(key)
		if !bytes.Equal(saved, key) {
			t.Fatal("input changed")
		}
		if err != nil {
			matches := 0
			for _, s := range outcomes() {
				if errors.Is(err, s) {
					matches++
				}
				if errors.Is(err, s) != errors.Is(again, s) {
					t.Fatal("nondeterministic")
				}
			}
			if matches != 1 {
				t.Fatal("error class")
			}
			return
		}
		if again != nil || len(key) != 32 {
			t.Fatal("success boundary")
		}
		checkOracleAdmission(t, key)
	})
}
