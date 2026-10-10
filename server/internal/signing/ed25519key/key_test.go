package ed25519key

import (
	"bytes"
	"errors"
	"math/big"
	"sync"
	"testing"
)

func outcomes() map[string]error {
	return map[string]error{"ErrLength": ErrLength, "ErrNonCanonical": ErrNonCanonical, "ErrPoint": ErrPoint, "ErrSmallOrder": ErrSmallOrder, "ErrMixedOrder": ErrMixedOrder}
}
func checkOutcome(t testing.TB, got, want error) {
	t.Helper()
	if want == nil && got != nil {
		t.Fatalf("want accept, got %v", got)
	}
	for name, s := range outcomes() {
		if errors.Is(got, s) != (want == s) {
			t.Fatalf("%s: got %v, want %v", name, got, want)
		}
	}
}
func TestValidatePrecedence(t *testing.T) {
	o := newOracle()
	b, tr := o.basis(t)
	for _, v := range []struct {
		key  []byte
		want error
	}{
		{append(rawY(o.p, 1), 0), ErrLength}, {rawY(new(big.Int).Add(o.p, big.NewInt(2)), 0), ErrNonCanonical},
		{rawY(big.NewInt(1), 1), ErrNonCanonical}, {rawY(big.NewInt(1), 0), ErrSmallOrder},
		{o.encode(o.add(b, tr)), ErrMixedOrder}} {
		checkOutcome(t, Validate(v.key), v.want)
	}
}
func TestValidateBoundaries(t *testing.T) {
	for _, n := range []int{0, 1, 30, 31, 34, 1 << 20} {
		checkOutcome(t, Validate(make([]byte, n)), ErrLength)
	}
	checkOutcome(t, Validate(nil), ErrLength)
	checkOutcome(t, Validate(make([]byte, 32)), ErrSmallOrder)
	o := newOracle()
	for _, offset := range []int64{-1, 0, 1, 18} {
		for s := uint(0); s < 2; s++ {
			want := ErrNonCanonical
			if offset == -1 && s == 0 {
				want = ErrSmallOrder
			}
			checkOutcome(t, Validate(rawY(new(big.Int).Add(o.p, big.NewInt(offset)), s)), want)
		}
	}
}
func TestValidateInputOwnership(t *testing.T) {
	for _, v := range loadVectors(t) {
		key := strictHex(t, v.Public)
		saved := bytes.Clone(key)
		for i := 0; i < 3; i++ {
			checkOutcome(t, Validate(key), outcomes()[v.Expected])
			if v.Expected == "accept" {
				checkOracleAdmission(t, key)
			}
			if !bytes.Equal(key, saved) {
				t.Fatal("input changed")
			}
		}
	}
}
func TestValidateConcurrent(t *testing.T) {
	vectors := loadVectors(t)
	var wg sync.WaitGroup
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for _, v := range vectors {
				key := strictHex(t, v.Public)
				saved := bytes.Clone(key)
				checkOutcome(t, Validate(key), outcomes()[v.Expected])
				if v.Expected == "accept" {
					checkOracleAdmission(t, key)
				}
				if !bytes.Equal(key, saved) {
					t.Error("input changed")
				}
			}
		}()
	}
	wg.Wait()
}
