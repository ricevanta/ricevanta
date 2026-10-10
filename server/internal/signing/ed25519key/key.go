// Package ed25519key admits canonical nonidentity prime-subgroup public keys.
package ed25519key

import (
	"errors"
	"math/big"
)

var (
	ErrLength       = errors.New("ed25519 public key length")
	ErrNonCanonical = errors.New("ed25519 public key encoding is not canonical")
	ErrPoint        = errors.New("ed25519 public key does not encode a point")
	ErrSmallOrder   = errors.New("ed25519 public key has small order")
	ErrMixedOrder   = errors.New("ed25519 public key has mixed order")
)

// Validate checks raw Ed25519 public-key admission, not authority or possession.
// Callers must not mutate publicKey during validation.
func Validate(publicKey []byte) error {
	if len(publicKey) != 32 {
		return ErrLength
	}
	var encoded [32]byte
	copy(encoded[:], publicKey)
	sign := uint(encoded[31] >> 7)
	encoded[31] &= 127
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		encoded[i], encoded[j] = encoded[j], encoded[i]
	}
	y := new(big.Int).SetBytes(encoded[:])
	f := newField()
	if y.Cmp(f.p) >= 0 {
		return ErrNonCanonical
	}
	yy := f.mul(y, y)
	denominator := f.add(f.mul(f.d, yy), big.NewInt(1))
	inverse := new(big.Int).ModInverse(denominator, f.p)
	if inverse == nil {
		return ErrPoint
	}
	square := f.mul(f.sub(yy, big.NewInt(1)), inverse)
	x := new(big.Int).ModSqrt(square, f.p)
	if x == nil || f.mul(x, x).Cmp(square) != 0 {
		return ErrPoint
	}
	if x.Sign() == 0 && sign != 0 {
		return ErrNonCanonical
	}
	if x.Bit(0) != sign {
		x = f.sub(big.NewInt(0), x)
	}
	a := point{x: x, y: y, z: big.NewInt(1), t: f.mul(x, y)}
	eight := a
	for i := 0; i < 3; i++ {
		eight = f.plus(eight, eight)
		if !f.valid(eight) {
			return ErrPoint
		}
	}
	if f.identity(eight) {
		return ErrSmallOrder
	}
	l := new(big.Int).Lsh(big.NewInt(1), 252)
	tail, _ := new(big.Int).SetString("27742317777372353535851937790883648493", 10)
	l.Add(l, tail)
	multiple, ok := f.multiply(a, l)
	if !ok {
		return ErrPoint
	}
	if !f.identity(multiple) {
		return ErrMixedOrder
	}
	return nil
}
