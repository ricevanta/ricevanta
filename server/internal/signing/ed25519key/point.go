package ed25519key

import "math/big"

// Each field and point belongs to one validation call. Every operation returns
// a fresh receiver, so operands and field constants remain unchanged.
type field struct{ p, d *big.Int }
type point struct{ x, y, z, t *big.Int }

func newField() field {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	inverse := new(big.Int).ModInverse(big.NewInt(121666), p)
	return field{p: p, d: new(big.Int).Mod(new(big.Int).Mul(big.NewInt(-121665), inverse), p)}
}
func (f field) add(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Add(a, b), f.p) }
func (f field) sub(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Sub(a, b), f.p) }
func (f field) mul(a, b *big.Int) *big.Int { return new(big.Int).Mod(new(big.Int).Mul(a, b), f.p) }

// plus is the complete extended-coordinate addition formula for a=-1.
func (f field) plus(p, q point) point {
	a := f.mul(f.sub(p.y, p.x), f.sub(q.y, q.x))
	b := f.mul(f.add(p.y, p.x), f.add(q.y, q.x))
	c := f.mul(f.mul(big.NewInt(2), f.d), f.mul(p.t, q.t))
	d := f.mul(big.NewInt(2), f.mul(p.z, q.z))
	e := f.sub(b, a)
	ff := f.sub(d, c)
	g := f.add(d, c)
	h := f.add(b, a)
	return point{x: f.mul(e, ff), y: f.mul(g, h), z: f.mul(ff, g), t: f.mul(e, h)}
}
func (f field) valid(p point) bool { return new(big.Int).Mod(p.z, f.p).Sign() != 0 }
func (f field) identity(p point) bool {
	return f.valid(p) && new(big.Int).Mod(p.x, f.p).Sign() == 0 && f.sub(p.y, p.z).Sign() == 0
}
func (f field) multiply(a point, n *big.Int) (point, bool) {
	r := point{x: big.NewInt(0), y: big.NewInt(1), z: big.NewInt(1), t: big.NewInt(0)}
	// Multiply by the integer L, without scalar-field reduction.
	for i := n.BitLen() - 1; i >= 0; i-- {
		r = f.plus(r, r)
		if !f.valid(r) {
			return point{}, false
		}
		if n.Bit(i) != 0 {
			r = f.plus(r, a)
			if !f.valid(r) {
				return point{}, false
			}
		}
	}
	return r, true
}
