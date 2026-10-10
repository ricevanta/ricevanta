package ed25519key

import (
	"bytes"
	"math/big"
	"testing"
)

// The affine oracle uses Fermat inversion and the p=5 mod 8 root formula.
// It shares no point operations or constants with production arithmetic.
type affine struct{ x, y *big.Int }
type oracle struct{ p, d, l *big.Int }

func newOracle() oracle {
	p := new(big.Int).Sub(new(big.Int).Lsh(big.NewInt(1), 255), big.NewInt(19))
	o := oracle{p: p, l: new(big.Int).Add(new(big.Int).Lsh(big.NewInt(1), 252), decimal("27742317777372353535851937790883648493"))}
	o.d = o.mod(new(big.Int).Mul(big.NewInt(-121665), o.inv(big.NewInt(121666))))
	return o
}
func decimal(s string) *big.Int {
	n, ok := new(big.Int).SetString(s, 10)
	if !ok {
		panic("invalid test integer")
	}
	return n
}
func (o oracle) mod(n *big.Int) *big.Int { return new(big.Int).Mod(n, o.p) }
func (o oracle) inv(n *big.Int) *big.Int {
	return new(big.Int).Exp(n, new(big.Int).Sub(o.p, big.NewInt(2)), o.p)
}
func rawY(y *big.Int, sign uint) []byte {
	n := new(big.Int).Set(y)
	n.SetBit(n, 255, sign)
	b := n.FillBytes(make([]byte, 32))
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		b[i], b[j] = b[j], b[i]
	}
	return b
}
func (o oracle) decode(b []byte) (affine, bool) {
	if len(b) != 32 {
		return affine{}, false
	}
	rev := append([]byte(nil), b...)
	for i, j := 0, 31; i < j; i, j = i+1, j-1 {
		rev[i], rev[j] = rev[j], rev[i]
	}
	sign := uint(rev[0] >> 7)
	rev[0] &= 127
	y := new(big.Int).SetBytes(rev)
	if y.Cmp(o.p) >= 0 {
		return affine{}, false
	}
	yy := o.mod(new(big.Int).Mul(y, y))
	den := o.mod(new(big.Int).Add(new(big.Int).Mul(o.d, yy), big.NewInt(1)))
	if den.Sign() == 0 {
		return affine{}, false
	}
	q := o.mod(new(big.Int).Mul(new(big.Int).Sub(yy, big.NewInt(1)), o.inv(den)))
	x := new(big.Int).Exp(q, new(big.Int).Rsh(new(big.Int).Add(o.p, big.NewInt(3)), 3), o.p)
	if o.mod(new(big.Int).Mul(x, x)).Cmp(q) != 0 {
		x = o.mod(new(big.Int).Mul(x, new(big.Int).Exp(big.NewInt(2), new(big.Int).Rsh(new(big.Int).Sub(o.p, big.NewInt(1)), 2), o.p)))
	}
	if o.mod(new(big.Int).Mul(x, x)).Cmp(q) != 0 || x.Sign() == 0 && sign == 1 {
		return affine{}, false
	}
	if x.Bit(0) != sign {
		x = new(big.Int).Sub(o.p, x)
	}
	return affine{x, y}, true
}
func (o oracle) add(a, b affine) affine {
	xy := o.mod(new(big.Int).Mul(new(big.Int).Mul(a.x, b.x), new(big.Int).Mul(a.y, b.y)))
	z := o.mod(new(big.Int).Mul(o.d, xy))
	x := o.mod(new(big.Int).Mul(new(big.Int).Add(new(big.Int).Mul(a.x, b.y), new(big.Int).Mul(a.y, b.x)), o.inv(o.mod(new(big.Int).Add(big.NewInt(1), z)))))
	y := o.mod(new(big.Int).Mul(new(big.Int).Add(new(big.Int).Mul(a.y, b.y), new(big.Int).Mul(a.x, b.x)), o.inv(o.mod(new(big.Int).Sub(big.NewInt(1), z)))))
	return affine{x, y}
}
func (o oracle) mul(a affine, n *big.Int) affine {
	r := affine{big.NewInt(0), big.NewInt(1)}
	for i := 0; i < n.BitLen(); i++ {
		if n.Bit(i) == 1 {
			r = o.add(r, a)
		}
		a = o.add(a, a)
	}
	return r
}
func (o oracle) encode(a affine) []byte { return rawY(a.y, a.x.Bit(0)) }
func isOrigin(a affine) bool            { return a.x.Sign() == 0 && a.y.Cmp(big.NewInt(1)) == 0 }
func (o oracle) basis(t testing.TB) (affine, affine) {
	t.Helper()
	b, ok := o.decode(rawY(o.mod(new(big.Int).Mul(big.NewInt(4), o.inv(big.NewInt(5)))), 0))
	if !ok {
		t.Fatal("base decode")
	}
	a, ok := o.decode(rawY(big.NewInt(3), 0))
	if !ok {
		t.Fatal("torsion source decode")
	}
	torsion := o.mul(a, o.l)
	if !isOrigin(o.mul(torsion, big.NewInt(8))) || isOrigin(o.mul(torsion, big.NewInt(4))) {
		t.Fatal("T must have order eight")
	}
	return b, torsion
}

func checkOracleAdmission(t testing.TB, key []byte) {
	t.Helper()
	o := newOracle()
	a, ok := o.decode(key)
	if !ok || !bytes.Equal(o.encode(a), key) || isOrigin(a) || isOrigin(o.mul(a, big.NewInt(8))) || !isOrigin(o.mul(a, o.l)) {
		t.Fatal("oracle rejected admitted key")
	}
}
