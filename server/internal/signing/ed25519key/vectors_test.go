package ed25519key

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"math/big"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

type vector struct {
	Name, Kind string
	Recipe     struct {
		Length    int
		Y, Scalar string
		SeedHex   string `json:"seed_hex"`
		Sign      uint
		Multiple  int `json:"multiple"`
	} `json:"recipe"`
	Public   string `json:"public_key_hex"`
	Expected string
}

func loadVectors(t testing.TB) []vector {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("source path")
	}
	b, e := os.ReadFile(filepath.Join(filepath.Dir(source), "../../../../schemas/dsse/v1/key-admission-vectors.json"))
	if e != nil {
		t.Fatal(e)
	}
	var c struct {
		Format string
		Cases  []vector `json:"vectors"`
	}
	if e = json.Unmarshal(b, &c); e != nil {
		t.Fatal(e)
	}
	if c.Format != "ricevanta-ed25519-key-admission-v1" || len(c.Cases) != 80 {
		t.Fatal("corpus format or coverage")
	}
	seen := map[string]bool{}
	for i := range c.Cases {
		v := &c.Cases[i]
		if v.Name == "" || seen[v.Name] {
			t.Fatal("duplicate or empty name")
		}
		seen[v.Name] = true
		if v.Expected != "accept" && outcomes()[v.Expected] == nil {
			t.Fatal("unknown outcome")
		}
		strictHex(t, v.Public)
	}
	return c.Cases
}
func strictHex(t testing.TB, s string) []byte {
	t.Helper()
	if strings.Trim(s, "0123456789abcdef") != "" {
		t.Fatal("non-lowercase hex")
	}
	b, e := hex.DecodeString(s)
	if e != nil {
		t.Fatal(e)
	}
	return b
}
func TestValidateVectors(t *testing.T) {
	for _, v := range loadVectors(t) {
		t.Run(v.Name, func(t *testing.T) { checkOutcome(t, Validate(strictHex(t, v.Public)), outcomes()[v.Expected]) })
	}
}
func TestVectorRecipes(t *testing.T) {
	o := newOracle()
	b, tr := o.basis(t)
	seen := map[string]bool{}
	for _, v := range loadVectors(t) {
		var got []byte
		switch v.Kind {
		case "length":
			got = make([]byte, v.Recipe.Length)
		case "y-sign":
			got = rawY(decimal(v.Recipe.Y), v.Recipe.Sign)
		case "torsion":
			got = o.encode(o.mul(tr, big.NewInt(int64(v.Recipe.Multiple))))
		case "base":
			got = o.encode(o.mul(b, decimal(v.Recipe.Scalar)))
		case "mixed":
			got = o.encode(o.add(o.mul(b, decimal(v.Recipe.Scalar)), o.mul(tr, big.NewInt(int64(v.Recipe.Multiple)))))
		case "seed":
			seed := strictHex(t, v.Recipe.SeedHex)
			if len(seed) != 32 {
				t.Fatal("seed length")
			}
			got = ed25519.NewKeyFromSeed(seed)[32:]
		default:
			t.Fatalf("unknown recipe %s", v.Kind)
		}
		if !bytes.Equal(got, strictHex(t, v.Public)) {
			t.Fatalf("recipe differs: %s", v.Name)
		}
		seen[v.Public] = true
	}
	// Eight canonical torsion encodings plus four y aliases and two signed zeros.
	torsion := [][]byte{}
	for i := int64(0); i < 8; i++ {
		torsion = append(torsion, o.encode(o.mul(tr, big.NewInt(i))))
	}
	for _, y := range []*big.Int{o.p, new(big.Int).Add(o.p, big.NewInt(1))} {
		for s := uint(0); s < 2; s++ {
			torsion = append(torsion, rawY(y, s))
		}
	}
	torsion = append(torsion, rawY(big.NewInt(1), 1), rawY(new(big.Int).Sub(o.p, big.NewInt(1)), 1))
	if len(torsion) != 14 {
		t.Fatal("torsion enumeration")
	}
	for _, key := range torsion {
		if !seen[hex.EncodeToString(key)] || Validate(key) == nil {
			t.Fatal("missing or admitted torsion encoding")
		}
	}
	for i := int64(0); i < 19; i++ {
		for s := uint(0); s < 2; s++ {
			if !seen[hex.EncodeToString(rawY(new(big.Int).Add(o.p, big.NewInt(i)), s))] {
				t.Fatal("missing overflow encoding")
			}
		}
	}
}
