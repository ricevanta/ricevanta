package reportvalidate

import (
	"bytes"
	"encoding/json"
	"reflect"
	"testing"
)

func FuzzValidate(f *testing.F) {
	for _, x := range fixtures(f) {
		b, e := json.Marshal(x.Document)
		if e != nil {
			f.Fatal(e)
		}
		f.Add(b)
	}
	for _, b := range [][]byte{[]byte(`null`), []byte(`{"x":null}`), []byte(`{"x":[true,0,"ế"]}`), []byte(`{"x":{"param":"x","eq":1}}`)} {
		f.Add(b)
	}
	c, e := Builtin()
	if e != nil {
		f.Fatal(e)
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var d map[string]any
		if json.Unmarshal(b, &d) != nil {
			return
		}
		if scan(d) != nil {
			return
		}
		before, e := json.Marshal(d)
		if e != nil {
			t.Fatal(e)
		}
		r, e := Validate(d, c)
		r2, e2 := Validate(d, c)
		if !reflect.DeepEqual(r, r2) || !reflect.DeepEqual(e, e2) {
			t.Fatal("nondeterminism")
		}
		if e != nil && !reflect.DeepEqual(r, Result{}) {
			t.Fatal("partial result")
		}
		after, _ := json.Marshal(d)
		if !bytes.Equal(before, after) {
			t.Fatal("mutation")
		}
	})
}
func FuzzBudget(f *testing.F) {
	for _, s := range []string{`null`, `true`, `false`, `0`, `"ế"`, `[0]`, `{"a":0}`, `"\"\\\n"`, `{"a":[{"b":"x"}]}`} {
		f.Add([]byte(s))
	}
	f.Fuzz(func(t *testing.T, b []byte) {
		if len(b) > 65536 {
			return
		}
		var v any
		if json.Unmarshal(b, &v) != nil {
			return
		}
		root := map[string]any{"v": v}
		if scan(root) != nil {
			return
		}
		if got, want := charge(v), oracleCharge(v); got != want {
			t.Fatalf("charge %d/%d", got, want)
		}
	})
}
