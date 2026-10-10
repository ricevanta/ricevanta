package dsse

import (
	"bytes"
	"testing"
)

func TestPAE(t *testing.T) {
	for _, v := range loadCorpus(t).Positive {
		if !bytes.Equal(pae(PayloadType(v.Type), unhex(t, v.Payload)), unhex(t, v.PAE)) {
			t.Fatal(v.Name)
		}
	}
	for _, v := range []struct {
		typ  PayloadType
		p    []byte
		want string
	}{{"", nil, "DSSEv1 0  0 "}, {"é", []byte("雪"), "DSSEv1 2 é 3 雪"}} {
		if string(pae(v.typ, v.p)) != v.want {
			t.Fatal("byte lengths differ")
		}
	}
}
