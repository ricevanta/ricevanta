package ocsf

import (
	"bytes"
	"testing"
)

func FuzzValidate(f *testing.F) {
	for _, path := range []string{"examples/vectors.json", "fixtures/events.json"} {
		for _, c := range fixtures(f, path).Events {
			f.Add([]byte(c.EventJSON), c.Source == "server")
		}
	}
	f.Fuzz(func(t *testing.T, data []byte, server bool) {
		if len(data) > MaxTotalBytes {
			return
		}
		v, err := decode(string(data))
		if err != nil {
			return
		}
		s := Agent
		if server {
			s = Server
		}
		before := snapshot(t, v)
		a := Validate(v, s)
		b := Validate(v, s)
		if (a == nil) != (b == nil) || a != nil && a.Error() != b.Error() {
			t.Fatal("unstable result")
		}
		if !bytes.Equal(before, snapshot(t, v)) {
			t.Fatal("mutation")
		}
	})
}
