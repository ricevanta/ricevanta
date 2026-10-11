package ocsf

import (
	"bytes"
	"testing"
)

func fixtureSeeds(cases fixtureSet) []fixture {
	return append(append([]fixture{}, cases.Events...), cases.Parser...)
}

func FuzzValidate(f *testing.F) {
	for _, path := range []string{"examples/vectors.json", "fixtures/events.json"} {
		for _, c := range fixtureSeeds(fixtures(f, path)) {
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

func TestFixtureSeedsIncludeParser(t *testing.T) {
	for _, path := range []string{"examples/vectors.json", "fixtures/events.json"} {
		cases := fixtures(t, path)
		seeds := fixtureSeeds(cases)
		if len(seeds) != len(cases.Events)+len(cases.Parser) {
			t.Fatalf("%s: got %d seeds, want %d", path, len(seeds), len(cases.Events)+len(cases.Parser))
		}
		for i, c := range cases.Parser {
			if seeds[len(cases.Events)+i].EventJSON != c.EventJSON {
				t.Fatalf("%s: missing parser seed %s", path, c.Name)
			}
		}
	}
}
