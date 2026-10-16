package admission

import (
	"reflect"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

// Synthetic fixture digests do not uniquely identify a typed projection.
// Every named seed must select its complete evidence, even when its digests
// match another vector whose components or capabilities differ.
func TestFuzzEvidencePreservesProjections(t *testing.T) {
	evidence, index := fuzzEvidence(t)
	var distinct []Evidence
	valid, substituted := 0, 0
	for _, c := range corpusCases(t) {
		want, err := FromPackage(corpusPackage(t, c.Evidence), manifest.Options{})
		if err != nil {
			continue
		}
		valid++
		found := false
		for _, previous := range distinct {
			if reflect.DeepEqual(previous, want) {
				found = true
				break
			}
		}
		if !found {
			distinct = append(distinct, want)
		}
		i, ok := index[c.Name]
		if !ok || i < 0 || i >= len(evidence) || !reflect.DeepEqual(evidence[i], want) {
			substituted++
			t.Errorf("%s: named fuzz seed does not select its complete evidence", c.Name)
		}
	}
	if valid != 169 || len(distinct) != 40 || len(evidence) != len(distinct) || substituted != 0 {
		t.Errorf("evidence=%d distinct=%d substituted=%d, want 40/40/0", len(evidence), len(distinct), substituted)
	}
	t.Logf("valid cases=%d, distinct projections=%d, selected projections=%d, substitutions=%d", valid, len(distinct), len(evidence), substituted)
}

// Expected orders come from the contract: only unsigned decimal identifiers
// are numeric; a hyphen is an ordinary character in a nonnumeric identifier.
// This test deliberately does not call the production release comparator.
func TestReleaseOracleHyphenIdentifiers(t *testing.T) {
	for _, pair := range [][2]string{
		{"0.2.0-rc.2", "0.2.0-rc.-1"},
		{"0.2.0-rc.2", "0.2.0-rc.-0"},
		{"0.2.0-2", "0.2.0--1"},
		{"0.2.0--1", "0.2.0-alpha"},
		{"0.2.0-rc.999999999999999999999999999999", "0.2.0-rc.-1"},
	} {
		t.Run(pair[0]+"/"+pair[1], func(t *testing.T) {
			a, b := pair[0], pair[1]
			if !validVersion(a) || !validVersion(b) {
				t.Fatal("regression versions must be schema-valid")
			}
			if got := oracleReleaseOrder(a, b); got >= 0 {
				t.Errorf("forward order=%d, want negative", got)
			}
			if got := oracleReleaseOrder(b, a); got <= 0 {
				t.Errorf("reverse order=%d, want positive", got)
			}
			for _, version := range pair {
				if got := oracleReleaseOrder(version, version); got != 0 {
					t.Errorf("self order=%d, want zero", got)
				}
			}
		})
	}
}
