package loader

import (
	"reflect"
	"sync"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func TestYAMLAccounting(t *testing.T) {
	for _, source := range []string{"a: b", "\xff", "a: [", "a: ! x", "a: null", "a: b\na: c", mappingSource(897), "a: 18446744073709551616"} {
		got, u, err := decodeVerifiedYAMLAccounted([]byte(source))
		want, e := decodeVerifiedYAML([]byte(source))
		if err != e || !reflect.DeepEqual(got, want) {
			t.Fatal("wrapper disagreement")
		}
		if u.bytes == 0 || u.objects == 0 {
			t.Fatal("failure lost cumulative charges")
		}
		if err != nil && got != nil {
			t.Fatal("partial map")
		}

		_, ledger, parseErr := yamltokens.DecodeAccounted([]byte(source))
		pb, po := ledger.Usage()
		if u.bytes < pb || u.objects < po {
			t.Fatal("converter refunded parser charges")
		}
		if parseErr == nil && (u.bytes == pb || u.objects == po) {
			t.Fatal("missing conversion stage charges")
		}
		copied := u
		u.bytes = 0
		u.objects = 0
		_, v, _ := decodeVerifiedYAMLAccounted([]byte(source))
		if copied != v {
			t.Fatal("nonrepeatable charges")
		}
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m, u, e := decodeVerifiedYAMLAccounted([]byte("a: b"))
			if e != nil || m == nil || u.bytes == 0 {
				t.Error("independent concurrent conversion failed")
			}
			m["a"] = "changed"
		}()
	}
	wg.Wait()
}
func TestLoadYAMLAccounting(t *testing.T) {
	c := corpus(t)
	for _, v := range c.Cases {
		t.Run(v.Name, func(t *testing.T) {
			archive := packageArchive(t, []byte(v.ArchiveManifest), []byte(v.Envelope), fixtureFiles(t)...)
			key := keyPublic(t)
			calls := 0
			var u yamlUsage
			p, e := loadWithDependencies(archiveReader(archive, 64<<20), key, Options{}, loadDependencies{
				decode: func(b []byte) (map[string]any, error) {
					calls++
					m, usage, err := decodeVerifiedYAMLAccounted(b)
					u = usage
					return m, err
				}, validate: manifest.Validate})
			direct, err := loadBytes(archive, key, Options{})
			if e != err || !reflect.DeepEqual(p, direct) {
				t.Fatal("observed load differs")
			}
			expected := 1
			if v.Result == "dsse.ErrSignature" || v.Result == "ErrPayloadMismatch" {
				expected = 0
			}
			if calls != expected {
				t.Fatalf("decode calls %d want %d", calls, expected)
			}
			if calls == 0 && u != (yamlUsage{}) || calls == 1 && (u.bytes == 0 || u.objects == 0) {
				t.Fatal("wrong same-call usage")
			}
			if e != nil && !reflect.DeepEqual(p, Package{}) {
				t.Fatal("partial package")
			}
		})
	}
}
