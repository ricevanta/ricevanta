package admission

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"sort"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func decodeNumbers(t testing.TB, raw []byte, out any) {
	t.Helper()
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	if err := d.Decode(out); err != nil {
		t.Fatal(err)
	}
}

func digestHex(t testing.TB, s string) [32]byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		t.Fatalf("bad digest %q", s)
	}
	var d [32]byte
	copy(d[:], b)
	return d
}

type corpusEvidence struct {
	Document map[string]any `json:"document"`
	Package  string         `json:"package_sha256"`
	Manifest string         `json:"manifest_sha256"`
	Envelope string         `json:"envelope_sha256"`
}

// corpusPackage builds the loader result a corpus case stands for.
func corpusPackage(t testing.TB, raw json.RawMessage) loader.Package {
	t.Helper()
	var e corpusEvidence
	decodeNumbers(t, raw, &e)
	p := loader.Package{Document: e.Document, PackageSHA256: digestHex(t, e.Package), ManifestSHA256: digestHex(t, e.Manifest), EnvelopeSHA256: digestHex(t, e.Envelope)}
	if m, ok := e.Document["metadata"].(map[string]any); ok {
		if pub, ok := m["publisher"].(map[string]any); ok {
			p.PublisherFingerprint, _ = pub["key"].(string)
		}
	}
	return p
}

func checkProjection(t *testing.T, e Evidence, doc map[string]any) {
	t.Helper()
	names := make([]string, len(e.Components))
	for i, c := range e.Components {
		names[i] = c.Name
		v := c.Requested
		set := map[string]bool{"content": v.Content != nil, "browser-adapter": v.BrowserAdapter != nil, "agent-module": v.AgentModule != nil, "console-module": v.ConsoleModule != nil, "service-connector": v.ServiceConnector != nil}
		for kind, present := range set {
			if present != (kind == c.Kind) {
				t.Errorf("%s: Values field %s present=%v", c.Name, kind, present)
			}
		}
		if !valuesAgree(c.Kind, c.Interface, &c.Requested) {
			t.Errorf("%s: requested values disagree with %s", c.Name, c.Interface)
		}
		if c.Kind == kindConsoleModule {
			keys := make([]string, 0, len(v.ConsoleModule.Slots))
			for k := range v.ConsoleModule.Slots {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			slots := append([]string{}, c.Slots...)
			sort.Strings(slots)
			if !stringsEqual(keys, slots) {
				t.Errorf("%s: console slots %v, requested %v", c.Name, c.Slots, keys)
			}
		}
	}
	if !sort.StringsAreSorted(names) || !uniqueStrings(names) {
		t.Errorf("components not sorted and unique: %v", names)
	}
	components := doc["spec"].(map[string]any)["components"].([]any)
	if len(components) != len(e.Components) {
		t.Errorf("%d components projected, %d declared", len(e.Components), len(components))
	}
	if r := checkEvidence(&e); !r {
		t.Error("projected evidence fails the input.evidence checks")
	}
}

func TestFromPackage(t *testing.T) {
	b, err := os.ReadFile(schemaDir + "package-loader-vectors.json")
	if err != nil {
		t.Fatal(err)
	}
	var loaderCorpus struct {
		Fingerprint string `json:"publisher_fingerprint"`
		Cases       []struct {
			Name     string         `json:"name"`
			Document map[string]any `json:"decoded_document"`
		} `json:"cases"`
	}
	decodeNumbers(t, b, &loaderCorpus)
	digest := [32]byte{1}
	for _, c := range loaderCorpus.Cases {
		t.Run("loader/"+c.Name, func(t *testing.T) {
			p := loader.Package{Document: c.Document, PackageSHA256: digest, ManifestSHA256: digest, EnvelopeSHA256: digest, PublisherFingerprint: loaderCorpus.Fingerprint}
			e, err := FromPackage(p, manifest.Options{})
			if c.Name == "wrong-publisher" {
				// The document names another key than the loader verified under.
				if !errors.Is(err, ErrEvidence) {
					t.Fatalf("got %v, want ErrEvidence", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			checkProjection(t, e, c.Document)
		})
	}
	for _, c := range corpusCases(t) {
		t.Run("admission/"+c.Name, func(t *testing.T) {
			p := corpusPackage(t, c.Evidence)
			e, err := FromPackage(p, manifest.Options{})
			if c.Name == "input-evidence-invalid-document" {
				if !errors.Is(err, ErrEvidence) || !errors.Is(manifest.Validate(p.Document, manifest.Options{AllowReservedID: true}), manifest.ErrShape) {
					t.Fatalf("got %v, want ErrEvidence from a manifest failure", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			checkProjection(t, e, p.Document)
			if e.ID != p.Document["metadata"].(map[string]any)["id"] || e.PackageSHA256 != p.PackageSHA256 || e.ManifestSHA256 != p.ManifestSHA256 || e.EnvelopeSHA256 != p.EnvelopeSHA256 {
				t.Error("identity or digests not projected")
			}
		})
	}
	base := corpusPackage(t, corpusCases(t)[0].Evidence)
	for name, mutate := range map[string]func(*loader.Package){
		"zero package digest":  func(p *loader.Package) { p.PackageSHA256 = [32]byte{} },
		"zero manifest digest": func(p *loader.Package) { p.ManifestSHA256 = [32]byte{} },
		"zero envelope digest": func(p *loader.Package) { p.EnvelopeSHA256 = [32]byte{} },
		"fingerprint differs":  func(p *loader.Package) { p.PublisherFingerprint = "sha256:" + hex.EncodeToString(make([]byte, 32)) },
		"no document":          func(p *loader.Package) { p.Document = nil },
		"options ceiling":      nil,
	} {
		t.Run(name, func(t *testing.T) {
			p := base
			options := manifest.Options{}
			if mutate == nil {
				options.MaxTotalFileBytes = manifest.HardMaxTotalFileBytes + 1
			} else {
				mutate(&p)
			}
			if _, err := FromPackage(p, options); !errors.Is(err, ErrEvidence) {
				t.Fatalf("got %v, want ErrEvidence", err)
			}
		})
	}
	t.Run("reserved id allowed", func(t *testing.T) {
		for _, c := range corpusCases(t) {
			if c.Name != "first-start-release-fixed-install" {
				continue
			}
			if _, err := FromPackage(corpusPackage(t, c.Evidence), manifest.Options{AllowReservedID: false}); err != nil {
				t.Fatalf("reserved id refused: %v", err)
			}
		}
	})
}

func validEvidence(t testing.TB) Evidence {
	t.Helper()
	for _, c := range corpusCases(t) {
		if c.Name == "mixed-package-approval-required" {
			e, err := FromPackage(corpusPackage(t, c.Evidence), manifest.Options{})
			if err != nil {
				t.Fatal(err)
			}
			return e
		}
	}
	t.Fatal("no mixed package case")
	return Evidence{}
}

func TestEvidenceChecks(t *testing.T) {
	base := validEvidence(t)
	if !checkEvidence(&base) {
		t.Fatal("valid evidence refused")
	}
	if len(base.Components) < 3 {
		t.Fatal("mixed package needs several components")
	}
	clone := func() Evidence {
		e := base
		e.Components = append([]Component{}, base.Components...)
		e.Requires = map[string][]string{}
		for k, v := range base.Requires {
			e.Requires[k] = append([]string{}, v...)
		}
		return e
	}
	cases := map[string]func(*Evidence){
		"zero package digest":   func(e *Evidence) { e.PackageSHA256 = [32]byte{} },
		"zero manifest digest":  func(e *Evidence) { e.ManifestSHA256 = [32]byte{} },
		"zero envelope digest":  func(e *Evidence) { e.EnvelopeSHA256 = [32]byte{} },
		"id grammar":            func(e *Evidence) { e.ID = "Com.Example" },
		"id single label":       func(e *Evidence) { e.ID = "example" },
		"version grammar":       func(e *Evidence) { e.Version = "1.0" },
		"fingerprint uppercase": func(e *Evidence) { e.PublisherFingerprint = "sha256:" + string(bytes.Repeat([]byte("A"), 64)) },
		"fingerprint prefix":    func(e *Evidence) { e.PublisherFingerprint = e.PublisherFingerprint[7:] },
		"unsorted":              func(e *Evidence) { e.Components[0], e.Components[1] = e.Components[1], e.Components[0] },
		"repeated name":         func(e *Evidence) { e.Components[1].Name = e.Components[0].Name },
		"no components":         func(e *Evidence) { e.Components = nil; e.Requires = map[string][]string{} },
		"undefined pair":        func(e *Evidence) { e.Components[0].Interface = "ext.ricevanta.io/other/v1" },
		"values kind": func(e *Evidence) {
			e.Components[0].Requested = Values{ServiceConnector: &ServiceConnectorValues{}}
		},
		"values two fields": func(e *Evidence) {
			e.Components[0].Requested.Content = &struct{}{}
			e.Components[0].Requested.ServiceConnector = &ServiceConnectorValues{}
		},
		"requires extra kind":      func(e *Evidence) { e.Requires["content"] = []string{"ext.ricevanta.io/content/v1"} },
		"requires missing kind":    func(e *Evidence) { delete(e.Requires, e.Components[0].Kind) },
		"requires other interface": func(e *Evidence) { e.Requires[e.Components[0].Kind] = []string{"ext.ricevanta.io/enricher/v1"} },
		"requires duplicate":       func(e *Evidence) { k := e.Components[0].Kind; e.Requires[k] = append(e.Requires[k], e.Requires[k]...) },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := clone()
			mutate(&e)
			if checkEvidence(&e) {
				t.Fatal("defective evidence accepted")
			}
		})
	}
	if !checkEvidence(&base) {
		t.Fatal("base evidence changed by a case")
	}
}
