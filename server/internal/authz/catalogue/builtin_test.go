package catalogue

import (
	"bytes"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

const canonicalPath = "../../../../schemas/permissions/v1/catalogue.json"

func TestBuiltin(t *testing.T) {
	c, err := Builtin()
	if err != nil || c == nil {
		t.Fatalf("builtin %v", err)
	}
	if c.Revision() == 0 || len(c.Entries()) == 0 {
		t.Fatal("empty builtin")
	}
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			again, err := Builtin()
			if again != c || err != nil {
				t.Error("builtin not cached")
			}
		}()
	}
	wg.Wait()
	if !bytes.Equal(c.JSON(), []byte(embeddedCatalogue)) {
		t.Fatal("builtin bytes changed")
	}
	// The first catalogue has no earlier catalogue baseline. The name fixture
	// independently keeps the retirement API contract exercised.
	for _, name := range []string{"dlp.evidence.read", "identity.tokens.manage", "identity.authority.approve", "authz.approvals.read", "audit.events.read", "policy.ownership.override", "events.reports.run"} {
		checkLookup(t, c, name, nil)
	}
}
func checkDrift(path string, embedded []byte) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(b, embedded) {
		return ErrEntry
	}
	return nil
}
func TestBuiltinDrift(t *testing.T) {
	if err := checkDrift(canonicalPath, []byte(embeddedCatalogue)); err != nil {
		t.Fatal(err)
	}
	tmp := filepath.Join(t.TempDir(), "canonical.json")
	if err := os.WriteFile(tmp, []byte(embeddedCatalogue), 0600); err != nil {
		t.Fatal(err)
	}
	changed := []byte(embeddedCatalogue)
	changed[0] ^= 1
	if err := checkDrift(tmp, changed); err == nil {
		t.Fatal("one-byte mismatch accepted")
	}
	if err := checkDrift(filepath.Join(t.TempDir(), "missing"), []byte(embeddedCatalogue)); err == nil {
		t.Fatal("missing source accepted")
	}
}
func TestBuiltinFailure(t *testing.T) {
	for _, input := range []string{"", "{}", string(encode(t, baseDoc()))} {
		var loader builtinLoader
		var wg sync.WaitGroup
		for i := 0; i < 16; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c, err := loader.load(input)
				if input == "" {
					if c != nil || err != ErrJSON {
						t.Errorf("malformed builtin: %v", err)
					}
				} else if input == "{}" {
					if c != nil || err != ErrShape {
						t.Errorf("shape builtin: %v", err)
					}
				} else if c == nil || err != nil {
					t.Errorf("valid builtin: %v", err)
				}
			}()
		}
		wg.Wait()
		c, err := loader.load(input)
		again, sameErr := loader.load("malformed later input")
		if c != again || err != sameErr {
			t.Fatal("cache changed")
		}
	}
}
