package manifest_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	m "github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func sentinels() map[string]error {
	return map[string]error{"ok": nil, "ErrOptions": m.ErrOptions, "ErrTree": m.ErrTree, "ErrShape": m.ErrShape, "ErrField": m.ErrField, "ErrReserved": m.ErrReserved, "ErrDuplicate": m.ErrDuplicate, "ErrPath": m.ErrPath, "ErrLimit": m.ErrLimit, "ErrRequires": m.ErrRequires, "ErrReference": m.ErrReference, "ErrCapability": m.ErrCapability, "ErrLicense": m.ErrLicense, "ErrURL": m.ErrURL}
}
func TestFixtures(t *testing.T) {
	seen := map[string]bool{}
	for _, c := range cases(t) {
		if seen[c.Name] {
			t.Fatalf("duplicate case %q", c.Name)
		}
		seen[c.Name] = true
		want, ok := sentinels()[c.Error]
		if !ok {
			t.Fatalf("unknown expectation %q", c.Error)
		}
		t.Run(c.Name, func(t *testing.T) {
			err := m.Validate(c.Manifest, m.Options{AllowReservedID: c.Options.Allow, MaxTotalFileBytes: c.Options.Max})
			// Caller options and decoded-tree restrictions can precede schema checks.
			if !errors.Is(err, m.ErrOptions) && !errors.Is(err, m.ErrTree) {
				localInvalid := errors.Is(err, m.ErrShape) || errors.Is(err, m.ErrField)
				if c.SchemaValid == localInvalid {
					t.Fatalf("schema_valid=%v disagrees with validator result %v", c.SchemaValid, err)
				}
			}
			if want == nil {
				if err != nil {
					t.Fatal(err)
				}
			} else if !errors.Is(err, want) {
				t.Fatalf("got %v, want %v", err, want)
			}
		})
	}
}
func TestFixtureDigests(t *testing.T) {
	b, e := os.ReadFile("../../../../schemas/extension/v1alpha1/fixtures.json")
	if e != nil {
		t.Fatal(e)
	}
	var p struct {
		PublicKeyHex string `json:"public_key_hex"`
		Fingerprint  string `json:"publisher_fingerprint"`
		Vectors      []struct {
			Text   string `json:"utf8"`
			Size   uint64
			Digest string `json:"sha256"`
		} `json:"file_vectors"`
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if e = d.Decode(&p); e != nil {
		t.Fatal(e)
	}
	key, e := hex.DecodeString(p.PublicKeyHex)
	if e != nil || len(key) != 32 {
		t.Fatal("invalid test public key")
	}
	fingerprint := fmt.Sprintf("sha256:%x", sha256.Sum256(key))
	if p.Fingerprint != fingerprint {
		t.Fatal("fingerprint mismatch")
	}
	digests := map[string]uint64{}
	for _, v := range p.Vectors {
		digest := fmt.Sprintf("%x", sha256.Sum256([]byte(v.Text)))
		if digest != v.Digest || uint64(len(v.Text)) != v.Size {
			t.Fatal("file vector mismatch")
		}
		digests[digest] = v.Size
	}
	if len(p.Vectors) != 2 {
		t.Fatal("expected both vectors")
	}
	for _, c := range cases(t) {
		if c.Error != "ok" {
			continue
		}
		if c.Manifest["metadata"].(map[string]any)["publisher"].(map[string]any)["key"] != fingerprint {
			t.Fatalf("%s fingerprint mismatch", c.Name)
		}
		for _, f := range c.Manifest["files"].([]any) {
			f := f.(map[string]any)
			size, ok := digests[f["sha256"].(string)]
			if !ok || f["size"].(json.Number).String() != fmt.Sprint(size) {
				t.Fatalf("%s file vector mismatch", c.Name)
			}
		}
	}
}
