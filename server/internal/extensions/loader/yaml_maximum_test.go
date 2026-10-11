package loader

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"go.yaml.in/yaml/v3"
	"os"
	"regexp"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/qualificationfixture"
	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func validateManifestWitness(t *testing.T, b []byte) {
	t.Helper()
	var doc any
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	if err := d.Decode(&doc); err != nil {
		t.Fatal(err)
	}
	if err := manifest.Validate(doc, manifest.Options{}); err != nil {
		t.Fatal(err)
	}
	schemaBytes, err := os.ReadFile("../../../../schemas/extension/v1alpha1/manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	validator := schemaReference{Root: schema, Patterns: make(map[string]*regexp.Regexp)}
	if !validator.valid(doc, schema) {
		t.Fatal("independent manifest schema rejection")
	}

}
func TestMaximumManifest(t *testing.T) {
	compact := qualificationfixture.MaximumManifest()
	if len(compact) != 639793 {
		t.Fatalf("compact bytes %d", len(compact))
	}
	commented := qualificationfixture.InterleaveComments(compact, false)
	if len(commented) != 855713 {
		t.Fatalf("commented bytes %d", len(commented))
	}
	if fmt.Sprintf("%x", sha256.Sum256(commented)) != "af263524ee80433b68ef296023ef57e099d23d5f08fe3237c384f82738ca30bb" {
		t.Fatal("exact witness byte order")
	}
	validateManifestWitness(t, compact)
	for _, name := range []string{"maximum-compact", "maximum-commented", "maximum-boundaries", "maximum-padded"} {
		t.Run(name, func(t *testing.T) {
			b := qualificationfixture.MaximumPayload(name)
			want, err := referenceAcceptance(b)
			if err != nil {
				t.Fatal(err)
			}
			nodes, depth := nodeCounts(want)
			if witnessText(want) != 477323 {
				t.Fatal("decoded text count")
			}
			if nodes != 62437 || depth != 7 {
				t.Fatalf("nodes=%d depth=%d", nodes, depth)
			}
			assertAgreement(t, b)
			got, _, err := yamltokens.Decode(b)
			if err != nil {
				t.Fatal(err)
			}
			if n, _ := nodeCounts(got); n != 62437 {
				t.Fatal("candidate witness count")
			}
		})
	}
}

func TestMaximumManifestBranches(t *testing.T) {
	schemaBytes, err := os.ReadFile("../../../../schemas/extension/v1alpha1/manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(schemaBytes, &schema); err != nil {
		t.Fatal(err)
	}
	branches := schema["$defs"].(map[string]any)["component"].(map[string]any)["oneOf"].([]any)
	for i := range branches {
		if i == len(branches)-1 {
			continue
		}
		t.Run(fmt.Sprintf("branch-%d", i), func(t *testing.T) {
			b := qualificationfixture.MaximumBranch(i, schemaBytes)
			validateManifestWitness(t, b)
			assertAgreement(t, b)
		})
	}
}

func witnessText(n *yaml.Node) int {
	total := len(n.Value)
	for _, child := range n.Content {
		total += witnessText(child)
	}
	return total
}
