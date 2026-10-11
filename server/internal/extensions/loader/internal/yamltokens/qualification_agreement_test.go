package yamltokens

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

// A child must reject oracle data that differs only in a scalar value.
func TestMeasurementRejectsTreeMismatch(t *testing.T) {
	dir := t.TempDir()
	tree := &yaml.Node{Kind: yaml.DocumentNode, Content: []*yaml.Node{{Kind: yaml.ScalarNode, Tag: "!!str", Value: "corrupted", Line: 1, Column: 1}}, Line: 1, Column: 1}
	data, err := json.Marshal(tree)
	if err != nil {
		t.Fatal(err)
	}
	treePath := filepath.Join(dir, "tree.json")
	if err := os.WriteFile(treePath, data, 0600); err != nil {
		t.Fatal(err)
	}
	data, err = json.Marshal(map[string]any{"plain/64": map[string]any{"Accepted": true, "Arities": []uint32{0}, "Tree": treePath}})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "reference.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"node", "combined"} {
		t.Run(mode, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestParserMeasurementChild$", "-test.v")
			cmd.Env = append(os.Environ(), "RICEVANTA_REFERENCE="+path, "RICEVANTA_PARSER_RECIPE=plain", "RICEVANTA_PARSER_SIZE=64", "RICEVANTA_PARSER_ACCEPTED=true", "RICEVANTA_PARSER_MODE="+mode)
			out, err := cmd.CombinedOutput()
			if err == nil || !strings.Contains(string(out), "complete-tree disagreement") {
				t.Fatalf("child must reject scalar mismatch: err=%v\n%s", err, out)
			}
		})
	}
}
