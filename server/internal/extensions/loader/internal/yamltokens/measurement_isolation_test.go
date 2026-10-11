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

// Hostile inherited settings must not affect any fresh measurement child.
func TestParserMeasurementIsolation(t *testing.T) {
	// The unmodified decoder supplies accepted-case metadata outside every
	// measured child. No candidate setup computes arities or the expected tree.
	var tree yaml.Node
	if err := yaml.NewDecoder(strings.NewReader(strings.Repeat("x", 64))).Decode(&tree); err != nil {
		t.Fatal(err)
	}
	treeData, err := json.Marshal(&tree)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	treePath := filepath.Join(dir, "tree.json")
	if err := os.WriteFile(treePath, treeData, 0600); err != nil {
		t.Fatal(err)
	}
	referenceData, err := json.Marshal(map[string]measurementOracle{
		"plain/64": {Accepted: true, Arities: []uint32{0}, Tree: treePath},
		"tags/64":  {Accepted: false, Error: "YAML tag"},
	})
	if err != nil {
		t.Fatal(err)
	}
	referencePath := filepath.Join(dir, "reference.json")
	if err := os.WriteFile(referencePath, referenceData, 0600); err != nil {
		t.Fatal(err)
	}
	for _, recipe := range []string{"tags", "plain"} {
		for _, mode := range []string{"preflight", "node", "combined"} {
			t.Run(recipe+"/"+mode, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestParserMeasurementChild$", "-test.v")
				env := os.Environ()
				for _, key := range []string{"GOMAXPROCS", "GOMEMLIMIT", "GOGC", "RICEVANTA_PARSER_RECIPE", "RICEVANTA_PARSER_SIZE", "RICEVANTA_PARSER_MODE", "RICEVANTA_PARSER_ACCEPTED", "RICEVANTA_PARSER_ERROR", "RICEVANTA_REFERENCE"} {
					for i := 0; i < len(env); {
						if strings.HasPrefix(env[i], key+"=") {
							env = append(env[:i], env[i+1:]...)
						} else {
							i++
						}
					}
				}
				accepted, class := "false", "YAML tag"
				if recipe == "plain" {
					accepted, class = "true", ""
				}
				cmd.Env = append(env, "GOMAXPROCS=2", "GOMEMLIMIT=1MiB", "GOGC=1", "RICEVANTA_PARSER_RECIPE="+recipe, "RICEVANTA_PARSER_SIZE=64", "RICEVANTA_PARSER_MODE="+mode, "RICEVANTA_PARSER_ACCEPTED="+accepted, "RICEVANTA_PARSER_ERROR="+class, "RICEVANTA_REFERENCE="+referencePath)
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("child: %v\n%s", err, out)
				}
				found := false
				for _, line := range strings.Split(string(out), "\n") {
					if data, ok := strings.CutPrefix(line, "PARSER_MEASUREMENT "); ok {
						if _, err := decodeParserMeasurement([]byte(data)); err != nil {
							t.Fatal(err)
						}
						found = true
					}
				}
				if !found {
					t.Fatal("missing measurement")
				}
			})
		}
	}
}
