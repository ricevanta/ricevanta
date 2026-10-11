package loader

import (
	"encoding/json"
	"flag"
	"fmt"
	"go.yaml.in/yaml/v3"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
)

var budgetExtended = flag.Bool("loader-budget-extended", false, "run the native parser qualification corpus")

func rootBudget(t *testing.T, extended bool) {
	t.Helper()
	// Classify every recipe before the candidate and pass data to a separate test
	// binary. Oracle allocations stay outside all measured candidate children.
	classification := make(map[string]referenceMeasurement)
	dir := t.TempDir()
	for _, c := range parserCorpus(extended) {
		payload := parserPayload(c)
		node, err := referenceAcceptance(payload)
		var arities []uint32
		if err == nil {
			var visit func(*yaml.Node)
			visit = func(n *yaml.Node) {
				if n.Kind != yaml.DocumentNode {
					arities = append(arities, uint32(len(n.Content)))
				}
				for _, child := range n.Content {
					visit(child)
				}
			}
			visit(node)
		}
		treePath := ""
		if err == nil {
			eraseComments(node)
			treeData, marshalErr := json.Marshal(node)
			if marshalErr != nil {
				t.Fatal(marshalErr)
			}
			treePath = filepath.Join(dir, fmt.Sprintf("tree-%d.json", len(classification)))
			if writeErr := os.WriteFile(treePath, treeData, 0600); writeErr != nil {
				t.Fatal(writeErr)
			}
		}
		class := ""
		if err != nil {
			class = err.Error()
		}
		classification[c.Name+"/"+strconv.Itoa(c.Size)] = referenceMeasurement{Accepted: err == nil, Arities: arities, Error: class, Tree: treePath}
	}
	data, err := json.Marshal(classification)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "reference.json")
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	target := "^TestParserBudgetHarness$"
	args := []string{"test", "-count=1", "./internal/yamltokens", "-run", target, "-v"}
	if extended {
		args = append(args, "-args", "-loader-budget-extended")
	}
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "RICEVANTA_REFERENCE="+path)
	out, err := cmd.CombinedOutput()
	t.Log(string(out))
	if err != nil {
		t.Fatalf("parser qualification: %v", err)
	}
}
func TestParserBudgetSmoke(t *testing.T) { rootBudget(t, false) }
func TestParserBudgetExtended(t *testing.T) {
	if !*budgetExtended {
		t.Skip("requires -loader-budget-extended")
	}
	rootBudget(t, true)
}

type referenceMeasurement struct {
	Accepted bool
	Arities  []uint32
	Error    string
	Tree     string
}
