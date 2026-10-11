package loader

import (
	"encoding/json"
	"flag"
	"fmt"
	"go.yaml.in/yaml/v3"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var budgetExtended = flag.Bool("loader-budget-extended", false, "run the native parser qualification corpus")
var budgetRepeat = flag.String("loader-budget-repeat", "", "repeat one parser recipe/size/mode from the native corpus")
var budgetRepeatCount = flag.Int("loader-budget-repeat-count", 1, "number of fresh measurement children for the selected parser recipe")

func rootBudget(t *testing.T, extended bool) {
	t.Helper()
	corpus := parserCorpus(extended)
	target := "^TestParserBudgetHarness$"
	count := 1
	if *budgetRepeatCount < 1 || (*budgetRepeat == "" && *budgetRepeatCount != 1) {
		t.Fatal("invalid parser repetition: count must be positive and requires a selector")
	}
	if *budgetRepeat != "" {
		parts := strings.Split(*budgetRepeat, "/")
		if len(parts) != 3 || (parts[2] != "preflight" && parts[2] != "node" && parts[2] != "combined") {
			t.Fatal("invalid parser repetition: expected recipe/size/preflight, node or combined")
		}
		corpus = nil
		for _, c := range parserCorpus(true) {
			if c.Name+"/"+strconv.Itoa(c.Size) == parts[0]+"/"+parts[1] {
				corpus = []parserInput{c}
				break
			}
		}
		if len(corpus) == 0 {
			t.Fatal("invalid parser repetition: unknown recipe or size")
		}
		for _, part := range parts {
			target += "/^" + regexp.QuoteMeta(part) + "$"
		}
		count = *budgetRepeatCount
		extended = true
	}
	// Classify every recipe before the candidate and pass data to a separate test
	// binary. Oracle allocations stay outside all measured candidate children.
	// Each fresh child isolates runtime activity under section 6 before measuring
	// one cold candidate call with raw counters and zero extra allowance.
	classification := make(map[string]referenceMeasurement)
	dir := t.TempDir()
	for _, c := range corpus {
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
	// Repeating the selected subtest still starts a fresh measurement child for
	// each sample. The independent classification above runs only once.
	args := []string{"test", "-count=" + strconv.Itoa(count), "./internal/yamltokens", "-run", target, "-v"}
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

func TestParserBudgetRepeatFlags(t *testing.T) {
	for _, tc := range []struct {
		name, selector, count string
		wantFailure           bool
	}{
		{"two-samples", "comment-collections/262144/combined", "2", false},
		{"unknown-recipe", "unknown/262144/combined", "1", true},
		{"unknown-size", "comment-collections/123/combined", "1", true},
		{"invalid-size", "comment-collections/no/combined", "1", true},
		{"unknown-mode", "comment-collections/262144/unknown", "1", true},
		{"missing-mode", "comment-collections/262144", "1", true},
		{"zero-count", "comment-collections/262144/combined", "0", true},
		{"negative-count", "comment-collections/262144/combined", "-1", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cmd := exec.Command(os.Args[0], "-test.run=^TestParserBudgetSmoke$", "-test.v", "-loader-budget-repeat="+tc.selector, "-loader-budget-repeat-count="+tc.count)
			out, err := cmd.CombinedOutput()
			if tc.wantFailure {
				if err == nil || !strings.Contains(string(out), "invalid parser repetition") {
					t.Fatalf("expected repetition validation failure: %v\n%s", err, out)
				}
				return
			}
			if err != nil {
				t.Fatalf("repetition: %v\n%s", err, out)
			}
			samples := 0
			for _, line := range strings.Split(string(out), "\n") {
				_, data, ok := strings.Cut(line, "PARSER_MEASUREMENT ")
				if !ok {
					continue
				}
				var m struct {
					Input, Mode string
					Bytes       int
				}
				if err := json.Unmarshal([]byte(data), &m); err != nil {
					t.Fatal(err)
				}
				if m.Input != "comment-collections" || m.Mode != "combined" || m.Bytes != 262144 {
					t.Fatalf("unexpected measurement: %+v", m)
				}
				samples++
			}
			if samples != 2 {
				t.Fatalf("got %d samples, want 2\n%s", samples, out)
			}
		})
	}
}
