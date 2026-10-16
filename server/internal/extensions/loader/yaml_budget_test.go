package loader

import (
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

var budgetExtended = flag.Bool("loader-budget-extended", false, "run the native parser qualification corpus")
var budgetRepeat = flag.String("loader-budget-repeat", "", "repeat one parser recipe/size/mode from the native corpus")
var budgetRepeatCount = flag.Int("loader-budget-repeat-count", 1, "number of fresh measurement children for the selected parser recipe")

func rootBudget(t *testing.T, extended bool) {
	t.Helper()
	corpus := parserCorpus(extended)
	target := "^TestParserBudgetHarness$"
	count := 1
	modes := parserEvidenceModes
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
		modes = []string{parts[2]}
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
	// each sample. The independent classification above runs only once. The
	// expected recipe/size/mode/sample keys come from the corpus before the
	// child runs; the child's test2json stream must account for each of them.
	expected := expectedParserEvidence(corpus, modes, count)
	args := []string{"test", "-count=" + strconv.Itoa(count), "./internal/yamltokens", "-run", target, "-json"}
	if extended {
		args = append(args, "-args", "-loader-budget-extended")
	}
	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(), "RICEVANTA_REFERENCE="+path)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err = cmd.Run()
	t.Log(parserEvidenceText(stdout.Bytes()))
	if stderr.Len() > 0 {
		t.Log(stderr.String())
	}
	if err != nil {
		t.Fatalf("parser qualification: %v", err)
	}
	if err := verifyParserEvidence(stdout.Bytes(), expected, count); err != nil {
		t.Fatalf("parser qualification evidence: %v", err)
	}
}

// parserEvidenceKey names one nested measurement: the harness subtest and the
// repetition sample that produced it.
type parserEvidenceKey struct {
	Input  string
	Size   int
	Mode   string
	Sample int
}

func (k parserEvidenceKey) subtest() string {
	return "TestParserBudgetHarness/" + k.Input + "/" + strconv.Itoa(k.Size) + "/" + k.Mode
}

// parserEvidence mirrors the child's PARSER_MEASUREMENT record. Every field is
// required; JSON decoding into fixed-width integers rejects non-finite values.
type parserEvidence struct {
	Input                                              string
	Size                                               int
	Mode                                               string
	Sample                                             int
	Toolchain, OS, Arch, Status                        string
	Bytes                                              int
	Alloc, Objects, StackGrowth, RetainedHeap, PeakRSS uint64
	Nanoseconds                                        int64
	LedgerBytes, LedgerObjects                         uint64
	ErrorClass                                         string
	ProcsBefore, ProcsAfter                            int
	MemoryLimitBefore, MemoryLimitAfter                int64
	GCPercentBefore, GCPercentAfter                    uint64
	GCBefore, GCAfter                                  uint32
}

type testEvent struct {
	Action, Package, Test, Output string
}

var parserEvidenceModes = []string{"preflight", "node", "combined"}

func expectedParserEvidence(corpus []parserInput, modes []string, count int) map[parserEvidenceKey]bool {
	expected := make(map[parserEvidenceKey]bool, len(corpus)*len(modes)*count)
	for _, c := range corpus {
		for _, mode := range modes {
			for sample := 1; sample <= count; sample++ {
				expected[parserEvidenceKey{c.Name, c.Size, mode, sample}] = true
			}
		}
	}
	return expected
}

func decodeParserEvidence(data []byte) (parserEvidence, error) {
	var m parserEvidence
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&m); err != nil {
		return m, err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return m, err
	}
	reportType := reflect.TypeOf(m)
	for i := 0; i < reportType.NumField(); i++ {
		name := reportType.Field(i).Name
		value, present := fields[name]
		if !present || string(value) == "null" {
			return m, fmt.Errorf("missing measurement field %s", name)
		}
	}
	if m.Sample < 1 || m.Size < 0 || m.Bytes < 0 || m.Nanoseconds < 0 {
		return m, fmt.Errorf("measurement identity or counters out of range: %+v", m)
	}
	if m.Alloc > m.LedgerBytes || m.Objects > m.LedgerObjects {
		return m, fmt.Errorf("source charge below measured allocation: %+v", m)
	}
	if m.Alloc > 64<<20 || m.Objects > 1000000 || m.StackGrowth > 8<<20 {
		return m, fmt.Errorf("parser budget exceeded: %+v", m)
	}
	return m, nil
}

// verifyParserEvidence checks a nested harness stream: every expected subtest
// ran and passed once per sample, every expected key has exactly one complete
// measurement attributed to its own subtest, and nothing else was measured.
func verifyParserEvidence(stream []byte, expected map[parserEvidenceKey]bool, count int) error {
	if len(bytes.TrimSpace(stream)) == 0 {
		return errors.New("empty nested harness output")
	}
	if count < 1 {
		return errors.New("invalid sample count")
	}
	wantSubtests := make(map[string]bool)
	for key := range expected {
		wantSubtests[key.subtest()] = true
	}
	const root = "TestParserBudgetHarness"
	runs, passes := make(map[string]int), make(map[string]int)
	packagePass := 0
	seen := make(map[parserEvidenceKey]bool, len(expected))
	for _, line := range bytes.Split(stream, []byte("\n")) {
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var event testEvent
		decoder := json.NewDecoder(bytes.NewReader(line))
		if err := decoder.Decode(&event); err != nil {
			return fmt.Errorf("malformed test2json event: %w", err)
		}
		switch event.Action {
		case "run":
			runs[event.Test]++
		case "pass":
			if event.Test == "" {
				packagePass++
			} else {
				passes[event.Test]++
			}
		case "skip", "fail":
			return fmt.Errorf("nested %s: %q", event.Action, event.Test)
		case "output":
			_, data, ok := strings.Cut(event.Output, "PARSER_MEASUREMENT ")
			if !ok {
				continue
			}
			m, err := decodeParserEvidence([]byte(strings.TrimRight(data, "\r\n")))
			if err != nil {
				return err
			}
			key := parserEvidenceKey{m.Input, m.Size, m.Mode, m.Sample}
			if event.Test != key.subtest() {
				return fmt.Errorf("measurement %+v attributed to %q", key, event.Test)
			}
			if !expected[key] {
				return fmt.Errorf("unexpected measurement %+v", key)
			}
			if seen[key] {
				return fmt.Errorf("duplicate measurement %+v", key)
			}
			seen[key] = true
		}
	}
	if packagePass != 1 {
		return fmt.Errorf("nested package pass events %d", packagePass)
	}
	if runs[root] != count || passes[root] != count {
		return fmt.Errorf("%s ran %d and passed %d times, want %d", root, runs[root], passes[root], count)
	}
	for name := range wantSubtests {
		if runs[name] != count || passes[name] != count {
			return fmt.Errorf("%s ran %d and passed %d times, want %d", name, runs[name], passes[name], count)
		}
	}
	for name := range passes {
		if name != root && !wantSubtests[name] {
			return fmt.Errorf("unexpected nested test %q", name)
		}
	}
	for key := range expected {
		if !seen[key] {
			return fmt.Errorf("missing measurement %+v", key)
		}
	}
	return nil
}

// parserEvidenceText restores the plain test output for retained logs.
func parserEvidenceText(stream []byte) string {
	var text strings.Builder
	for _, line := range bytes.Split(stream, []byte("\n")) {
		var event testEvent
		if json.Unmarshal(line, &event) == nil && event.Action == "output" {
			text.WriteString(event.Output)
		}
	}
	return text.String()
}

// syntheticParserEvidence builds a valid stream for one harness run per
// sample, in the shape the pinned go test -json runner emits.
func syntheticParserEvidence(t *testing.T, corpus []parserInput, count int, mutate func(*parserEvidence)) []byte {
	t.Helper()
	var stream bytes.Buffer
	emit := func(event map[string]any) {
		data, err := json.Marshal(event)
		if err != nil {
			t.Fatal(err)
		}
		stream.Write(data)
		stream.WriteByte('\n')
	}
	emit(map[string]any{"Action": "start", "Package": "p"})
	for sample := 1; sample <= count; sample++ {
		emit(map[string]any{"Action": "run", "Package": "p", "Test": "TestParserBudgetHarness"})
		for _, c := range corpus {
			for _, mode := range parserEvidenceModes {
				key := parserEvidenceKey{c.Name, c.Size, mode, sample}
				m := parserEvidence{Input: c.Name, Size: c.Size, Mode: mode, Sample: sample, Toolchain: "go", OS: "linux", Arch: "amd64", Status: "accepted", Bytes: c.Size, Alloc: 10, Objects: 2, Nanoseconds: 5, LedgerBytes: 10, LedgerObjects: 2, ProcsBefore: 1, ProcsAfter: 1, MemoryLimitBefore: math.MaxInt64, MemoryLimitAfter: math.MaxInt64, GCPercentBefore: math.MaxUint64, GCPercentAfter: math.MaxUint64}
				if mutate != nil {
					mutate(&m)
				}
				record, err := json.Marshal(m)
				if err != nil {
					t.Fatal(err)
				}
				emit(map[string]any{"Action": "run", "Package": "p", "Test": key.subtest()})
				emit(map[string]any{"Action": "output", "Package": "p", "Test": key.subtest(), "Output": "    qualification_test.go:1: PARSER_MEASUREMENT " + string(record) + "\n"})
				emit(map[string]any{"Action": "pass", "Package": "p", "Test": key.subtest()})
			}
		}
		emit(map[string]any{"Action": "pass", "Package": "p", "Test": "TestParserBudgetHarness"})
	}
	emit(map[string]any{"Action": "pass", "Package": "p"})
	return stream.Bytes()
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
			samples := make(map[int]bool)
			for _, line := range strings.Split(string(out), "\n") {
				_, data, ok := strings.Cut(line, "PARSER_MEASUREMENT ")
				if !ok {
					continue
				}
				m, err := decodeParserEvidence([]byte(strings.TrimSpace(data)))
				if err != nil {
					t.Fatal(err)
				}
				if m.Input != "comment-collections" || m.Size != 262144 || m.Mode != "combined" || m.Bytes != 262144 || samples[m.Sample] {
					t.Fatalf("unexpected or repeated measurement: %+v", m)
				}
				samples[m.Sample] = true
			}
			if len(samples) != 2 || !samples[1] || !samples[2] {
				t.Fatalf("got samples %v, want identities 1 and 2\n%s", samples, out)
			}
		})
	}
}

// Synthetic test2json streams prove the parent rejects nested children that
// exit zero without complete, correctly attributed measurements.
func TestParserBudgetEvidence(t *testing.T) {
	corpus := []parserInput{{"plain", 64}, {"tags", 64}}
	expected := expectedParserEvidence(corpus, parserEvidenceModes, 2)
	if len(expected) != len(corpus)*3*2 {
		t.Fatalf("expected keys %d", len(expected))
	}
	valid := syntheticParserEvidence(t, corpus, 2, nil)
	if err := verifyParserEvidence(valid, expected, 2); err != nil {
		t.Fatalf("valid evidence rejected: %v", err)
	}
	controls := map[string]func(lines []string) []string{
		"empty-output": func([]string) []string { return nil },
		"child-rename": func(lines []string) []string {
			return replaceAll(lines, "TestParserBudgetHarness", "TestParserBudgetHarnes")
		},
		"subtest-rename": func(lines []string) []string {
			return replaceAll(lines, "TestParserBudgetHarness/plain/64/node", "TestParserBudgetHarness/plain/64/nodes")
		},
		"skipped-child": func(lines []string) []string {
			return replaceAll(lines, `"Action":"pass","Package":"p","Test":"TestParserBudgetHarness"`, `"Action":"skip","Package":"p","Test":"TestParserBudgetHarness"`)
		},
		"skipped-subtest": func(lines []string) []string {
			return replaceAll(lines, `"Action":"pass","Package":"p","Test":"TestParserBudgetHarness/tags/64/combined"`, `"Action":"skip","Package":"p","Test":"TestParserBudgetHarness/tags/64/combined"`)
		},
		"failed-subtest": func(lines []string) []string {
			return replaceAll(lines, `"Action":"pass","Package":"p","Test":"TestParserBudgetHarness/tags/64/combined"`, `"Action":"fail","Package":"p","Test":"TestParserBudgetHarness/tags/64/combined"`)
		},
		"missing-measurement": func(lines []string) []string {
			return dropFirst(lines, `PARSER_MEASUREMENT {\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":2`)
		},
		"extra-measurement": func(lines []string) []string {
			return append(lines, strings.Replace(findFirst(lines, `\"Mode\":\"node\",\"Sample\":2`), `\"Mode\":\"node\"`, `\"Mode\":\"extra\"`, 1))
		},
		"duplicate-measurement": func(lines []string) []string {
			return append(lines, findFirst(lines, `\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":2`))
		},
		"repeated-sample-id": func(lines []string) []string {
			return replaceAll(lines, `\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":2`, `\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":1`)
		},
		"sample-out-of-range": func(lines []string) []string {
			return replaceAll(lines, `\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":2`, `\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":3`)
		},
		"non-finite-counter": func(lines []string) []string {
			return replaceAll(lines, `\"Alloc\":10,`, `\"Alloc\":1e999,`)
		},
		"non-numeric-counter": func(lines []string) []string {
			return replaceAll(lines, `\"Nanoseconds\":5,`, `\"Nanoseconds\":\"NaN\",`)
		},
		"missing-field": func(lines []string) []string { return replaceAll(lines, `\"StackGrowth\":0,`, ``) },
		"bound-exceeded": func(lines []string) []string {
			return replaceAll(lines, `\"Alloc\":10,\"Objects\":2,`, `\"Alloc\":67108865,\"Objects\":2,`)
		},
		"ledger-below-raw": func(lines []string) []string {
			return replaceAll(lines, `\"LedgerBytes\":10,`, `\"LedgerBytes\":9,`)
		},
		"misattributed-output": func(lines []string) []string {
			line := findFirst(lines, `\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":2`)
			return append(dropFirst(lines, `\"Input\":\"plain\",\"Size\":64,\"Mode\":\"node\",\"Sample\":2`),
				strings.Replace(line, `"Test":"TestParserBudgetHarness/plain/64/node"`, `"Test":"TestParserBudgetHarness/plain/64/combined"`, 1))
		},
		"truncated-output": func(lines []string) []string {
			last := lines[len(lines)-1]
			return append(lines[:len(lines)-1], last[:len(last)/2])
		},
		"package-failure": func(lines []string) []string {
			return replaceAll(lines, `{"Action":"pass","Package":"p"}`, `{"Action":"fail","Package":"p"}`)
		},
		"missing-package-pass": func(lines []string) []string { return dropFirst(lines, `{"Action":"pass","Package":"p"}`) },
	}
	for name, mutate := range controls {
		t.Run(name, func(t *testing.T) {
			lines := strings.Split(strings.TrimRight(string(valid), "\n"), "\n")
			mutated := mutate(append([]string(nil), lines...))
			stream := []byte(strings.Join(mutated, "\n") + "\n")
			if err := verifyParserEvidence(stream, expected, 2); err == nil {
				t.Fatal("defective nested evidence accepted")
			}
		})
	}
	t.Run("fifty-copies-of-one-sample", func(t *testing.T) {
		single := syntheticParserEvidence(t, corpus, 50, func(m *parserEvidence) { m.Sample = 1 })
		if err := verifyParserEvidence(single, expectedParserEvidence(corpus, parserEvidenceModes, 50), 50); err == nil {
			t.Fatal("repeated sample identity accepted")
		}
		if err := verifyParserEvidence(syntheticParserEvidence(t, corpus, 50, nil), expectedParserEvidence(corpus, parserEvidenceModes, 50), 50); err != nil {
			t.Fatal(err)
		}
	})
}

func replaceAll(lines []string, old, repl string) []string {
	out := make([]string, len(lines))
	for i, line := range lines {
		out[i] = strings.ReplaceAll(line, old, repl)
	}
	return out
}
func findFirst(lines []string, needle string) string {
	for _, line := range lines {
		if strings.Contains(line, needle) {
			return line
		}
	}
	panic("fixture line missing: " + needle)
}
func dropFirst(lines []string, needle string) []string {
	for i, line := range lines {
		if strings.Contains(line, needle) {
			return append(lines[:i:i], lines[i+1:]...)
		}
	}
	panic("fixture line missing: " + needle)
}
