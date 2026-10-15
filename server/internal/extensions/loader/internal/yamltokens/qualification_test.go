package yamltokens

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/qualificationfixture"
	"go.yaml.in/yaml/v3"
)

var budgetExtended = flag.Bool("loader-budget-extended", false, "run the native parser qualification corpus")

type parserInput struct {
	Name string
	Size int
}

// Input, Size, Mode and Sample identify one measured sample; the root parent
// requires every expected key exactly once per sample number.
type parserMeasurement struct {
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

func parserPayload(c parserInput) []byte {
	n := c.Size
	if strings.HasPrefix(c.Name, "maximum-branch") {
		index, err := strconv.Atoi(strings.TrimPrefix(c.Name, "maximum-branch"))
		if err != nil {
			panic(err)
		}
		schema, err := os.ReadFile("../../../../../../schemas/extension/v1alpha1/manifest.schema.json")
		if err != nil {
			panic(err)
		}
		return qualificationfixture.MaximumBranch(index, schema)
	}
	if c.Name == "implicit-binary" {
		return []byte("[" + strings.Repeat("0b2,", n-2) + "0b2]")
	}
	if c.Name == "implicit-octal" {
		return []byte("[" + strings.Repeat("0o9,", n-2) + "0o9]")
	}
	if c.Name == "implicit-float" {
		return []byte("[" + strings.Repeat("1e999,", n-2) + "1e999]")
	}
	if strings.HasPrefix(c.Name, "maximum-") {
		return qualificationfixture.MaximumPayload(c.Name)
	}
	switch c.Name {
	case "comment-collections":
		return []byte(strings.Repeat("- {} #c\n", n/8))
	case "plain":
		return []byte(strings.Repeat("x", n))
	case "comment-keys":
		return []byte(strings.Repeat("a: b #c\n", n/8))
	case "comments":
		return []byte("a: b\n#" + strings.Repeat("c", max(0, n-6)))
	case "tiny-comments":
		return []byte("a: b\n" + strings.Repeat("#\n", max(0, (n-5)/2)))
	case "escaped":
		return []byte("\"" + strings.Repeat("\\L", max(0, (n-2)/2)) + "\"")
	case "block":
		return []byte("a: |-\n  " + strings.Repeat("x", max(0, n-8)))
	case "empty-flow":
		return []byte("[" + strings.Repeat("{},", max(0, (n-3)/3)) + "{}]")
	case "tiny-keys":
		return []byte(strings.Repeat("a: b\n", n/5))
	case "indent":
		var b strings.Builder
		for i := 0; i < n; i++ {
			b.WriteString(strings.Repeat(" ", i) + "a:\n")
		}
		b.WriteString(strings.Repeat(" ", n) + "b\n")
		return []byte(b.String())
	case "flow":
		return []byte(strings.Repeat("[", n) + "0" + strings.Repeat("]", n))
	case "explicit-key":
		return []byte(strings.Repeat("? a\n: b\n", n/8))
	case "tags":
		return []byte(strings.Repeat("! a\n", n/4))
	case "anchors":
		return []byte(strings.Repeat("&a b\n", n/5))
	case "missing-end":
		return []byte("[" + strings.Repeat(" ", max(0, n-1)))
	case "malformed-suffix":
		return []byte("a: b\n...\n" + strings.Repeat("[", max(0, n-9)))
	case "nodes":
		return []byte("[" + strings.Repeat("0,", n-2) + "0]")
	default:
		panic("unknown qualification recipe")
	}
}

func parserCorpus(extended bool) []parserInput {
	var out []parserInput
	names := []string{"comment-collections", "plain", "comment-keys", "comments", "tiny-comments", "escaped", "block", "empty-flow", "tiny-keys", "explicit-key", "tags", "anchors", "missing-end", "malformed-suffix"}
	sizes := []int{1 << 20}
	if extended {
		sizes = nil
		for n := 64; n < 1<<20; n *= 2 {
			sizes = append(sizes, n)
		}
		sizes = append(sizes, (1<<20)-1, 1<<20, (1<<20)+1)
	}
	for _, name := range names {
		for _, n := range sizes {
			out = append(out, parserInput{name, n})
		}
	}
	for _, name := range []string{"flow", "indent"} {
		for _, n := range []int{15, 16, 17, 63, 64, 65} {
			out = append(out, parserInput{name, n})
		}
	}
	for _, n := range []int{65535, 65536, 65537} {
		out = append(out, parserInput{"nodes", n})
	}
	out = append(out, parserInput{"tiny-keys", 32767 * 5}, parserInput{"explicit-key", 32767 * 8}, parserInput{"comment-keys", 32767 * 8}, parserInput{"empty-flow", 196608}, parserInput{"comment-collections", 65535 * 8})
	for _, name := range []string{"maximum-compact", "maximum-commented", "maximum-boundaries", "maximum-padded"} {
		out = append(out, parserInput{name, 0})
	}
	for i := 0; i < 7; i++ {
		out = append(out, parserInput{fmt.Sprintf("maximum-branch%d", i), 0})
	}
	for _, name := range []string{"implicit-binary", "implicit-octal", "implicit-float"} {
		out = append(out, parserInput{name, 65536})
	}
	return out
}

// nodeCounts walks only the Node tree, independently of scanner/event accounting.
func nodeCounts(root *yaml.Node) (nodes, depth int) {
	type item struct {
		N     *yaml.Node
		Depth int
	}
	todo := []item{{root, 0}}
	for len(todo) > 0 {
		it := todo[len(todo)-1]
		todo = todo[:len(todo)-1]
		if it.N.Kind == yaml.DocumentNode {
			for _, c := range it.N.Content {
				todo = append(todo, item{c, it.Depth})
			}
			continue
		}
		nodes++
		d := it.Depth
		if it.N.Kind == yaml.MappingNode || it.N.Kind == yaml.SequenceNode {
			d++
			depth = max(depth, d)
		}
		for _, c := range it.N.Content {
			todo = append(todo, item{c, d})
		}
	}
	return
}

// TestParserMeasurementChild runs exactly one measured operation in a fresh process.
func TestParserMeasurementChild(t *testing.T) {
	recipe := os.Getenv("RICEVANTA_PARSER_RECIPE")
	if recipe == "" {
		t.Skip("measurement child only")
	}
	runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(math.MaxInt64)
	size, err := strconv.Atoi(os.Getenv("RICEVANTA_PARSER_SIZE"))
	if err != nil {
		t.Fatal(err)
	}
	sample, err := strconv.Atoi(os.Getenv("RICEVANTA_PARSER_SAMPLE"))
	if err != nil || sample < 1 {
		t.Fatal("measurement child requires a positive sample identity")
	}
	mode := os.Getenv("RICEVANTA_PARSER_MODE")
	payload := parserPayload(parserInput{recipe, size})
	accepted := os.Getenv("RICEVANTA_PARSER_ACCEPTED") == "true"
	var stats *statistics
	if accepted && mode == "node" {
		// Parent supplies independent arities; no candidate pass runs before the snapshot.
		reference := measurementReference(t, parserInput{recipe, size})
		stats = &statistics{arities: reference.Arities}
	}
	prepareMeasurementRuntime()
	var before, after runtime.MemStats
	samples := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	runtime.GC()
	old := debug.SetGCPercent(-1)
	defer debug.SetGCPercent(old)
	procsBefore := runtime.GOMAXPROCS(0)
	limitBefore := debug.SetMemoryLimit(-1)
	metrics.Read(samples)
	gcPercentBefore := samples[0].Value.Uint64()
	runtime.ReadMemStats(&before)
	start := time.Now()
	var node *yaml.Node
	var checkErr error
	var ledger *Budget
	switch mode {
	case "preflight":
		ledger = newBudget()
		_, _, checkErr = prepare(payload, ledger)
	case "node":
		if accepted {
			ledger = newBudget()
			node, checkErr = construct(payload, stats, ledger)
		}
	case "combined":
		ledger = newBudget()
		node, _, checkErr = decodeBudget(payload, ledger)
	default:
		t.Fatal("unknown measurement mode")
	}
	elapsed := time.Since(start)
	runtime.ReadMemStats(&after)
	procsAfter := runtime.GOMAXPROCS(0)
	limitAfter := debug.SetMemoryLimit(-1)
	metrics.Read(samples)
	gcPercentAfter := samples[0].Value.Uint64()
	runtime.KeepAlive(payload)
	runtime.KeepAlive(node)
	class := os.Getenv("RICEVANTA_PARSER_ERROR")
	if mode != "node" || accepted {
		actual := ""
		if checkErr != nil {
			actual = checkErr.Error()
		}
		if actual != class {
			t.Fatalf("sanitized error disagreement: candidate=%s reference=%s", actual, class)
		}
	}
	status := "accepted"
	if !accepted {
		status = "preflight-rejected"
	}
	if !accepted && mode != "node" && checkErr == nil {
		t.Fatal("unexpected candidate acceptance")
	}
	if accepted && checkErr != nil {
		t.Fatal("accepted stream failed Node decode")
	}
	if accepted && mode != "preflight" {
		nodes, depth := nodeCounts(node)
		if nodes > 65536 || depth > 16 {
			t.Fatal("Node accounting disagreement")
		}
	}
	stack := uint64(0)
	if after.StackInuse > before.StackInuse {
		stack = after.StackInuse - before.StackInuse
	}
	heap := uint64(0)
	if after.HeapAlloc > before.HeapAlloc {
		heap = after.HeapAlloc - before.HeapAlloc
	}
	peakRSS, err := parserPeakRSS()
	if err != nil {
		t.Fatalf("peak resident memory: %v", err)
	}
	m := parserMeasurement{Input: recipe, Size: size, Mode: mode, Sample: sample, Toolchain: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH, Status: status, Bytes: len(payload), Alloc: after.TotalAlloc - before.TotalAlloc, Objects: after.Mallocs - before.Mallocs, StackGrowth: stack, RetainedHeap: heap, PeakRSS: peakRSS, Nanoseconds: elapsed.Nanoseconds()}
	m.ProcsBefore, m.ProcsAfter = procsBefore, procsAfter
	m.MemoryLimitBefore, m.MemoryLimitAfter = limitBefore, limitAfter
	m.GCPercentBefore, m.GCPercentAfter = gcPercentBefore, gcPercentAfter
	m.GCBefore, m.GCAfter = before.NumGC, after.NumGC
	m.ErrorClass = class
	if ledger != nil {
		m.LedgerBytes = ledger.bytes
		m.LedgerObjects = ledger.objects
	}
	if m.Alloc > m.LedgerBytes || m.Objects > m.LedgerObjects {
		t.Fatalf("source charge below measured allocation: %+v", m)
	}
	// Compare after every measurement, including peak RSS, so oracle storage
	// and tree comparison cannot enter candidate allocation or timing totals.
	if accepted && mode != "preflight" {
		reference := measurementReference(t, parserInput{recipe, size})
		data, err := os.ReadFile(reference.Tree)
		if err != nil {
			t.Fatal(err)
		}
		var want yaml.Node
		if err := json.Unmarshal(data, &want); err != nil {
			t.Fatal(err)
		}
		eraseMeasurementComments(node)
		if !reflect.DeepEqual(node, &want) {
			t.Fatal("complete-tree disagreement: candidate differs from independent oracle")
		}
	}
	b, _ := json.Marshal(m)
	fmt.Printf("PARSER_MEASUREMENT %s\n", b)
}

func runParserBudget(t *testing.T, extended bool, sample int) {
	t.Helper()
	for _, c := range parserCorpus(extended) {
		for _, mode := range []string{"preflight", "node", "combined"} {
			t.Run(fmt.Sprintf("%s/%d/%s", c.Name, c.Size, mode), func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestParserMeasurementChild$", "-test.v")
				reference := measurementReference(t, c)
				accepted, class := reference.Accepted, reference.Error
				cmd.Env = append(os.Environ(), "RICEVANTA_PARSER_ACCEPTED="+strconv.FormatBool(accepted), "RICEVANTA_PARSER_ERROR="+class, "RICEVANTA_PARSER_RECIPE="+c.Name, "RICEVANTA_PARSER_SIZE="+strconv.Itoa(c.Size), "RICEVANTA_PARSER_MODE="+mode, "RICEVANTA_PARSER_SAMPLE="+strconv.Itoa(sample))
				out, err := cmd.CombinedOutput()
				if err != nil {
					t.Fatalf("child: %v\n%s", err, out)
				}
				found := 0
				for _, line := range strings.Split(string(out), "\n") {
					if strings.HasPrefix(line, "PARSER_MEASUREMENT ") {
						m, reportErr := decodeParserMeasurement([]byte(strings.TrimPrefix(line, "PARSER_MEASUREMENT ")))
						if reportErr != nil {
							t.Fatal(reportErr)
						}
						if m.Input != c.Name || m.Size != c.Size || m.Mode != mode || m.Sample != sample {
							t.Fatalf("measurement identity %s/%d/%s/%d differs from the sample %s/%d/%s/%d", m.Input, m.Size, m.Mode, m.Sample, c.Name, c.Size, mode, sample)
						}
						found++
						t.Log(line)
					}
				}
				if found != 1 {
					t.Fatalf("measurement records %d, want exactly one", found)
				}
			})
		}
	}
}

// harnessSamples numbers each repetition of the harness within one test
// binary, so -count=N yields sample identities 1 through N.
var harnessSamples int

func TestParserBudgetHarness(t *testing.T) {
	if os.Getenv("RICEVANTA_REFERENCE") == "" {
		t.Skip("root qualification subprocess only")
	}
	harnessSamples++
	runParserBudget(t, *budgetExtended, harnessSamples)
}

type measurementOracle struct {
	Accepted bool
	Arities  []uint32
	Error    string
	Tree     string
}

func eraseMeasurementComments(n *yaml.Node) {
	if n == nil {
		return
	}
	n.HeadComment, n.LineComment, n.FootComment = "", "", ""
	for _, child := range n.Content {
		eraseMeasurementComments(child)
	}
}

func measurementReference(t *testing.T, c parserInput) measurementOracle {
	t.Helper()
	path := os.Getenv("RICEVANTA_REFERENCE")
	if path == "" {
		t.Fatal("missing independent classification")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var cases map[string]measurementOracle
	if err := json.Unmarshal(data, &cases); err != nil {
		t.Fatal(err)
	}
	v, ok := cases[c.Name+"/"+strconv.Itoa(c.Size)]
	if !ok {
		t.Fatal("unclassified measurement recipe")
	}
	return v
}

// decodeParserMeasurement is the parent report path used by every sample.
func decodeParserMeasurement(data []byte) (parserMeasurement, error) {
	var m parserMeasurement
	if err := json.Unmarshal(data, &m); err != nil {
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
	if m.ProcsBefore != 1 || m.ProcsAfter != 1 {
		return m, fmt.Errorf("GOMAXPROCS must stay at 1: %+v", m)
	}
	if m.MemoryLimitBefore != math.MaxInt64 || m.MemoryLimitAfter != math.MaxInt64 {
		return m, fmt.Errorf("memory limit must stay disabled: %+v", m)
	}
	if m.GCPercentBefore != math.MaxUint64 || m.GCPercentAfter != math.MaxUint64 || m.GCBefore != m.GCAfter {
		return m, fmt.Errorf("GC must stay disabled through both snapshots: %+v", m)
	}
	if m.Alloc > m.LedgerBytes || m.Objects > m.LedgerObjects {
		return m, fmt.Errorf("source charge below measured allocation: %+v", m)
	}
	if m.Alloc > 64<<20 || m.Objects > 1000000 || m.StackGrowth > 8<<20 {
		return m, fmt.Errorf("parser budget exceeded: %+v", m)
	}
	return m, nil
}
