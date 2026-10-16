//go:build !race

package body

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/events/admission"
)

// Diagnostic branch only. This test writes no qualification receipt and must
// be removed before a landing PR. The original 50-case test stays unchanged.
func TestIngestCostDiagnose(t *testing.T) {
	if os.Getenv("RICEVANTA_INGEST_DIAG_CHILD") == "1" {
		ingestCostDiagnostics = newCostMemoryDiagnostics()
		defer ingestCostDiagnostics.dump()
		costDiagnosePhase("entry", 0)
		costChild(t)
		return
	}
	if os.Getenv("RICEVANTA_INGEST_DIAGNOSE") != "1" {
		t.Fatal("temporary diagnosis requires RICEVANTA_INGEST_DIAGNOSE=1")
	}
	c := adversarialCostInput(t, "blocks-4m-over")
	checkCostInput(t, c)
	framePath := filepath.Join(t.TempDir(), "blocks-4m-over.zst")
	if err := os.WriteFile(framePath, c.frame, 0o600); err != nil {
		t.Fatal(err)
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(exe, "-test.run=^TestIngestCostDiagnose$", "-test.v", "-test.count=1", "-test.timeout=10m")
	// Only public diagnostic parameters are passed. Do not dump or inherit an
	// arbitrary environment into the retained diagnostic output.
	cmd.Env = []string{
		"GOGC=100", "GOMEMLIMIT=off", "GODEBUG=gctrace=1,scavtrace=1",
		"RICEVANTA_INGEST_DIAG_CHILD=1", costChildEnv + "=" + framePath,
		"RICEVANTA_COST_CASE=blocks-4m-over", "RICEVANTA_COST_MODE=limited", "RICEVANTA_COST_SHAPE=blocks-4m-over",
		"RICEVANTA_COST_N=1", "RICEVANTA_COST_LINES=4", "RICEVANTA_COST_WINDOW=4194304", "RICEVANTA_COST_SIZE=4194304",
		"RICEVANTA_COST_BADID=false", "RICEVANTA_COST_ERROR=" + errorName(c.want),
		"RICEVANTA_COST_BLOCKS=34", "RICEVANTA_COST_CODECS=0", "RICEVANTA_COST_RATE=false",
	}
	t.Logf("DIAG_CHILD_ARGV=%q", cmd.Args)
	t.Logf("DIAG_HOST go=%s os=%s arch=%s cpus=%d gomaxprocs=%d", runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0))
	output, err := cmd.CombinedOutput()
	t.Logf("%s", output)
	if err != nil {
		t.Fatalf("blocks-4m-over limited diagnostic child failed: %v", err)
	}
	limited, err := parseCostMeasurement(output, costTag("limited"), "blocks-4m-over", "limited")
	if err != nil {
		t.Fatal(err)
	}
	if err := validateCostValues(limited, 1, 4<<20, 4<<20, admission.CompressedWeight, admission.MinCharge); err != nil {
		t.Fatal(err)
	}
	if limited["repeats"] != "32" || limited["blocks"] != "34" || limited["codecs"] != "0" {
		t.Fatalf("diagnostic changed the measured input: repeats=%s blocks=%s codecs=%s", limited["repeats"], limited["blocks"], limited["codecs"])
	}
	// These are the original limited-memory acceptance assertions, unchanged.
	if limited["limiter_cycle"] != "0" {
		t.Errorf("%s: the GC CPU limiter engaged at cycle %s", "blocks-4m-over", limited["limiter_cycle"])
	}
	peak, _ := strconv.ParseFloat(limited["peak_ratio"], 64)
	peakBytes, _ := strconv.ParseUint(limited["peak"], 10, 64)
	limitBytes, _ := strconv.ParseUint(limited["limit"], 10, 64)
	if float64(peakBytes) > 1.1*float64(limitBytes) {
		t.Errorf("%s: peak %s is %.3f of the limit %s", "blocks-4m-over", limited["peak"], peak, limited["limit"])
	}
}

var ingestCostDiagnostics *costMemoryDiagnostics

var costDiagnosticMetricNames = [...]string{
	"/memory/classes/total:bytes", "/memory/classes/heap/released:bytes",
	"/memory/classes/heap/objects:bytes", "/memory/classes/heap/free:bytes", "/memory/classes/heap/unused:bytes",
	"/memory/classes/heap/stacks:bytes", "/memory/classes/os-stacks:bytes",
	"/memory/classes/metadata/mcache/inuse:bytes", "/memory/classes/metadata/mcache/free:bytes",
	"/memory/classes/metadata/mspan/inuse:bytes", "/memory/classes/metadata/mspan/free:bytes",
	"/memory/classes/metadata/other:bytes", "/memory/classes/other:bytes", "/memory/classes/profiling/buckets:bytes",
	"/gc/heap/live:bytes", "/gc/heap/objects:objects", "/gc/heap/goal:bytes",
	"/gc/cycles/total:gc-cycles", "/gc/limiter/last-enabled:gc-cycle", "/sched/goroutines:goroutines",
}

var costDiagnosticMetricKeys = [...]string{
	"total", "released", "heap_objects", "heap_free", "heap_unused", "heap_stacks", "os_stacks",
	"mcache_inuse", "mcache_free", "mspan_inuse", "mspan_free", "metadata_other", "other", "profiling",
	"gc_live", "gc_objects", "gc_goal", "gc_cycles", "limiter_cycle", "goroutines",
}

type costMemoryRecord struct {
	source, phase string
	iteration     int
	elapsed       time.Duration
	values        [len(costDiagnosticMetricNames)]uint64
}

// Memory records use fixed storage established before the baseline. Retained
// output is bounded to 256 records plus one final maximal cost-sample record.
// This observer affects runtime state and provides diagnosis, never proof.
type costMemoryDiagnostics struct {
	mu              sync.Mutex
	start           time.Time
	samples         [len(costDiagnosticMetricNames)]metrics.Sample
	records         [256]costMemoryRecord
	n, peaks, drops int
	phase           string
	iteration       int
	maxCostSample   costMemoryRecord
}

func newCostMemoryDiagnostics() *costMemoryDiagnostics {
	d := &costMemoryDiagnostics{start: time.Now()}
	for i, name := range costDiagnosticMetricNames {
		d.samples[i].Name = name
	}
	return d
}

func costDiagnosePhase(phase string, iteration int) {
	if ingestCostDiagnostics != nil {
		ingestCostDiagnostics.capture("phase", phase, iteration)
	}
}

func (d *costMemoryDiagnostics) capture(source, phase string, iteration int) uint64 {
	d.mu.Lock()
	defer d.mu.Unlock()
	if phase != "" {
		d.phase, d.iteration = phase, iteration
	}
	metrics.Read(d.samples[:])
	r := costMemoryRecord{source: source, phase: d.phase, iteration: d.iteration, elapsed: time.Since(d.start)}
	for i, s := range d.samples {
		if s.Value.Kind() != metrics.KindUint64 {
			panic("unsupported diagnostic metric: " + s.Name)
		}
		r.values[i] = s.Value.Uint64()
	}
	used := r.values[0] - r.values[1]
	if source == "cost-sample" {
		if used <= d.maxCostSample.values[0]-d.maxCostSample.values[1] {
			return used
		}
		d.maxCostSample = r
		if d.peaks >= 64 {
			d.drops++
			return used
		}
		d.peaks++
	}
	if d.n < len(d.records) {
		d.records[d.n] = r
		d.n++
	} else {
		d.drops++
	}
	return used
}

func (d *costMemoryDiagnostics) dump() {
	d.mu.Lock()
	defer d.mu.Unlock()
	printRecord := func(seq int, r costMemoryRecord) {
		var out strings.Builder
		fmt.Fprintf(&out, "DIAG_MEM seq=%d source=%s phase=%s iteration=%d elapsed_ns=%d used=%d", seq, r.source, r.phase, r.iteration, r.elapsed.Nanoseconds(), r.values[0]-r.values[1])
		for i, key := range costDiagnosticMetricKeys {
			fmt.Fprintf(&out, " %s=%d", key, r.values[i])
		}
		fmt.Println(out.String())
	}
	for i, name := range costDiagnosticMetricNames {
		fmt.Printf("DIAG_METRIC key=%s metric=%s\n", costDiagnosticMetricKeys[i], name)
	}
	for i := range d.n {
		printRecord(i, d.records[i])
	}
	d.maxCostSample.source = "max-cost-sample"
	printRecord(d.n, d.maxCostSample)
	fmt.Printf("DIAG_END records=%d new_peak_records=%d dropped_new_peaks_or_records=%d\n", d.n, d.peaks, d.drops)
}
