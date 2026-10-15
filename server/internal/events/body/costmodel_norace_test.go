//go:build !race

package body

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/events/admission"
)

// costMeasurementKeys are the fields every COST_MEASUREMENT line carries.
var costMeasurementKeys = []string{"case", "mode", "shape", "n", "window", "size", "weight", "baseline", "limit", "lines", "allocs", "cpu_ms", "wall_ms", "peak", "peak_ratio", "vmhwm", "gc_cycles", "limiter_cycle"}

// TestDecodeCostModel proves the admission weight model of ingest admission
// section 2 against the decoder that ships (section 9). The parent generates
// every frame, then runs one child per case under a memory limit the child
// sets itself, and one without a limit for the wall-time reference.
//
// Every case runs when the test is selected alone with
// -run '^TestDecodeCostModel$', as the CI command does. Other runs, such as the
// ordinary suite, measure only costModelSmoke. RICEVANTA_COST_MODEL_CASES
// selects case keys by regular expression for reduced local runs.
func TestDecodeCostModel(t *testing.T) {
	if os.Getenv(costChildEnv) != "" {
		costChild(t)
		return
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	pattern := os.Getenv("RICEVANTA_COST_MODEL_CASES")
	if run := flag.Lookup("test.run"); pattern == "" && (run == nil || run.Value.String() != "^TestDecodeCostModel$") {
		pattern = costModelSmoke
	}
	selector := regexp.MustCompile(pattern)
	var cases []costCase
	for _, c := range costCases() {
		if selector.MatchString(c.key()) {
			cases = append(cases, c)
		}
	}
	if len(cases) == 0 {
		t.Fatal("no cost-model case selected")
	}
	type generated struct {
		path                 string
		lines                int
		window, size         uint64
		badID, hostile, flat bool
	}
	dir := t.TempDir()
	frames := map[string]generated{}
	for _, s := range costShapes() {
		needed := false
		for _, c := range cases {
			needed = needed || c.shape == s.name
		}
		if !needed {
			continue
		}
		plain := s.plain()
		frame := encodeCostFrame(t, plain, s.single)
		f, err := ReadFrame(&io.LimitedReader{R: bytes.NewReader(frame), N: compressedBudget})
		if err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, s.name+".zst")
		if err := os.WriteFile(path, frame, 0o600); err != nil {
			t.Fatal(err)
		}
		frames[s.name] = generated{path, bytes.Count(plain, []byte{'\n'}), f.Window(), f.ContentSize(), s.badID, s.hostile, s.flat}
		t.Logf("COST_FRAME shape=%s size=%d lines=%d compressed=%d window=%d", s.name, len(plain), frames[s.name].lines, len(frame), f.Window())
	}
	var hostileCPU, flatCPU int64
	for _, c := range cases {
		g := frames[c.shape]
		results := map[string]map[string]string{}
		for _, mode := range []string{"limited", "reference"} {
			cmd := exec.Command(exe, "-test.run=^TestDecodeCostModel$", "-test.v", "-test.count=1", "-test.timeout=10m")
			cmd.Env = append(os.Environ(), "GOGC=100", "GOMEMLIMIT=off", costChildEnv+"="+g.path,
				"RICEVANTA_COST_CASE="+c.key(), "RICEVANTA_COST_MODE="+mode, "RICEVANTA_COST_SHAPE="+c.shape,
				"RICEVANTA_COST_N="+strconv.Itoa(c.n), "RICEVANTA_COST_LINES="+strconv.Itoa(g.lines),
				"RICEVANTA_COST_WINDOW="+strconv.FormatUint(g.window, 10), "RICEVANTA_COST_SIZE="+strconv.FormatUint(g.size, 10),
				"RICEVANTA_COST_BADID="+strconv.FormatBool(g.badID))
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s %s child failed: %v\n%s", c.key(), mode, err, output)
			}
			fields, err := parseCostMeasurement(output, c.key(), mode)
			if err != nil {
				t.Fatalf("%s %s: %v\n%s", c.key(), mode, err, output)
			}
			t.Log(fields["line"])
			results[mode] = fields
		}
		limited, reference := results["limited"], results["reference"]
		if limited["limiter_cycle"] != "0" {
			t.Errorf("%s: the GC CPU limiter engaged at cycle %s", c.key(), limited["limiter_cycle"])
		}
		peak, _ := strconv.ParseFloat(limited["peak_ratio"], 64)
		if peak > 1.1 {
			t.Errorf("%s: peak %s is %.3f of the limit %s", c.key(), limited["peak"], peak, limited["limit"])
		}
		wall, _ := strconv.ParseInt(limited["wall_ms"], 10, 64)
		refWall, _ := strconv.ParseInt(reference["wall_ms"], 10, 64)
		ratio := float64(wall) / float64(max(refWall, 1))
		t.Logf("COST_CASE case=%s peak_ratio=%.3f wall_ratio=%.3f", c.key(), peak, ratio)
		if wall > 2*refWall {
			t.Errorf("%s: limited wall %d ms exceeds twice the reference %d ms", c.key(), wall, refWall)
		}
		if c.n == 1 {
			cpu, _ := strconv.ParseInt(reference["cpu_ms"], 10, 64)
			if g.hostile {
				hostileCPU = max(hostileCPU, cpu)
			}
			if g.flat {
				flatCPU = max(flatCPU, cpu)
			}
		}
	}
	if hostileCPU > 0 && flatCPU > 0 {
		ratio := float64(hostileCPU) / float64(flatCPU)
		t.Logf("COST_CPU_RATIO hostile_cpu_ms=%d flat_cpu_ms=%d ratio=%.3f", hostileCPU, flatCPU, ratio)
		if ratio > 1.5 {
			t.Logf("COST_CPU_RATIO above 1.5: the 5.0 s planning maximum returns to design (report only)")
		}
	}
}

// parseCostMeasurement requires exactly one well-formed COST_MEASUREMENT line
// for the expected case and mode.
func parseCostMeasurement(output []byte, key, mode string) (map[string]string, error) {
	var found map[string]string
	for _, line := range strings.Split(string(output), "\n") {
		i := strings.Index(line, "COST_MEASUREMENT ")
		if i < 0 {
			continue
		}
		if found != nil {
			return nil, errorString("duplicate measurement line")
		}
		found = map[string]string{"line": strings.TrimSpace(line[i:])}
		for _, field := range strings.Fields(line[i+len("COST_MEASUREMENT "):]) {
			k, v, ok := strings.Cut(field, "=")
			if !ok || v == "" {
				return nil, errorString("malformed field " + field)
			}
			if _, dup := found[k]; dup {
				return nil, errorString("duplicate field " + k)
			}
			found[k] = v
		}
	}
	if found == nil {
		return nil, errorString("missing measurement line")
	}
	if len(found) != len(costMeasurementKeys)+1 {
		return nil, errorString("unexpected measurement fields")
	}
	for _, k := range costMeasurementKeys {
		v, ok := found[k]
		if !ok {
			return nil, errorString("missing field " + k)
		}
		switch k {
		case "case", "mode", "shape":
		case "peak_ratio":
			if _, err := strconv.ParseFloat(v, 64); err != nil {
				return nil, errorString("malformed " + k)
			}
		default:
			if _, err := strconv.ParseInt(v, 10, 64); err != nil {
				return nil, errorString("malformed " + k)
			}
		}
	}
	if found["case"] != key || found["mode"] != mode {
		return nil, errorString("measurement for another case")
	}
	return found, nil
}

type errorString string

func (e errorString) Error() string { return string(e) }

const (
	costChildEnv   = "RICEVANTA_COST_CHILD"
	costModelSmoke = `^(badid-10000-single|minok-10000-single)/1$`
)

func costEnvInt(t *testing.T, name string) int64 {
	t.Helper()
	v, err := strconv.ParseInt(os.Getenv(name), 10, 64)
	if err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return v
}

func readUint64Metric(name string) uint64 {
	sample := []metrics.Sample{{Name: name}}
	metrics.Read(sample)
	if sample[0].Value.Kind() != metrics.KindUint64 {
		return 0
	}
	return sample[0].Value.Uint64()
}

// usedMemory is the quantity debug.SetMemoryLimit bounds: total mapped
// runtime memory minus memory released to the operating system.
func usedMemory() uint64 {
	sample := []metrics.Sample{{Name: "/memory/classes/total:bytes"}, {Name: "/memory/classes/heap/released:bytes"}}
	metrics.Read(sample)
	return sample[0].Value.Uint64() - sample[1].Value.Uint64()
}

// processCPU returns user plus system CPU time from /proc/self/stat (clock
// ticks of 10 ms), or the runtime's own CPU estimate where /proc is absent.
func processCPU() time.Duration {
	if b, err := os.ReadFile("/proc/self/stat"); err == nil {
		if i := bytes.LastIndexByte(b, ')'); i > 0 {
			fields := strings.Fields(string(b[i+1:]))
			if len(fields) > 13 {
				user, e1 := strconv.ParseInt(fields[11], 10, 64)
				system, e2 := strconv.ParseInt(fields[12], 10, 64)
				if e1 == nil && e2 == nil {
					return time.Duration(user+system) * 10 * time.Millisecond
				}
			}
		}
	}
	sample := []metrics.Sample{{Name: "/cpu/classes/user:cpu-seconds"}, {Name: "/cpu/classes/gc/total:cpu-seconds"}, {Name: "/cpu/classes/scavenge/total:cpu-seconds"}}
	metrics.Read(sample)
	seconds := 0.0
	for _, s := range sample {
		if s.Value.Kind() == metrics.KindFloat64 {
			seconds += s.Value.Float64()
		}
	}
	return time.Duration(seconds * float64(time.Second))
}

func vmHWM() uint64 {
	b, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return 0
	}
	for _, line := range strings.Split(string(b), "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "VmHWM:" {
			kb, _ := strconv.ParseUint(fields[1], 10, 64)
			return kb * 1024
		}
	}
	return 0
}

// costChild runs N concurrent decodes of one frame and prints one
// COST_MEASUREMENT line.
func costChild(t *testing.T) {
	key, mode, shape := os.Getenv("RICEVANTA_COST_CASE"), os.Getenv("RICEVANTA_COST_MODE"), os.Getenv("RICEVANTA_COST_SHAPE")
	n := int(costEnvInt(t, "RICEVANTA_COST_N"))
	lines := int(costEnvInt(t, "RICEVANTA_COST_LINES"))
	window := uint64(costEnvInt(t, "RICEVANTA_COST_WINDOW"))
	size := uint64(costEnvInt(t, "RICEVANTA_COST_SIZE"))
	badID := os.Getenv("RICEVANTA_COST_BADID") == "true"
	frame, err := os.ReadFile(os.Getenv(costChildEnv))
	if err != nil {
		t.Fatal(err)
	}
	weight, err := admission.Weight(window, size)
	if err != nil {
		t.Fatal(err)
	}
	d := costDescriptor(lines)
	runtime.GC()
	baseline := usedMemory()
	limit := int64(baseline) + int64(n)*weight
	if mode == "limited" {
		debug.SetMemoryLimit(limit)
	}
	fmt.Printf("COST_LIMIT case=%s mode=%s baseline=%d limit=%d\n", key, mode, baseline, limit)
	allocs0 := readUint64Metric("/gc/heap/allocs:objects")
	gc0 := readUint64Metric("/gc/cycles/total:gc-cycles")
	var peak atomic.Uint64
	peak.Store(baseline)
	sample := func() {
		used := usedMemory()
		for {
			old := peak.Load()
			if used <= old || peak.CompareAndSwap(old, used) {
				return
			}
		}
	}
	done, sampled := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(sampled)
		ticker := time.NewTicker(time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-ticker.C:
				sample()
			case <-done:
				return
			}
		}
	}()
	cpu0 := processCPU()
	start := time.Now()
	results := make([][]Line, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i], errs[i] = Decode(&io.LimitedReader{R: bytes.NewReader(frame), N: compressedBudget}, d, "device-a")
		}()
	}
	wg.Wait()
	wall := time.Since(start)
	cpu := processCPU() - cpu0
	sample()
	close(done)
	<-sampled
	allocs := readUint64Metric("/gc/heap/allocs:objects") - allocs0
	cycles := readUint64Metric("/gc/cycles/total:gc-cycles") - gc0
	limiterCycle := readUint64Metric("/gc/limiter/last-enabled:gc-cycle")
	hwm := vmHWM()
	for i := range n {
		if errs[i] != nil || len(results[i]) != lines {
			t.Fatalf("decode %d: %v, %d lines, want %d", i, errs[i], len(results[i]), lines)
		}
		for _, line := range results[i] {
			if badID && !errors.Is(line.Err, ErrEventID) || !badID && line.Err != nil {
				t.Fatalf("decode %d line %d: %v", i, line.Number, line.Err)
			}
		}
	}
	runtime.KeepAlive(results)
	fmt.Printf("COST_MEASUREMENT case=%s mode=%s shape=%s n=%d window=%d size=%d weight=%d baseline=%d limit=%d lines=%d allocs=%d cpu_ms=%d wall_ms=%d peak=%d peak_ratio=%.3f vmhwm=%d gc_cycles=%d limiter_cycle=%d\n",
		key, mode, shape, n, window, size, weight, baseline, limit, lines, allocs, cpu.Milliseconds(), wall.Milliseconds(), peak.Load(), float64(peak.Load())/float64(limit), hwm, cycles, limiterCycle)
}
