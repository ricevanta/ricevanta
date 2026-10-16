//go:build !race

package body

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
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
var costMeasurementKeys = []string{"case", "mode", "shape", "n", "window", "size", "weight", "baseline", "limit", "lines", "allocs", "cpu_ms", "wall_ms", "peak", "peak_ratio", "vmhwm", "gc_cycles", "limiter_cycle", "preflight_cpu_ns", "decode_cpu_ns", "cpu_ns", "blocks", "codecs", "paid", "repeats"}

// TestDecodeCostModel proves the admission weight model of ingest admission
// section 2 against the decoder that ships (section 9). The parent generates
// every frame, then runs one child per case under a memory limit the child
// sets itself, and one without a limit for the wall-time reference.
//
// The test runs only with RICEVANTA_COST_MODEL=full, and then runs all 50
// cases of the fixed table whatever -run selects; ordinary go test runs skip
// it. The limited child of each case logs one COST_MEASUREMENT line, the
// reference child one COST_REFERENCE line, and the parent ends with
// COST_MODEL_CASES n=50, which the CI wrapper verifies.
func TestDecodeCostModel(t *testing.T) {
	if os.Getenv(costChildEnv) != "" {
		costChild(t)
		return
	}
	if os.Getenv("RICEVANTA_COST_MODEL") != "full" {
		t.Skip("set RICEVANTA_COST_MODEL=full to run the ingest cost model")
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cases := costCases()
	if len(cases) != costModelCases {
		t.Fatalf("%d cost-model cases, want %d", len(cases), costModelCases)
	}
	type generated struct {
		path                 string
		lines                int
		window, size         uint64
		badID, hostile, flat bool
		input                *costInput
		digest               [32]byte
		compressed           int
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
		frames[s.name] = generated{path, bytes.Count(plain, []byte{'\n'}), f.Window(), f.ContentSize(), s.badID, s.hostile, s.flat, nil, sha256.Sum256(frame), len(frame)}
		t.Logf("COST_FRAME shape=%s size=%d lines=%d compressed=%d window=%d", s.name, len(plain), frames[s.name].lines, len(frame), f.Window())
	}
	for _, key := range adversarialCostKeys {
		c := adversarialCostInput(t, key)
		path := filepath.Join(dir, key+".zst")
		if err := os.WriteFile(path, c.frame, 0600); err != nil {
			t.Fatal(err)
		}
		digest, compressed := sha256.Sum256(c.frame), len(c.frame)
		c.frame = nil // Only the child needs compressed bytes after the file is written.
		frames[key] = generated{path: path, lines: c.lines, window: c.window, size: c.size, input: &c, digest: digest, compressed: compressed}
	}
	t.Logf("COST_TOOLCHAIN go=%s arch=%s compiler=%s", runtime.Version(), runtime.GOARCH, runtime.Compiler)
	for _, c := range cases {
		g := frames[c.shape]
		t.Logf("COST_FIXTURE case=%s sha256=%x compressed=%d", c.key(), g.digest, g.compressed)
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
			if g.input != nil {
				c := g.input
				cmd.Env = append(cmd.Env, "RICEVANTA_COST_ERROR="+errorName(c.want), "RICEVANTA_COST_BLOCKS="+strconv.Itoa(c.blocks), "RICEVANTA_COST_CODECS="+strconv.Itoa(c.codecs), "RICEVANTA_COST_RATE="+strconv.FormatBool(c.rateDeficit))
			}
			output, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("%s %s child failed: %v\n%s", c.key(), mode, err, output)
			}
			fields, err := parseCostMeasurement(output, costTag(mode), c.key(), mode)
			if err != nil {
				t.Fatalf("%s %s: %v\n%s", c.key(), mode, err, output)
			}
			if fields["shape"] != c.shape || fields["lines"] != strconv.Itoa(g.lines) {
				t.Fatalf("%s: wrong measurement shape or line count\n%s", c.key(), output)
			}
			if g.input != nil && (fields["blocks"] != strconv.Itoa(g.input.blocks) || fields["codecs"] != strconv.Itoa(g.input.codecs)) {
				t.Fatalf("%s: wrong preflight or codec stage\n%s", c.key(), output)
			}
			weight, _ := admission.Weight(g.window, g.size)
			paid := max(g.window, g.size, admission.MinCharge)
			if g.input != nil && g.input.codecs == 0 {
				weight = admission.CompressedWeight
				paid = admission.MinCharge
			}
			if err := validateCostChildValues(output, fields, c.n, g.window, g.size, weight, paid); err != nil {
				t.Fatalf("%s %s: %v", c.key(), mode, err)
			}
			cpuLines, _ := validateCostCPU(output, fields, c.n, paid)
			for _, line := range cpuLines {
				t.Log(line)
			}
			t.Log(fields["line"])
			results[mode] = fields
		}
		limited, reference := results["limited"], results["reference"]
		if limited["limiter_cycle"] != "0" {
			t.Errorf("%s: the GC CPU limiter engaged at cycle %s", c.key(), limited["limiter_cycle"])
		}
		peak, _ := strconv.ParseFloat(limited["peak_ratio"], 64)
		peakBytes, _ := strconv.ParseUint(limited["peak"], 10, 64)
		limitBytes, _ := strconv.ParseUint(limited["limit"], 10, 64)
		if float64(peakBytes) > 1.1*float64(limitBytes) {
			t.Errorf("%s: peak %s is %.3f of the limit %s", c.key(), limited["peak"], peak, limited["limit"])
		}
		wall, _ := strconv.ParseInt(limited["wall_ms"], 10, 64)
		refWall, _ := strconv.ParseInt(reference["wall_ms"], 10, 64)
		ratio := float64(wall) / float64(max(refWall, 1))
		t.Logf("COST_CASE case=%s peak_ratio=%.3f wall_ratio=%.3f", c.key(), peak, ratio)
		// Twice the reference from 500 ms, else the reference plus 500 ms:
		// children of 25 to 100 ms vary by more than twice between identical runs.
		if bound := costWallBound(refWall); wall > bound {
			t.Errorf("%s: limited wall %d ms exceeds %d ms for a reference of %d ms", c.key(), wall, bound, refWall)
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
	t.Logf("COST_MODEL_CASES n=%d", len(cases))
	if hostileCPU > 0 && flatCPU > 0 {
		ratio := float64(hostileCPU) / float64(flatCPU)
		t.Logf("COST_CPU_RATIO hostile_cpu_ms=%d flat_cpu_ms=%d ratio=%.3f", hostileCPU, flatCPU, ratio)
	}
}

const costModelCases = 50

// costWallBound is the most wall time in milliseconds the limited child may
// take: twice a reference of at least 500 ms, else the reference plus 500 ms.
func costWallBound(reference int64) int64 {
	if reference >= 500 {
		return 2 * reference
	}
	return reference + 500
}

func costTag(mode string) string {
	if mode == "limited" {
		return "COST_MEASUREMENT"
	}
	return "COST_REFERENCE"
}

// parseCostMeasurement requires exactly one well-formed line with tag for the
// expected case and mode.
func parseCostMeasurement(output []byte, tag, key, mode string) (map[string]string, error) {
	var found map[string]string
	for _, line := range strings.Split(string(output), "\n") {
		i := strings.Index(line, tag+" ")
		if i < 0 {
			continue
		}
		if found != nil {
			return nil, errorString("duplicate measurement line")
		}
		found = map[string]string{"line": strings.TrimSpace(line[i:])}
		for _, field := range strings.Fields(line[i+len(tag)+1:]) {
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
			if n, err := strconv.ParseFloat(v, 64); err != nil || math.IsNaN(n) || math.IsInf(n, 0) || n < 0 {
				return nil, errorString("malformed " + k)
			}
		default:
			if n, err := strconv.ParseInt(v, 10, 64); err != nil || n < 0 {
				return nil, errorString("malformed " + k)
			}
		}
	}
	if found["case"] != key || found["mode"] != mode {
		return nil, errorString("measurement for another case")
	}
	return found, nil
}

// validateCostChildValues preserves the child's complete diagnostic output when
// a successful child process reports a measurement that fails validation.
func validateCostChildValues(output []byte, f map[string]string, n int, window, size uint64, weight int64, paid uint64) error {
	if err := validateCostValues(f, n, window, size, weight, paid); err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	if _, err := validateCostCPU(output, f, n, paid); err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

// validateCostValues binds measured numbers to the generated input and checks
// relationships that could otherwise hide a stale or misreported measurement.
func validateCostValues(f map[string]string, n int, window, size uint64, weight int64, paid uint64) error {
	expected := map[string]uint64{"n": uint64(n), "window": window, "size": size, "weight": uint64(weight), "paid": paid}
	for k, want := range expected {
		got, err := strconv.ParseUint(f[k], 10, 64)
		if err != nil || got != want {
			return errorString("wrong measurement " + k)
		}
	}
	read := func(k string) int64 { v, _ := strconv.ParseInt(f[k], 10, 64); return v }
	baseline, limit, peak := read("baseline"), read("limit"), read("peak")
	if baseline <= 0 || limit != baseline+int64(n)*weight || peak < baseline || read("repeats") <= 0 {
		return errorString("invalid measurement memory or repetitions")
	}
	ratio, err := strconv.ParseFloat(f["peak_ratio"], 64)
	if err != nil || math.Abs(ratio-float64(peak)/float64(limit)) > .00051 {
		return errorString("inconsistent peak ratio")
	}
	if (size <= 128<<10 || paid == admission.MinCharge) && read("repeats") < 2 {
		return errorString("short measurement was not repeated")
	}
	cpu := read("cpu_ns")
	if cpu < 0 || cpu != read("preflight_cpu_ns")+read("decode_cpu_ns") || read("cpu_ms") != cpu/int64(time.Millisecond) {
		return errorString("inconsistent CPU measurement")
	}
	if cpu > int64(5*time.Second)*int64(paid)/(64<<20) {
		return errorString("CPU exceeds paid-charge bound")
	}
	return nil
}

type errorString string

func (e errorString) Error() string { return string(e) }

const costChildEnv = "RICEVANTA_COST_CHILD"

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
	var want error
	for _, e := range []error{ErrFrame, ErrChecksum, ErrContentSize} {
		if errorName(e) == os.Getenv("RICEVANTA_COST_ERROR") {
			want = e
		}
	}
	codecs := 1
	blocks := uint64(0)
	if os.Getenv("RICEVANTA_COST_CODECS") != "" {
		codecs = int(costEnvInt(t, "RICEVANTA_COST_CODECS"))
	}
	_, _, preflightErr := inspectFrameCount(frame, &blocks)
	if os.Getenv("RICEVANTA_COST_BLOCKS") != "" && blocks != uint64(costEnvInt(t, "RICEVANTA_COST_BLOCKS")) {
		t.Fatalf("header visits %d", blocks)
	}
	if codecs == 0 {
		weight = admission.CompressedWeight
	}
	paid := max(window, size, admission.MinCharge)
	if codecs == 0 {
		paid = admission.MinCharge
	}
	if codecs == 0 && os.Getenv("RICEVANTA_COST_RATE") == "true" && preflightErr != nil {
		t.Fatalf("rate case preflight: %v", preflightErr)
	}
	repeats := 1
	if size <= 128<<10 || codecs == 0 {
		repeats = 32
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
	start := time.Now()
	var codecCalls atomic.Int64
	results := make([][]Line, n)
	frames := make([]Frame, n)
	errs := make([]error, n)
	// This noinline allocator is deliberately after the unchanged baseline and limit.
	cpuStorage := newCostCPUStorage()
	cpuStorage.readErr = cpuStorage.clock.read(&cpuStorage.samples[0])
	cpuStorage.count = 0
	if cpuStorage.readErr == nil {
		cpuStorage.count = 1
	}
	for iteration := 0; iteration < repeats && cpuStorage.readErr == nil; iteration++ {
		var wg sync.WaitGroup
		for i := range n {
			wg.Add(1)
			go func() {
				defer wg.Done()
				frames[i], errs[i] = ReadFrame(&io.LimitedReader{R: bytes.NewReader(frame), N: compressedBudget})
			}()
		}
		wg.Wait()
		cpuStorage.readErr = cpuStorage.clock.read(&cpuStorage.samples[2*iteration+1])
		if cpuStorage.readErr != nil {
			break
		}
		cpuStorage.count++
		for i := range n {
			if codecs == 0 {
				if os.Getenv("RICEVANTA_COST_RATE") == "true" {
					costRateRefusal(t, window, size)
				} else if !errors.Is(errs[i], want) {
					t.Fatalf("preflight: %v want %v", errs[i], want)
				}
				continue
			}
			if errs[i] != nil {
				t.Fatalf("preflight: %v", errs[i])
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				codecCalls.Add(1)
				results[i], errs[i] = DecodeFrame(frames[i], d, "device-a")
			}()
		}
		wg.Wait()
		for i := range n {
			if codecs != 0 && (!errors.Is(errs[i], want) || want != nil && results[i] != nil || want == nil && len(results[i]) != lines) {
				t.Fatalf("decode: %v lines=%d want=%v", errs[i], len(results[i]), want)
			}
			for _, line := range results[i] {
				if badID && !errors.Is(line.Err, ErrEventID) || !badID && line.Err != nil {
					t.Fatalf("line: %v", line.Err)
				}
			}
		}
		sample()
		if repeats > 1 {
			clear(frames)
			clear(results)
			runtime.GC()
		}
		cpuStorage.readErr = cpuStorage.clock.read(&cpuStorage.samples[2*iteration+2])
		if cpuStorage.readErr == nil {
			cpuStorage.count++
		}
	}
	if cpuStorage.readErr == nil && codecCalls.Load() != int64(codecs*n*repeats) {
		t.Fatalf("codec entries=%d", codecCalls.Load())
	}
	wall := time.Since(start) / time.Duration(repeats)
	cpuStorage.normalize(n, repeats)

	sample()
	close(done)
	<-sampled
	allocs := readUint64Metric("/gc/heap/allocs:objects") - allocs0
	cycles := readUint64Metric("/gc/cycles/total:gc-cycles") - gc0
	limiterCycle := readUint64Metric("/gc/limiter/last-enabled:gc-cycle")
	hwm := vmHWM()
	runtime.KeepAlive(results)
	emitCostCPULedger(t, cpuStorage, key, mode, n, repeats)
	fmt.Printf("%s case=%s mode=%s shape=%s n=%d window=%d size=%d weight=%d baseline=%d limit=%d lines=%d allocs=%d cpu_ms=%d wall_ms=%d peak=%d peak_ratio=%.3f vmhwm=%d gc_cycles=%d limiter_cycle=%d preflight_cpu_ns=%d decode_cpu_ns=%d cpu_ns=%d blocks=%d codecs=%d paid=%d repeats=%d\n",
		costTag(mode), key, mode, shape, n, window, size, weight, baseline, limit, lines, allocs, cpuStorage.cpu.Milliseconds(), wall.Milliseconds(), peak.Load(), float64(peak.Load())/float64(limit), hwm, cycles, limiterCycle, cpuStorage.preflight.Nanoseconds(), cpuStorage.decode.Nanoseconds(), cpuStorage.cpu.Nanoseconds(), blocks, codecs, paid, repeats)
}

func TestCostModelHarness(t *testing.T) {
	if n := len(costCases()); n != 50 {
		t.Fatalf("%d cases", n)
	}
	for _, c := range []struct{ reference, bound int64 }{{0, 500}, {31, 531}, {499, 999}, {500, 1000}, {3128, 6256}} {
		if got := costWallBound(c.reference); got != c.bound {
			t.Fatalf("reference %d: bound %d, want %d", c.reference, got, c.bound)
		}
	}
	line := "COST_MEASUREMENT case=a/1 mode=limited shape=a n=1 window=1 size=1 weight=1 baseline=1 limit=1 lines=1 allocs=1 cpu_ms=1 wall_ms=1 peak=1 peak_ratio=0.5 vmhwm=1 gc_cycles=1 limiter_cycle=0 preflight_cpu_ns=1 decode_cpu_ns=1 cpu_ns=2 blocks=1 codecs=1 paid=131072 repeats=1"
	if _, err := parseCostMeasurement([]byte("x\n"+line+"\n"), "COST_MEASUREMENT", "a/1", "limited"); err != nil {
		t.Fatal(err)
	}
	for name, output := range map[string]string{
		"missing":   "nothing\n",
		"duplicate": line + "\n" + line + "\n",
		"malformed": strings.Replace(line, "wall_ms=1", "wall_ms=x", 1),
		"short":     strings.Replace(line, " limiter_cycle=0 preflight_cpu_ns=1 decode_cpu_ns=1 cpu_ns=2 blocks=1 codecs=1 paid=131072 repeats=1", "", 1),
		"other":     strings.Replace(line, "case=a/1", "case=b/1", 1),
	} {
		if _, err := parseCostMeasurement([]byte(output), "COST_MEASUREMENT", "a/1", "limited"); err == nil {
			t.Fatalf("%s accepted", name)
		}
	}
}

func TestCostMeasurementValues(t *testing.T) {
	fields := map[string]string{"n": "1", "window": "103", "size": "103", "weight": "9197000", "paid": "131072", "baseline": "1000000", "limit": "10197000", "peak": "10000000", "peak_ratio": "0.981", "preflight_cpu_ns": "1000000", "decode_cpu_ns": "2000000", "cpu_ns": "3000000", "cpu_ms": "3", "repeats": "32"}
	if err := validateCostValues(fields, 1, 103, 103, 9197000, 131072); err != nil {
		t.Fatal(err)
	}
	for key, value := range map[string]string{"n": "2", "window": "104", "size": "102", "weight": "1", "paid": "67108864", "baseline": "0", "limit": "999999999", "peak": "1", "peak_ratio": "0.1", "cpu_ns": "3000001", "cpu_ms": "4", "repeats": "1"} {
		t.Run(key, func(t *testing.T) {
			copy := make(map[string]string)
			for k, v := range fields {
				copy[k] = v
			}
			copy[key] = value
			if err := validateCostValues(copy, 1, 103, 103, 9197000, 131072); err == nil {
				t.Fatalf("accepted invalid %s", key)
			}
		})
	}
}

func TestCostCPUBoundary(t *testing.T) {
	fields := map[string]string{"case": "boundary", "mode": "limited", "size": "103", "codecs": "0", "repeats": "32", "cpu_ns": "9765562", "preflight_cpu_ns": "0", "decode_cpu_ns": "9765562", "cpu_ms": "9"}
	if _, err := validateCostCPU([]byte(costCPUTestLedger("boundary", "limited", 312498000, 0, 32)), fields, 1, 131072); err != nil {
		t.Fatal(err)
	}
	if _, err := validateCostCPU([]byte(costCPUTestLedger("boundary", "limited", 312498001, 0, 32)), fields, 1, 131072); err == nil {
		t.Fatal("fractional overrun hidden by displayed average")
	}
}

func TestCostChildValidationDiagnostics(t *testing.T) {
	for _, c := range []struct {
		name string
		cpu  int64
		fail bool
	}{
		{"at-bound", 51324304, false},
		{"above-bound", 51324305, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			output := []byte(fmt.Sprintf("=== RUN   TestDecodeCostModel\nCOST_LIMIT case=badid-10000-single/1 mode=limited baseline=5000000 limit=19877646\nCOST_MEASUREMENT case=badid-10000-single/1 mode=limited shape=badid-10000-single n=1 window=688890 size=688890 weight=14877646 baseline=5000000 limit=19877646 lines=10000 allocs=55000 cpu_ms=%d wall_ms=50 peak=18000000 peak_ratio=0.906 vmhwm=20000000 gc_cycles=6 limiter_cycle=0 preflight_cpu_ns=0 decode_cpu_ns=%d cpu_ns=%d blocks=6 codecs=1 paid=688890 repeats=1\n--- PASS: TestDecodeCostModel\n", c.cpu/int64(time.Millisecond), c.cpu, c.cpu))
			output = append([]byte(costCPUTestLedger("badid-10000-single/1", "limited", c.cpu, 0, 1)), output...)
			fields, err := parseCostMeasurement(output, "COST_MEASUREMENT", "badid-10000-single/1", "limited")
			if err != nil {
				t.Fatal(err)
			}
			err = validateCostChildValues(output, fields, 1, 688890, 688890, 14877646, 688890)
			if !c.fail {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			cause := errorString("CPU exceeds paid-charge bound")
			if !errors.Is(err, cause) {
				t.Fatalf("validation: %v, want %v", err, cause)
			}
			if want := string(cause) + "\n" + string(output); err.Error() != want {
				t.Fatalf("validation discarded child diagnostics: %q, want %q", err, want)
			}
		})
	}
}
