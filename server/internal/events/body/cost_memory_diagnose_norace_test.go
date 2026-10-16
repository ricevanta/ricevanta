//go:build !race

package body

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unsafe"

	"github.com/ricevanta/ricevanta/server/internal/events/admission"
)

const (
	memoryDiagScalarSHA = "b290698ed682166309167e3287f6d4836fad402693a5f27567ca053db3c0c897"
	memoryDiagRecords   = 32*4 + 2
	memoryDiagClasses   = 14
	memoryDiagTotal     = 13
	memoryDiagReleased  = 2
)

func memoryDiagSchedule() []string {
	return strings.Fields("A B C D D C B A A C B D")
}

// Every leaf memory class in the pinned Go version, including released heap.
// Their sum is total. Only released heap is removed from the limit quantity.
var memoryDiagNames = [memoryDiagClasses]string{
	"/memory/classes/heap/free:bytes",
	"/memory/classes/heap/objects:bytes",
	"/memory/classes/heap/released:bytes",
	"/memory/classes/heap/stacks:bytes",
	"/memory/classes/heap/unused:bytes",
	"/memory/classes/metadata/mcache/free:bytes",
	"/memory/classes/metadata/mcache/inuse:bytes",
	"/memory/classes/metadata/mspan/free:bytes",
	"/memory/classes/metadata/mspan/inuse:bytes",
	"/memory/classes/metadata/other:bytes",
	"/memory/classes/os-stacks:bytes",
	"/memory/classes/other:bytes",
	"/memory/classes/profiling/buckets:bytes",
	"/memory/classes/total:bytes",
}

type memoryDiagBoundary struct {
	stage    int
	baseline uint64
	record   func(string)
}

func (b *memoryDiagBoundary) baselineRead(value uint64) error {
	if b.stage != 0 || value == 0 {
		return errorString("invalid scalar baseline phase")
	}
	b.baseline, b.stage = value, 1
	if b.record != nil {
		b.record("baseline")
	}
	return nil
}

func (b *memoryDiagBoundary) limitSet(value int64) error {
	if b.stage != 1 || value <= 0 || uint64(value) != b.baseline+uint64(admission.CompressedWeight) {
		return errorString("invalid scalar limit phase")
	}
	b.stage = 2
	if b.record != nil {
		b.record("limit")
	}
	return nil
}

func (b *memoryDiagBoundary) start(create func() *memoryDiagObserver) (*memoryDiagObserver, error) {
	if b.stage != 2 {
		return nil, errorString("observer before scalar baseline and limit")
	}
	b.stage = 3
	if b.record != nil {
		b.record("observer")
	}
	return create(), nil
}

type memoryDiagSnapshot struct {
	ID          uint64
	Iteration   int
	Phase       string
	MonotonicNS int64
	Values      [memoryDiagClasses]uint64
	Used        uint64
}

type memoryDiagObserver struct {
	mu             sync.Mutex
	samples        [memoryDiagClasses]metrics.Sample
	records        [memoryDiagRecords]memoryDiagSnapshot
	maximum        memoryDiagSnapshot
	count          int
	sequence       uint64
	iteration      int
	phase          string
	origin         time.Time
	read           func(*[memoryDiagClasses]metrics.Sample) ([memoryDiagClasses]uint64, error)
	now            func() time.Time
	failure        error
	requestedBytes uint64
	allocatedBytes uint64
	allocations    uint64
	setupCPU       time.Duration
}

func memoryDiagRead(samples *[memoryDiagClasses]metrics.Sample) ([memoryDiagClasses]uint64, error) {
	metrics.Read(samples[:])
	var values [memoryDiagClasses]uint64
	for i := range samples {
		if samples[i].Value.Kind() != metrics.KindUint64 {
			return values, errorString("non-uint64 memory metric")
		}
		values[i] = samples[i].Value.Uint64()
	}
	return values, nil
}

func memoryDiagUsed(values [memoryDiagClasses]uint64) (uint64, error) {
	var sum uint64
	for _, value := range values[:memoryDiagTotal] {
		if value > math.MaxInt64 || sum > math.MaxInt64-value {
			return 0, errorString("memory class sum overflow")
		}
		sum += value
	}
	if sum != values[memoryDiagTotal] || values[memoryDiagReleased] > sum {
		return 0, errorString("inconsistent disjoint memory class sum")
	}
	return sum - values[memoryDiagReleased], nil
}

func newMemoryDiagObserver(baseline uint64, limit int64, peak *atomic.Uint64) (*memoryDiagObserver, error) {
	// These calls certify already completed scalar operations. The source
	// overlay places this factory strictly after SetMemoryLimit and peak.Store.
	var boundary memoryDiagBoundary
	if err := boundary.baselineRead(baseline); err != nil {
		return nil, err
	}
	if err := boundary.limitSet(limit); err != nil {
		return nil, err
	}
	cpu0 := processCPU()
	observer, err := boundary.start(func() *memoryDiagObserver {
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		o := new(memoryDiagObserver)
		o.origin, o.now, o.read = time.Now(), time.Now, memoryDiagRead
		o.phase = "observer-ready"
		o.requestedBytes = uint64(unsafe.Sizeof(*o))
		for i, name := range memoryDiagNames {
			o.samples[i].Name = name
		}
		runtime.ReadMemStats(&after)
		o.allocatedBytes, o.allocations = after.TotalAlloc-before.TotalAlloc, after.Mallocs-before.Mallocs
		if o.requestedBytes > 64<<10 || o.allocatedBytes > 64<<10 {
			o.failure = errorString("observer heap exceeds 64 KiB")
		}
		return o
	})
	if err != nil {
		return nil, err
	}
	observer.mark(0, "observer-ready", "between", peak)
	observer.setupCPU = processCPU() - cpu0
	return observer, nil
}

// captureLocked performs one paired snapshot and maximum update. It never
// formats, writes output, grows storage or starts a goroutine.
func (o *memoryDiagObserver) captureLocked(phase string, peak *atomic.Uint64) memoryDiagSnapshot {
	values, err := o.read(&o.samples)
	if err != nil && o.failure == nil {
		o.failure = err
	}
	used, err := memoryDiagUsed(values)
	if err != nil && o.failure == nil {
		o.failure = err
	}
	o.sequence++
	record := memoryDiagSnapshot{o.sequence, o.iteration, phase, o.now().Sub(o.origin).Nanoseconds(), values, used}
	if o.maximum.ID == 0 || used > o.maximum.Used {
		o.maximum = record
	}
	if used > peak.Load() {
		peak.Store(used)
	}
	return record
}

func (o *memoryDiagObserver) sample(peak *atomic.Uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.captureLocked(o.phase, peak)
}

func (o *memoryDiagObserver) mark(iteration int, phase, next string, peak *atomic.Uint64) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.iteration = iteration
	record := o.captureLocked(phase, peak)
	if o.count == len(o.records) {
		if o.failure == nil {
			o.failure = errorString("observer record capacity overflow")
		}
		return
	}
	o.records[o.count] = record
	o.count++
	o.phase = next
}

func memoryDiagValidateRecords(records []memoryDiagSnapshot, maximum memoryDiagSnapshot, peak uint64) error {
	if len(records) != memoryDiagRecords {
		return errorString("missing observer phases")
	}
	var previousID uint64
	var previousNS int64
	for i, record := range records {
		iteration, phase := 0, "observer-ready"
		if i == memoryDiagRecords-1 {
			iteration, phase = 32, "final"
		} else if i > 0 {
			iteration = (i-1)/4 + 1
			phase = [...]string{"before-worker", "after-worker", "before-gc", "after-gc"}[(i-1)%4]
		}
		if record.Iteration != iteration || record.Phase != phase || record.ID <= previousID || record.MonotonicNS < previousNS {
			return errorString("invalid observer phase sequence")
		}
		used, err := memoryDiagUsed(record.Values)
		if err != nil || used != record.Used || record.Used > maximum.Used {
			return errorString("invalid observer phase memory")
		}
		previousID, previousNS = record.ID, record.MonotonicNS
	}
	used, err := memoryDiagUsed(maximum.Values)
	if err != nil || used != maximum.Used || maximum.Used != peak || maximum.ID == 0 || maximum.MonotonicNS < 0 {
		return errorString("lost or inconsistent peak class record")
	}
	if maximum.ID > previousID {
		// The original scalar sampler includes a final synchronous sample and
		// may tick after the final phase record, before it is joined.
		if maximum.Phase != "final" || maximum.Iteration != 32 || maximum.MonotonicNS < previousNS {
			return errorString("peak after final phase is mislabeled")
		}
		return nil
	}
	for i, record := range records {
		if record.ID == maximum.ID {
			if record != maximum {
				return errorString("peak differs from its phase snapshot")
			}
			return nil
		}
		if record.ID < maximum.ID && i+1 < len(records) && records[i+1].ID > maximum.ID {
			nextPhase := map[string]string{
				"observer-ready": "between", "before-worker": "worker",
				"after-worker": "post-worker", "before-gc": "gc", "after-gc": "between",
			}[record.Phase]
			if nextPhase == "" || maximum.Phase != nextPhase || maximum.Iteration != record.Iteration || maximum.MonotonicNS < record.MonotonicNS || maximum.MonotonicNS > records[i+1].MonotonicNS {
				return errorString("peak has no matching enclosing phase")
			}
			return nil
		}
	}
	return errorString("peak has no matching snapshot sequence")
}

type memoryDiagRecordOutput struct {
	Record                memoryDiagSnapshot
	DeltaObserverReady    [memoryDiagClasses]int64
	HasPriorAfterGC       bool
	PriorAfterGCIteration int
	DeltaPriorAfterGC     [memoryDiagClasses]int64
}

func memoryDiagRecordDeltas(record, ready memoryDiagSnapshot, records []memoryDiagSnapshot) memoryDiagRecordOutput {
	out := memoryDiagRecordOutput{Record: record}
	var prior memoryDiagSnapshot
	for _, candidate := range records {
		if candidate.ID < record.ID && candidate.Phase == "after-gc" {
			prior = candidate
		}
	}
	for i := range record.Values {
		out.DeltaObserverReady[i] = int64(record.Values[i]) - int64(ready.Values[i])
		if prior.ID != 0 {
			out.DeltaPriorAfterGC[i] = int64(record.Values[i]) - int64(prior.Values[i])
		}
	}
	out.HasPriorAfterGC, out.PriorAfterGCIteration = prior.ID != 0, prior.Iteration
	return out
}

func (o *memoryDiagObserver) dump(t *testing.T, peak uint64) {
	// The existing sampler has stopped, and scalar counters have been read.
	// All formatting and I/O, including validation errors, begin here.
	encoder := json.NewEncoder(os.Stdout)
	header := struct {
		Classes        [memoryDiagClasses]string
		RequestedBytes uint64
		AllocatedBytes uint64
		Allocations    uint64
		SetupCPUNS     int64
		Count          int
	}{memoryDiagNames, o.requestedBytes, o.allocatedBytes, o.allocations, o.setupCPU.Nanoseconds(), o.count}
	fmt.Print("MEMORY_DIAG_OBSERVER ")
	if err := encoder.Encode(header); err != nil {
		t.Error(err)
	}
	for _, record := range o.records[:o.count] {
		fmt.Print("MEMORY_DIAG_RECORD ")
		if err := encoder.Encode(memoryDiagRecordDeltas(record, o.records[0], o.records[:o.count])); err != nil {
			t.Error(err)
		}
	}
	fmt.Print("MEMORY_DIAG_MAXIMUM ")
	if err := encoder.Encode(memoryDiagRecordDeltas(o.maximum, o.records[0], o.records[:o.count])); err != nil {
		t.Error(err)
	}
	if o.failure != nil {
		t.Error(o.failure)
	}
	if err := memoryDiagValidateRecords(o.records[:o.count], o.maximum, peak); err != nil {
		t.Error(err)
	}
}

// Only costChild is transformed. The required parent, validator and assertions
// in this scalar source remain byte-identical in every generated arm.
func memoryDiagArmSource(source, arm string) (string, error) {
	if arm != "A" && arm != "B" && arm != "C" && arm != "D" {
		return "", errorString("unknown memory experiment arm")
	}
	if arm == "A" {
		return source, nil
	}
	start := strings.Index(source, "func costChild(t *testing.T) {")
	end := strings.Index(source, "\nfunc TestCostModelHarness(")
	if start < 0 || end <= start {
		return "", errorString("scalar child source boundary changed")
	}
	child := source[start:end]
	replace := func(old, next string) error {
		if strings.Count(child, old) != 1 {
			return fmt.Errorf("arm %s source hook count for %q", arm, old)
		}
		child = strings.Replace(child, old, next, 1)
		return nil
	}
	control := arm == "C" || arm == "D"
	observed := arm == "B" || arm == "D"
	if control {
		edits := [][2]string{
			{"\t\t\t\tframes[i], errs[i] = ReadFrame(&io.LimitedReader{R: bytes.NewReader(frame), N: compressedBudget})",
				"\t\t\t\t_ = i // Control: omit ReadFrame; leave both result slots untouched."},
			{"} else if !errors.Is(errs[i], want) {\n\t\t\t\t\tt.Fatalf(\"preflight: %v want %v\", errs[i], want)\n\t\t\t\t}",
				"}"},
			{"\t\tcostTag(mode), key, mode, shape,", "\t\t\"MEMORY_DIAG_CONTROL\", key, mode, shape,"},
		}
		for _, edit := range edits {
			if err := replace(edit[0], edit[1]); err != nil {
				return "", err
			}
		}
	}
	if observed {
		sampleStart := strings.Index(child, "\tsample := func() {")
		sampleEnd := strings.Index(child, "\tdone, sampled :=")
		if sampleStart < 0 || sampleEnd <= sampleStart {
			return "", errorString("scalar sampler source boundary changed")
		}
		oldSample := child[sampleStart:sampleEnd]
		edits := [][2]string{
			{"\tpeak.Store(baseline)\n", "\tpeak.Store(baseline)\n\tobserver, observerErr := newMemoryDiagObserver(baseline, limit, &peak)\n\tif observerErr != nil {\n\t\tt.Fatal(observerErr)\n\t}\n"},
			{oldSample, "\tsample := func() { observer.sample(&peak) }\n"},
			{"\tfor range repeats {\n", "\tfor iteration := 1; iteration <= repeats; iteration++ {\n"},
			{"\t\tcpu0 := processCPU()\n\t\tvar wg", "\t\tcpu0 := processCPU()\n\t\tobserver.mark(iteration, \"before-worker\", \"worker\", &peak)\n\t\tvar wg"},
			{"\t\twg.Wait()\n\t\tpreflightCPU", "\t\twg.Wait()\n\t\tobserver.mark(iteration, \"after-worker\", \"post-worker\", &peak)\n\t\tpreflightCPU"},
			{"\t\t\tclear(results)\n\t\t\truntime.GC()", "\t\t\tclear(results)\n\t\t\tobserver.mark(iteration, \"before-gc\", \"gc\", &peak)\n\t\t\truntime.GC()"},
			{"\t\t\truntime.GC()\n\t\t}", "\t\t\truntime.GC()\n\t\t\tobserver.mark(iteration, \"after-gc\", \"between\", &peak)\n\t\t}"},
			{"\t\tdecodeCPU += processCPU() - cpu0\n", "\t\tif iteration == repeats {\n\t\t\tobserver.mark(repeats, \"final\", \"final\", &peak)\n\t\t}\n\t\tdecodeCPU += processCPU() - cpu0\n"},
			{"cpu.Nanoseconds(), blocks, codecs, paid, repeats)\n", "cpu.Nanoseconds(), blocks, codecs, paid, repeats)\n\tobserver.dump(t, peak.Load())\n"},
		}
		for _, edit := range edits {
			if err := replace(edit[0], edit[1]); err != nil {
				return "", err
			}
		}
	}
	return source[:start] + child + source[end:], nil
}

func memoryDiagSHA(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

func memoryDiagHashFile(path string) (string, error) {
	file, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, file); err != nil {
		return "", err
	}
	return hex.EncodeToString(hash.Sum(nil)), nil
}

// No general environment dump or inherited credential variables.
func memoryDiagEnvironment() []string {
	var env []string
	for _, key := range []string{"PATH", "GOROOT", "GOCACHE", "GOMODCACHE", "GOENV", "GOCACHEPROG", "GOTOOLCHAIN", "GOFLAGS", "CGO_ENABLED", "GOMAXPROCS", "TMPDIR"} {
		if value, ok := os.LookupEnv(key); ok {
			env = append(env, key+"="+value)
		}
	}
	return append(env, "GOGC=100", "GOMEMLIMIT=off")
}

func memoryDiagChildEnvironment(environment []string, fixturePath string) []string {
	return append(append([]string{}, environment...), costChildEnv+"="+fixturePath,
		"RICEVANTA_COST_CASE=blocks-4m-over", "RICEVANTA_COST_MODE=limited", "RICEVANTA_COST_SHAPE=blocks-4m-over",
		"RICEVANTA_COST_N=1", "RICEVANTA_COST_LINES=4", "RICEVANTA_COST_WINDOW=4194304", "RICEVANTA_COST_SIZE=4194304",
		"RICEVANTA_COST_BADID=false", "RICEVANTA_COST_ERROR="+errorName(ErrFrame), "RICEVANTA_COST_BLOCKS=34",
		"RICEVANTA_COST_CODECS=0", "RICEVANTA_COST_RATE=false")
}

type memoryDiagArm struct {
	Arm        string
	SourceSHA  string
	HelperSHA  string
	BinarySHA  string
	BinaryPath string
	BuildArgv  []string
}

type memoryDiagChild struct {
	Index         int
	Arm           string
	Kind          string
	CPUWork       string
	Argv          []string
	Environment   []string
	ExitStatus    int
	Validation    string
	SourceSHA     string
	HelperSHA     string
	BinarySHA     string
	FixtureSHA    string
	Measurement   map[string]string
	ExactExcess10 int64
	ObserverSHA   string
}

func memoryDiagRun(cmd *exec.Cmd, dir, name string) int {
	stdout, err := os.Create(filepath.Join(dir, name+".stdout"))
	if err != nil {
		return -1
	}
	defer stdout.Close()
	stderr, err := os.Create(filepath.Join(dir, name+".stderr"))
	if err != nil {
		return -1
	}
	defer stderr.Close()
	cmd.Stdout, cmd.Stderr = stdout, stderr
	status := 0
	if err := cmd.Run(); err != nil {
		status = -1
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			status = exit.ExitCode()
		}
	}
	_ = os.WriteFile(filepath.Join(dir, name+".status"), []byte(strconv.Itoa(status)+"\n"), 0600)
	return status
}

func memoryDiagWriteJSON(path string, value any) error {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(data, '\n'), 0600)
}

func memoryDiagValidatePopulation(children []memoryDiagChild, arms map[string]memoryDiagArm, fixtureSHA string) error {
	schedule := memoryDiagSchedule()
	if len(children) != len(schedule) {
		return errorString("omitted or extra diagnostic children")
	}
	for i, child := range children {
		kind := "request"
		cpuWork := "request_and_machinery"
		if child.Arm == "C" || child.Arm == "D" {
			kind = "control"
			cpuWork = "machinery_only"
		}
		if child.Index != i+1 || child.Arm != schedule[i] || child.Kind != kind || child.CPUWork != cpuWork || len(child.Argv) == 0 {
			return errorString("invalid diagnostic child identity or order")
		}
		for _, digest := range []string{child.SourceSHA, child.HelperSHA, child.BinarySHA, child.FixtureSHA} {
			decoded, err := hex.DecodeString(digest)
			if err != nil || len(decoded) != sha256.Size {
				return errorString("malformed diagnostic identity digest")
			}
		}
		arm, ok := arms[child.Arm]
		if !ok || child.SourceSHA != arm.SourceSHA || child.HelperSHA != arm.HelperSHA || child.BinarySHA != arm.BinarySHA || child.FixtureSHA != fixtureSHA {
			return errorString("diagnostic identity does not match build or fixture")
		}
		if child.ExitStatus != 0 || child.Validation != "" || len(child.Measurement) == 0 {
			return errorString("failed or partial diagnostic evidence")
		}
		if child.Arm == "B" || child.Arm == "D" {
			digest, err := hex.DecodeString(child.ObserverSHA)
			if err != nil || len(digest) != sha256.Size {
				return errorString("missing or malformed observed-arm evidence")
			}
		}
		tag := "COST_MEASUREMENT"
		if child.Kind == "control" {
			tag = "MEMORY_DIAG_CONTROL"
		}
		if !strings.HasPrefix(child.Measurement["line"], tag+" ") {
			return errorString("control mislabeled as a case result")
		}
		if err := memoryDiagValidateMeasurement(child.Measurement); err != nil {
			return err
		}
	}
	return nil
}

func memoryDiagJSONKeys(payload []byte, keys ...string) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(payload))
	token, err := decoder.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errorString("diagnostic JSON object required")
	}
	fields := map[string]json.RawMessage{}
	for decoder.More() {
		token, err := decoder.Token()
		key, ok := token.(string)
		if err != nil || !ok {
			return nil, errorString("malformed diagnostic JSON key")
		}
		if _, duplicate := fields[key]; duplicate {
			return nil, errorString("duplicate diagnostic JSON field")
		}
		var value json.RawMessage
		if err := decoder.Decode(&value); err != nil {
			return nil, err
		}
		fields[key] = value
	}
	if _, err := decoder.Token(); err != nil {
		return nil, err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return nil, errorString("trailing diagnostic JSON")
	}
	if len(fields) != len(keys) {
		return nil, errorString("missing or unknown diagnostic JSON fields")
	}
	for _, key := range keys {
		if _, ok := fields[key]; !ok {
			return nil, errorString("missing diagnostic JSON field")
		}
	}
	return fields, nil
}

func memoryDiagDecodeRecord(payload string) (memoryDiagRecordOutput, error) {
	var row memoryDiagRecordOutput
	fields, err := memoryDiagJSONKeys([]byte(payload), "Record", "DeltaObserverReady", "HasPriorAfterGC", "PriorAfterGCIteration", "DeltaPriorAfterGC")
	if err != nil {
		return row, err
	}
	record, err := memoryDiagJSONKeys(fields["Record"], "ID", "Iteration", "Phase", "MonotonicNS", "Values", "Used")
	if err != nil {
		return row, err
	}
	for _, value := range []json.RawMessage{record["Values"], fields["DeltaObserverReady"], fields["DeltaPriorAfterGC"]} {
		var elements []json.RawMessage
		if err := json.Unmarshal(value, &elements); err != nil || len(elements) != memoryDiagClasses {
			return row, errorString("wrong memory class array length")
		}
	}
	if err := json.Unmarshal([]byte(payload), &row); err != nil {
		return row, err
	}
	return row, nil
}

func memoryDiagValidateMeasurement(fields map[string]string) error {
	tag, _, _ := strings.Cut(fields["line"], " ")
	if tag != "COST_MEASUREMENT" && tag != "MEMORY_DIAG_CONTROL" {
		return errorString("missing diagnostic measurement line")
	}
	parsed, err := parseCostMeasurement([]byte(fields["line"]), tag, "blocks-4m-over", "limited")
	if err != nil || len(parsed) != len(fields) {
		return errorString("malformed diagnostic measurement fields")
	}
	for key, value := range parsed {
		if fields[key] != value {
			return errorString("diagnostic values differ from measurement line")
		}
	}
	for key, want := range map[string]string{
		"case": "blocks-4m-over", "mode": "limited", "shape": "blocks-4m-over",
		"lines": "4", "blocks": "34", "codecs": "0", "repeats": "32",
	} {
		if fields[key] != want {
			return fmt.Errorf("wrong diagnostic measurement %s", key)
		}
	}
	if err := validateCostValues(fields, 1, 4<<20, 4<<20, admission.CompressedWeight, admission.MinCharge); err != nil {
		return err
	}
	if fields["limiter_cycle"] != "0" {
		return errorString("the GC CPU limiter engaged")
	}
	peakBytes, _ := strconv.ParseUint(fields["peak"], 10, 64)
	limitBytes, _ := strconv.ParseUint(fields["limit"], 10, 64)
	// Preserve the original scalar parent's assertion, without adjustment.
	if float64(peakBytes) > 1.1*float64(limitBytes) {
		return fmt.Errorf("peak %s is %s of the limit %s", fields["peak"], fields["peak_ratio"], fields["limit"])
	}
	return nil
}

func memoryDiagValidateObserver(output []byte, peak uint64) (string, error) {
	var records []memoryDiagSnapshot
	var maximum memoryDiagSnapshot
	headers, maxima := 0, 0
	for _, line := range strings.Split(string(output), "\n") {
		prefix, payload, _ := strings.Cut(line, " ")
		switch prefix {
		case "MEMORY_DIAG_OBSERVER":
			headers++
			if _, err := memoryDiagJSONKeys([]byte(payload), "Classes", "RequestedBytes", "AllocatedBytes", "Allocations", "SetupCPUNS", "Count"); err != nil {
				return "", err
			}
			var header struct {
				Classes        [memoryDiagClasses]string
				RequestedBytes uint64
				AllocatedBytes uint64
				Allocations    uint64
				SetupCPUNS     int64
				Count          int
			}
			if err := json.Unmarshal([]byte(payload), &header); err != nil || header.Classes != memoryDiagNames || header.Count != memoryDiagRecords || header.RequestedBytes == 0 || header.RequestedBytes > 64<<10 || header.AllocatedBytes < header.RequestedBytes || header.AllocatedBytes > 64<<10 || header.Allocations == 0 || header.SetupCPUNS < 0 {
				return "", errorString("malformed or oversized observer header")
			}
		case "MEMORY_DIAG_RECORD", "MEMORY_DIAG_MAXIMUM":
			row, err := memoryDiagDecodeRecord(payload)
			if err != nil {
				return "", errorString("malformed observer record")
			}
			if prefix == "MEMORY_DIAG_MAXIMUM" {
				maxima++
				maximum = row.Record
			} else {
				records = append(records, row.Record)
			}
		}
	}
	if headers != 1 || maxima != 1 {
		return "", errorString("missing or duplicate observer evidence")
	}
	if err := memoryDiagValidateRecords(records, maximum, peak); err != nil {
		return "", err
	}
	// Reparse and reconcile the emitted deltas too; silently wrong attribution
	// is incomplete evidence even when its raw snapshots are valid.
	for _, line := range strings.Split(string(output), "\n") {
		prefix, payload, _ := strings.Cut(line, " ")
		if prefix != "MEMORY_DIAG_RECORD" && prefix != "MEMORY_DIAG_MAXIMUM" {
			continue
		}
		row, err := memoryDiagDecodeRecord(payload)
		if err != nil || row != memoryDiagRecordDeltas(row.Record, records[0], records) {
			return "", errorString("inconsistent observer class deltas")
		}
	}
	return memoryDiagSHA(output), nil
}

// TestCostMemoryExperiment is a temporary CI-only driver. It never produces a
// qualification receipt. Ordinary and local helper selections do not call it.
func TestCostMemoryExperiment(t *testing.T) {
	if os.Getenv("RICEVANTA_MEMORY_DIAG_RUN") != "full" {
		t.Skip("isolated twelve-child memory experiment runs only in reviewed CI")
	}
	if runtime.Version() != "go1.27.1" || runtime.GOOS != "linux" || runtime.GOARCH != "amd64" {
		t.Fatal("memory experiment requires pinned Go 1.27.1 Linux x64")
	}
	dir := os.Getenv("RICEVANTA_MEMORY_DIAG_DIR")
	if !filepath.IsAbs(dir) {
		t.Fatal("absolute diagnostic output directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		t.Fatal(err)
	}
	sourcePath, err := filepath.Abs("internal/events/body/costmodel_norace_test.go")
	if err != nil {
		t.Fatal(err)
	}
	helperPath, err := filepath.Abs("internal/events/body/cost_memory_diagnose_norace_test.go")
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.ReadFile(sourcePath)
	if err != nil || memoryDiagSHA(source) != memoryDiagScalarSHA {
		t.Fatal("scalar harness identity differs from the approved experiment base")
	}
	helper, err := os.ReadFile(helperPath)
	if err != nil {
		t.Fatal(err)
	}
	goPath, err := exec.LookPath("go")
	if err != nil {
		t.Fatal(err)
	}
	toolchainSHA, err := memoryDiagHashFile(goPath)
	if err != nil {
		t.Fatal(err)
	}
	// Construction is in this driver only, never in a measurement child.
	input := adversarialCostInput(t, "blocks-4m-over")
	if input.window != 4<<20 || input.size != 4<<20 || input.lines != 4 || input.blocks != 34 || input.codecs != 0 || !errors.Is(input.want, ErrFrame) {
		t.Fatal("diagnostic fixture metadata changed")
	}
	fixturePath := filepath.Join(dir, "blocks-4m-over.zst")
	if err := os.WriteFile(fixturePath, input.frame, 0600); err != nil {
		t.Fatal(err)
	}
	fixtureSHA := memoryDiagSHA(input.frame)
	environment := memoryDiagEnvironment()
	identity := struct {
		ScalarSHA     string
		HelperSHA     string
		FixtureSHA    string
		ToolchainSHA  string
		ToolchainPath string
		GoVersion     string
		GOOS          string
		GOARCH        string
		CPUs          int
		MaxProcs      int
		PageSize      int
		Environment   []string
		Schedule      []string
	}{memoryDiagScalarSHA, memoryDiagSHA(helper), fixtureSHA, toolchainSHA, goPath, runtime.Version(), runtime.GOOS, runtime.GOARCH, runtime.NumCPU(), runtime.GOMAXPROCS(0), os.Getpagesize(), environment, memoryDiagSchedule()}
	if err := memoryDiagWriteJSON(filepath.Join(dir, "identity.json"), identity); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "scalar-costmodel_norace_test.go"), source, 0600); err != nil {
		t.Fatal(err)
	}
	arms := map[string]memoryDiagArm{}
	for _, arm := range []string{"A", "B", "C", "D"} {
		armDir := filepath.Join(dir, "arm-"+arm)
		if err := os.Mkdir(armDir, 0700); err != nil {
			t.Fatal(err)
		}
		derived, err := memoryDiagArmSource(string(source), arm)
		if err != nil {
			t.Fatal(err)
		}
		armSource := filepath.Join(armDir, "costmodel_norace_test.go")
		armHelper := filepath.Join(armDir, "cost_memory_diagnose_norace_test.go")
		helperData := helper
		if arm == "A" || arm == "C" {
			// A is compiled from the original scalar harness without even the
			// observer's imports/test registration. C differs only as mapped.
			helperData = []byte("//go:build !race\n\npackage body\n")
		}
		for path, data := range map[string][]byte{armSource: []byte(derived), armHelper: helperData} {
			if err := os.WriteFile(path, data, 0600); err != nil {
				t.Fatal(err)
			}
		}
		overlayPath := filepath.Join(armDir, "overlay.json")
		if err := memoryDiagWriteJSON(overlayPath, struct{ Replace map[string]string }{map[string]string{sourcePath: armSource, helperPath: armHelper}}); err != nil {
			t.Fatal(err)
		}
		binary := filepath.Join(armDir, "body.test")
		cmd := exec.Command(goPath, "test", "-c", "-o", binary, "-overlay", overlayPath, "./internal/events/body")
		cmd.Env = environment
		if err := memoryDiagWriteJSON(filepath.Join(armDir, "build-command.json"), cmd.Args); err != nil {
			t.Fatal(err)
		}
		if status := memoryDiagRun(cmd, armDir, "build"); status != 0 {
			t.Fatalf("arm %s build failed: %d; diagnostics retained in %s", arm, status, armDir)
		}
		binarySHA, err := memoryDiagHashFile(binary)
		if err != nil {
			t.Fatal(err)
		}
		arms[arm] = memoryDiagArm{arm, memoryDiagSHA([]byte(derived)), memoryDiagSHA(helperData), binarySHA, binary, cmd.Args}
	}
	if err := memoryDiagWriteJSON(filepath.Join(dir, "arms.json"), arms); err != nil {
		t.Fatal(err)
	}
	var children []memoryDiagChild
	for i, arm := range memoryDiagSchedule() {
		build := arms[arm]
		childDir := filepath.Join(dir, fmt.Sprintf("child-%02d-%s", i+1, arm))
		if err := os.Mkdir(childDir, 0700); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(build.BinaryPath, "-test.run=^TestDecodeCostModel$", "-test.v", "-test.count=1", "-test.timeout=10m")
		cmd.Env = memoryDiagChildEnvironment(environment, fixturePath)
		child := memoryDiagChild{Index: i + 1, Arm: arm, Kind: "request", CPUWork: "request_and_machinery", Argv: cmd.Args, Environment: cmd.Env,
			SourceSHA: build.SourceSHA, HelperSHA: build.HelperSHA, BinarySHA: build.BinarySHA, FixtureSHA: fixtureSHA}
		tag := "COST_MEASUREMENT"
		if arm == "C" || arm == "D" {
			child.Kind, tag = "control", "MEMORY_DIAG_CONTROL"
			child.CPUWork = "machinery_only"
		}
		if err := memoryDiagWriteJSON(filepath.Join(childDir, "command.json"), child); err != nil {
			t.Fatal(err)
		}
		child.ExitStatus = memoryDiagRun(cmd, childDir, "child")
		output, readErr := os.ReadFile(filepath.Join(childDir, "child.stdout"))
		fields, parseErr := parseCostMeasurement(output, tag, "blocks-4m-over", "limited")
		var problems []error
		if readErr != nil {
			problems = append(problems, readErr)
		}
		if parseErr != nil {
			problems = append(problems, parseErr)
		} else {
			child.Measurement = fields
			if err := memoryDiagValidateMeasurement(fields); err != nil {
				problems = append(problems, err)
			}
			peak, _ := strconv.ParseUint(fields["peak"], 10, 64)
			limit, _ := strconv.ParseUint(fields["limit"], 10, 64)
			if peak > math.MaxInt64/11 || limit > math.MaxInt64/11 {
				problems = append(problems, errorString("exact excess arithmetic overflow"))
			} else {
				child.ExactExcess10 = int64(10*peak) - int64(11*limit)
			}
			if arm == "B" || arm == "D" {
				digest, err := memoryDiagValidateObserver(output, peak)
				child.ObserverSHA = digest
				if err != nil {
					problems = append(problems, err)
				}
			}
		}
		if child.ExitStatus != 0 {
			problems = append(problems, fmt.Errorf("child exit status %d", child.ExitStatus))
		}
		if err := errors.Join(problems...); err != nil {
			child.Validation = err.Error()
		}
		children = append(children, child)
		if err := memoryDiagWriteJSON(filepath.Join(childDir, "result.json"), child); err != nil {
			t.Fatal(err)
		}
		t.Logf("MEMORY_DIAG_CHILD index=%d arm=%s kind=%s exit=%d validation=%q", child.Index, child.Arm, child.Kind, child.ExitStatus, child.Validation)
		// A failed assertion is collected, never used to stop or retry a child.
	}
	if err := memoryDiagWriteJSON(filepath.Join(dir, "population.json"), children); err != nil {
		t.Fatal(err)
	}
	if err := memoryDiagValidatePopulation(children, arms, fixtureSHA); err != nil {
		t.Error(err)
	}
	t.Log("MEMORY_DIAG_POPULATION children=12 qualification=blocked")
}

func TestMemoryDiagSchedule(t *testing.T) {
	got := memoryDiagSchedule()
	if strings.Join(got, " ") != "A B C D D C B A A C B D" {
		t.Fatalf("schedule %v", got)
	}
	counts := map[string]int{}
	for _, arm := range got {
		counts[arm]++
	}
	for _, arm := range []string{"A", "B", "C", "D"} {
		if counts[arm] != 3 {
			t.Fatalf("arm %s count=%d", arm, counts[arm])
		}
	}
}

func TestMemoryDiagChildEnvironment(t *testing.T) {
	values := map[string]string{}
	for _, entry := range memoryDiagChildEnvironment([]string{"GOGC=100", "GOMEMLIMIT=off"}, "/fixture.zst") {
		key, value, ok := strings.Cut(entry, "=")
		if !ok {
			t.Fatalf("malformed environment %q", entry)
		}
		if _, duplicate := values[key]; duplicate {
			t.Fatalf("duplicate environment key %s", key)
		}
		values[key] = value
	}
	for key, want := range map[string]string{
		"RICEVANTA_COST_ERROR": "event body frame", "RICEVANTA_COST_CODECS": "0",
		"RICEVANTA_COST_BLOCKS": "34", "GOGC": "100", "GOMEMLIMIT": "off",
	} {
		if values[key] != want {
			t.Fatalf("%s=%q, want %q", key, values[key], want)
		}
	}
}

func TestMemoryDiagBoundary(t *testing.T) {
	var phases []string
	boundary := memoryDiagBoundary{record: func(phase string) { phases = append(phases, phase) }}
	creates := 0
	create := func() *memoryDiagObserver {
		creates++
		return nil
	}
	if _, err := boundary.start(create); err == nil || creates != 0 || len(phases) != 0 {
		t.Fatal("observer ran before scalar baseline")
	}
	if err := boundary.baselineRead(1000); err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.start(create); err == nil || creates != 0 {
		t.Fatal("observer ran before scalar limit")
	}
	if err := boundary.limitSet(5001001); err == nil {
		t.Fatal("accepted a different memory budget")
	}
	if err := boundary.limitSet(5001000); err != nil {
		t.Fatal(err)
	}
	if _, err := boundary.start(create); err != nil || creates != 1 || strings.Join(phases, " ") != "baseline limit observer" {
		t.Fatalf("phase chronology %v creates=%d error=%v", phases, creates, err)
	}
	if _, err := boundary.start(create); err == nil || creates != 1 {
		t.Fatal("observer was initialized twice")
	}
}

func memoryDiagSyntheticObserver() (*memoryDiagObserver, uint64) {
	now := time.Unix(0, 0)
	values := [memoryDiagClasses]uint64{0: 100, memoryDiagReleased: 10, memoryDiagTotal: 110}
	o := &memoryDiagObserver{
		origin: now,
		now: func() time.Time {
			now = now.Add(time.Nanosecond)
			return now
		},
		read: func(*[memoryDiagClasses]metrics.Sample) ([memoryDiagClasses]uint64, error) { return values, nil },
	}
	var peak atomic.Uint64
	o.mark(0, "observer-ready", "between", &peak)
	for iteration := 1; iteration <= 32; iteration++ {
		o.mark(iteration, "before-worker", "worker", &peak)
		if iteration == 7 {
			values[1], values[memoryDiagTotal] = 777, 887
			o.sample(&peak)
			values[1], values[memoryDiagTotal] = 0, 110
		}
		o.mark(iteration, "after-worker", "post-worker", &peak)
		o.mark(iteration, "before-gc", "gc", &peak)
		o.mark(iteration, "after-gc", "between", &peak)
	}
	o.mark(32, "final", "final", &peak)
	return o, peak.Load()
}

func TestMemoryDiagObserverPairing(t *testing.T) {
	o, peak := memoryDiagSyntheticObserver()
	t.Logf("observer_requested_bytes=%d record_capacity=%d", unsafe.Sizeof(*o), len(o.records))
	if unsafe.Sizeof(*o) > 64<<10 || o.count != 130 || peak != 877 || o.maximum.ID != 27 || o.maximum.Iteration != 7 || o.maximum.Phase != "worker" || o.maximum.Values[1] != 777 {
		t.Fatalf("incorrect paired maximum %+v, peak=%d count=%d bytes=%d", o.maximum, peak, o.count, unsafe.Sizeof(*o))
	}
	if err := memoryDiagValidateRecords(o.records[:o.count], o.maximum, peak); err != nil {
		t.Fatal(err)
	}
	delta := memoryDiagRecordDeltas(o.maximum, o.records[0], o.records[:o.count])
	if delta.DeltaObserverReady[1] != 777 || delta.DeltaPriorAfterGC[1] != 777 || !delta.HasPriorAfterGC || delta.PriorAfterGCIteration != 6 {
		t.Fatalf("wrong deltas %+v", delta)
	}
	for name, mutate := range map[string]func(*memoryDiagObserver){
		"missing-phase":   func(o *memoryDiagObserver) { o.count-- },
		"wrong-phase":     func(o *memoryDiagObserver) { o.records[4].Phase = "before-gc" },
		"class-sum":       func(o *memoryDiagObserver) { o.records[8].Values[1]++ },
		"lost-pair":       func(o *memoryDiagObserver) { o.maximum.Values[1]-- },
		"fake-peak-phase": func(o *memoryDiagObserver) { o.maximum.Phase = "invented" },
	} {
		t.Run(name, func(t *testing.T) {
			copy := memoryDiagObserver{records: o.records, maximum: o.maximum, count: o.count}
			mutate(&copy)
			if err := memoryDiagValidateRecords(copy.records[:copy.count], copy.maximum, peak); err == nil {
				t.Fatal("accepted corrupt observer evidence")
			}
		})
	}
	var scalar atomic.Uint64
	scalar.Store(peak)
	o.mark(32, "final", "final", &scalar)
	if o.failure == nil || o.count != 130 {
		t.Fatal("record overflow was not rejected")
	}
	bad := [memoryDiagClasses]uint64{0: 100, memoryDiagTotal: 99}
	if _, err := memoryDiagUsed(bad); err == nil {
		t.Fatal("inconsistent disjoint classes accepted")
	}
}

func TestMemoryDiagFinalSample(t *testing.T) {
	o, peak := memoryDiagSyntheticObserver()
	o.read = func(*[memoryDiagClasses]metrics.Sample) ([memoryDiagClasses]uint64, error) {
		return [memoryDiagClasses]uint64{1: 2000, memoryDiagTotal: 2000}, nil
	}
	var scalar atomic.Uint64
	scalar.Store(peak)
	o.sample(&scalar)
	if err := memoryDiagValidateRecords(o.records[:o.count], o.maximum, scalar.Load()); err != nil {
		t.Fatalf("final sampler maximum was lost: %v", err)
	}
}

func TestMemoryDiagArmSources(t *testing.T) {
	source, err := os.ReadFile("costmodel_norace_test.go")
	if err != nil {
		t.Fatal(err)
	}
	if memoryDiagSHA(source) != memoryDiagScalarSHA {
		t.Fatal("approved scalar source changed")
	}
	dir := os.Getenv("RICEVANTA_MEMORY_DIAG_PREPARE")
	for _, arm := range []string{"A", "B", "C", "D"} {
		derived, err := memoryDiagArmSource(string(source), arm)
		if err != nil {
			t.Fatal(err)
		}
		if arm == "A" && derived != string(source) {
			t.Fatal("arm A changed")
		}
		childStart, childEnd := strings.Index(derived, "func costChild("), strings.Index(derived, "\nfunc TestCostModelHarness(")
		if derived[:childStart] != string(source[:strings.Index(string(source), "func costChild(")]) || derived[childEnd:] != string(source[strings.Index(string(source), "\nfunc TestCostModelHarness("):]) {
			t.Fatal("non-child source changed")
		}
		child := derived[childStart:childEnd]
		observed := arm == "B" || arm == "D"
		if strings.Contains(child, "newMemoryDiagObserver") != observed {
			t.Fatal("wrong observer mapping")
		}
		if observed && strings.Index(child, "newMemoryDiagObserver") < strings.Index(child, "debug.SetMemoryLimit(limit)") {
			t.Fatal("observer is before scalar limit")
		}
		control := arm == "C" || arm == "D"
		if strings.Contains(child, "frames[i], errs[i] = ReadFrame(") == control || strings.Contains(child, "MEMORY_DIAG_CONTROL") != control {
			t.Fatal("wrong receive/control mapping")
		}
		if dir != "" {
			armDir := filepath.Join(dir, arm)
			if err := os.MkdirAll(armDir, 0700); err != nil {
				t.Fatal(err)
			}
			scalarPath, _ := filepath.Abs("costmodel_norace_test.go")
			helperPath, _ := filepath.Abs("cost_memory_diagnose_norace_test.go")
			helper, err := os.ReadFile(helperPath)
			if err != nil {
				t.Fatal(err)
			}
			if !observed {
				helper = []byte("//go:build !race\n\npackage body\n")
			}
			armSource, armHelper := filepath.Join(armDir, "costmodel_norace_test.go"), filepath.Join(armDir, "cost_memory_diagnose_norace_test.go")
			if err := os.WriteFile(armSource, []byte(derived), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(armHelper, helper, 0600); err != nil {
				t.Fatal(err)
			}
			if err := memoryDiagWriteJSON(filepath.Join(armDir, "overlay.json"), struct{ Replace map[string]string }{map[string]string{scalarPath: armSource, helperPath: armHelper}}); err != nil {
				t.Fatal(err)
			}
		}
	}
}

func memoryDiagSyntheticMeasurement(t *testing.T, control bool) map[string]string {
	t.Helper()
	tag := "COST_MEASUREMENT"
	if control {
		tag = "MEMORY_DIAG_CONTROL"
	}
	line := tag + " case=blocks-4m-over mode=limited shape=blocks-4m-over n=1 window=4194304 size=4194304 weight=5000000 baseline=5000000 limit=10000000 lines=4 allocs=10 cpu_ms=1 wall_ms=1 peak=10000000 peak_ratio=1.000 vmhwm=10000000 gc_cycles=32 limiter_cycle=0 preflight_cpu_ns=100000 decode_cpu_ns=900000 cpu_ns=1000000 blocks=34 codecs=0 paid=131072 repeats=32"
	fields, err := parseCostMeasurement([]byte(line), tag, "blocks-4m-over", "limited")
	if err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestMemoryDiagPopulation(t *testing.T) {
	digest := strings.Repeat("a", 64)
	arms := map[string]memoryDiagArm{}
	for _, arm := range []string{"A", "B", "C", "D"} {
		arms[arm] = memoryDiagArm{Arm: arm, SourceSHA: digest, HelperSHA: digest, BinarySHA: digest}
	}
	var rows []memoryDiagChild
	for i, arm := range strings.Fields("A B C D D C B A A C B D") {
		control, kind := arm == "C" || arm == "D", "request"
		if control {
			kind = "control"
		}
		cpuWork := "request_and_machinery"
		if control {
			cpuWork = "machinery_only"
		}
		row := memoryDiagChild{Index: i + 1, Arm: arm, Kind: kind, CPUWork: cpuWork, Argv: []string{"body.test"}, SourceSHA: digest, HelperSHA: digest, BinarySHA: digest, FixtureSHA: digest, Measurement: memoryDiagSyntheticMeasurement(t, control)}
		if arm == "B" || arm == "D" {
			row.ObserverSHA = digest
		}
		rows = append(rows, row)
	}
	if err := memoryDiagValidatePopulation(rows, arms, digest); err != nil {
		t.Fatal(err)
	}
	if err := memoryDiagValidatePopulation(rows[:11], arms, digest); err == nil {
		t.Fatal("omitted child accepted")
	}
	for name, mutate := range map[string]func(*memoryDiagChild){
		"order":           func(row *memoryDiagChild) { row.Arm = "D" },
		"failed":          func(row *memoryDiagChild) { row.ExitStatus = 1 },
		"partial":         func(row *memoryDiagChild) { row.Measurement = nil },
		"malformed-value": func(row *memoryDiagChild) { row.Measurement["allocs"] = "nan" },
		"wrong-digest":    func(row *memoryDiagChild) { row.BinarySHA = strings.Repeat("b", 64) },
	} {
		t.Run(name, func(t *testing.T) {
			copy := append([]memoryDiagChild{}, rows...)
			copy[0].Measurement = memoryDiagSyntheticMeasurement(t, false)
			mutate(&copy[0])
			if err := memoryDiagValidatePopulation(copy, arms, digest); err == nil {
				t.Fatal("invalid diagnostic evidence accepted")
			}
		})
	}
	incomplete := append([]memoryDiagChild{}, rows...)
	incomplete[1].ObserverSHA = ""
	if err := memoryDiagValidatePopulation(incomplete, arms, digest); err == nil {
		t.Fatal("missing observed-arm evidence accepted")
	}
}

func TestMemoryDiagObserverEvidence(t *testing.T) {
	o, peak := memoryDiagSyntheticObserver()
	var output bytes.Buffer
	write := func(prefix string, value any) {
		fmt.Fprint(&output, prefix+" ")
		if err := json.NewEncoder(&output).Encode(value); err != nil {
			t.Fatal(err)
		}
	}
	write("MEMORY_DIAG_OBSERVER", struct {
		Classes        [memoryDiagClasses]string
		RequestedBytes uint64
		AllocatedBytes uint64
		Allocations    uint64
		SetupCPUNS     int64
		Count          int
	}{memoryDiagNames, 24000, 24576, 1, 0, 130})
	for _, record := range o.records[:o.count] {
		write("MEMORY_DIAG_RECORD", memoryDiagRecordDeltas(record, o.records[0], o.records[:o.count]))
	}
	partial := append([]byte{}, output.Bytes()...)
	write("MEMORY_DIAG_MAXIMUM", memoryDiagRecordDeltas(o.maximum, o.records[0], o.records[:o.count]))
	if _, err := memoryDiagValidateObserver(output.Bytes(), peak); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string][]byte{
		"partial":         partial,
		"malformed":       []byte("MEMORY_DIAG_RECORD {broken}\n"),
		"bad-delta":       bytes.Replace(output.Bytes(), []byte("\"DeltaObserverReady\":[0,"), []byte("\"DeltaObserverReady\":[1,"), 1),
		"missing-setup":   bytes.Replace(output.Bytes(), []byte("\"SetupCPUNS\":0,"), nil, 1),
		"duplicate-setup": bytes.Replace(output.Bytes(), []byte("\"SetupCPUNS\":0,"), []byte("\"SetupCPUNS\":0,\"SetupCPUNS\":0,"), 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := memoryDiagValidateObserver(bad, peak); err == nil {
				t.Fatal("invalid observer evidence accepted")
			}
		})
	}
}
