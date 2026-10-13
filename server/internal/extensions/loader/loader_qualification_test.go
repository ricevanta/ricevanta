package loader

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"runtime/debug"
	"runtime/metrics"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
	"github.com/ricevanta/ricevanta/server/internal/signing/dsse"
)

// Inputs and reference trials are prepared in the parent. Measured children
// never invoke the candidate or dependency initialization before the interval.
type loaderBudgetInput struct {
	Name             string
	Payload, Archive []byte
	Options          Options
	want             error
}
type loaderBudgetReference struct {
	Public                                                         ed25519.PublicKey
	Name, PayloadPath, ArchivePath, DocumentPath, Error, YAMLError string
	Options                                                        Options
	DecodeCalls                                                    int
}
type loaderMeasurement struct {
	Input, Mode, Toolchain, OS, Arch, ErrorClass       string
	Calls                                              int
	Alloc, Objects, StackGrowth, RetainedHeap, PeakRSS uint64
	LedgerBytes, LedgerObjects, Ceiling                uint64
	Nanoseconds                                        int64
	ProcsBefore, ProcsAfter                            int
	MemoryLimitBefore, MemoryLimitAfter                int64
	GCPercentBefore, GCPercentAfter                    uint64
	GCBefore, GCAfter                                  uint32
}

func loaderBudgetCorpus(t *testing.T, extended bool) []loaderBudgetInput {
	t.Helper()
	var out []loaderBudgetInput
	add := func(name string, payload, env []byte, files []archiveEntry) {
		if env == nil {
			env = signedEnvelope(t, payload)
		}
		out = append(out, loaderBudgetInput{Name: name, Payload: payload, Archive: packageArchive(t, payload, env, files...)})
	}
	c := corpus(t)
	for _, v := range c.Cases {
		out = append(out, loaderBudgetInput{Name: "golden/" + v.Name, Payload: []byte(v.Payload), Archive: packageArchive(t, []byte(v.ArchiveManifest), []byte(v.Envelope), fixtureFiles(t)...)})
	}
	parserCases := parserCorpus(extended)
	if !extended {
		parserCases = []parserInput{{"comment-collections", 65535 * 8}, {"maximum-compact", 0}, {"maximum-commented", 0}, {"maximum-padded", 0}, {"malformed-suffix", 1 << 20}, {"nodes", 65537}}
	}
	for _, p := range parserCases {
		payload := parserPayload(p)
		if len(payload) > 1<<20 {
			add(fmt.Sprintf("parser/%s/%d", p.Name, p.Size), payload, []byte("{}"), nil)
			continue
		}
		payload = bytes.ReplaceAll(payload, []byte("sha256:"+strings.Repeat("0", 64)), []byte(c.Fingerprint))
		var files []archiveEntry
		if strings.HasPrefix(p.Name, "maximum-") {
			doc, e := decodeVerifiedYAML(payload)
			if e != nil {
				t.Fatal(e)
			}
			if e := manifest.Validate(doc, manifest.Options{}); e != nil {
				t.Fatal(e)
			}
			for _, v := range doc["files"].([]any) {
				m := v.(map[string]any)
				files = append(files, archiveEntry{m["path"].(string), nil})
			}
		}
		add(fmt.Sprintf("parser/%s/%d", p.Name, p.Size), payload, nil, files)
	}
	arities := []int{0, 1, 8, 9, 13, 14, 895, 896, 897}
	for _, n := range []int{14, 28, 56, 112, 224, 448, 896} {
		arities = append(arities, n-1, n, n+1)
	}
	for _, n := range arities {
		add(fmt.Sprintf("mapping/%d", n), []byte(mappingSource(n)), nil, nil)
	}
	for _, c := range []struct{ name, source string }{
		{"profile-before-guard", "bad: null\nlarge: " + mappingSource(897)},
		{"profile-after-guard", "large: " + mappingSource(897) + "\nbad: null"},
		{"duplicate-before-guard", "a: x\na: y\nlarge: " + mappingSource(897)},
		{"duplicate-after-guard", "large: " + mappingSource(897) + "\na: x\na: y"},
		{"tag-before-syntax", "a: ! x\nb: ["}, {"syntax-before-tag", "a: [}\nb: ! x"},
	} {
		add(c.name, []byte(c.source), nil, nil)
	}

	// Archive/framing defects combined with authentication/YAML defects.
	badPayload := []byte("a: ! x")
	raw := tarFixture(t, archiveEntry{"extension.yaml", badPayload}, archiveEntry{"envelope.json", []byte("{}")})
	for _, mutation := range []struct {
		name   string
		offset int
		value  byte
	}{{"header-before-envelope", 148, 'x'}, {"type-before-envelope", 156, '2'}, {"padding-before-envelope", 512 + len(badPayload), 1}} {
		copyRaw := bytes.Clone(raw)
		copyRaw[mutation.offset] = mutation.value
		if mutation.offset == 156 {
			checksumHeader(copyRaw[:512])
		}
		out = append(out, loaderBudgetInput{Name: mutation.name, Payload: badPayload, Archive: compressFixture(t, copyRaw)})
	}
	base := []byte(c.Cases[0].Payload)
	add("shape-before-publisher", []byte(strings.Replace(string(base), "kind: Extension", "kind: Wrong", 1)), nil, fixtureFiles(t))
	add("publisher-before-digest", []byte(strings.Replace(string(base), c.Fingerprint, "sha256:"+strings.Repeat("0", 64), 1)), nil, []archiveEntry{{fixtureFiles(t)[0].name, []byte("bad")}})
	add("fileset-before-size", base, nil, nil)
	add("size-before-digest", base, nil, []archiveEntry{{fixtureFiles(t)[0].name, []byte("wrong-size")}})
	add("digest-after-size", base, nil, []archiveEntry{{fixtureFiles(t)[0].name, []byte("bad")}})
	if extended {
		for _, f := range []uint64{1, manifest.DefaultMaxTotalFileBytes - 1, manifest.DefaultMaxTotalFileBytes, manifest.DefaultMaxTotalFileBytes + 1, manifest.HardMaxTotalFileBytes - 1, manifest.HardMaxTotalFileBytes, manifest.HardMaxTotalFileBytes + 1} {
			h := tarFixture(t, controlEntries()...)
			h = append(h[:len(h)-1024], tarFixture(t, archiveEntry{"f", nil})...)
			fieldHeader(h[len(h)-1536:len(h)-1024], 124, 136, strconv.FormatUint(f, 8))
			checksumHeader(h[len(h)-1536 : len(h)-1024])
			out = append(out, loaderBudgetInput{Name: fmt.Sprintf("file-ceiling/%d", f), Archive: compressFixture(t, h), Options: Options{MaxTotalFileBytes: min(f, manifest.HardMaxTotalFileBytes)}})
		}
		// Actual default file-cap successes retain every copy; hard overrides also
		// receive declared-header rejection cases without allocating GiB fixtures.
		for _, delta := range []int{-1, 0, 1} {
			file := make([]byte, int(manifest.DefaultMaxTotalFileBytes)+delta)
			digest := sha256.Sum256(file)
			d := baseDocument(t)
			first := d["files"].([]any)[0].(map[string]any)
			first["size"] = json.Number(strconv.Itoa(len(file)))
			first["sha256"] = hex.EncodeToString(digest[:])
			payload := jsonPayload(t, d)
			add(fmt.Sprintf("file-default-cap/%d", delta), payload, nil, []archiveEntry{{first["path"].(string), file}})
		}
		for _, count := range []int{4095, 4096, 4097} {
			entries := controlEntries()
			for i := 0; i < count; i++ {
				entries = append(entries, archiveEntry{fmt.Sprintf("f%04d", i), nil})
			}
			out = append(out, loaderBudgetInput{Name: fmt.Sprintf("member-count/%d", count), Archive: compressFixture(t, tarFixture(t, entries...))})
		}
		for _, n := range []int{(2 << 20) - 1, 2 << 20, (2 << 20) + 1} {
			env := denseEnvelopePayload(n)
			out = append(out, loaderBudgetInput{Name: fmt.Sprintf("envelope-tokens/%d", n), Archive: packageArchive(t, base, env, fixtureFiles(t)...), Payload: base})
		}
		for _, delta := range []int{-1, 0, 1} {
			limit := uint64(1)
			n := int(limit+archiveOverhead+compressedOverhead) + delta
			out = append(out, loaderBudgetInput{Name: fmt.Sprintf("compressed-cap/%d", delta), Archive: make([]byte, n), Options: Options{MaxTotalFileBytes: limit}})
		}
		for _, delta := range []int64{-1, 0, 1} {
			limit := uint64(1)
			size := uint64(int64(limit+archiveOverhead) + delta)
			out = append(out, loaderBudgetInput{Name: fmt.Sprintf("tar-cap/%d", delta), Archive: append(rawFrameHeader(size, false, 0x68), 1, 0, 0, 0, 0, 0, 0), Options: Options{MaxTotalFileBytes: limit}})
		}
		for _, role := range []struct {
			name string
			cap  int
		}{{"extension.yaml", 1 << 20}, {"envelope.json", 2 << 20}} {
			for _, delta := range []int{-1, 0, 1} {
				entries := controlEntries()
				for i := range entries {
					if entries[i].name == role.name {
						entries[i].data = make([]byte, role.cap+delta)
					}
				}
				out = append(out, loaderBudgetInput{Name: fmt.Sprintf("role/%s/%d", role.name, delta), Archive: compressFixture(t, tarFixture(t, entries...))})
			}
		}
	}
	out = append(out, loaderMembershipRecipes(t)...)
	out = append(out, loaderBudgetInput{Name: "reader/cause", Options: Options{MaxTotalFileBytes: 1}, want: ErrRead})
	return out
}
func errorClass(err error) string {
	if err != nil {
		return err.Error()
	}
	return ""
}
func effectiveFileLimit(o Options) uint64 {
	if o.MaxTotalFileBytes != 0 {
		return o.MaxTotalFileBytes
	}
	return manifest.DefaultMaxTotalFileBytes
}

func runLoaderBudget(t *testing.T, extended bool) {
	t.Helper()
	dir := t.TempDir()
	for index, c := range loaderBudgetCorpus(t, extended) {
		node, oracleErr := referenceAcceptance(c.Payload)
		got, b, e := yamltokens.Decode(c.Payload)
		assertAgreementResults(t, node, oracleErr, yamltokens.Check(c.Payload), got, b, e)
		ref := loaderBudgetReference{Name: c.Name, Options: c.Options, Public: keyPublic(t)}
		doc, _, ye := decodeVerifiedYAMLAccounted(c.Payload)
		ref.YAMLError = errorClass(ye)
		calls := 0
		p, err := loadWithDependencies(loaderRecipeReader(c.Name, c.Archive, effectiveFileLimit(c.Options)), keyPublic(t), c.Options, loadDependencies{
			decode: func(b []byte) (map[string]any, error) { calls++; return decodeVerifiedYAML(b) }, validate: manifest.Validate})
		if c.want != nil {
			assertLoadError(t, p, err, c.want)
		}
		ref.Error = errorClass(err)
		if c.Name == "reader/cause" {
			ref.Error = "extension read"
		}
		ref.DecodeCalls = calls
		if doc != nil {
			ref.DocumentPath = filepath.Join(dir, fmt.Sprintf("document-%d.json", index))
			data, e := json.Marshal(doc)
			if e != nil {
				t.Fatal(e)
			}
			if e = os.WriteFile(ref.DocumentPath, data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		if err == nil {
			assertPackageCommitments(t, p, c.Archive)
		}
		ref.PayloadPath = filepath.Join(dir, fmt.Sprintf("payload-%d", index))
		ref.ArchivePath = filepath.Join(dir, fmt.Sprintf("archive-%d", index))
		for path, data := range map[string][]byte{ref.PayloadPath: c.Payload, ref.ArchivePath: c.Archive} {
			if e := os.WriteFile(path, data, 0600); e != nil {
				t.Fatal(e)
			}
		}
		refPath := filepath.Join(dir, "reference.bin")
		data, e := encodeLoaderReference(ref)
		if e != nil {
			t.Fatal(e)
		}
		if e = os.WriteFile(refPath, data, 0600); e != nil {
			t.Fatal(e)
		}
		modes := []string{"combined", "assembled", "full"}
		if c.Name == "golden/valid-yaml" || c.Name == "parser/maximum-commented/0" || strings.HasPrefix(c.Name, "membership/") || c.Name == "reader/cause" {
			modes = append(modes, "serial", "two-call")
		}
		for _, mode := range modes {
			t.Run(c.Name+"/"+mode, func(t *testing.T) {
				cmd := exec.Command(os.Args[0], "-test.run=^TestLoaderMeasurementChild$", "-test.v")
				cmd.Env = append(os.Environ(), "RICEVANTA_LOADER_REFERENCE="+refPath, "RICEVANTA_LOADER_MODE="+mode)
				output, e := cmd.CombinedOutput()
				t.Log(string(output))
				if e != nil {
					t.Fatalf("cold child: %v", e)
				}
				records := 0
				for _, line := range strings.Split(string(output), "\n") {
					if _, data, ok := strings.Cut(line, "LOADER_MEASUREMENT "); ok {
						var m loaderMeasurement
						if e := json.Unmarshal([]byte(data), &m); e != nil {
							t.Fatal(e)
						}
						if m.Input != c.Name || m.Mode != mode {
							t.Fatal("wrong measurement identity")
						}
						records++
					}
				}
				if records != 1 {
					t.Fatalf("measurement records %d", records)
				}
			})
		}
	}
}
func TestLoaderBudgetSmoke(t *testing.T) { runLoaderBudget(t, false) }
func TestLoaderBudgetExtended(t *testing.T) {
	if !*budgetExtended {
		t.Skip("requires -loader-budget-extended")
	}
	runLoaderBudget(t, true)
}

// The reviewed Gate A runtime helper, with the same release/join order.
func prepareLoaderMeasurementRuntime() {
	ready := make(chan struct{}, 2)
	release := make(chan struct{})
	var helpers sync.WaitGroup
	helpers.Add(2)
	for range 2 {
		go func() {
			defer helpers.Done()
			runtime.LockOSThread()
			ready <- struct{}{}
			<-release
			runtime.UnlockOSThread()
		}()
	}
	<-ready
	<-ready
	close(release)
	helpers.Wait()
}
func TestLoaderMeasurementChild(t *testing.T) {
	path := os.Getenv("RICEVANTA_LOADER_REFERENCE")
	if path == "" {
		t.Skip("fresh measurement child only")
	}
	normalProcs := runtime.GOMAXPROCS(1)
	debug.SetMemoryLimit(math.MaxInt64)
	data, e := os.ReadFile(path)
	if e != nil {
		t.Fatal(e)
	}
	ref, e := decodeLoaderReference(data)
	if e != nil {
		t.Fatal(e)
	}
	payload, e := os.ReadFile(ref.PayloadPath)
	if e != nil {
		t.Fatal(e)
	}
	archive, e := os.ReadFile(ref.ArchivePath)
	if e != nil {
		t.Fatal(e)
	}
	key := ref.Public
	mode := os.Getenv("RICEVANTA_LOADER_MODE")
	body := loaderRecipeReader(ref.Name, archive, effectiveFileLimit(ref.Options))
	bodies := [2]*io.LimitedReader{loaderRecipeReader(ref.Name, archive, effectiveFileLimit(ref.Options)), loaderRecipeReader(ref.Name, archive, effectiveFileLimit(ref.Options))}
	var before, after runtime.MemStats
	var usage yamlUsage
	var doc map[string]any
	var result Package
	var callErr error
	calls := 0
	var results [2]Package
	var errs [2]error
	samples := []metrics.Sample{{Name: "/gc/gogc:percent"}}
	prepareLoaderMeasurementRuntime()
	if mode == "serial" || mode == "two-call" {
		runtime.GOMAXPROCS(normalProcs)
	}
	runtime.GC()
	normalGC := mode == "serial" || mode == "two-call"
	if !normalGC {
		oldGC := debug.SetGCPercent(-1)
		defer debug.SetGCPercent(oldGC)
	}
	m := loaderMeasurement{Input: ref.Name, Mode: mode, Toolchain: runtime.Version(), OS: runtime.GOOS, Arch: runtime.GOARCH}
	m.ProcsBefore = runtime.GOMAXPROCS(0)
	m.MemoryLimitBefore = debug.SetMemoryLimit(-1)
	metrics.Read(samples)
	m.GCPercentBefore = samples[0].Value.Uint64()
	deps := loadDependencies{validate: manifest.Validate, decode: func(b []byte) (map[string]any, error) {
		calls++
		runtime.ReadMemStats(&before)
		start := time.Now()
		v, u, err := decodeVerifiedYAMLAccounted(b)
		m.Nanoseconds = time.Since(start).Nanoseconds()
		runtime.ReadMemStats(&after)
		usage = u
		doc = v
		runtime.KeepAlive(v)
		runtime.KeepAlive(b)
		return v, err
	}}
	if mode != "assembled" {
		runtime.ReadMemStats(&before)
	}
	start := time.Now()
	switch mode {
	case "combined":
		calls = 1
		doc, usage, callErr = decodeVerifiedYAMLAccounted(payload)
	case "assembled":
		result, callErr = loadWithDependencies(body, key, ref.Options, deps)
	case "full":
		calls = 1
		result, callErr = Load(body, key, ref.Options)
	case "serial":
		calls = 2
		for i := range results {
			results[i], errs[i] = Load(bodies[i], key, ref.Options)
		}
		callErr = errs[0]
	case "two-call":
		calls = 2
		var wg sync.WaitGroup
		wg.Add(2)
		barrier := make(chan struct{})
		for i := range results {
			go func() { defer wg.Done(); <-barrier; results[i], errs[i] = Load(bodies[i], key, ref.Options) }()
		}
		close(barrier)
		wg.Wait()
		callErr = errs[0]
	default:
		t.Fatal("unknown mode")
	}
	if mode != "assembled" {
		m.Nanoseconds = time.Since(start).Nanoseconds()
		runtime.ReadMemStats(&after)
	}
	m.ProcsAfter = runtime.GOMAXPROCS(0)
	m.MemoryLimitAfter = debug.SetMemoryLimit(-1)
	metrics.Read(samples)
	m.GCPercentAfter = samples[0].Value.Uint64()
	runtime.KeepAlive(payload)
	runtime.KeepAlive(archive)
	runtime.KeepAlive(key)
	runtime.KeepAlive(doc)
	runtime.KeepAlive(result)
	runtime.KeepAlive(results)
	m.Calls = calls
	m.ErrorClass = errorClass(callErr)
	m.GCBefore = before.NumGC
	m.GCAfter = after.NumGC
	if mode != "assembled" || calls != 0 {
		m.Alloc = after.TotalAlloc - before.TotalAlloc
		m.Objects = after.Mallocs - before.Mallocs
		if after.StackInuse > before.StackInuse {
			m.StackGrowth = after.StackInuse - before.StackInuse
		}
		if after.HeapAlloc > before.HeapAlloc {
			m.RetainedHeap = after.HeapAlloc - before.HeapAlloc
		}
	}
	m.LedgerBytes, m.LedgerObjects = usage.bytes, usage.objects
	peak, e := parserPeakRSS()
	if e != nil {
		t.Fatalf("native RSS: %v", e)
	}
	m.PeakRSS = peak
	f := effectiveFileLimit(ref.Options)
	tarCeiling := f + archiveOverhead
	compressedCeiling := tarCeiling + compressedOverhead
	m.Ceiling = 4*compressedCeiling + 4*tarCeiling + (128 << 20)
	if mode == "serial" || mode == "two-call" {
		m.Ceiling *= 2
	}
	record, e := json.Marshal(m)
	if e != nil {
		t.Fatal(e)
	}
	fmt.Printf("LOADER_MEASUREMENT %s\n", record)
	if m.MemoryLimitBefore != math.MaxInt64 || m.MemoryLimitAfter != math.MaxInt64 {
		t.Fatal("memory limit changed")
	}
	if normalGC {
		if m.GCPercentBefore == math.MaxUint64 || m.GCPercentBefore != m.GCPercentAfter || m.ProcsBefore != normalProcs || m.ProcsAfter != normalProcs {
			t.Fatal("normal GC/scheduling not retained")
		}
	} else if m.GCPercentBefore != math.MaxUint64 || m.GCPercentAfter != math.MaxUint64 || m.GCBefore != m.GCAfter {
		t.Fatal("measurement runtime changed")
	}
	if mode != "serial" && mode != "two-call" && (m.ProcsBefore != 1 || m.ProcsAfter != 1) {
		t.Fatal("measurement scheduling changed")
	}
	wantErr := ref.Error
	if mode == "combined" {
		wantErr = ref.YAMLError
	}
	if m.ErrorClass != wantErr {
		t.Fatalf("error disagreement: got %q want %q", m.ErrorClass, wantErr)
	}
	if mode == "combined" || mode == "assembled" {
		if mode == "assembled" && calls != ref.DecodeCalls {
			t.Fatalf("decode calls %d want %d", calls, ref.DecodeCalls)
		}
		if m.Alloc > usage.bytes || m.Objects > usage.objects || m.Alloc > 64<<20 || m.Objects > 1000000 || m.StackGrowth > 8<<20 {
			t.Fatal("YAML source charge or ceiling exceeded")
		}
	} else if m.Alloc > m.Ceiling {
		t.Fatal("full Load envelope exceeded")
	}
	if callErr != nil {
		if mode == "combined" && doc != nil || mode != "combined" && !reflect.DeepEqual(result, Package{}) {
			t.Fatal("partial failure result")
		}
	} else if mode != "combined" && mode != "serial" && mode != "two-call" {
		assertPackageCommitments(t, result, archive)
	}
	if mode == "serial" || mode == "two-call" {
		for i, p := range results {
			if errorClass(errs[i]) != ref.Error {
				t.Fatal("two-call outcome mismatch")
			}
			if errs[i] == nil {
				assertPackageCommitments(t, p, archive)
			} else if !reflect.DeepEqual(p, Package{}) {
				t.Fatal("partial concurrent result")
			}
		}
		if !reflect.DeepEqual(results[0], results[1]) {
			t.Fatal("independent-call result disagreement")
		}
		if errs[0] == nil {
			runtime.GC()
			results[0].Archive[0] ^= 1
			if bytes.Equal(results[0].Archive, results[1].Archive) {
				t.Fatal("cross-call archive alias")
			}
			results[0].Document["kind"] = "changed"
			if results[1].Document["kind"] != "Extension" {
				t.Fatal("cross-call document alias")
			}
			runtime.KeepAlive(results)
		}
	}
	if doc != nil && ref.DocumentPath != "" {
		data, e := os.ReadFile(ref.DocumentPath)
		if e != nil {
			t.Fatal(e)
		}
		d := json.NewDecoder(bytes.NewReader(data))
		d.UseNumber()
		var want map[string]any
		if e = d.Decode(&want); e != nil {
			t.Fatal(e)
		}
		if !reflect.DeepEqual(doc, want) {
			t.Fatal("converted document disagreement")
		}
	}
}

// Keep the runtime recipe accessible without constructing the extended corpus.
func denseEnvelopePayload(n int) []byte {
	const prefix = `{"unknown":[`
	const suffix = "0]}"
	minimum := len(prefix) + len(suffix)
	if n < minimum {
		panic("dense envelope recipe too short")
	}
	text := prefix + strings.Repeat("0,", (n-minimum)/2) + suffix
	return []byte(text + strings.Repeat(" ", n-len(text)))
}

func TestDenseEnvelopeRecipe(t *testing.T) {
	key := keyPublic(t)
	for _, n := range []int{64, 65, 66, (2 << 20) - 1, 2 << 20, (2 << 20) + 1} {
		t.Run(strconv.Itoa(n), func(t *testing.T) {
			env := denseEnvelopePayload(n)
			if len(env) != n {
				t.Errorf("envelope length %d, want %d", len(env), n)
			}
			var root struct {
				Unknown []json.Number `json:"unknown"`
			}
			decoder := json.NewDecoder(bytes.NewReader(env))
			decoder.UseNumber()
			if err := decoder.Decode(&root); err != nil {
				t.Fatalf("dense root must be an object: %v", err)
			}
			if len(root.Unknown) < (n-16)/2 {
				t.Fatal("recipe is not a dense scalar array")
			}
			if n <= 2<<20 {
				if err := checkPayloadBudget(env); err != nil {
					t.Fatalf("limits-only preflight rejected valid dense object: %v", err)
				}
				if _, err := dsse.Verify(env, dsse.TypeExtensionManifest, key); err != dsse.ErrEnvelope {
					t.Fatalf("DSSE rejection %v, want envelope sentinel", err)
				}
				archive := packageArchive(t, []byte("a: b"), env)
				p, err := loadBytes(archive, key, Options{})
				assertLoadError(t, p, err, dsse.ErrEnvelope)
			} else {
				// Role size rejection precedes body extent/DSSE; a declared over-cap
				// header suffices without running any extended allocation measurement.
				raw := tarFixture(t, archiveEntry{"extension.yaml", []byte("a: b")}, archiveEntry{"envelope.json", nil})
				fieldHeader(raw[1024:1536], 124, 136, strconv.FormatInt(int64(n), 8))
				checksumHeader(raw[1024:1536])
				_, err := walkTar(raw, manifest.DefaultMaxTotalFileBytes)
				if err != ErrArchiveLimit {
					t.Fatalf("role rejection %v, want archive limit", err)
				}
			}
		})
	}
}

const loaderReferenceMagic = "RVLB1"
const loaderReferenceStringLimit = 4096
const loaderReferenceByteLimit = 32 << 10

var errLoaderReference = errors.New("loader qualification reference")

// The fixed-format transport calls no JSON, reflection, base64, parser,
// converter or dependency-pool path in measured-child setup.
func encodeLoaderReference(ref loaderBudgetReference) ([]byte, error) {
	if len(ref.Public) != ed25519.PublicKeySize || ref.DecodeCalls < 0 || ref.DecodeCalls > 1 {
		return nil, errLoaderReference
	}
	fields := [...]string{ref.Name, ref.PayloadPath, ref.ArchivePath, ref.DocumentPath, ref.Error, ref.YAMLError}
	size := len(loaderReferenceMagic) + 8 + 2 + ed25519.PublicKeySize
	for _, field := range fields {
		if len(field) > loaderReferenceStringLimit {
			return nil, errLoaderReference
		}
		size += 2 + len(field)
	}
	if size > loaderReferenceByteLimit {
		return nil, errLoaderReference
	}
	data := make([]byte, 0, size)
	data = append(data, loaderReferenceMagic...)
	data = binary.BigEndian.AppendUint64(data, ref.Options.MaxTotalFileBytes)
	flag := byte(0)
	if ref.Options.AllowReservedID {
		flag = 1
	}
	data = append(data, flag, byte(ref.DecodeCalls))
	data = append(data, ref.Public...)
	for _, field := range fields {
		data = binary.BigEndian.AppendUint16(data, uint16(len(field)))
		data = append(data, field...)
	}
	return data, nil
}
func decodeLoaderReference(data []byte) (loaderBudgetReference, error) {
	const header = len(loaderReferenceMagic) + 8 + 2 + ed25519.PublicKeySize
	if len(data) < header || len(data) > loaderReferenceByteLimit || string(data[:len(loaderReferenceMagic)]) != loaderReferenceMagic {
		return loaderBudgetReference{}, errLoaderReference
	}
	offset := len(loaderReferenceMagic)
	ceiling := binary.BigEndian.Uint64(data[offset : offset+8])
	offset += 8
	if data[offset] > 1 || data[offset+1] > 1 {
		return loaderBudgetReference{}, errLoaderReference
	}
	ref := loaderBudgetReference{Options: Options{AllowReservedID: data[offset] == 1, MaxTotalFileBytes: ceiling}, DecodeCalls: int(data[offset+1])}
	offset += 2
	ref.Public = bytes.Clone(data[offset : offset+ed25519.PublicKeySize])
	offset += ed25519.PublicKeySize
	fields := [...]*string{&ref.Name, &ref.PayloadPath, &ref.ArchivePath, &ref.DocumentPath, &ref.Error, &ref.YAMLError}
	for _, field := range fields {
		if len(data)-offset < 2 {
			return loaderBudgetReference{}, errLoaderReference
		}
		n := int(binary.BigEndian.Uint16(data[offset : offset+2]))
		offset += 2
		if n > loaderReferenceStringLimit || n > len(data)-offset {
			return loaderBudgetReference{}, errLoaderReference
		}
		*field = string(data[offset : offset+n])
		offset += n
	}
	if offset != len(data) {
		return loaderBudgetReference{}, errLoaderReference
	}
	return ref, nil
}

func TestLoaderReferenceTransport(t *testing.T) {
	ref := loaderBudgetReference{Public: bytes.Repeat([]byte{0xff}, ed25519.PublicKeySize), Name: "recipe/\u03bb\x00\n", PayloadPath: "/tmp/payload", ArchivePath: "/tmp/archive", DocumentPath: "", Error: "static error", YAMLError: "", Options: Options{AllowReservedID: true, MaxTotalFileBytes: ^uint64(0)}, DecodeCalls: 1}
	data, err := encodeLoaderReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(data, []byte(loaderReferenceMagic)) {
		t.Error("transport must use the versioned binary format")
	}
	got, err := decodeLoaderReference(data)
	if err != nil || !reflect.DeepEqual(got, ref) {
		t.Fatalf("transport changed exact values: %v", err)
	}
	ref.Name = strings.Repeat("x", loaderReferenceStringLimit)
	atLimit, err := encodeLoaderReference(ref)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = decodeLoaderReference(atLimit); err != nil {
		t.Fatal(err)
	}
	ref.Name += "x"
	if _, err = encodeLoaderReference(ref); err == nil {
		t.Error("accepted oversized reference string")
	}
	ref.Name = "valid"
	ref.Public = nil
	if _, err = encodeLoaderReference(ref); err == nil {
		t.Error("accepted invalid public-key length")
	}
	for name, invalid := range map[string][]byte{"legacy-json": []byte(`{}`), "oversized": make([]byte, loaderReferenceByteLimit+1), "suffix": append(bytes.Clone(data), 0), "truncated": data[:len(data)-1]} {
		t.Run(name, func(t *testing.T) {
			got, err := decodeLoaderReference(invalid)
			if err == nil || !reflect.DeepEqual(got, loaderBudgetReference{}) {
				t.Fatal("invalid transport accepted or partial reference returned")
			}
		})
	}
	if bytes.HasPrefix(data, []byte(loaderReferenceMagic)) {
		for _, offset := range []int{0, len(loaderReferenceMagic) + 8, len(loaderReferenceMagic) + 9} {
			invalid := bytes.Clone(data)
			invalid[offset] = 0xff
			if got, err := decodeLoaderReference(invalid); err == nil || !reflect.DeepEqual(got, loaderBudgetReference{}) {
				t.Fatal("invalid binary header accepted")
			}
		}
		for n := 0; n < len(data); n++ {
			if got, err := decodeLoaderReference(data[:n]); err == nil || !reflect.DeepEqual(got, loaderBudgetReference{}) {
				t.Fatalf("truncated transport accepted at %d", n)
			}
		}
	}
}

func TestLoaderMembershipRecipes(t *testing.T) {
	for _, recipe := range loaderMembershipRecipes(t) {
		t.Run(recipe.Name, func(t *testing.T) {
			p, err := Load(loaderRecipeReader(recipe.Name, recipe.Archive, effectiveFileLimit(recipe.Options)), keyPublic(t), recipe.Options)
			if recipe.want != nil {
				assertLoadError(t, p, err, recipe.want)
			} else if err != nil {
				t.Fatal(err)
			} else {
				assertPackageCommitments(t, p, recipe.Archive)
			}
		})
	}
}

func TestLoaderReadFailureRecipe(t *testing.T) {
	reader := loaderRecipeReader("reader/cause", nil, 1)
	p, err := Load(reader, keyPublic(t), Options{MaxTotalFileBytes: 1})
	if !reflect.DeepEqual(p, Package{}) || !errors.Is(err, ErrRead) || !errors.Is(err, loaderRecipeCause) {
		t.Fatal("read failure lost its zero result or cause")
	}
	if err.Error() != "extension read" {
		t.Fatal("read failure must have the static read-error message")
	}
}

// All recipe construction and signing happens in the parent, before measurement.
func loaderMembershipRecipes(t *testing.T) []loaderBudgetInput {
	t.Helper()
	var out []loaderBudgetInput
	add := func(name string, d map[string]any, files []archiveEntry, want error) {
		payload := jsonPayload(t, d)
		out = append(out, loaderBudgetInput{Name: "membership/" + name, Payload: payload,
			Archive: packageArchive(t, payload, signedEnvelope(t, payload), files...),
			Options: Options{MaxTotalFileBytes: 1}, want: want})
	}
	// Eight-letter ordinary paths prove the F=1 reference-failure stage is
	// reachable. They make no assertion about the runtime's secret hash seed.
	for _, n := range []int{896, 897, 4096} {
		d := baseDocument(t)
		c := d["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
		paths := make([]any, n)
		for i := range paths {
			path := []byte("aaaaaaaa")
			for v, j := i, 7; v > 0; v, j = v/26, j-1 {
				path[j] += byte(v % 26)
			}
			paths[i] = string(path)
		}
		c["files"], c["file"] = paths, paths[0]
		file := []byte("x")
		h := sha256.Sum256(file)
		d["files"] = []any{map[string]any{"path": "listed", "size": json.Number("1"), "sha256": hex.EncodeToString(h[:])}}
		add(fmt.Sprintf("reference-witness/%d", n), d, []archiveEntry{{"listed", file}}, manifest.ErrReference)
		// Earlier field/path stages still dominate the missing references.
		c["files"] = append(paths, paths[0])
		add(fmt.Sprintf("field-before-reference/%d", n), d, []archiveEntry{{"listed", file}}, manifest.ErrField)
		c["files"] = paths
		c["file"] = "con"
		add(fmt.Sprintf("path-before-reference/%d", n), d, []archiveEntry{{"listed", file}}, manifest.ErrPath)
	}
	// Full listing and single-component ownership capacities, including long
	// common prefixes and zero-size files, remain accepted at F=1.
	for _, prefix := range []string{"f", strings.Repeat("a", 32) + "/"} {
		d := baseDocument(t)
		c := d["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
		paths, listing := make([]any, 4096), make([]any, 4096)
		files := make([]archiveEntry, 4096)
		h := sha256.Sum256(nil)
		for i := range paths {
			path := fmt.Sprintf("%s%04d", prefix, i)
			paths[i] = path
			listing[i] = map[string]any{"path": path, "size": json.Number("0"), "sha256": hex.EncodeToString(h[:])}
			files[i] = archiveEntry{path, nil}
		}
		c["files"], c["file"], d["files"] = paths, paths[0], listing
		name := "maximum-listing-ownership"
		if len(prefix) > 1 {
			name += "-common-prefix"
		}
		add(name, d, files, nil)
		// Unequal records sharing a path precede the now-missing ownership.
		listing[4095].(map[string]any)["path"] = paths[0]
		listing[4095].(map[string]any)["sha256"] = strings.Repeat("0", 64)
		add(name+"-duplicate-before-reference", d, files, manifest.ErrDuplicate)
	}
	return out
}

type loaderFailureCause struct{}

func (*loaderFailureCause) Error() string { panic("qualification cause must never be formatted") }

var loaderRecipeCause = &loaderFailureCause{}

type loaderFailureReader struct{}

func (*loaderFailureReader) Read([]byte) (int, error) { return 0, loaderRecipeCause }
func loaderRecipeReader(name string, archive []byte, f uint64) *io.LimitedReader {
	reader := archiveReader(archive, f)
	if name == "reader/cause" {
		reader.R = &loaderFailureReader{}
	}
	return reader
}
