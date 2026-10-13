package manifest_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"reflect"
	"runtime"
	"runtime/debug"
	"strings"
	"testing"

	m "github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func TestFieldOrderBehavior(t *testing.T) {
	t.Run("valid-kinds", func(t *testing.T) {
		for _, name := range []string{"content", "browser-adapter", "classifier", "parser", "collector", "responder", "console-module", "service-connector"} {
			t.Run(name, func(t *testing.T) { membershipCheck(t, fixture(t, name), m.Options{}, nil) })
		}
	})
	t.Run("capacity", TestMembershipCapacity)
	for _, position := range []int{0, 1, 2} {
		t.Run(fmt.Sprintf("invalid-child-%d", position), func(t *testing.T) {
			d := base(t)
			membershipComponent(d)["files"] = []any{"a", "b", "c"}
			membershipComponent(d)["files"].([]any)[position] = "BAD"
			membershipCheck(t, d, m.Options{}, m.ErrField)
		})
		t.Run(fmt.Sprintf("invalid-root-record-%d", position), func(t *testing.T) {
			d := base(t)
			d["files"] = []any{membershipFile("a"), membershipFile("b"), membershipFile("c")}
			d["files"].([]any)[position].(map[string]any)["path"] = "BAD"
			membershipCheck(t, d, m.Options{}, m.ErrField)
		})
	}
	tests := []struct {
		name string
		edit func(map[string]any)
		want error
	}{
		{"structural-duplicate", func(d map[string]any) { a := d["files"].([]any); d["files"] = append(a, membershipReorder(a[0])) }, m.ErrField},
		{"unequal-same-path", func(d map[string]any) {
			a := d["files"].([]any)
			f := clone(a[0]).(map[string]any)
			f["size"] = json.Number("4")
			d["files"] = append(a, f)
		}, m.ErrDuplicate},
		{"nested-invalid", func(d map[string]any) { membershipComponent(d)["name"] = "BAD" }, m.ErrField},
		{"excess-child-cardinality", func(d map[string]any) {
			a := make([]any, 4097)
			for i := range a {
				a[i] = "a"
			}
			membershipComponent(d)["files"] = a
		}, m.ErrField},
		{"duplicate-plus-invalid", func(d map[string]any) { membershipComponent(d)["files"] = []any{"a", "a", "BAD"} }, m.ErrField},
		{"nested-duplicate", func(d map[string]any) { membershipComponent(d)["files"] = []any{"a", "a"} }, m.ErrField},
		{"tree-before-field", func(d map[string]any) { membershipComponent(d)["name"] = "BAD"; d["invalid"] = nil }, m.ErrTree},
		{"shape-before-field", func(d map[string]any) { membershipComponent(d)["name"] = "BAD"; d["invalid"] = true }, m.ErrShape},
		{"field-before-reference", func(d map[string]any) {
			membershipComponent(d)["name"] = "BAD"
			membershipComponent(d)["file"] = "missing"
		}, m.ErrField},
		{"field-before-license", func(d map[string]any) {
			membershipComponent(d)["name"] = "BAD"
			d["metadata"].(map[string]any)["license"] = "MIT AND"
		}, m.ErrField},
		{"field-before-url", func(d map[string]any) {
			membershipComponent(d)["name"] = "BAD"
			d["metadata"].(map[string]any)["source"] = "https://example.com/%GG"
		}, m.ErrField},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) { d := base(t); tc.edit(d); membershipCheck(t, d, m.Options{}, tc.want) })
	}
}

// fieldOrderAllocationDocument constructs the fixed family without warming
// Validate, Marshal, or any candidate encoder. Only the selected path is invalid.
func fieldOrderAllocationDocument(kind string) map[string]any {
	c := map[string]any{"name": "a", "kind": "content", "interface": "ext.ricevanta.io/content/v1", "file": "a", "format": "sigma", "files": []any{"a"}, "capabilities": map[string]any{}}
	f := membershipFile("a")
	d := map[string]any{
		"apiVersion": "ricevanta.io/v1alpha1", "kind": "Extension",
		"metadata": map[string]any{"id": "a.b", "version": "1.0.0", "publisher": map[string]any{"name": "a", "key": "sha256:" + strings.Repeat("0", 64)}, "license": "MIT", "source": "https://a.b"},
		"spec":     map[string]any{"requires": map[string]any{"content": []any{"ext.ricevanta.io/content/v1"}}, "components": []any{c}},
		"files":    []any{f},
	}
	invalid := strings.Repeat("&", 256<<10)
	if kind == "component-child" {
		c["files"] = []any{invalid}
	} else {
		f["path"] = invalid
	}
	return d
}

func TestFieldOrderAllocation(t *testing.T) {
	const childEnv = "RICEVANTA_MANIFEST_FIELD_ORDER_CHILD"
	kind := os.Getenv(childEnv)
	if kind == "" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		// A fixed finite family, one cold process per case, with no retries.
		for _, kind := range []string{"component-child", "root-file"} {
			t.Run(kind, func(t *testing.T) {
				cmd := exec.Command(executable, "-test.run=^TestFieldOrderAllocation$", "-test.count=1", "-test.v")
				cmd.Env = append(os.Environ(), childEnv+"="+kind)
				output, err := cmd.CombinedOutput()
				t.Logf("%s", output)
				if err != nil {
					t.Fatalf("cold child failed: %v", err)
				}
			})
		}
		return
	}
	if kind != "component-child" && kind != "root-file" {
		t.Fatal("unknown allocation fixture")
	}
	d := fieldOrderAllocationDocument(kind)
	unchanged := membershipReorder(d)
	oldProcs := runtime.GOMAXPROCS(1)
	defer runtime.GOMAXPROCS(oldProcs)
	var before, after runtime.MemStats
	runtime.GC()
	oldGC := debug.SetGCPercent(-1)
	runtime.ReadMemStats(&before)
	err := m.Validate(d, m.Options{})
	runtime.ReadMemStats(&after)
	debug.SetGCPercent(oldGC)
	runtime.KeepAlive(d)
	if !errors.Is(err, m.ErrField) {
		t.Fatalf("got %v, want ErrField", err)
	}
	if !reflect.DeepEqual(d, unchanged) {
		t.Fatal("validation changed input")
	}
	if after.NumGC != before.NumGC {
		t.Fatal("GC ran in cold interval")
	}
	// Source-derived before measurement: full regex/tail families plus four
	// <=1KiB encoder chains/copies and bounded reflection/slices/key sorting.
	// No subtraction, noise allowance, elapsed-time limit, or warmup is used.
	const upper = 731008 + 76856 + 1256 + 512 + 4*6400 + 4*2*1024 + 128*128 + 128 + 5856
	allocated := after.TotalAlloc - before.TotalAlloc
	t.Logf("%s raw TotalAlloc=%d source upper=%d", kind, allocated, upper)
	if allocated > upper {
		t.Fatalf("unchecked item serialization: allocated %d bytes, upper %d", allocated, upper)
	}
}
