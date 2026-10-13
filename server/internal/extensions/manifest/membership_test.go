package manifest_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"

	m "github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func membershipComponent(d map[string]any) map[string]any {
	return d["spec"].(map[string]any)["components"].([]any)[0].(map[string]any)
}
func membershipFile(path string) map[string]any {
	return map[string]any{"path": path, "size": json.Number("0"), "sha256": strings.Repeat("0", 64)}
}
func membershipListing(d map[string]any, paths ...string) {
	files := make([]any, len(paths))
	refs := make([]any, len(paths))
	for i, p := range paths {
		files[i] = membershipFile(p)
		refs[i] = p
	}
	d["files"] = files
	c := membershipComponent(d)
	c["files"] = refs
	c["file"] = paths[0]
}
func membershipCheck(t *testing.T, d map[string]any, o m.Options, want error) {
	t.Helper()
	before, err := json.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	for range 3 {
		check(t, d, o, want)
	}
	after, err := json.Marshal(d)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("validation changed input")
	}
	// Reinsert every map in reverse key order, preserving arrays.
	check(t, membershipReorder(d), o, want)
}
func membershipReorder(v any) any {
	switch x := v.(type) {
	case map[string]any:
		keys := make([]string, 0, len(x))
		for k := range x {
			keys = append(keys, k)
		}
		slices.Sort(keys)
		slices.Reverse(keys)
		out := make(map[string]any, len(x))
		for _, k := range keys {
			out[k] = membershipReorder(x[k])
		}
		return out
	case []any:
		out := make([]any, len(x))
		for i, v := range x {
			out[i] = membershipReorder(v)
		}
		return out
	default:
		return v
	}
}

func TestMembershipCapacity(t *testing.T) {
	for _, n := range []int{896, 897, 4096} {
		t.Run(fmt.Sprintf("valid-%d", n), func(t *testing.T) {
			d := base(t)
			paths := make([]string, n)
			for i := range paths {
				paths[i] = fmt.Sprintf("common-prefix/f%04d", n-i)
			}
			membershipListing(d, paths...)
			membershipCheck(t, d, m.Options{MaxTotalFileBytes: 1}, nil)
		})
		t.Run(fmt.Sprintf("missing-F1-%d", n), func(t *testing.T) {
			d := base(t)
			d["files"].([]any)[0].(map[string]any)["size"] = json.Number("1")
			refs := make([]any, n)
			for i := range refs {
				refs[i] = fmt.Sprintf("missing/f%04d", i)
			}
			membershipComponent(d)["files"] = refs
			membershipCheck(t, d, m.Options{MaxTotalFileBytes: 1}, m.ErrReference)
		})
	}
	d := base(t)
	paths := make([]string, 64)
	for i := range paths {
		paths[i] = fmt.Sprintf("f%02d", i)
	}
	membershipListing(d, paths...)
	template := membershipComponent(d)
	components := make([]any, 64)
	for i, p := range paths {
		c := clone(template).(map[string]any)
		c["name"] = fmt.Sprintf("c%d", i)
		c["files"] = []any{p}
		c["file"] = p
		components[i] = c
	}
	d["spec"].(map[string]any)["components"] = components
	membershipCheck(t, d, m.Options{}, nil)
	t.Run("other-array-ceilings", membershipOtherArrayCeilings)
}

func TestMembershipDuplicates(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
		want   error
	}{
		{"equal-file-reordered-keys", func(d map[string]any) { f := d["files"].([]any)[0]; d["files"] = []any{f, membershipReorder(f)} }, m.ErrField},
		{"unequal-file-same-path", func(d map[string]any) {
			f := clone(d["files"].([]any)[0]).(map[string]any)
			f["size"] = json.Number("0")
			d["files"] = append(d["files"].([]any), f)
		}, m.ErrDuplicate},
		{"equal-component-reordered-keys", func(d map[string]any) {
			c := membershipComponent(d)
			d["spec"].(map[string]any)["components"] = []any{c, membershipReorder(c)}
		}, m.ErrField},
		{"unequal-component-same-name", func(d map[string]any) {
			c := clone(membershipComponent(d)).(map[string]any)
			c["format"] = "yara"
			d["spec"].(map[string]any)["components"] = []any{membershipComponent(d), c}
		}, m.ErrDuplicate},
		{"changed-array-order-distinct", func(d map[string]any) {
			membershipListing(d, "a", "b")
			c := clone(membershipComponent(d)).(map[string]any)
			c["files"] = []any{"b", "a"}
			d["spec"].(map[string]any)["components"] = []any{membershipComponent(d), c}
		}, m.ErrDuplicate},
		{"duplicate-component-reference", func(d map[string]any) { c := membershipComponent(d); c["files"] = []any{c["file"], c["file"]} }, m.ErrField},
	} {
		t.Run(tc.name, func(t *testing.T) { d := base(t); tc.mutate(d); membershipCheck(t, d, m.Options{}, tc.want) })
	}
}

func TestMembershipRelations(t *testing.T) {
	for _, tc := range []struct {
		name, fixture string
		mutate        func(map[string]any)
		want          error
	}{
		{"shared", "content", func(d map[string]any) {
			c := clone(membershipComponent(d)).(map[string]any)
			c["name"] = "second"
			d["spec"].(map[string]any)["components"] = []any{membershipComponent(d), c}
		}, m.ErrReference},
		{"wrong-owner-entry", "console-module", func(d map[string]any) {
			c := membershipComponent(d)
			path := c["entry"].(string)
			second := clone(c).(map[string]any)
			second["name"] = "second"
			second["files"] = []any{"second.js"}
			second["entry"] = path
			d["files"] = append(d["files"].([]any), membershipFile("second.js"))
			d["spec"].(map[string]any)["components"] = []any{c, second}
		}, m.ErrReference},
		{"absent-entry", "console-module", func(d map[string]any) { membershipComponent(d)["entry"] = "absent.js" }, m.ErrReference},
		{"absent-row-schema", "collector", func(d map[string]any) { membershipComponent(d)["row_schema"] = "absent.json" }, m.ErrReference},
		{"unowned", "content", func(d map[string]any) { d["files"] = append(d["files"].([]any), membershipFile("unowned")) }, m.ErrReference},
		{"unowned-attestation", "content", func(d map[string]any) { d["files"] = append(d["files"].([]any), membershipFile("attestations/proof")) }, nil},
		{"owned-attestation", "content", func(d map[string]any) { membershipListing(d, "attestations/proof") }, m.ErrReference},
		{"prefix-nonneighbor", "content", func(d map[string]any) { membershipListing(d, "a", "a-b", "a/b") }, m.ErrPath},
		{"prefix-absent", "content", func(d map[string]any) { membershipListing(d, "a-b", "a/b") }, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := fixture(t, tc.fixture)
			tc.mutate(d)
			membershipCheck(t, d, m.Options{}, tc.want)
		})
	}
}

func TestMembershipPrecedence(t *testing.T) {
	defects := []struct {
		want  error
		apply func(map[string]any)
	}{
		{m.ErrField, func(d map[string]any) { membershipComponent(d)["files"] = []any{"same", "same"} }},
		{m.ErrReserved, func(d map[string]any) { d["metadata"].(map[string]any)["id"] = "io.ricevanta" }},
		{m.ErrDuplicate, func(d map[string]any) {
			f := clone(d["files"].([]any)[0]).(map[string]any)
			f["size"] = json.Number("1")
			d["files"] = append(d["files"].([]any), f)
		}},
		{m.ErrPath, func(d map[string]any) { d["files"] = append(d["files"].([]any), membershipFile("con.bin")) }},
		{m.ErrLimit, func(d map[string]any) { d["files"].([]any)[0].(map[string]any)["size"] = json.Number("67108865") }},
		{m.ErrRequires, func(d map[string]any) {
			d["spec"].(map[string]any)["requires"].(map[string]any)["content"] = []any{"ext.ricevanta.io/content/v1"}
		}},
		{m.ErrReference, func(d map[string]any) { membershipComponent(d)["row_schema"] = "absent.json" }},
		{m.ErrCapability, func(d map[string]any) {
			caps := membershipComponent(d)["capabilities"].(map[string]any)
			caps["max_bytes_per_file"] = json.Number("2")
			caps["max_input_bytes"] = json.Number("1")
		}},
		{m.ErrLicense, func(d map[string]any) { d["metadata"].(map[string]any)["license"] = "MIT AND" }},
	}
	for i, first := range defects {
		for j := i + 1; j < len(defects); j++ {
			t.Run(fmt.Sprintf("%d-before-%d", i, j), func(t *testing.T) {
				d := fixture(t, "collector")
				first.apply(d)
				defects[j].apply(d)
				membershipCheck(t, d, m.Options{}, first.want)
			})
		}
	}
}

// The schema supplies the independent enum oracle; generated strings and
// records exercise the non-enum ceilings with distinct elements.
func membershipOtherArrayCeilings(t *testing.T) {
	b, err := os.ReadFile("../../../../schemas/extension/v1alpha1/manifest.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err = json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	branches := schema["$defs"].(map[string]any)["component"].(map[string]any)["oneOf"].([]any)
	for _, tc := range []struct {
		fixture, field string
		cap            int
	}{
		{"parser", "mime_types", 32}, {"responder", "actions", 9}, {"console-module", "operations", 23},
		{"console-module", "slots", 6}, {"service-connector", "outbound", 64}, {"browser-adapter", "policy_names", 64},
	} {
		t.Run(tc.fixture+"-"+tc.field, func(t *testing.T) {
			d := fixture(t, tc.fixture)
			c := membershipComponent(d)
			target := c["capabilities"].(map[string]any)
			var enum []any
			for _, v := range branches {
				props := v.(map[string]any)["properties"].(map[string]any)
				if props["kind"].(map[string]any)["const"] != c["kind"] {
					continue
				}
				iface := props["interface"].(map[string]any)
				if constant, ok := iface["const"]; ok && constant != c["interface"] {
					continue
				}
				fieldProps := props["capabilities"].(map[string]any)["properties"].(map[string]any)
				if tc.field == "slots" {
					fieldProps = props
					target = c
				}
				if field, ok := fieldProps[tc.field].(map[string]any); ok {
					enum, _ = field["items"].(map[string]any)["enum"].([]any)
				}
			}
			values := make([]any, tc.cap)
			for i := range values {
				switch tc.field {
				case "mime_types":
					values[i] = fmt.Sprintf("application/x%d", i)
				case "outbound":
					values[i] = map[string]any{"host": fmt.Sprintf("h%d.example", i), "port": json.Number("1"), "transport": "tcp"}
				case "policy_names":
					values[i] = fmt.Sprintf("Policy%d", i)
				default:
					if len(enum) != tc.cap {
						t.Fatal("enum ceiling oracle")
					}
					values[i] = enum[i]
				}
			}
			if tc.field == "policy_names" {
				osCaps := target["os"].(map[string]any)
				for _, name := range []string{"macos", "windows", "linux"} {
					osCaps[name] = map[string]any{"policy_names": slices.Clone(values), "native_host": true}
				}
				target = osCaps["linux"].(map[string]any)
			}
			target[tc.field] = values
			membershipCheck(t, d, m.Options{}, nil)
			target[tc.field] = append(slices.Clone(values), values[0])
			membershipCheck(t, d, m.Options{}, m.ErrField)
		})
	}
	t.Run("all-requirement-arrays", func(t *testing.T) {
		d := base(t)
		var components, files []any
		requires := map[string]any{}
		specProps := schema["properties"].(map[string]any)["spec"].(map[string]any)["properties"].(map[string]any)
		reqProps := specProps["requires"].(map[string]any)["properties"].(map[string]any)
		for _, name := range []string{"content", "browser-adapter", "classifier", "parser", "collector", "responder", "console-module", "service-connector"} {
			c := clone(membershipComponent(fixture(t, name))).(map[string]any)
			kind := c["kind"].(string)
			if _, ok := requires[kind]; !ok {
				requires[kind] = slices.Clone(reqProps[kind].(map[string]any)["items"].(map[string]any)["enum"].([]any))
			}
			interfaces := []any{c["interface"]}
			if kind == "service-connector" {
				interfaces = requires[kind].([]any)
			}
			for _, iface := range interfaces {
				component := clone(c).(map[string]any)
				component["interface"] = iface
				component["name"] = fmt.Sprintf("c%d", len(components))
				owned := []any{}
				for _, key := range []string{"file", "entry", "row_schema"} {
					if _, ok := component[key]; ok {
						p := fmt.Sprintf("c%d/%s", len(components), key)
						component[key] = p
						owned = append(owned, p)
						files = append(files, membershipFile(p))
					}
				}
				component["files"] = owned
				components = append(components, component)
			}
		}
		d["files"] = files
		spec := d["spec"].(map[string]any)
		spec["components"] = components
		spec["requires"] = requires
		membershipCheck(t, d, m.Options{}, nil)
		for kind, v := range requires {
			a := v.([]any)
			requires[kind] = append(slices.Clone(a), a[0])
			membershipCheck(t, d, m.Options{}, m.ErrField)
			requires[kind] = a
		}
	})
}
