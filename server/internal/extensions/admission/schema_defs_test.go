package admission

import (
	"bytes"
	"encoding/json"
	"os"
	"reflect"
	"sort"
	"testing"
)

const schemaDir = "../../../../schemas/extension/v1alpha1/"

func readJSON(t testing.TB, name string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(schemaDir + name)
	if err != nil {
		t.Fatal(err)
	}
	d := json.NewDecoder(bytes.NewReader(b))
	d.UseNumber()
	var v map[string]any
	if err := d.Decode(&v); err != nil {
		t.Fatal(err)
	}
	return v
}

func defs(t testing.TB, schema map[string]any) map[string]any {
	t.Helper()
	d, ok := schema["$defs"].(map[string]any)
	if !ok {
		t.Fatal("schema has no $defs")
	}
	return d
}

func TestSchemaDefsIdentical(t *testing.T) {
	resource := readJSON(t, "extension-resource.schema.json")
	grant := readJSON(t, "capability-grant.schema.json")
	vectors := readJSON(t, "admission-vectors.schema.json")
	shared := []string{"id", "name", "version", "digest", "fingerprint", "uint64", "uuid", "targets"}
	for _, name := range shared {
		r, g, v := defs(t, resource)[name], defs(t, grant)[name], defs(t, vectors)[name]
		if r == nil || !reflect.DeepEqual(r, g) || !reflect.DeepEqual(g, v) {
			t.Errorf("$defs/%s differs across the three schemas", name)
		}
	}
	if g := defs(t, grant)["grant"]; g == nil || !reflect.DeepEqual(defs(t, resource)["grant"], g) {
		t.Error("$defs/grant differs between the resource and grant schemas")
	}
	if _, ok := defs(t, vectors)["grant"]; ok {
		t.Error("the vectors schema must type embedded grants as object only")
	}
	approval := defs(t, grant)["approval"].(map[string]any)["oneOf"].([]any)
	request := vectors["properties"].(map[string]any)["cases"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["request"].(map[string]any)
	branches := request["properties"].(map[string]any)["approval"].(map[string]any)["oneOf"].([]any)
	if len(branches) != 4 || !reflect.DeepEqual(branches[0], map[string]any{"type": "null"}) || !reflect.DeepEqual(branches[1:], approval) {
		t.Error("approval shapes differ between the grant schema and the vectors schema")
	}
}

// TestSchemaEnumParity keeps the Go enumerations equal to the schema enums.
func TestSchemaEnumParity(t *testing.T) {
	vectors := readJSON(t, "admission-vectors.schema.json")
	expected := vectors["properties"].(map[string]any)["cases"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["expected"].(map[string]any)["properties"].(map[string]any)
	enum := func(v any) []string {
		var out []string
		for _, x := range v.(map[string]any)["enum"].([]any) {
			out = append(out, x.(string))
		}
		sort.Strings(out)
		return out
	}
	codes := enum(expected["reasons"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["code"])
	var goCodes []string
	for _, c := range allCodes {
		goCodes = append(goCodes, string(c))
	}
	sort.Strings(goCodes)
	if !reflect.DeepEqual(codes, goCodes) || len(goCodes) != 53 {
		t.Errorf("reason codes differ: schema %v, Go %v", codes, goCodes)
	}
	stages := enum(expected["stage"])
	var goStages []string
	for _, s := range stageOrder {
		goStages = append(goStages, string(s))
	}
	sort.Strings(goStages)
	if !reflect.DeepEqual(stages, goStages) {
		t.Errorf("stages differ: schema %v, Go %v", stages, goStages)
	}
	snapshot := vectors["properties"].(map[string]any)["cases"].(map[string]any)["items"].(map[string]any)["properties"].(map[string]any)["snapshot"].(map[string]any)["properties"].(map[string]any)
	interfaces := enum(snapshot["served_interfaces"].(map[string]any)["items"])
	var goInterfaces []string
	for _, p := range componentPairs {
		goInterfaces = append(goInterfaces, p.iface)
	}
	sort.Strings(goInterfaces)
	if !reflect.DeepEqual(interfaces, goInterfaces) {
		t.Errorf("interfaces differ: schema %v, Go %v", interfaces, goInterfaces)
	}
}
