package ocsf

import (
	"bytes"
	"io/fs"
	"os"
	"testing"
	"testing/fstest"
)

func TestCompiledDrift(t *testing.T) {
	entries, err := schemas.ReadDir("schema")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 5 {
		t.Fatal("embed inventory")
	}
	for _, e := range entries {
		a, err := schemas.ReadFile("schema/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile("../../../../schemas/ocsf/compiled/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Fatal("embed drift")
		}
	}
}
func TestSchemaLoader(t *testing.T) {
	if _, err := loadSchemas(schemas); err != nil {
		t.Fatal(err)
	}
	for _, text := range []string{`{"type":"null"}`, `{"unknown":true}`, `{"$ref":"https://example.com"}`, `{"additionalProperties":true}`, `{"x-rule":["unknown"]}`, `{"$defs":{"a":{"$ref":"#/$defs/a"}},"$ref":"#/$defs/a"}`} {
		v, err := decode(text)
		if err != nil {
			t.Fatal(err)
		}
		if _, err = compileSchema(v, nil, 0); err == nil {
			t.Fatalf("schema accepted %s", text)
		}
	}
}

func TestSchemaNestedDefinitions(t *testing.T) {
	v, err := decode(`{"properties":{"x":{"$defs":{"a":{"unknown":true}}}}}`)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = compileSchema(v, nil, 0); err == nil {
		t.Fatal("unchecked nested definitions")
	}
}

func TestSchemaLogicalBranches(t *testing.T) {
	for _, c := range []struct {
		schema, value string
		want          bool
	}{
		{`{"oneOf":[{"type":"string"},{"type":"integer"}]}`, `"s"`, true},
		{`{"oneOf":[{"type":"string"},{"type":"string"}]}`, `"s"`, false},
		{`{"anyOf":[{"const":1},{"const":2}]}`, `2`, true},
		{`{"anyOf":[{"const":1},{"const":2}]}`, `3`, false},
		{`{"allOf":[{"type":"integer"},{"minimum":1}]}`, `0`, false},
		{`{"allOf":[{"type":"integer"},{"minimum":1}]}`, `1`, true},
		{`{"not":{"const":0}}`, `0`, false},
		{`{"if":{"const":1},"then":{"const":2},"else":{"const":3}}`, `1`, false},
		{`{"if":{"const":1},"then":{"const":2},"else":{"const":3}}`, `3`, true},
		{`{"$defs":{"a":{"type":"integer","x-integer":"uint64"}},"$ref":"#/$defs/a"}`, `18446744073709551615`, true},
		{`{"$defs":{"a":{"type":"integer","x-integer":"uint64"}},"$ref":"#/$defs/a"}`, `18446744073709551616`, false},
		{`{"type":"number","maximum":100}`, `99.999999`, true},
		{`{"type":"number","maximum":100}`, `100.000001`, false},
		{`{"const":1}`, `true`, false},
	} {
		raw, err := decode(c.schema)
		if err != nil {
			t.Fatal(err)
		}
		s, err := compileSchema(raw, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		v, err := decode(c.value)
		if err != nil {
			t.Fatal(err)
		}
		if s.matches(v, Agent) != c.want {
			t.Fatalf("schema case %s", c.schema)
		}
	}
}
func TestDamagedArtifacts(t *testing.T) {
	baseline := fstest.MapFS{}
	entries, err := schemas.ReadDir("schema")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		data, err := schemas.ReadFile("schema/" + e.Name())
		if err != nil {
			t.Fatal(err)
		}
		baseline["schema/"+e.Name()] = &fstest.MapFile{Data: data}
	}
	for _, kind := range []string{"missing", "extra", "digest", "duplicate", "manifest", "symlink"} {
		fsys := fstest.MapFS{}
		for k, v := range baseline {
			fsys[k] = &fstest.MapFile{Data: append([]byte{}, v.Data...)}
		}
		switch kind {
		case "missing":
			delete(fsys, "schema/99901001.schema.json")
		case "extra":
			fsys["schema/extra.json"] = &fstest.MapFile{Data: []byte("{}")}
		case "digest":
			fsys["schema/99901001.schema.json"].Data = append(fsys["schema/99901001.schema.json"].Data, ' ')
		case "duplicate":
			fsys["schema/manifest.json"].Data = []byte(`{"format":1,"format":1}`)
		case "manifest":
			fsys["schema/manifest.json"].Data = []byte(`{}`)
		case "symlink":
			fsys["schema/99901001.schema.json"].Mode = fs.ModeSymlink
		}
		if _, err := loadSchemas(fsys); err == nil {
			t.Fatalf("accepted artifact mutation %s", kind)
		}
	}
}
