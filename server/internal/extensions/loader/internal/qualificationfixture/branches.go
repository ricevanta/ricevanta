package qualificationfixture

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

func MaximumBranch(index int, data []byte) []byte {
	var schema map[string]any
	if err := json.Unmarshal(data, &schema); err != nil {
		panic(err)
	}
	branches := schema["$defs"].(map[string]any)["component"].(map[string]any)["oneOf"].([]any)
	var document map[string]any
	d := json.NewDecoder(bytes.NewReader(MaximumManifest()))
	d.UseNumber()
	if err := d.Decode(&document); err != nil {
		panic(err)
	}
	spec := document["spec"].(map[string]any)
	prototype := branches[index].(map[string]any)["properties"].(map[string]any)
	kind := prototype["kind"].(map[string]any)["const"].(string)
	iface := prototype["interface"].(map[string]any)
	interfaceName, _ := iface["const"].(string)
	if interfaceName == "" {
		interfaceName = iface["enum"].([]any)[0].(string)
	}
	components := spec["components"].([]any)
	for j, v := range components {
		old := v.(map[string]any)
		c := map[string]any{"name": fmt.Sprintf("c%d", j), "kind": kind, "interface": interfaceName, "files": old["files"]}
		for key, rule := range prototype {
			if key == "name" || key == "kind" || key == "interface" || key == "files" {
				continue
			}
			if key == "file" || key == "entry" || key == "row_schema" {
				c[key] = old["file"]
				continue
			}
			c[key] = schemaLimitValue(rule.(map[string]any), schema["$defs"].(map[string]any), key)
		}
		components[j] = c
	}
	spec["requires"] = map[string]any{kind: []any{interfaceName}}
	b, err := json.Marshal(document)
	if err != nil {
		panic(err)
	}
	return b
}
func schemaLimitValue(rule, defs map[string]any, key string) any {
	if ref, ok := rule["$ref"].(string); ok {
		return schemaLimitValue(defs[strings.TrimPrefix(ref, "#/$defs/")].(map[string]any), defs, key)
	}
	if value, ok := rule["const"]; ok {
		return value
	}
	if enum, ok := rule["enum"].([]any); ok {
		return enum[0]
	}
	switch rule["type"] {
	case "integer":
		return json.Number(fmt.Sprintf("%.0f", rule["maximum"]))
	case "boolean":
		return true
	case "string":
		switch key {
		case "registration":
			return "a.b"
		case "mime_types":
			return "a/" + strings.Repeat("b", 125)
		case "policy_names":
			return "Policy"
		default:
			return "a"
		}
	case "object":
		out := map[string]any{}
		props, _ := rule["properties"].(map[string]any)
		for k, r := range props {
			out[k] = schemaLimitValue(r.(map[string]any), defs, k)
		}
		return out
	case "array":
		n := int(rule["maxItems"].(float64))
		out := make([]any, n)
		item := rule["items"].(map[string]any)
		if enum, ok := item["enum"].([]any); ok {
			copy(out, enum)
			return out
		}
		for i := range out {
			switch key {
			case "policy_names":
				out[i] = fmt.Sprintf("Policy%d", i)
			case "mime_types":
				out[i] = fmt.Sprintf("a%d/", i) + strings.Repeat("b", 127-len(fmt.Sprintf("a%d/", i)))
			default:
				out[i] = schemaLimitValue(item, defs, key)
			}
		}
		return out
	}
	panic("unsupported branch schema")
}
