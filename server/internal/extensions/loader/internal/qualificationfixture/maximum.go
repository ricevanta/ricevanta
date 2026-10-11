package qualificationfixture

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"strings"
)

var connectorInterfaces = []string{"ext.ricevanta.io/export-destination/v1", "ext.ricevanta.io/ca-connector/v1", "ext.ricevanta.io/notifier/v1", "ext.ricevanta.io/enricher/v1"}

func MaximumManifest() []byte {
	digest := fmt.Sprintf("%x", sha256.Sum256(nil))
	files := make([]any, 4096)
	for i := range files {
		files[i] = map[string]any{"path": fmt.Sprintf("f%04d", i), "sha256": digest, "size": 0}
	}
	components := make([]any, 64)
	for i := range components {
		paths := make([]string, 64)
		for j := range paths {
			paths[j] = fmt.Sprintf("f%04d", i*64+j)
		}
		outbound := make([]any, 64)
		for j := range outbound {
			outbound[j] = map[string]any{"host": fmt.Sprintf("h%d.x", j), "port": 1, "transport": "tcp"}
		}
		components[i] = map[string]any{"name": fmt.Sprintf("c%d", i), "kind": "service-connector", "interface": connectorInterfaces[i%4], "files": paths, "file": paths[0], "capabilities": map[string]any{"outbound": outbound}}
	}
	doc := map[string]any{"apiVersion": "ricevanta.io/v1alpha1", "kind": "Extension", "metadata": map[string]any{"id": "a.b", "version": "1.0.0", "publisher": map[string]any{"name": "a", "key": "sha256:" + strings.Repeat("0", 64)}, "license": "MIT", "source": "https://a.b", "homepage": "https://a.b"}, "spec": map[string]any{"requires": map[string]any{"service-connector": connectorInterfaces}, "components": components}, "files": files}
	b, err := witnessJSON(doc)
	if err != nil {
		panic(err)
	}
	return b
}
func InterleaveComments(payload []byte, boundaries bool) []byte {
	var b bytes.Buffer
	quoted, escaped := false, false
	for _, c := range payload {
		b.WriteByte(c)
		if escaped {
			escaped = false
			continue
		}
		if quoted && c == '\\' {
			escaped = true
			continue
		}
		if c == '"' {
			quoted = !quoted
			continue
		}
		if !quoted && (c == ',' || c == ':' || boundaries && (c == '{' || c == '[' || c == '}' || c == ']')) {
			b.WriteString(" #c\n")
		}
	}
	return b.Bytes()
}
func MaximumPayload(name string) []byte {
	b := MaximumManifest()
	switch name {
	case "maximum-compact":
		return b
	case "maximum-commented":
		return InterleaveComments(b, false)
	case "maximum-boundaries":
		return InterleaveComments(b, true)
	case "maximum-padded":
		return append(b, []byte("\n#"+strings.Repeat("c", (1<<20)-len(b)-2))...)
	default:
		panic("unknown maximum recipe")
	}
}

// witnessJSON fixes the reviewed witness's field order, independent of map
// iteration. This is test input generation, not YAML reserialization.
func witnessJSON(v any) ([]byte, error) {
	m, ok := v.(map[string]any)
	if !ok {
		if a, ok := v.([]any); ok {
			var b bytes.Buffer
			b.WriteByte('[')
			for i, c := range a {
				if i > 0 {
					b.WriteByte(',')
				}
				part, err := witnessJSON(c)
				if err != nil {
					return nil, err
				}
				b.Write(part)
			}
			b.WriteByte(']')
			return b.Bytes(), nil
		}
		return json.Marshal(v)
	}
	var keys []string
	switch {
	case m["apiVersion"] != nil:
		keys = []string{"apiVersion", "kind", "metadata", "spec", "files"}
	case m["id"] != nil:
		keys = []string{"id", "version", "publisher", "license", "source", "homepage"}
	case m["key"] != nil:
		keys = []string{"name", "key"}
	case m["requires"] != nil:
		keys = []string{"requires", "components"}
	case m["kind"] != nil:
		keys = []string{"name", "kind", "interface", "files", "file", "capabilities"}
	case m["path"] != nil:
		keys = []string{"path", "sha256", "size"}
	default:
		return json.Marshal(m)
	}
	var b bytes.Buffer
	b.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			b.WriteByte(',')
		}
		key, _ := json.Marshal(k)
		b.Write(key)
		b.WriteByte(':')
		part, err := witnessJSON(m[k])
		if err != nil {
			return nil, err
		}
		b.Write(part)
	}
	b.WriteByte('}')
	return b.Bytes(), nil
}
