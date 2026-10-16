package config_test

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"

	"github.com/ricevanta/ricevanta/server/internal/platform/config"
)

// vocabulary is the text of the package's non-test sources: every key name,
// enum value, bound and reason an error can legitimately contain. A scalar
// found in an error but not here can only have come from the input.
func vocabulary(tb testing.TB) string {
	tb.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		tb.Fatal(err)
	}
	var b strings.Builder
	for _, f := range files {
		if strings.HasSuffix(f, "_test.go") {
			continue
		}
		data, err := os.ReadFile(f)
		if err != nil {
			tb.Fatal(err)
		}
		b.Write(data)
	}
	return b.String()
}

// scalars returns every scalar of the document, keys and values, that yaml.v3
// can parse; a document that does not parse yields none.
func scalars(data []byte) []string {
	var n yaml.Node
	if yaml.Unmarshal(data, &n) != nil {
		return nil
	}
	var out []string
	var walk func(*yaml.Node)
	walk = func(n *yaml.Node) {
		if n == nil {
			return
		}
		if n.Kind == yaml.ScalarNode {
			out = append(out, n.Value)
		}
		for _, c := range n.Content {
			walk(c)
		}
	}
	walk(&n)
	return out
}

var lineNumbers = regexp.MustCompile(`line [0-9]+`)

// FuzzLoad parses arbitrary documents. An accepted document's effective JSON,
// which is itself YAML, must parse to the same effective configuration, and
// no error may echo a scalar it was given.
func FuzzLoad(f *testing.F) {
	for _, c := range loadCases(f).Cases {
		f.Add(toYAML(f, c.Instance))
	}
	f.Add([]byte(minimalYAML))
	f.Add([]byte(minimalYAML + "schema: ricevanta-server-config-v1\n"))
	f.Add([]byte(strings.Replace(minimalYAML, "roles: [api]", "roles: &r [api]", 1)))
	f.Add([]byte(minimalYAML + "log: &l {level: info}\nconsole: *l\n"))
	f.Add([]byte(strings.Replace(minimalYAML, "mode: none", "mode: !!str none", 1)))
	f.Add([]byte(minimalYAML + "---\n" + minimalYAML))
	f.Add([]byte("ricevanta\n"))
	f.Add([]byte(strings.Replace(minimalYAML, "127.0.0.1:8080", "0.0.0.0:8080", 1)))
	f.Add([]byte(strings.Replace(minimalYAML, "127.0.0.1:8080", "s3cr3t-value", 1)))
	f.Add([]byte(minimalYAML + "s3cr3t-key: 1\n"))
	f.Add([]byte(minimalYAML + "log: {level: \"s3cr3t\", level: x}\n"))
	vocab := vocabulary(f)
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := config.Parse(data, noEnv)
		if err != nil {
			msg := lineNumbers.ReplaceAllString(err.Error(), "")
			for _, s := range scalars(data) {
				if len(s) >= 4 && strings.Contains(msg, s) && !strings.Contains(vocab, s) {
					t.Fatalf("error %q echoes input scalar %q", err, s)
				}
			}
			return
		}
		again, err := config.Parse(c.JSON(), noEnv)
		if err != nil {
			t.Fatalf("effective JSON %s rejected: %v", c.JSON(), err)
		}
		if !bytes.Equal(again.JSON(), c.JSON()) {
			t.Fatalf("round trip changed %s to %s", c.JSON(), again.JSON())
		}
	})
}
