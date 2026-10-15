package config_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/platform/config"
)

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
	f.Fuzz(func(t *testing.T, data []byte) {
		c, err := config.Parse(data, noEnv)
		if err != nil {
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
