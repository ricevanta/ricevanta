package exportdest

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"
)

const fixturePath = "../../../../schemas/export/v1alpha1/fixtures.json"

type fixture struct {
	ID       string `json:"id"`
	Valid    bool   `json:"valid"`
	Resource any    `json:"resource"`
	Error    string `json:"error"`
}

func sentinels() map[string]error {
	return map[string]error{"ErrInput": ErrInput, "ErrLimits": ErrLimits, "ErrResource": ErrResource, "ErrAdapter": ErrAdapter, "ErrCommon": ErrCommon, "ErrParameters": ErrParameters, "ErrCombination": ErrCombination}
}

func readFixtures(t testing.TB) []fixture {
	t.Helper()
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatal(err)
	}
	var manifest struct {
		Version int       `json:"version"`
		Cases   []fixture `json:"cases"`
	}
	if err := json.Unmarshal(data, &manifest); err != nil {
		t.Fatal(err)
	}
	if manifest.Version != 1 || len(manifest.Cases) == 0 {
		t.Fatal("invalid manifest")
	}
	seen := map[string]bool{}
	for _, c := range manifest.Cases {
		if c.ID == "" || seen[c.ID] {
			t.Fatal("duplicate or absent fixture ID")
		}
		seen[c.ID] = true
		if c.Valid && c.Error != "" || !c.Valid && (sentinels()[c.Error] == nil || c.Error == "ErrInput" || c.Error == "ErrLimits") {
			t.Fatal("invalid fixture expectation")
		}
	}
	return manifest.Cases
}

func fixtureMismatch(c fixture) error {
	var want error
	if !c.Valid {
		want = sentinels()[c.Error]
	}
	if !errors.Is(Validate(c.Resource), want) {
		return fmt.Errorf("fixture outcome differs: %s", c.ID)
	}
	return nil
}

func TestFixtureDrift(t *testing.T) {
	for _, c := range readFixtures(t) {
		t.Run(c.ID, func(t *testing.T) {
			if err := fixtureMismatch(c); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func clone(v any) any {
	switch x := v.(type) {
	case map[string]any:
		m := make(map[string]any, len(x))
		for k, v := range x {
			m[k] = clone(v)
		}
		return m
	case []any:
		a := make([]any, len(x))
		for i, v := range x {
			a[i] = clone(v)
		}
		return a
	default:
		return v
	}
}

func base(adapter string) map[string]any {
	s := map[string]any{"type": adapter}
	if adapter != "kafka" && adapter != "connector" {
		s["endpoint"] = "https://a.example"
	}
	s["credentialRef"] = "credential"
	b := map[string]any{}
	switch adapter {
	case "elasticsearch":
		b["auth"] = "api_key"
	case "opensearch":
		b["auth"] = "basic"
	case "syslog":
		b["transport"] = "tls"
		s["endpoint"] = "tls://a.example:1"
		delete(s, "credentialRef")
	case "otlp":
		b["auth"] = "bearer"
	case "loki":
		b["auth"] = "basic"
	case "sentinel":
		b = map[string]any{"cloud": "public", "auth": "certificate", "tenantId": "11111111-1111-4111-8111-111111111111", "clientId": "22222222-2222-4222-8222-222222222222", "dcrImmutableId": "dcr-aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}
	case "kafka":
		b = map[string]any{"auth": "plain", "brokers": []any{"a.example:1"}}
	case "s3":
		b = map[string]any{"bucket": "events", "region": "us-east-1", "auth": "access_key"}
	case "connector":
		b["registrationRef"] = "connector"
		delete(s, "credentialRef")
	}
	s[adapter] = b
	return map[string]any{"apiVersion": "ricevanta.io/v1alpha1", "kind": "ExportDestination", "metadata": map[string]any{"name": "soc"}, "spec": s}
}

func spec(r map[string]any) map[string]any { return r["spec"].(map[string]any) }

func put(r map[string]any, path []string, value any) {
	m := r
	for _, k := range path[:len(path)-1] {
		if m[k] == nil {
			m[k] = map[string]any{}
		}
		m = m[k].(map[string]any)
	}
	m[path[len(path)-1]] = value
}
