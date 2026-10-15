package admission

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"testing"
	"unicode/utf8"
)

type schemaCase struct {
	ID       string          `json:"id"`
	Valid    bool            `json:"valid"`
	Instance json.RawMessage `json:"instance"`
}

func schemaCases(t testing.TB, path, schema string) []schemaCase {
	t.Helper()
	b, err := os.ReadFile(schemaDir + path)
	if err != nil {
		t.Fatal(err)
	}
	var suite struct {
		Schema string       `json:"schema"`
		Cases  []schemaCase `json:"cases"`
	}
	if err := json.Unmarshal(b, &suite); err != nil {
		t.Fatal(err)
	}
	if suite.Schema != schema || len(suite.Cases) == 0 {
		t.Fatalf("%s: unexpected suite header", path)
	}
	return suite.Cases
}

// TestSchemaCases requires Go acceptance to equal schema validity, with no
// exception list. A disagreement is a design finding, not a test edit.
func TestSchemaCases(t *testing.T) {
	suites := []struct {
		path, schema string
		count        int
		parse        func([]byte) error
	}{
		{"extension-resource/schema-cases.json", "extension-resource.schema.json", 33, func(b []byte) error { _, e := ParseResource(b); return e }},
		{"capability-grant/schema-cases.json", "capability-grant.schema.json", 20, func(b []byte) error { _, e := ParseGrantRecord(b); return e }},
		{"admission-vectors/schema-cases.json", "admission-vectors.schema.json", 28, vectorsEnvelope},
	}
	for _, s := range suites {
		cases := schemaCases(t, s.path, s.schema)
		if len(cases) != s.count {
			t.Errorf("%s: %d cases, want %d", s.path, len(cases), s.count)
		}
		for _, c := range cases {
			t.Run(s.schema+"/"+c.ID, func(t *testing.T) {
				err := s.parse(compact(t, c.Instance))
				if (err == nil) != c.Valid {
					t.Fatalf("valid=%v but Go returned %v", c.Valid, err)
				}
			})
		}
	}
}

// compact re-encodes a fixture instance in the producers' compact encoding.
func compact(t testing.TB, raw []byte) []byte {
	t.Helper()
	var b bytes.Buffer
	if err := json.Compact(&b, raw); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

var (
	caseName   = regexp.MustCompile(`^[a-z0-9-]+$`)
	hexDigest  = regexp.MustCompile(`^[0-9a-f]{64}$`)
	shaFinger  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	uuidSeven  = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-7[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)
	nameFormat = regexp.MustCompile(`^[a-z][a-z0-9]*(?:-[a-z0-9]+)*$`)
)

// vectorsEnvelope checks the corpus envelope: the snapshot and request through
// the package parsers, the rest against the envelope schema in test code.
func vectorsEnvelope(data []byte) error {
	var root map[string]json.RawMessage
	if err := strictObject(data, &root, []string{"profile", "cases"}, nil); err != nil {
		return err
	}
	var profile string
	if json.Unmarshal(root["profile"], &profile) != nil || profile != "extension-admission-v1alpha1" {
		return fmt.Errorf("profile")
	}
	var cases []json.RawMessage
	if json.Unmarshal(root["cases"], &cases) != nil || len(cases) < 1 || len(cases) > 256 {
		return fmt.Errorf("cases")
	}
	for _, raw := range cases {
		if err := vectorCase(raw); err != nil {
			return err
		}
	}
	return nil
}

func strictObject(data []byte, out *map[string]json.RawMessage, required, optional []string) error {
	if json.Unmarshal(data, out) != nil || *out == nil {
		return fmt.Errorf("object")
	}
	allowed := map[string]bool{}
	for _, k := range append(append([]string{}, required...), optional...) {
		allowed[k] = true
	}
	for k := range *out {
		if !allowed[k] {
			return fmt.Errorf("unknown field %s", k)
		}
	}
	for _, k := range required {
		if _, ok := (*out)[k]; !ok {
			return fmt.Errorf("missing field %s", k)
		}
	}
	return nil
}

func stringField(raw json.RawMessage, min, max int, pattern *regexp.Regexp) error {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return fmt.Errorf("string")
	}
	n := utf8.RuneCountInString(s)
	if n < min || n > max || pattern != nil && !pattern.MatchString(s) {
		return fmt.Errorf("string value")
	}
	return nil
}

func enumField(raw json.RawMessage, values ...string) error {
	var s string
	if json.Unmarshal(raw, &s) != nil {
		return fmt.Errorf("enum")
	}
	for _, v := range values {
		if s == v {
			return nil
		}
	}
	return fmt.Errorf("enum value")
}

func vectorCase(raw json.RawMessage) error {
	var c map[string]json.RawMessage
	if err := strictObject(raw, &c, []string{"name", "description", "evidence", "snapshot", "request", "verdicts", "expected"}, nil); err != nil {
		return err
	}
	if err := stringField(c["name"], 1, 80, caseName); err != nil {
		return err
	}
	if err := stringField(c["description"], 1, 512, nil); err != nil {
		return err
	}
	var evidence map[string]json.RawMessage
	if err := strictObject(c["evidence"], &evidence, []string{"document", "package_sha256", "manifest_sha256", "envelope_sha256"}, nil); err != nil {
		return err
	}
	var document map[string]json.RawMessage
	if json.Unmarshal(evidence["document"], &document) != nil || document == nil {
		return fmt.Errorf("document")
	}
	for _, k := range []string{"package_sha256", "manifest_sha256", "envelope_sha256"} {
		if err := stringField(evidence[k], 64, 64, hexDigest); err != nil {
			return err
		}
	}
	if _, err := ParseSnapshot(c["snapshot"]); err != nil {
		return err
	}
	if _, err := ParseRequest(c["request"]); err != nil {
		return err
	}
	var verdicts []json.RawMessage
	if json.Unmarshal(c["verdicts"], &verdicts) != nil || verdicts == nil && string(c["verdicts"]) != "[]" || len(verdicts) > 64 {
		return fmt.Errorf("verdicts")
	}
	seen := map[string]bool{}
	for _, v := range verdicts {
		var o map[string]json.RawMessage
		if err := strictObject(v, &o, []string{"component", "outcome"}, nil); err != nil {
			return err
		}
		if err := stringField(o["component"], 1, 63, nameFormat); err != nil {
			return err
		}
		if err := enumField(o["outcome"], "ok", "failed"); err != nil {
			return err
		}
		key := string(o["component"]) + string(o["outcome"])
		if seen[key] {
			return fmt.Errorf("duplicate verdict")
		}
		seen[key] = true
	}
	return expectedShape(c["expected"])
}

func expectedShape(raw json.RawMessage) error {
	var e map[string]json.RawMessage
	if err := strictObject(raw, &e, []string{"outcome", "reasons"}, []string{"operation", "stage", "closure_digest", "request_digest", "intent"}); err != nil {
		return err
	}
	if err := enumField(e["outcome"], "admit", "approval_required", "identical_retry", "reject"); err != nil {
		return err
	}
	operations := []string{"install", "upgrade", "reinstall", "grant_update"}
	if v, ok := e["operation"]; ok {
		if err := enumField(v, operations...); err != nil {
			return err
		}
	}
	if v, ok := e["stage"]; ok {
		var stages []string
		for _, s := range stageOrder {
			stages = append(stages, string(s))
		}
		if err := enumField(v, stages...); err != nil {
			return err
		}
	}
	for _, k := range []string{"closure_digest", "request_digest"} {
		if v, ok := e[k]; ok {
			if err := stringField(v, 71, 71, shaFinger); err != nil {
				return err
			}
		}
	}
	var reasons []json.RawMessage
	if json.Unmarshal(e["reasons"], &reasons) != nil || reasons == nil && string(e["reasons"]) != "[]" || len(reasons) > 256 {
		return fmt.Errorf("reasons")
	}
	var codes []string
	for _, c := range allCodes {
		codes = append(codes, string(c))
	}
	for _, r := range reasons {
		var o map[string]json.RawMessage
		if err := strictObject(r, &o, []string{"code", "subject"}, nil); err != nil {
			return err
		}
		if err := enumField(o["code"], codes...); err != nil {
			return err
		}
		if err := stringField(o["subject"], 0, 253, nil); err != nil {
			return err
		}
	}
	if v, ok := e["intent"]; ok {
		var in map[string]json.RawMessage
		if err := strictObject(v, &in, []string{"operation", "approval_kind", "tombstone_create", "ownership_create", "enabled", "grants", "targets", "registration_bind", "approval_consume"}, nil); err != nil {
			return err
		}
		if err := enumField(in["operation"], operations...); err != nil {
			return err
		}
		if err := enumField(in["approval_kind"], "operator", "single-administrator", "release-fixed"); err != nil {
			return err
		}
	}
	return nil
}
