package admission

import (
	"encoding/json"
	"go/parser"
	"go/token"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/manifest"
)

func TestJCSEmitter(t *testing.T) {
	cases := []struct {
		name  string
		value jv
		want  string
	}{
		{"empty object", jobj(), `{}`},
		{"empty array", jarr(), `[]`},
		{"literals", jarr(jnull(), jbool(true), jbool(false)), `[null,true,false]`},
		{"integers", jarr(jint(0), jint(7), jint(1000000000), jint(1<<53)), `[0,7,1000000000,9007199254740992]`},
		{"sorted keys", jobj("b", jint(1), "a", jint(2), "aa", jint(3), "A", jint(4), "_", jint(5)), `{"A":4,"_":5,"a":2,"aa":3,"b":1}`},
		{"nested unsorted", jobj("z", jobj("y", jarr(jobj("b", jnull(), "a", jstr("x"))), "x", jarr()), "a", jarr(jarr(jint(1)), jint(2))), `{"a":[[1],2],"z":{"x":[],"y":[{"a":"x","b":null}]}}`},
		{"quote and backslash", jstr(`a"b\c/d`), `"a\"b\\c/d"`},
		{"short escapes", jstr("\b\f\n\r\t"), `"\b\f\n\r\t"`},
		{"other controls", jstr("\x00\x01\x1f\x0b"), `"\u0000\u0001\u001f\u000b"`},
		{"del and html stay literal", jstr("\x7f<>&"), "\"\x7f<>&\""},
		{"array order kept", jarr(jstr("b"), jstr("a")), `["b","a"]`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := c.value.encode(nil)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != c.want {
				t.Fatalf("got %s, want %s", got, c.want)
			}
		})
	}
	for name, v := range map[string]jv{
		"non-ascii string":   jstr("café"),
		"non-ascii key":      jobj("é", jnull()),
		"line separator":     jstr(" "),
		"integer above 2^53": jint(1<<53 + 1),
		"duplicate key":      jobj("a", jnull(), "a", jnull()),
		"nested failure":     jarr(jobj("k", jstr("ÿ"))),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := v.encode(nil); err == nil {
				t.Fatal("emitter accepted input outside the closed digest types")
			}
		})
	}
}

type expectation struct {
	Outcome       string `json:"outcome"`
	Operation     string `json:"operation"`
	Stage         string `json:"stage"`
	ClosureDigest string `json:"closure_digest"`
	RequestDigest string `json:"request_digest"`
	Reasons       []struct {
		Code    string `json:"code"`
		Subject string `json:"subject"`
	} `json:"reasons"`
	Intent *struct {
		Operation       string   `json:"operation"`
		ApprovalKind    string   `json:"approval_kind"`
		TombstoneCreate bool     `json:"tombstone_create"`
		OwnershipCreate bool     `json:"ownership_create"`
		Enabled         bool     `json:"enabled"`
		Grants          []string `json:"grants"`
		Targets         struct {
			DeviceGroups []string `json:"device_groups"`
			AllDevices   bool     `json:"all_devices"`
			Console      bool     `json:"console"`
			Jobs         bool     `json:"jobs"`
		} `json:"targets"`
		RegistrationBind []struct {
			Registration string `json:"registration"`
			Component    string `json:"component"`
		} `json:"registration_bind"`
		ApprovalConsume *string `json:"approval_consume"`
	} `json:"intent"`
}

// corpusInputs parses one corpus case through the package's own parsers.
func corpusInputs(t testing.TB, c corpusCase) (Evidence, error, Snapshot, Request, []Verdict, expectation) {
	t.Helper()
	e, evidenceErr := FromPackage(corpusPackage(t, c.Evidence), manifest.Options{})
	s, err := ParseSnapshot(compact(t, c.Snapshot))
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	r, err := ParseRequest(compact(t, c.Request))
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	var raw []struct {
		Component string `json:"component"`
		Outcome   string `json:"outcome"`
	}
	if err := json.Unmarshal(c.Verdicts, &raw); err != nil {
		t.Fatal(err)
	}
	verdicts := make([]Verdict, len(raw))
	for i, v := range raw {
		verdicts[i] = Verdict{Component: v.Component, OK: v.Outcome == "ok"}
	}
	var x expectation
	if err := json.Unmarshal(c.Expected, &x); err != nil {
		t.Fatal(err)
	}
	return e, evidenceErr, s, r, verdicts, x
}

func TestDigests(t *testing.T) {
	checked := 0
	for _, c := range corpusCases(t) {
		e, evidenceErr, s, r, _, x := corpusInputs(t, c)
		if x.ClosureDigest == "" {
			if x.RequestDigest != "" {
				t.Errorf("%s: request digest without closure digest", c.Name)
			}
			continue
		}
		if evidenceErr != nil {
			t.Fatalf("%s: %v", c.Name, evidenceErr)
		}
		closure, err := ClosureDigest(e, s, r)
		if err != nil || closure != x.ClosureDigest {
			t.Errorf("%s: closure %s %v, want %s", c.Name, closure, err, x.ClosureDigest)
		}
		request, err := RequestDigest(e, s, r, Operation(x.Operation))
		if err != nil || request != x.RequestDigest {
			t.Errorf("%s: request %s %v, want %s", c.Name, request, err, x.RequestDigest)
		}
		checked++
	}
	if checked != 45 {
		t.Errorf("checked %d recorded digest pairs, want 45", checked)
	}
	first := corpusCases(t)[0]
	var x expectation
	if err := json.Unmarshal(first.Expected, &x); err != nil {
		t.Fatal(err)
	}
	if x.ClosureDigest != "sha256:bbeccf4b02703e63331e4b4dc051fa0353160bfbed00d668219389c6e015165e" || x.RequestDigest != "sha256:a7986aab67d48ff8e0878fb0e54db689b805131a26019b0c35344d7e760bc4e7" {
		t.Error("first corpus case digests differ from the contracts' section 3")
	}
}

// TestDigestSourceAvoidsEncodingJSON keeps digest input away from
// encoding/json, whose map ordering and HTML escaping would change digests:
// digest.go may import only the packages listed here.
func TestDigestSourceAvoidsEncodingJSON(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "digest.go", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{`"crypto/sha256"`: true, `"encoding/hex"`: true, `"errors"`: true, `"sort"`: true, `"strconv"`: true}
	for _, spec := range f.Imports {
		if !allowed[spec.Path.Value] {
			t.Errorf("digest.go imports %s", spec.Path.Value)
		}
	}
}
