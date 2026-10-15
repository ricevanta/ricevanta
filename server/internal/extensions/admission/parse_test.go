package admission

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// corpusRaw returns the compact snapshot and request of one corpus case.
func corpusRaw(t testing.TB, index int) (snapshot, request []byte) {
	t.Helper()
	cases := corpusCases(t)
	return compact(t, cases[index].Snapshot), compact(t, cases[index].Request)
}

func grantCase(t testing.TB, id string) []byte {
	t.Helper()
	for _, c := range schemaCases(t, "capability-grant/schema-cases.json", "capability-grant.schema.json") {
		if c.ID == id {
			return compact(t, c.Instance)
		}
	}
	t.Fatalf("no grant case %q", id)
	return nil
}

func replaceOnce(t testing.TB, b []byte, old, new string) []byte {
	t.Helper()
	if bytes.Count(b, []byte(old)) < 1 {
		t.Fatalf("fixture does not contain %q", old)
	}
	return bytes.Replace(b, []byte(old), []byte(new), 1)
}

func TestParsePhases(t *testing.T) {
	snapshot, request := corpusRaw(t, 0)
	collector := grantCase(t, "collector-max-generation-lexeme")
	parseSnapshot := func(b []byte) error { _, e := ParseSnapshot(b); return e }
	parseRequest := func(b []byte) error { _, e := ParseRequest(b); return e }
	parseGrant := func(b []byte) error { _, e := ParseGrantRecord(b); return e }
	cases := []struct {
		name  string
		parse func([]byte) error
		input []byte
		want  error
	}{
		{"snapshot ok", parseSnapshot, snapshot, nil},
		{"request ok", parseRequest, request, nil},
		{"grant ok", parseGrant, collector, nil},
		{"null release version", parseSnapshot, replaceOnce(t, snapshot, `"release_version":"0.1.0"`, `"release_version":null`), nil},
		{"duplicate key", parseRequest, replaceOnce(t, request, `"source":"upload"`, `"source":"upload","source":"upload"`), ErrJSON},
		{"duplicate escaped key", parseRequest, replaceOnce(t, request, `"source":"upload"`, `"source":"upload","sourc\u0065":"upload"`), ErrJSON},
		{"lone surrogate", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, `"Example \ud800"`), ErrJSON},
		{"reversed surrogates", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, `"Example \udc00\ud800"`), ErrJSON},
		{"invalid utf-8", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, "\"Example \xff\""), ErrJSON},
		{"raw control in string", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, "\"Example\x01\""), ErrJSON},
		{"fraction token", parseGrant, replaceOnce(t, collector, `"memory_pages":256`, `"memory_pages":256.0`), ErrJSON},
		{"exponent token", parseGrant, replaceOnce(t, collector, `"memory_pages":256`, `"memory_pages":2e2`), ErrJSON},
		{"negative token", parseGrant, replaceOnce(t, collector, `"memory_pages":256`, `"memory_pages":-1`), ErrJSON},
		{"leading zero token", parseGrant, replaceOnce(t, collector, `"memory_pages":256`, `"memory_pages":0256`), ErrJSON},
		{"trailing data", parseRequest, append(append([]byte{}, request...), '{', '}'), ErrJSON},
		{"empty input", parseRequest, nil, ErrJSON},
		{"depth 17", parseGrant, replaceOnce(t, collector, `"disclosure_profile":"inventory.software.v1"`, `"disclosure_profile":`+strings.Repeat("[", 14)+strings.Repeat("]", 14)), ErrJSON},
		{"integer epoch", parseSnapshot, replaceOnce(t, snapshot, `"recovery_epoch":"3"`, `"recovery_epoch":3`), ErrShape},
		{"integer generation in record", parseGrant, replaceOnce(t, collector, `"recovery_epoch":"3","grant_generation"`, `"recovery_epoch":3,"grant_generation"`), ErrShape},
		{"missing field", parseRequest, replaceOnce(t, request, `"grant_update":false,`, ``), ErrShape},
		{"unknown field", parseRequest, replaceOnce(t, request, `"grant_update":false,`, `"grant_update":false,"extra":1,`), ErrShape},
		{"null request", parseRequest, []byte(`null`), ErrShape},
		{"leading zero generation", parseGrant, replaceOnce(t, collector, `"grant_generation":"18446744073709551615"`, `"grant_generation":"07"`), ErrField},
		{"generation above uint64", parseGrant, replaceOnce(t, collector, `"grant_generation":"18446744073709551615"`, `"grant_generation":"18446744073709551616"`), ErrField},
		{"generation 21 digits", parseGrant, replaceOnce(t, collector, `"grant_generation":"18446744073709551615"`, `"grant_generation":"111111111111111111111"`), ErrField},
		{"dot-dot root segment", parseGrant, replaceOnce(t, collector, `"/var/lib/example"`, `"/var/../example"`), ErrField},
		{"dot root segment", parseGrant, replaceOnce(t, collector, `"/var/lib/example"`, `"/var/./example"`), ErrField},
		{"windows root posix path", parseGrant, replaceOnce(t, collector, `{"os":"linux","path":"/var/lib/example"}`, `{"os":"windows","path":"/var/lib/example"}`), ErrField},
		{"linux root drive path", parseGrant, replaceOnce(t, collector, `"/var/lib/example"`, `"C:\\Data"`), ErrField},
		{"windows segment period", parseGrant, replaceOnce(t, collector, `{"os":"linux","path":"/var/lib/example"}`, `{"os":"windows","path":"C:\\Data."}`), ErrField},
		{"windows interior period accepted", parseGrant, replaceOnce(t, collector, `{"os":"linux","path":"/var/lib/example"}`, `{"os":"windows","path":"C:\\Data.d\\x"}`), nil},
		{"unknown root os", parseGrant, replaceOnce(t, collector, `"os":"linux"`, `"os":"android"`), ErrField},
		{"trust name C0", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, `"Example\u0007Security"`), ErrField},
		{"trust name C1", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, `"Example\u009bSecurity"`), ErrField},
		{"trust name DEL", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, `"Example\u007fSecurity"`), ErrField},
		{"trust name 128 runes", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, `"`+strings.Repeat("\u00e9", 128)+`"`), nil},
		{"trust name 129 runes", parseSnapshot, replaceOnce(t, snapshot, `"Example Security"`, `"`+strings.Repeat("\u00e9", 129)+`"`), ErrField},
		{"uppercase uuid", parseRequest, replaceOnce(t, request, `"requester":"017f22e2-79b0-7cc3-98c4-dc0c0c07398f"`, `"requester":"017F22E2-79B0-7CC3-98C4-DC0C0C07398F"`), ErrField},
		{"null release-fixed version", parseRequest, replaceOnce(t, request, `"approval":null`, `"approval":{"kind":"release-fixed","release_version":null}`), ErrShape},
		{"unknown approval kind", parseRequest, replaceOnce(t, request, `"approval":null`, `"approval":{"kind":"automatic"}`), ErrField},
		{"unknown grant kind", parseRequest, replaceOnce(t, request, `"kind":"content"`, `"kind":"plugin"`), ErrGrant},
		{"grant kind interface mismatch", parseRequest, replaceOnce(t, request, `"interface":"ext.ricevanta.io/content/v1"`, `"interface":"ext.ricevanta.io/console-module/v1"`), ErrGrant},
		{"content grant with values", parseRequest, replaceOnce(t, request, `"values":{}`, `"values":{"formats":[]}`), ErrGrant},
		{"grant value type", parseGrant, replaceOnce(t, collector, `"max_rows":100`, `"max_rows":"100"`), ErrGrant},
		{"grant missing value", parseGrant, replaceOnce(t, collector, `"max_rows":100,`, ``), ErrGrant},
		{"grant value above ceiling", parseGrant, replaceOnce(t, collector, `"memory_pages":256`, `"memory_pages":4097`), ErrField},
		{"grant value overflow", parseGrant, replaceOnce(t, collector, `"memory_pages":256`, `"memory_pages":18446744073709551616`), ErrField},
		{"field before grant", parseGrant, replaceOnce(t, replaceOnce(t, collector, `"max_rows":100`, `"max_rows":"100"`), `"grant_generation":"18446744073709551615"`, `"grant_generation":"07"`), ErrField},
		{"shape before field", parseGrant, replaceOnce(t, replaceOnce(t, collector, `"recovery_epoch":"3","grant_generation"`, `"recovery_epoch":3,"grant_generation"`), `"/var/lib/example"`, `"/var/../example"`), ErrShape},
		{"shape before grant", parseRequest, replaceOnce(t, replaceOnce(t, request, `"kind":"content"`, `"kind":"plugin"`), `"grant_update":false`, `"grant_update":0`), ErrShape},
		{"json before shape", parseRequest, replaceOnce(t, replaceOnce(t, request, `"grant_update":false`, `"grant_update":0`), `"source":"upload"`, `"source":"upload","source":"upload"`), ErrJSON},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := c.parse(c.input)
			if c.want == nil {
				if err != nil {
					t.Fatalf("got %v, want acceptance", err)
				}
				return
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("got %v, want %v", err, c.want)
			}
			for _, other := range []error{ErrJSON, ErrShape, ErrField, ErrGrant, ErrEvidence} {
				if other != c.want && errors.Is(err, other) {
					t.Fatalf("error %v matches more than one sentinel", err)
				}
			}
		})
	}
}

const maxU64 = "18446744073709551615"

func maxLabel(i int, ch string) string {
	head := fmt.Sprintf("x%05d", i)
	return head + strings.Repeat(ch, 63-len(head))
}
func maxID(i int, ch string) string {
	return strings.Join([]string{maxLabel(i, ch), strings.Repeat("b", 63), strings.Repeat("c", 63), strings.Repeat("d", 61)}, ".")
}
func maxVersion(i int) string {
	v := fmt.Sprintf("1.0.%d-", i)
	return v + strings.Repeat("a", 128-len(v))
}
func uuid7(i int) string           { return fmt.Sprintf("017f22e2-79b0-7cc3-98c4-%012x", i) }
func testFingerprint(i int) string { return fmt.Sprintf("sha256:%064x", i) }

var (
	testSlots      = []string{"navigation", "device-tab", "alert-panel", "finding-panel", "dashboard-panel", "settings"}
	testOperations = []string{"listDevices", "getDevice", "getDeviceInventory", "listDeviceSoftware", "getDeviceCapabilities", "getDevicePolicyState", "getDeviceFootprint", "listComplianceResults", "listAlerts", "getAlert", "listInvestigations", "listResponseActions", "listDlpFindings", "getDlpFinding", "listClassifications", "listExceptions", "queryLineage", "getLineageEdge", "updateAlert", "createInvestigation", "updateInvestigation", "updateDlpFinding", "createResponseAction"}
)

// maximalGrants builds the largest candidate grant of each kind as the
// contracts' section 2 describes and returns the largest.
func maximalGrant(t testing.TB) (map[string]any, map[string]int) {
	t.Helper()
	n := maxLabel(0, "a")
	out := map[string]map[string]any{}
	var outbound []any
	for i := 0; i < 64; i++ {
		outbound = append(outbound, map[string]any{"host": maxID(i, "a"), "port": 65535, "transport": "tcp"})
	}
	out["service-connector"] = map[string]any{"component": n, "kind": "service-connector", "interface": "ext.ricevanta.io/export-destination/v1", "values": map[string]any{"outbound": outbound}}
	var names []any
	for i := 0; i < 64; i++ {
		names = append(names, fmt.Sprintf("P%05d", i)+strings.Repeat("a", 58))
	}
	os := map[string]any{}
	for _, o := range []string{"macos", "windows", "linux"} {
		os[o] = map[string]any{"policy_names": names, "native_host": false}
	}
	out["browser-adapter"] = map[string]any{"component": n, "kind": "browser-adapter", "interface": "ext.ricevanta.io/browser-adapter/v1", "values": map[string]any{"registration": maxID(0, "a"), "os": os}}
	var roots []any
	for i := 0; i < 16; i++ {
		roots = append(roots, map[string]any{"os": "windows", "path": "C:" + strings.Repeat(`\`+string(rune('a'+i)), 127)})
	}
	out["collector"] = map[string]any{"component": n, "kind": "agent-module", "interface": "ricevanta:agent/collector@1.0.0", "values": map[string]any{
		"memory_pages": 4096, "fuel_per_call": 1000000000, "deadline_ms": 60000, "max_roots": 16, "max_path_depth": 32, "max_directory_entries": 10000,
		"max_open_handles": 64, "max_list_requests": 1024, "max_read_requests": 4096, "max_bytes_per_file": 16777216, "max_input_bytes": 67108864,
		"max_rows": 10000, "max_output_bytes": 16777216, "roots": roots, "disclosure_profile": strings.Repeat("p", 128)}}
	var mimes []any
	for i := 0; i < 32; i++ {
		head := fmt.Sprintf("application/x%05d", i)
		mimes = append(mimes, head+strings.Repeat("a", 127-len(head)))
	}
	out["parser"] = map[string]any{"component": n, "kind": "agent-module", "interface": "ricevanta:agent/parser@1.0.0", "values": map[string]any{"memory_pages": 4096, "fuel_per_call": 1000000000, "deadline_ms": 60000, "mime_types": mimes}}
	out["responder"] = map[string]any{"component": n, "kind": "agent-module", "interface": "ricevanta:agent/responder@1.0.0", "values": map[string]any{
		"memory_pages": 4096, "fuel_per_call": 1000000000, "deadline_ms": 60000, "actions": []any{"edr.kill_process", "edr.quarantine_file", "edr.restore_file", "edr.isolate_host", "edr.unisolate_host", "edr.kill_and_ban", "edr.unban", "edr.collect", "edr.scan"},
		"max_entities": 256, "max_parameters_bytes": 65536, "max_plan_steps": 256, "max_plan_bytes": 1048576}}
	slots := map[string]any{}
	for _, s := range testSlots {
		slots[s] = testOperations
	}
	out["console-module"] = map[string]any{"component": n, "kind": "console-module", "interface": "ext.ricevanta.io/console-module/v1", "values": map[string]any{"slots": slots}}
	sizes := map[string]int{}
	largest := ""
	for kind, g := range out {
		sizes[kind] = len(marshal(t, g))
		if largest == "" || sizes[kind] > sizes[largest] {
			largest = kind
		}
	}
	return out[largest], sizes
}

func marshal(t testing.TB, v any) []byte {
	t.Helper()
	var b bytes.Buffer
	e := json.NewEncoder(&b)
	e.SetEscapeHTML(false)
	if err := e.Encode(v); err != nil {
		t.Fatal(err)
	}
	return bytes.TrimSuffix(b.Bytes(), []byte("\n"))
}

func cloneJSON(t testing.TB, v any) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(marshal(t, v), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func maxTargets() map[string]any {
	var groups []any
	for i := 0; i < 1024; i++ {
		groups = append(groups, uuid7(i))
	}
	return map[string]any{"device_groups": groups, "all_devices": false, "console": true, "jobs": true}
}

func maximalInstances(t testing.TB) (request, resource, record, snapshot []byte, sizes map[string]int) {
	t.Helper()
	grant, sizes := maximalGrant(t)
	var grants []any
	for i := 0; i < 64; i++ {
		g := cloneJSON(t, grant)
		g["component"] = maxLabel(i, "a")
		grants = append(grants, g)
	}
	approval := map[string]any{"kind": "single-administrator", "request_digest": testFingerprint(1), "approval_uid": uuid7(1), "principal": uuid7(2), "recovery_epoch": maxU64}
	request = marshal(t, map[string]any{"source": "upload", "requester": uuid7(3), "grant_update": false, "grants": grants, "targets": maxTargets(), "approval": approval})
	prefix := "https://" + maxID(0, "a") + ":65535/"
	resource = marshal(t, map[string]any{"apiVersion": "ricevanta.io/v1alpha1", "kind": "Extension", "metadata": map[string]any{"name": maxID(0, "a")},
		"spec": map[string]any{"version": maxVersion(0), "source": map[string]any{"url": prefix + strings.Repeat("a", 2048-len(prefix)), "sha256": strings.Repeat("0", 64)},
			"grants": grants, "targets": maxTargets(), "enabled": true}})
	rec := map[string]any{"extension_id": maxID(0, "a"), "version": maxVersion(0), "package_sha256": strings.Repeat("0", 64), "recovery_epoch": maxU64, "grant_generation": maxU64, "approval": approval, "grant": grant}
	record = marshal(t, rec)
	var trust []any
	for i := 0; i < 1024; i++ {
		var prefixes []any
		for j := 0; j < 16; j++ {
			prefixes = append(prefixes, maxID(i*16+j, "a"))
		}
		trust = append(trust, map[string]any{"fingerprint": testFingerprint(i), "public_key_hex": fmt.Sprintf("%064x", i), "name": strings.Repeat("\U0001F600", 128),
			"prefixes": prefixes, "project_publisher": false, "revoked": false, "retired": false, "generation": maxU64})
	}
	var records []any
	for _, g := range grants {
		r := cloneJSON(t, rec)
		r["grant"] = g
		records = append(records, r)
	}
	var regNames []any
	for i := 0; i < 64; i++ {
		regNames = append(regNames, fmt.Sprintf("P%05d", i)+strings.Repeat("a", 58))
	}
	var registrations []any
	for i := 0; i < 64; i++ {
		os := map[string]any{}
		for _, o := range []string{"macos", "windows", "linux"} {
			os[o] = map[string]any{"policy_names": regNames, "native_host": false}
		}
		registrations = append(registrations, map[string]any{"id": maxID(i, "r"), "browser": maxLabel(i, "a"), "registration_generation": maxU64, "os": os,
			"bound": map[string]any{"id": maxID(0, "a"), "component": maxLabel(i, "a"), "state": "recovery_pending"}})
	}
	var priors, profiles, groups []any
	for i := 0; i < 1023; i++ {
		priors = append(priors, testFingerprint(6000+i))
	}
	for i := 0; i < 64; i++ {
		profiles = append(profiles, fmt.Sprintf("p%05d", i)+strings.Repeat("p", 122))
	}
	for i := 0; i < 1024; i++ {
		groups = append(groups, uuid7(i))
	}
	var interfaces []any
	for _, p := range componentPairs {
		interfaces = append(interfaces, p.iface)
	}
	var tombstones []any
	for i := 0; i < 2; i++ {
		tombstones = append(tombstones, map[string]any{"id": maxID(0, "a"), "version": maxVersion(i), "publisher": testFingerprint(i), "manifest_sha256": strings.Repeat("0", 64), "package_sha256": strings.Repeat("0", 64)})
	}
	snapshot = marshal(t, map[string]any{"recovery_epoch": maxU64, "approval_policy_disabled": false, "approval_policy_generation": maxU64,
		"first_start": false, "release_version": maxVersion(0), "project_key": testFingerprint(4000),
		"served_interfaces": interfaces, "trust_list": trust,
		"revocations":           []any{map[string]any{"id": maxID(0, "a")}, map[string]any{"id": maxID(0, "a"), "version": maxVersion(0)}},
		"revocation_generation": maxU64,
		"ownership":             map[string]any{"id": maxID(0, "a"), "owner": testFingerprint(5000), "prior_owners": priors, "ownership_generation": maxU64},
		"tombstones":            tombstones,
		"install": map[string]any{"id": maxID(0, "a"), "version": maxVersion(0), "package_sha256": strings.Repeat("0", 64), "state": "recovery_pending",
			"enabled": false, "generation": maxU64, "targets": maxTargets(), "grants": records},
		"registrations": registrations, "disclosure_profiles": profiles, "device_groups": groups, "consumed_approvals": []any{uuid7(1)}})
	return request, resource, record, snapshot, sizes
}

func TestBounds(t *testing.T) {
	request, resource, record, snapshot, sizes := maximalInstances(t)
	// The contracts record the largest grant kind and the sizes it yields.
	for kind, want := range map[string]int{"service-connector": 19127, "browser-adapter": 13450, "collector": 7186} {
		if sizes[kind] != want {
			t.Errorf("%s grant: %d bytes, want %d", kind, sizes[kind], want)
		}
	}
	checks := []struct {
		name  string
		data  []byte
		size  int
		bound int
		parse func([]byte) error
	}{
		{"request", request, 1264586, 2 << 20, func(b []byte) error { _, e := ParseRequest(b); return e }},
		{"resource", resource, 1266858, 2 << 20, func(b []byte) error { _, e := ParseResource(b); return e }},
		{"grant record", record, 19994, 1 << 20, func(b []byte) error { _, e := ParseGrantRecord(b); return e }},
		{"snapshot", snapshot, 7346073, 16 << 20, func(b []byte) error { _, e := ParseSnapshot(b); return e }},
	}
	for _, c := range checks {
		t.Run(c.name, func(t *testing.T) {
			if len(c.data) != c.size {
				t.Errorf("maximal %s is %d bytes, want %d", c.name, len(c.data), c.size)
			}
			if err := c.parse(c.data); err != nil {
				t.Fatalf("maximal %s rejected: %v", c.name, err)
			}
			at := append(append([]byte{}, c.data...), bytes.Repeat([]byte{' '}, c.bound-len(c.data))...)
			if err := c.parse(at); err != nil {
				t.Fatalf("%s padded to its bound rejected: %v", c.name, err)
			}
			over := append(at, ' ')
			if err := c.parse(over); !errors.Is(err, ErrJSON) {
				t.Fatalf("%s one byte over its bound: %v, want ErrJSON", c.name, err)
			}
		})
	}
}

func TestBoundsValues(t *testing.T) {
	collector := grantCase(t, "collector-max-generation-lexeme")
	parseGrant := func(b []byte) error { _, e := ParseGrantRecord(b); return e }
	for _, c := range []struct {
		lexeme string
		ok     bool
	}{{"0", true}, {"1", true}, {maxU64, true}, {"18446744073709551616", false}, {"99999999999999999999", false}, {"00", false}, {"", false}} {
		in := replaceOnce(t, collector, `"grant_generation":"18446744073709551615"`, `"grant_generation":"`+c.lexeme+`"`)
		if err := parseGrant(in); (err == nil) != c.ok {
			t.Errorf("generation %q: %v", c.lexeme, err)
		}
		in = replaceOnce(t, collector, `"recovery_epoch":"3","grant_generation"`, `"recovery_epoch":"`+c.lexeme+`","grant_generation"`)
		if err := parseGrant(in); (err == nil) != c.ok {
			t.Errorf("epoch %q: %v", c.lexeme, err)
		}
	}
	ceilings := map[string]uint64{"memory_pages": 4096, "fuel_per_call": 1000000000, "deadline_ms": 60000, "max_roots": 16, "max_path_depth": 32,
		"max_directory_entries": 10000, "max_open_handles": 64, "max_list_requests": 1024, "max_read_requests": 4096, "max_bytes_per_file": 16777216,
		"max_input_bytes": 67108864, "max_rows": 10000, "max_output_bytes": 16777216}
	var record map[string]any
	if err := json.Unmarshal(collector, &record); err != nil {
		t.Fatal(err)
	}
	for field, ceiling := range ceilings {
		for _, c := range []struct {
			v  uint64
			ok bool
		}{{0, false}, {1, true}, {ceiling, true}, {ceiling + 1, false}} {
			r := cloneJSON(t, record)
			values := r["grant"].(map[string]any)["values"].(map[string]any)
			values[field] = c.v
			roots := []any{}
			for i := 0; i < 16; i++ {
				roots = append(roots, map[string]any{"os": "linux", "path": fmt.Sprintf("/r%d", i)})
			}
			values["roots"] = roots[:1]
			if err := parseGrant(marshal(t, r)); (err == nil) != c.ok {
				t.Errorf("%s=%d: %v", field, c.v, err)
			}
		}
	}
	r := cloneJSON(t, record)
	var roots []any
	for i := 0; i < 17; i++ {
		roots = append(roots, map[string]any{"os": "linux", "path": fmt.Sprintf("/r%d", i)})
	}
	r["grant"].(map[string]any)["values"].(map[string]any)["roots"] = roots[:16]
	if err := parseGrant(marshal(t, r)); err != nil {
		t.Errorf("16 roots: %v", err)
	}
	r["grant"].(map[string]any)["values"].(map[string]any)["roots"] = roots
	if err := parseGrant(marshal(t, r)); !errors.Is(err, ErrField) {
		t.Errorf("17 roots: %v", err)
	}
	r["grant"].(map[string]any)["values"].(map[string]any)["roots"] = []any{map[string]any{"os": "linux", "path": "/" + strings.Repeat("a", 255)}}
	if err := parseGrant(marshal(t, r)); err != nil {
		t.Errorf("256-byte root: %v", err)
	}
	r["grant"].(map[string]any)["values"].(map[string]any)["roots"] = []any{map[string]any{"os": "linux", "path": "/" + strings.Repeat("a", 256)}}
	if err := parseGrant(marshal(t, r)); !errors.Is(err, ErrField) {
		t.Errorf("257-byte root: %v", err)
	}
}
