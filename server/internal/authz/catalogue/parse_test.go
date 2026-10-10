package catalogue

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"
	"strings"
	"testing"
)

type parseCase struct {
	ID        string
	Catalogue json.RawMessage
	WireHex   string `json:"wire_hex"`
	Error     string
}

func parseFixtures(t testing.TB) []parseCase {
	t.Helper()
	b, err := os.ReadFile("../../../../schemas/permissions/v1/fixtures/catalogues.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct{ Cases []parseCase }
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc.Cases
}
func fixtureBytes(t testing.TB, r parseCase) []byte {
	t.Helper()
	if r.Catalogue != nil {
		return r.Catalogue
	}
	b, err := hex.DecodeString(r.WireHex)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func sentinelTable() map[string]error {
	return map[string]error{"ErrLimit": ErrLimit, "ErrJSON": ErrJSON, "ErrShape": ErrShape, "ErrVersion": ErrVersion, "ErrNameFormat": ErrNameFormat, "ErrEntry": ErrEntry, "ErrDuplicate": ErrDuplicate, "ErrOrder": ErrOrder, "ErrRevision": ErrRevision, "ErrUnavailable": ErrUnavailable, "ErrUnknownPermission": ErrUnknownPermission, "ErrRetiredPermission": ErrRetiredPermission}
}
func checkParse(t testing.TB, b []byte, want error) *Catalogue {
	t.Helper()
	c, err := Parse(b)
	if want == nil {
		if err != nil || c == nil {
			t.Fatalf("want success, got %v", err)
		}
		return c
	}
	if c != nil || !errors.Is(err, want) {
		t.Fatalf("want nil/%v, got %v/%v", want, c, err)
	}
	matches := 0
	for _, sentinel := range sentinelTable() {
		if errors.Is(err, sentinel) {
			matches++
		}
	}
	if matches != 1 {
		t.Fatalf("sentinel matches %d", matches)
	}
	return nil
}
func baseEntry() map[string]any {
	return map[string]any{"name": "dlp.evidence.read", "owner": "dlp", "scope": "device_group", "protection": "none", "approval": "none", "rule": "none", "grant": "role", "status": "active", "introduced": 1, "uses": []any{"getEvidence"}, "source": "source#1", "note": "note"}
}
func baseDoc() map[string]any {
	return map[string]any{"format_version": 1, "revision": 2, "permissions": []any{baseEntry()}}
}
func encode(t testing.TB, v any) []byte {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
func docEntry(d map[string]any) map[string]any { return d["permissions"].([]any)[0].(map[string]any) }
func TestParseFixtures(t *testing.T) {
	for _, r := range parseFixtures(t) {
		t.Run(r.ID, func(t *testing.T) { checkParse(t, fixtureBytes(t, r), sentinelTable()[r.Error]) })
	}
	b, err := os.ReadFile("../../../../schemas/permissions/v1/fixtures/revocations.json")
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Cases []struct {
			ID        string
			Catalogue json.RawMessage
		} `json:"revocation_cases"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	for _, r := range doc.Cases {
		t.Run(r.ID, func(t *testing.T) { checkParse(t, r.Catalogue, nil) })
	}
}
func TestParseWireProfile(t *testing.T) {
	cases := []struct {
		b    []byte
		want error
	}{
		{nil, ErrJSON}, {[]byte(`{"name":0,"n\u0061me":1}`), ErrJSON}, {[]byte(`{"x":{"a":0,"a":1}}`), ErrJSON},
		{[]byte(`{"x":"\u+123"}`), ErrJSON}, {[]byte(`{"x":"\u0x12"}`), ErrJSON}, {[]byte(`{"x":"\u12_3"}`), ErrJSON},
		{[]byte(`{"x":"\ud800"}`), ErrJSON}, {[]byte(`{"x":"\udc00"}`), ErrJSON}, {[]byte(`{"x":"\ud800\u0041"}`), ErrJSON},
		{[]byte{'"', 0xff, '"'}, ErrJSON}, {[]byte("\xef\xbb\xbf{}"), ErrJSON}, {[]byte(`{} 1`), ErrJSON}, {[]byte(`{} {}`), ErrJSON},
		{[]byte(`{"a":`), ErrJSON}, {[]byte(`{"a":"\x00"}`), ErrJSON}, {[]byte(`{"a":01}`), ErrJSON},
	}
	for i, r := range cases {
		t.Run(fmt.Sprint(i), func(t *testing.T) { checkParse(t, r.b, r.want) })
	}
	d := baseDoc()
	docEntry(d)["note"] = json.RawMessage(`"\ud83d\ude00"`)
	checkParse(t, encode(t, d), ErrEntry)
	b := encode(t, baseDoc())
	checkParse(t, bytes.Replace(b, []byte(`dlp.evidence.read`), []byte(`dlp.evidence.r\u0065ad`), 1), nil)
	// Lexical defects before and after entry into depth 13 have different winners.
	checkParse(t, []byte(strings.Repeat("[", 12)+`"\ud800"`+strings.Repeat("]", 12)), ErrJSON)
	checkParse(t, []byte(strings.Repeat("[", 13)+`"\ud800"`+strings.Repeat("]", 13)), ErrLimit)
	checkParse(t, []byte(`{"x":0,"x":`+strings.Repeat("[", 13)), ErrJSON)
	checkParse(t, append([]byte(`"`), append([]byte{0xff}, []byte(strings.Repeat("[", 13))...)...), ErrJSON)
	checkParse(t, []byte(`{} `+strings.Repeat("[", 13)), ErrJSON)
}
func TestParseShape(t *testing.T) {
	for _, field := range []string{"format_version", "revision", "permissions"} {
		t.Run("missing-root-"+field, func(t *testing.T) { d := baseDoc(); delete(d, field); checkParse(t, encode(t, d), ErrShape) })
		for _, v := range []any{nil, true, "wrong", map[string]any{}} {
			d := baseDoc()
			d[field] = v
			checkParse(t, encode(t, d), ErrShape)
		}
	}
	for field := range baseEntry() {
		t.Run("missing-entry-"+field, func(t *testing.T) { d := baseDoc(); delete(docEntry(d), field); checkParse(t, encode(t, d), ErrShape) })
		for _, v := range []any{nil, true, 0, map[string]any{}} {
			d := baseDoc()
			docEntry(d)[field] = v
			if field == "introduced" && v == 0 {
				checkParse(t, encode(t, d), ErrEntry)
			} else {
				checkParse(t, encode(t, d), ErrShape)
			}
		}
	}
	for _, b := range []string{`null`, `[]`, `1`, `"a"`, `{"Format_version":1,"revision":1,"permissions":[]}`} {
		checkParse(t, []byte(b), ErrShape)
	}
	d := baseDoc()
	d["unknown"] = 1
	checkParse(t, encode(t, d), ErrShape)
	d = baseDoc()
	docEntry(d)["unknown"] = 1
	checkParse(t, encode(t, d), ErrShape)
	d = baseDoc()
	docEntry(d)["uses"] = []any{1}
	checkParse(t, encode(t, d), ErrShape)
	for _, field := range []string{"format_version", "revision", "introduced", "retired_in"} {
		for _, token := range []string{"-1", "-0", "1.0", "1e0", "4294967296", "true", "null", "\"1\""} {
			d := baseDoc()
			if field == "format_version" || field == "revision" {
				d[field] = json.RawMessage(token)
			} else {
				docEntry(d)[field] = json.RawMessage(token)
			}
			checkParse(t, encode(t, d), ErrShape)
		}
	}
}
func TestParseEntryMetadata(t *testing.T) {
	for field, values := range map[string][]any{"name": {"alien.evidence.read", "dlp.evidence.unknown"}, "owner": {"devices", "unknown"}, "scope": {"unknown"}, "protection": {"always", "unknown"}, "approval": {"access_policy", "unknown"}, "rule": {"unknown"}, "grant": {"direct", "connector", "unknown"}, "status": {"unknown"}, "uses": {[]any{}, []any{"a", "a"}, []any{""}, []any{"é"}}, "source": {"", "é", "line\n"}, "note": {"", "é", "line\n"}} {
		for i, v := range values {
			t.Run(fmt.Sprintf("%s-%d", field, i), func(t *testing.T) { d := baseDoc(); docEntry(d)[field] = v; checkParse(t, encode(t, d), ErrEntry) })
		}
	}
	for _, namespace := range []string{"audit", "authz", "dlp", "edr", "events", "extensions", "identity", "lineage", "mdm", "pki", "platform", "policy", "radius"} {
		owners := []string{namespace}
		if namespace == "edr" {
			owners = []string{"detection"}
		}
		if namespace == "mdm" {
			owners = []string{"mdm", "devices"}
		}
		for _, owner := range owners {
			d := baseDoc()
			p := docEntry(d)
			p["name"] = namespace + ".object.read"
			p["owner"] = owner
			checkParse(t, encode(t, d), nil)
		}
		d := baseDoc()
		p := docEntry(d)
		p["name"] = namespace + ".object.read"
		p["owner"] = "wrong"
		checkParse(t, encode(t, d), ErrEntry)
	}
	// Schema vocabulary is read only by tests; the runtime remains independent.
	b, err := os.ReadFile("../../../../schemas/permissions/v1/catalogue.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema map[string]any
	if err := json.Unmarshal(b, &schema); err != nil {
		t.Fatal(err)
	}
	props := schema["$defs"].(map[string]any)["permission"].(map[string]any)["properties"].(map[string]any)
	for _, r := range props["rule"].(map[string]any)["enum"].([]any) {
		d := baseDoc()
		p := docEntry(d)
		p["rule"] = r
		p["protection"] = "conditional"
		p["approval"] = "access_policy"
		switch r {
		case "none":
			p["protection"] = "none"
			p["approval"] = "none"
		case "always":
			p["protection"] = "always"
		case "identity_authority":
			p["protection"] = "always"
			p["approval"] = "identity_authority"
		}
		checkParse(t, encode(t, d), nil)
		p["approval"] = "wrong"
		checkParse(t, encode(t, d), ErrEntry)
	}
	// Every closed verb, independently copied from the approved schema pattern.
	for _, verb := range strings.Fields("advance approve assign backfill cancel capture collect complete confirm create delete diagnose disable disconnect enable execute export import install isolate_host key_operation kill_and_ban kill_process lock manage message override pause pin preflight promote publish quarantine_file read reclassify reconcile reject release remove replace replace_factor replay reset restart restore_file resume retire revoke rotate run run_script scan script shutdown simulate suspend test transfer unban uninstall unisolate_host unpin update update_os upgrade upload validate wipe withdraw") {
		d := baseDoc()
		docEntry(d)["name"] = "dlp.object." + verb
		checkParse(t, encode(t, d), nil)
	}
	for _, special := range []struct{ name, owner, grant string }{{"identity.authority.approve", "identity", "direct"}, {"extensions.ca_callback.complete", "extensions", "connector"}} {
		for _, grant := range []string{"role", "direct", "connector"} {
			d := baseDoc()
			p := docEntry(d)
			p["name"] = special.name
			p["owner"] = special.owner
			p["grant"] = grant
			want := ErrEntry
			if grant == special.grant {
				want = nil
			}
			checkParse(t, encode(t, d), want)
		}
	}
}
func TestParseRevision(t *testing.T) {
	for _, n := range []uint64{0, 1, 4294967295, 4294967296} {
		d := baseDoc()
		d["revision"] = n
		want := error(nil)
		if n == 0 || n > 4294967295 {
			want = ErrShape
		}
		checkParse(t, encode(t, d), want)
	}
	d := baseDoc()
	d["format_version"] = 0
	checkParse(t, encode(t, d), ErrVersion)
	d["format_version"] = 4294967295
	checkParse(t, encode(t, d), ErrVersion)
	for _, n := range []uint64{0, 1, 2, 4294967295, 4294967296} {
		d := baseDoc()
		docEntry(d)["introduced"] = n
		want := error(nil)
		switch {
		case n == 0:
			want = ErrEntry
		case n > 4294967295:
			want = ErrShape
		case n > 2:
			want = ErrRevision
		}
		checkParse(t, encode(t, d), want)
	}
	d = baseDoc()
	docEntry(d)["retired_in"] = 2
	checkParse(t, encode(t, d), ErrEntry)
	for _, n := range []uint64{0, 1, 2, 3, 4294967295, 4294967296} {
		d := baseDoc()
		p := docEntry(d)
		p["status"] = "retired"
		p["retired_in"] = n
		want := error(nil)
		switch {
		case n < 2:
			want = ErrEntry
		case n > 4294967295:
			want = ErrShape
		case n > 2:
			want = ErrRevision
		}
		checkParse(t, encode(t, d), want)
	}
	d = baseDoc()
	p := docEntry(d)
	p["status"] = "retired"
	checkParse(t, encode(t, d), ErrEntry)
	p["introduced"] = 2
	p["retired_in"] = 2
	checkParse(t, encode(t, d), ErrRevision)
	d = baseDoc()
	d["revision"] = uint64(4294967295)
	docEntry(d)["introduced"] = uint64(4294967295)
	checkParse(t, encode(t, d), nil)
}
func TestParseBounds(t *testing.T) {
	base := encode(t, baseDoc())
	for _, n := range []int{MaxBytes - 1, MaxBytes, MaxBytes + 1} {
		b := append(bytes.Clone(base), bytes.Repeat([]byte{' '}, n-len(base))...)
		want := error(nil)
		if n > MaxBytes {
			want = ErrLimit
		}
		checkParse(t, b, want)
	}
	checkParse(t, bytes.Repeat([]byte{'!'}, MaxBytes+1), ErrLimit)
	for _, depth := range []int{12, 13} {
		want := ErrShape
		if depth == 13 {
			want = ErrLimit
		}
		checkParse(t, []byte(strings.Repeat("[", depth)+"0"+strings.Repeat("]", depth)), want)
	}
	for _, n := range []int{0, 1, 2048, 2049} {
		d := baseDoc()
		entries := make([]any, n)
		for i := range entries {
			p := baseEntry()
			p["name"] = fmt.Sprintf("dlp.a%04d.read", i)
			entries[i] = p
		}
		d["permissions"] = entries
		want := error(nil)
		if n == 0 || n > MaxEntries {
			want = ErrShape
		}
		checkParse(t, encode(t, d), want)
	}
	for field, max := range map[string]int{"source": 160, "note": 512} {
		for _, n := range []int{0, 1, max, max + 1} {
			d := baseDoc()
			docEntry(d)[field] = strings.Repeat("x", n)
			want := error(nil)
			if n == 0 || n > max {
				want = ErrEntry
			}
			checkParse(t, encode(t, d), want)
		}
		for _, s := range []string{"\x1f", "\x7f", "\x00", " ", "~"} {
			d := baseDoc()
			docEntry(d)[field] = s
			want := error(nil)
			if s[0] < 32 || s[0] > 126 {
				want = ErrEntry
			}
			checkParse(t, encode(t, d), want)
		}
	}
	for _, n := range []int{0, 1, 32, 33} {
		d := baseDoc()
		uses := make([]any, n)
		for i := range uses {
			uses[i] = fmt.Sprint(i)
		}
		docEntry(d)["uses"] = uses
		want := error(nil)
		if n == 0 || n > 32 {
			want = ErrEntry
		}
		checkParse(t, encode(t, d), want)
	}
	for _, n := range []int{0, 1, 160, 161} {
		d := baseDoc()
		docEntry(d)["uses"] = []any{strings.Repeat("x", n)}
		want := error(nil)
		if n == 0 || n > 160 {
			want = ErrEntry
		}
		checkParse(t, encode(t, d), want)
	}
	for _, n := range []int{1, 32, 33} {
		d := baseDoc()
		docEntry(d)["name"] = "dlp." + strings.Repeat("a", n) + ".read"
		want := error(nil)
		if n > 32 {
			want = ErrNameFormat
		}
		checkParse(t, encode(t, d), want)
	}
}
func TestParsePrecedence(t *testing.T) {
	for _, r := range parseFixtures(t) {
		if strings.Contains(r.ID, "before") {
			checkParse(t, fixtureBytes(t, r), sentinelTable()[r.Error])
		}
	}
	d := baseDoc()
	d["format_version"] = 2
	docEntry(d)["scope"] = nil
	checkParse(t, encode(t, d), ErrShape)
	d = baseDoc()
	d["format_version"] = 2
	docEntry(d)["name"] = "BAD"
	checkParse(t, encode(t, d), ErrVersion)
	d = baseDoc()
	p := docEntry(d)
	p["scope"] = "bad"
	later := baseEntry()
	later["name"] = "BAD"
	d["permissions"] = []any{p, later}
	checkParse(t, encode(t, d), ErrNameFormat)
	d = baseDoc()
	p = docEntry(d)
	p["scope"] = "bad"
	d["permissions"] = []any{p, baseEntry()}
	checkParse(t, encode(t, d), ErrEntry)
	d = baseDoc()
	a, b, c := baseEntry(), baseEntry(), baseEntry()
	a["name"] = "dlp.z.read"
	d["permissions"] = []any{a, b, c}
	checkParse(t, encode(t, d), ErrDuplicate)
	d = baseDoc()
	a, b = baseEntry(), baseEntry()
	a["name"] = "dlp.z.read"
	a["introduced"] = 3
	d["permissions"] = []any{a, b}
	checkParse(t, encode(t, d), ErrOrder)
	bts := encode(t, d)
	checkParse(t, append(bts, '!'), ErrJSON)
}

// Generated seeds exercise the same bounded profiles as the unit vectors.
func generatedSeeds(t testing.TB) [][]byte {
	t.Helper()
	base := encode(t, baseDoc())
	seeds := [][]byte{base}
	for _, n := range []int{MaxBytes - 1, MaxBytes, MaxBytes + 1} {
		seeds = append(seeds, append(bytes.Clone(base), bytes.Repeat([]byte{' '}, n-len(base))...))
	}
	for _, n := range []int{12, 13} {
		seeds = append(seeds, []byte(strings.Repeat("[", n)+"0"+strings.Repeat("]", n)))
	}
	for _, n := range []int{0, 1, 2048, 2049} {
		d := baseDoc()
		entries := make([]any, n)
		for i := range entries {
			p := baseEntry()
			p["name"] = fmt.Sprintf("dlp.a%04d.read", i)
			entries[i] = p
		}
		d["permissions"] = entries
		seeds = append(seeds, encode(t, d))
	}
	for field, max := range map[string]int{"source": 160, "note": 512} {
		for _, n := range []int{0, 1, max, max + 1} {
			d := baseDoc()
			docEntry(d)[field] = strings.Repeat("x", n)
			seeds = append(seeds, encode(t, d))
		}
	}
	for _, n := range []int{0, 1, 32, 33} {
		d := baseDoc()
		uses := make([]any, n)
		for i := range uses {
			uses[i] = fmt.Sprint(i)
		}
		docEntry(d)["uses"] = uses
		seeds = append(seeds, encode(t, d))
	}
	for _, n := range []int{0, 1, 160, 161} {
		d := baseDoc()
		docEntry(d)["uses"] = []any{strings.Repeat("x", n)}
		seeds = append(seeds, encode(t, d))
	}
	for _, n := range []int{1, 32, 33} {
		d := baseDoc()
		docEntry(d)["name"] = "dlp." + strings.Repeat("a", n) + ".read"
		seeds = append(seeds, encode(t, d))
	}
	for _, field := range []string{"format_version", "revision", "introduced", "retired_in"} {
		for _, token := range []string{"0", "1", "4294967295", "4294967296", "-1", "-0", "1.0", "1e0", "1e+0"} {
			d := baseDoc()
			if field == "format_version" || field == "revision" {
				d[field] = json.RawMessage(token)
			} else {
				docEntry(d)[field] = json.RawMessage(token)
			}
			seeds = append(seeds, encode(t, d))
		}
	}
	return seeds
}

func FuzzParse(f *testing.F) {
	for _, r := range parseFixtures(f) {
		f.Add(fixtureBytes(f, r))
	}
	for _, b := range generatedSeeds(f) {
		f.Add(b)
	}
	b, err := os.ReadFile("../../../../schemas/permissions/v1/fixtures/revocations.json")
	if err != nil {
		f.Fatal(err)
	}
	var revocations struct {
		Cases []struct{ Catalogue json.RawMessage } `json:"revocation_cases"`
	}
	if err := json.Unmarshal(b, &revocations); err != nil {
		f.Fatal(err)
	}
	for _, r := range revocations.Cases {
		f.Add([]byte(r.Catalogue))
	}

	f.Fuzz(func(t *testing.T, b []byte) {
		c, err := Parse(b)
		if err == nil {
			if c == nil {
				t.Fatal("nil success")
			}
			if !bytes.Equal(c.JSON(), b) {
				t.Fatal("accepted bytes changed")
			}
			again := checkParse(t, c.JSON(), nil)
			if again.Revision() != c.Revision() || !reflect.DeepEqual(again.Entries(), c.Entries()) {
				t.Fatal("repeat parse changed metadata")
			}
			for _, p := range c.Entries() {
				want := error(nil)
				if p.Status == "retired" {
					want = ErrRetiredPermission
				}
				got := checkLookup(t, c, p.Name, want)
				if want == nil && !reflect.DeepEqual(got, p) {
					t.Fatal("lookup changed metadata")
				}
			}
			return
		}
		if c != nil {
			t.Fatal("partial output")
		}
		count := 0
		for _, s := range sentinelTable() {
			if errors.Is(err, s) {
				count++
			}
		}
		if count != 1 {
			t.Fatalf("unclassified error %v", err)
		}
	})
}

func TestUsesAllocationBound(t *testing.T) {
	d := baseDoc()
	docEntry(d)["uses"] = make([]string, 300000)
	input := encode(t, d)
	if len(input) > MaxBytes {
		t.Fatal("reviewer input exceeds MaxBytes")
	}
	runtime.GC()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	c, err := Parse(input)
	runtime.ReadMemStats(&after)
	if c != nil || !errors.Is(err, ErrEntry) {
		t.Fatalf("want nil/ErrEntry, got %v/%v", c, err)
	}
	// Allow bounded document copies and fixed overhead, not per-item storage.
	allocated := after.TotalAlloc - before.TotalAlloc
	limit := uint64(12*len(input) + 1<<20)
	t.Logf("input=%d allocated=%d limit=%d", len(input), allocated, limit)
	if allocated > limit {
		t.Fatalf("uses allocation exceeds bound: %d > %d", allocated, limit)
	}
}

func TestUsesOverflowPrecedence(t *testing.T) {
	uses := make([]any, 33)
	for i := range uses {
		uses[i] = fmt.Sprint(i)
	}
	d := baseDoc()
	docEntry(d)["uses"] = uses
	checkParse(t, encode(t, d), ErrEntry)
	d["format_version"] = 2
	checkParse(t, encode(t, d), ErrVersion)
	docEntry(d)["name"] = "BAD"
	d["format_version"] = 1
	checkParse(t, encode(t, d), ErrNameFormat)
	for _, wrong := range []any{nil, 1, true, []any{}, map[string]any{}} {
		uses[32] = wrong
		checkParse(t, encode(t, d), ErrShape)
	}
	uses[32] = "32"
	later := baseEntry()
	later["scope"] = nil
	d["permissions"] = []any{docEntry(d), later}
	checkParse(t, encode(t, d), ErrShape)
}
