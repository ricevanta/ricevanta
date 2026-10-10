package celdecl

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func document(t testing.TB) *Document {
	t.Helper()
	d, err := Parse(canonical(t))
	if err != nil {
		t.Fatal(err)
	}
	return d
}
func TestEmbeddedCatalogue(t *testing.T) {
	if !bytes.Equal(embeddedCatalogue, canonical(t)) {
		t.Fatal("embedded bytes differ")
	}
	root, err := parseShape(embeddedCatalogue)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateCatalogue(root); err != nil {
		t.Fatal(err)
	}
}
func TestSnapshotIsolation(t *testing.T) {
	input := canonical(t)
	d, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	before := d.Snapshot()
	view := d.Snapshot()
	view.Objects["device"].Fields["labels"].Type.Element.Kind = "int"
	e := view.Objects["certificate"].Fields["binding"]
	e.Values[0] = "bad"
	view.Objects["certificate"].Fields["binding"] = e
	view.Variables["rows"].Type.Element.Value.Kind = "int"
	view.Domains["edr"]["condition"][0] = "certificate"
	delete(view.Objects, "device")
	delete(view.Variables, "now")
	delete(view.Domains, "network")
	for i := range input {
		input[i] = '!'
	}
	if !reflect.DeepEqual(before, d.Snapshot()) {
		t.Fatal("mutation reached document")
	}
	b, err := json.Marshal(d.Snapshot())
	if err != nil {
		t.Fatal(err)
	}
	checkParse(t, b, nil)
}
func TestEnvironmentIsolation(t *testing.T) {
	d := document(t)
	a, err := d.Environment("mdm", "query")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := d.Environment("mdm", "query")
	for i := range a {
		if a[i].Name == "rows" {
			a[i].Entry.Type.Element.Value.Kind = "int"
		}
		a[i].Name = "bad"
	}
	c, _ := d.Environment("mdm", "query")
	if !reflect.DeepEqual(b, c) {
		t.Fatal("environment alias")
	}
}
func TestEnvironmentErrors(t *testing.T) {
	for _, pair := range [][2]string{{"unknown", "condition"}, {"edr", "unknown"}, {"edr", "query"}, {"edr", "collector"}, {"MDM", "condition"}, {"mdm", "Condition"}} {
		a, err := document(t).Environment(pair[0], pair[1])
		if a != nil || !errors.Is(err, ErrDomain) || errors.Is(err, ErrDocument) {
			t.Fatalf("pair %v: %v %v", pair, a, err)
		}
	}
}
func TestZeroDocument(t *testing.T) {
	for _, d := range []*Document{nil, {}} {
		if !reflect.DeepEqual(d.Snapshot(), Catalogue{}) {
			t.Fatal("nonzero snapshot")
		}
		for _, pair := range [][2]string{{"edr", "condition"}, {"unknown", "unknown"}} {
			a, err := d.Environment(pair[0], pair[1])
			if a != nil || !errors.Is(err, ErrDocument) || errors.Is(err, ErrDomain) {
				t.Fatalf("%v %v", a, err)
			}
		}
	}
}
func TestCatalogueInventory(t *testing.T) {
	d := document(t)
	c := d.Snapshot()
	names := []string{}
	for k := range c.Variables {
		names = append(names, k)
	}
	sort.Strings(names)
	if strings.Join(names, " ") != "access activity certificate destination device event gateway item match now rows session state user" {
		t.Fatal(names)
	}
	expected := map[string]map[string]string{
		"edr":     {"condition": "device event now user", "exception": "device event now user"},
		"lineage": {"condition": "device event now user", "exception": "device event now user"},
		"pki":     {"condition": "device event now user", "exception": "device event now user"},
		"dlp":     {"condition": "activity destination device event match now session user", "exception": "activity destination device event match now session user"},
		"network": {"condition": "access certificate device event gateway now user", "exception": "access certificate device event gateway now user"},
		"mdm":     {"condition": "device now state user", "exception": "device item now state user", "query": "device now rows state user", "collector": "device now rows state user"},
	}
	if len(c.Domains) != len(expected) {
		t.Fatal("domain inventory")
	}
	for domain, contexts := range expected {
		if len(c.Domains[domain]) != len(contexts) {
			t.Fatal(domain)
		}
		for context, want := range contexts {
			env, err := d.Environment(domain, context)
			if err != nil {
				t.Fatal(err)
			}
			got := []string{}
			for _, v := range env {
				got = append(got, v.Name)
				if !reflect.DeepEqual(v.Entry, c.Variables[v.Name]) {
					t.Fatal("entry differs", v.Name)
				}
			}
			if strings.Join(got, " ") != want || strings.Join(c.Domains[domain][context], " ") != want {
				t.Fatalf("%s/%s %v", domain, context, got)
			}
		}
	}
}
func TestSentinelText(t *testing.T) {
	suffix := map[string]string{"ErrRead": "read", "ErrSize": "size", "ErrJSON": "json", "ErrDuplicateKey": "duplicate key", "ErrShape": "shape", "ErrVersion": "version", "ErrProfile": "profile", "ErrOCSF": "ocsf version", "ErrName": "name", "ErrType": "type", "ErrLimit": "limit", "ErrDomain": "domain", "ErrReference": "reference", "ErrCycle": "cycle", "ErrCatalogue": "catalogue", "ErrDocument": "document"}
	for name, e := range fixtureSentinels() {
		if e.Error() != "cel declarations "+suffix[name] {
			t.Fatal(name, e)
		}
	}
}

func TestCatalogueFields(t *testing.T) {
	// Descriptors name kind, bound or reference, presence, and ordered enum values.
	expected := map[string]string{
		"device":        "uid=string:4096:required name=string:4096:required os=map:1024:json:required labels=list:32:string:4096:required groups=list:64:string:4096:required state=string:4096:required compliant=bool:required compliance=string:4096:required:compliant,grace,noncompliant,unknown compliance_time=timestamp:required compliance_time_ms=int:required",
		"user":          "uid=string:4096:required name=string:4096:required groups=list:256:string:4096:required source=string:4096:network:certificate,device_link",
		"session":       "uid=string:4096:required user=object:user:optional interactive=bool:required remote=bool:required",
		"rule_identity": "pack=string:4096:required version=string:4096:required pack_digest=string:4096:required rule_key=string:4096:required",
		"category":      "id=string:4096:required confidence=double:required count=int:required",
		"inherited":     "revision=map:1024:json:optional content_hash=string:4096:optional",
		"match":         "classification=string:4096:required confidence=double:required rules=list:64:object:rule_identity:required reference=string:4096:optional count=int:required categories=list:256:object:category:required coverage=string:4096:required:complete,truncated,encrypted,corrupt,unsupported,pending_ocr inherited=object:inherited:optional type_mismatch=bool:required",
		"removable":     "vendor_id=string:4096:optional product_id=string:4096:optional serial=string:4096:optional encrypted=bool:optional",
		"account":       "account=string:4096:optional tenant=string:4096:optional",
		"destination":   "kind=string:4096:required:removable,cloud_sync,browser,network,clipboard host=string:4096:optional managed=bool:required app=string:4096:optional device=object:removable:optional account=object:account:optional",
		"activity":      "removable_bytes_1h=int:required removable_files_1h=int:required uploads_10m=int:required upload_bytes_10m=int:required blocked_10m=int:required",
		"certificate":   "identity=string:4096:required kind=string:4096:required profile=string:4096:required binding=string:4096:required:exact,identity_only serial=string:4096:exact fingerprint=string:4096:exact issuer=string:4096:exact not_before=timestamp:exact not_after=timestamp:exact not_before_ms=int:exact not_after_ms=int:exact",
		"gateway":       "name=string:4096:required profile=string:4096:required labels=list:32:string:4096:required",
		"access":        "method=string:4096:required:eap_tls,certificate_derived medium=string:4096:required:vpn,wired,wireless ssid=string:4096:optional nas_port_type=int:optional calling_station=string:4096:optional tls_version=string:4096:optional",
		"item":          "baseline=string:4096:required id=string:4096:required",
	}
	c := document(t).Snapshot()
	if len(c.Objects) != len(expected) {
		t.Fatal("object inventory")
	}
	for name, fields := range expected {
		want := strings.Fields(fields)
		got := []string{}
		for field, e := range c.Objects[name].Fields {
			desc := field + "=" + typeDescriptor(e.Type) + ":" + e.Presence
			if len(e.Values) > 0 {
				desc += ":" + strings.Join(e.Values, ",")
			}
			got = append(got, desc)
		}
		sort.Strings(want)
		sort.Strings(got)
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("%s\ngot %v\nwant %v", name, got, want)
		}
	}
	vars := map[string]string{"device": "object:device:required", "user": "object:user:optional", "session": "object:session:optional", "match": "object:match:required", "destination": "object:destination:required", "activity": "object:activity:required", "certificate": "object:certificate:required", "gateway": "object:gateway:required", "access": "object:access:required", "item": "object:item:required", "event": "map:1024:json:required", "state": "map:1024:json:required", "rows": "list:10000:map:1024:json:required", "now": "timestamp:required"}
	for name, want := range vars {
		e := c.Variables[name]
		if got := typeDescriptor(e.Type) + ":" + e.Presence; got != want {
			t.Fatalf("%s %s", name, got)
		}
	}
}
func typeDescriptor(typ Type) string {
	switch typ.Kind {
	case "object":
		return "object:" + typ.Name
	case "string":
		return fmt.Sprintf("string:%d", typ.MaxLength)
	case "list":
		return fmt.Sprintf("list:%d:%s", typ.MaxItems, typeDescriptor(*typ.Element))
	case "map":
		if typ.Key != "string" {
			return "bad-key"
		}
		return fmt.Sprintf("map:%d:%s", typ.MaxEntries, typeDescriptor(*typ.Value))
	}
	return typ.Kind
}
