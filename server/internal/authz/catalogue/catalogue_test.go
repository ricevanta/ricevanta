package catalogue

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"sync"
	"testing"
)

func namedFixture(t testing.TB, id string) *Catalogue {
	t.Helper()
	for _, r := range parseFixtures(t) {
		if r.ID == id {
			return checkParse(t, fixtureBytes(t, r), nil)
		}
	}
	t.Fatalf("missing fixture %s", id)
	return nil
}
func checkLookup(t testing.TB, c *Catalogue, name string, want error) Permission {
	t.Helper()
	p, err := c.Lookup(name)
	if want == nil {
		if err != nil || p.Name != name || p.Status != "active" {
			t.Fatalf("lookup got %v/%v", p, err)
		}
		return p
	}
	if !reflect.DeepEqual(p, Permission{}) || !errors.Is(err, want) {
		t.Fatalf("want zero/%v, got %v/%v", want, p, err)
	}
	count := 0
	for _, s := range sentinelTable() {
		if errors.Is(err, s) {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("lookup sentinel count %d", count)
	}
	return p
}
func TestLookupFixtures(t *testing.T) {
	id, rows := nameFixtures(t)
	c := namedFixture(t, id)
	for _, r := range rows {
		t.Run(r.ID, func(t *testing.T) { checkLookup(t, c, r.Name, sentinelTable()[r.LookupError]) })
	}
	builtin, err := Builtin()
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(canonicalPath)
	if err != nil {
		t.Fatal(err)
	}
	checkMetadataAgainstJSON(t, builtin, data)
}
func TestLookupPrecedence(t *testing.T) {
	for _, c := range []*Catalogue{nil, {}, namedFixture(t, "active-and-retired")} {
		checkLookup(t, c, "BAD", ErrNameFormat)
		checkLookup(t, c, "a.b.\xff", ErrNameFormat)
	}
	for _, c := range []*Catalogue{nil, {}} {
		checkLookup(t, c, "alien.object.read", ErrUnavailable)
		checkLookup(t, c, "dlp.evidence.update", ErrUnavailable)
	}
	c := namedFixture(t, "active-and-retired")
	checkLookup(t, c, "alien.object.read", ErrUnknownPermission)
	checkLookup(t, c, "dlp.evidence.update", ErrRetiredPermission)
}
func TestZeroCatalogue(t *testing.T) {
	for _, c := range []*Catalogue{nil, {}} {
		if c.Entries() != nil || c.JSON() != nil || c.Revision() != 0 {
			t.Fatal("zero receiver differs")
		}
		checkLookup(t, c, "a.b.c", ErrUnavailable)
	}
}
func TestDefensiveCopies(t *testing.T) {
	input := encode(t, baseDoc())
	original := bytes.Clone(input)
	c := checkParse(t, input, nil)
	input[0] = '!'
	want := c.Entries()
	p := checkLookup(t, c, "dlp.evidence.read", nil)
	p.Uses[0] = "mutated"
	p.Name = "changed"
	entries := c.Entries()
	entries[0].Uses[0] = "mutated"
	entries[0] = Permission{}
	output := c.JSON()
	output[0] = '!'
	if !reflect.DeepEqual(c.Entries(), want) || !bytes.Equal(c.JSON(), original) || c.Revision() != 2 {
		t.Fatal("shared mutable state")
	}
	again := checkParse(t, c.JSON(), nil)
	if !reflect.DeepEqual(again.Entries(), want) || again.Revision() != c.Revision() {
		t.Fatal("reparse differs")
	}
	c = namedFixture(t, "active-and-retired")
	if len(c.Entries()) != 2 || c.Entries()[1].Status != "retired" {
		t.Fatal("tombstone omitted")
	}
}
func TestConcurrentReads(t *testing.T) {
	c := namedFixture(t, "active-and-retired")
	want := c.Entries()
	json := c.JSON()
	var wg sync.WaitGroup
	for i := 0; i < 32; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				p, err := c.Lookup("dlp.evidence.read")
				if err != nil || len(p.Uses) == 0 {
					t.Errorf("active concurrent lookup: %v", err)
					return
				}
				p.Uses[0] = "mutated"
				entries := c.Entries()
				entries[0].Uses[0] = "mutated"
				entries[0] = Permission{}
				b := c.JSON()
				b[0] = '!'
				retired, err := c.Lookup("dlp.evidence.update")
				if !errors.Is(err, ErrRetiredPermission) || !reflect.DeepEqual(retired, Permission{}) {
					t.Errorf("retired concurrent lookup: %v", err)
					return
				}
				if c.Revision() != 2 {
					t.Error("revision changed")
				}
			}
		}()
	}
	wg.Wait()
	if !reflect.DeepEqual(c.Entries(), want) || !bytes.Equal(c.JSON(), json) {
		t.Fatal("concurrent mutation escaped")
	}
}

// Decode expectations independently of Parse, Entries, Lookup and copyPermission.
func checkMetadataAgainstJSON(t *testing.T, c *Catalogue, data []byte) {
	t.Helper()
	var doc struct {
		Revision    uint32
		Permissions []struct {
			Name, Owner, Scope, Protection, Approval, Rule, Grant, Status string
			Introduced                                                    uint32
			RetiredIn                                                     uint32 `json:"retired_in"`
			Uses                                                          []string
			Source, Note                                                  string
		}
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatal(err)
	}
	entries := c.Entries()
	if c.Revision() != doc.Revision || len(entries) != len(doc.Permissions) {
		t.Fatal("root metadata differs from JSON")
	}
	for i, wire := range doc.Permissions {
		want := Permission{
			Name: wire.Name, Owner: wire.Owner, Scope: wire.Scope,
			Protection: wire.Protection, Approval: wire.Approval, Rule: wire.Rule,
			Grant: wire.Grant, Status: wire.Status, Introduced: wire.Introduced,
			RetiredIn: wire.RetiredIn, Uses: wire.Uses, Source: wire.Source, Note: wire.Note,
		}
		t.Run(wire.Name+"/Entries", func(t *testing.T) {
			if !reflect.DeepEqual(entries[i], want) {
				t.Fatalf("Entries differs from JSON: got %+v, want %+v", entries[i], want)
			}
		})
		t.Run(wire.Name+"/Lookup", func(t *testing.T) {
			if wire.Status == "retired" {
				checkLookup(t, c, wire.Name, ErrRetiredPermission)
			} else if got := checkLookup(t, c, wire.Name, nil); !reflect.DeepEqual(got, want) {
				t.Fatalf("Lookup differs from JSON: got %+v, want %+v", got, want)
			}
		})
	}
}

func TestFixtureReturnedMetadata(t *testing.T) {
	for _, r := range parseFixtures(t) {
		if r.Error != "" {
			continue
		}
		t.Run(r.ID, func(t *testing.T) {
			data := fixtureBytes(t, r)
			checkMetadataAgainstJSON(t, checkParse(t, data, nil), data)
		})
	}
}
