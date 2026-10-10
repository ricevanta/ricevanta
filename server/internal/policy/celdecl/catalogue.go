package celdecl

import (
	_ "embed"
	"reflect"
)

//go:embed variables.json
var embeddedCatalogue []byte

var trustedCatalogue, trustedError = readTrustedCatalogue()

func readTrustedCatalogue() (Catalogue, error) {
	root, err := parseShape(embeddedCatalogue)
	if err != nil {
		return Catalogue{}, err
	}
	return validateCatalogue(root)
}

// Snapshot returns a detached recursive copy of the validated catalogue.
func (d *Document) Snapshot() Catalogue {
	if d == nil || d.catalogue == nil {
		return Catalogue{}
	}
	c := *d.catalogue
	c.Objects = make(map[string]Object, len(d.catalogue.Objects))
	for name, o := range d.catalogue.Objects {
		copy := Object{Doc: o.Doc, Fields: make(map[string]Entry, len(o.Fields))}
		for field, e := range o.Fields {
			copy.Fields[field] = copyEntry(e)
		}
		c.Objects[name] = copy
	}
	c.Variables = make(map[string]Entry, len(d.catalogue.Variables))
	for name, e := range d.catalogue.Variables {
		c.Variables[name] = copyEntry(e)
	}
	c.Domains = make(map[string]map[string][]string, len(d.catalogue.Domains))
	for domain, contexts := range d.catalogue.Domains {
		c.Domains[domain] = make(map[string][]string, len(contexts))
		for context, names := range contexts {
			c.Domains[domain][context] = append([]string(nil), names...)
		}
	}
	return c
}

// Environment returns detached entries for an exact domain and context.
func (d *Document) Environment(domain, context string) ([]Variable, error) {
	if d == nil || d.catalogue == nil {
		return nil, ErrDocument
	}
	names, ok := d.catalogue.Domains[domain][context]
	if !ok {
		return nil, ErrDomain
	}
	out := make([]Variable, len(names))
	for i, name := range names {
		out[i] = Variable{Name: name, Entry: copyEntry(d.catalogue.Variables[name])}
	}
	return out, nil
}
func copyEntry(e Entry) Entry {
	e.Type = copyType(e.Type)
	if e.Values != nil {
		e.Values = append([]string(nil), e.Values...)
	}
	return e
}
func copyType(t Type) Type {
	if t.Element != nil {
		e := copyType(*t.Element)
		t.Element = &e
	}
	if t.Value != nil {
		v := copyType(*t.Value)
		t.Value = &v
	}
	return t
}
func matchesTrusted(c Catalogue) bool {
	return trustedError == nil && reflect.DeepEqual(c, trustedCatalogue)
}
