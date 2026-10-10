package celdecl

const MaxBytes = 262144

// Document holds a private validated catalogue.
type Document struct{ catalogue *Catalogue }

type Catalogue struct {
	FormatVersion      int                            `json:"format_version"`
	Profile            Profile                        `json:"profile"`
	DeclarationVersion int                            `json:"declaration_version"`
	OCSFVersion        string                         `json:"ocsf_version"`
	Objects            map[string]Object              `json:"objects"`
	Variables          map[string]Entry               `json:"variables"`
	Domains            map[string]map[string][]string `json:"domains"`
}
type Profile struct {
	ID      string `json:"id"`
	Version int    `json:"version"`
}
type Object struct {
	Doc    string           `json:"doc"`
	Fields map[string]Entry `json:"fields"`
}
type Entry struct {
	Type     Type     `json:"type"`
	Presence string   `json:"presence"`
	Doc      string   `json:"doc"`
	Values   []string `json:"values,omitempty"`
}
type Type struct {
	Kind       string `json:"kind"`
	Name       string `json:"name,omitempty"`
	Key        string `json:"key,omitempty"`
	Element    *Type  `json:"element,omitempty"`
	Value      *Type  `json:"value,omitempty"`
	MaxLength  int    `json:"max_length,omitempty"`
	MaxItems   int    `json:"max_items,omitempty"`
	MaxEntries int    `json:"max_entries,omitempty"`
}
type Variable struct {
	Name  string
	Entry Entry
}
