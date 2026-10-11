// Package ocsf validates decoded emitted events against the fixed foundation profile.
// Acceptance grants no identity, provenance, authorization or ingest guarantee.
package ocsf

import (
	"encoding/json"
	"errors"
	"regexp"
	"sort"
	"strconv"
	"sync"
	"unicode/utf8"
)

type Source uint8

const (
	Agent Source = iota + 1
	Server
)
const (
	MaxDepth        = 32
	MaxNodes        = 16384
	MaxObjectFields = 128
	MaxArrayItems   = 1024
	MaxStringBytes  = 32768
	MaxTotalBytes   = 1048576
)

var (
	ErrSource     = errors.New("ocsf source")
	ErrBudget     = errors.New("ocsf budget")
	ErrDecoded    = errors.New("ocsf decoded value")
	ErrVersion    = errors.New("ocsf version")
	ErrClass      = errors.New("ocsf class")
	ErrShape      = errors.New("ocsf shape")
	ErrConstraint = errors.New("ocsf constraint")
)
var jsonNumber = regexp.MustCompile(`^-?(0|[1-9][0-9]*)(\.[0-9]+)?([eE][+-]?[0-9]+)?$`)
var unsigned = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var signed = regexp.MustCompile(`^(0|-?[1-9][0-9]*)$`)
var decimal = regexp.MustCompile(`^(0|[1-9][0-9]*)(\.[0-9]{1,6})?$`)

type scanItem struct {
	value any
	depth int
	key   bool
}

func preflight(root any) error {
	stack := []scanItem{{value: root}}
	nodes, remaining := 0, MaxTotalBytes
	for len(stack) > 0 {
		item := stack[len(stack)-1]
		stack = stack[:len(stack)-1]
		if item.key {
			if !utf8.ValidString(item.value.(string)) {
				return ErrDecoded
			}
			continue
		}
		nodes++
		if nodes > MaxNodes {
			return ErrBudget
		}
		charge := 0
		switch v := item.value.(type) {
		case map[string]any:
			depth := item.depth + 1
			if depth > MaxDepth || len(v) > MaxObjectFields {
				return ErrBudget
			}
			if v == nil {
				return ErrDecoded
			}
			charge = 2
			for k := range v {
				if len(k) > MaxStringBytes || len(k) > remaining-charge {
					return ErrBudget
				}
				charge += len(k)
			}
			if charge > remaining {
				return ErrBudget
			}
			keys := make([]string, 0, len(v))
			for k := range v {
				keys = append(keys, k)
			}
			sort.Strings(keys)
			for i := len(keys) - 1; i >= 0; i-- {
				k := keys[i]
				stack = append(stack, scanItem{v[k], depth, false}, scanItem{k, depth, true})
			}
		case []any:
			depth := item.depth + 1
			if depth > MaxDepth || len(v) > MaxArrayItems {
				return ErrBudget
			}
			if v == nil {
				return ErrDecoded
			}
			charge = 2
			for i := len(v) - 1; i >= 0; i-- {
				stack = append(stack, scanItem{v[i], depth, false})
			}
		case string:
			charge = len(v)
			if charge > MaxStringBytes || charge > remaining {
				return ErrBudget
			}
			if !utf8.ValidString(v) {
				return ErrDecoded
			}
		case json.Number:
			charge = len(v)
			if charge > 64 || charge > remaining {
				return ErrBudget
			}
			if !jsonNumber.MatchString(string(v)) {
				return ErrDecoded
			}
		case bool, nil:
			charge = 1
		default:
			return ErrDecoded
		}
		if charge > remaining {
			return ErrBudget
		}
		remaining -= charge
	}
	return nil
}

var once sync.Once
var contract map[uint64]*schemaNode
var contractError error

// Validate never mutates event. Callers must not mutate event during validation.
// Callers own strict JSON decoding and authenticated source selection.
func Validate(event any, source Source) error {
	if source != Agent && source != Server {
		return ErrSource
	}
	if err := preflight(event); err != nil {
		return err
	}
	e, ok := event.(map[string]any)
	if !ok {
		return ErrShape
	}
	m, ok := e["metadata"].(map[string]any)
	if !ok {
		return ErrShape
	}
	version, ok := m["version"].(string)
	if !ok {
		return ErrShape
	}
	token, ok := e["class_uid"].(json.Number)
	if !ok {
		return ErrShape
	}
	if version != "1.9.0" {
		return ErrVersion
	}
	if !unsigned.MatchString(string(token)) {
		return ErrShape
	}
	cid, err := strconv.ParseUint(string(token), 10, 64)
	if err != nil {
		return ErrShape
	}
	if cid != 99901001 && cid != 99901002 && cid != 99901003 && cid != 99903001 {
		return ErrClass
	}
	once.Do(func() { contract, contractError = loadSchemas(schemas) })
	if contractError != nil {
		return contractError
	}
	s := contract[cid]
	if !s.matches(event, source) {
		return ErrShape
	}
	for _, rule := range s.rules {
		if !semantic(rule, e, source) {
			return ErrConstraint
		}
	}
	return nil
}
