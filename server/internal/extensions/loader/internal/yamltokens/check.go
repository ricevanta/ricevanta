// Package yamltokens checks the signed YAML stream without building a tree.
package yamltokens

import (
	"bytes"
	"errors"
	"go.yaml.in/yaml/v3"
	"unicode/utf8"
)

var (
	ErrSyntax = errors.New("YAML syntax")
	ErrLimit  = errors.New("YAML limit")
	ErrTag    = errors.New("YAML tag")
)

const (
	maxBytes  = 1 << 20
	maxTokens = 262208
	maxStack  = 64
	maxNodes  = 65536
	maxDepth  = 16
)

// Check requires caller authentication before use in a production pipeline.
func Check(payload []byte) error { _, _, err := prepare(payload, newBudget()); return err }

type statistics struct {
	arities []uint32
	nodes   []yaml.Node
	content []*yaml.Node
}

func prepare(payload []byte, b *Budget) (*statistics, *Budget, error) {
	if err := b.begin(); err != nil {
		return nil, nil, err
	}
	if len(payload) > maxBytes {
		return nil, nil, ErrLimit
	}
	if !utf8.Valid(payload) || bytes.HasPrefix(payload, []byte("\xef\xbb\xbf")) {
		return nil, nil, ErrSyntax
	}

	var p yaml_parser_t
	p.budget = b
	if !yaml_parser_initialize(&p) {
		return nil, nil, p.guardErr
	}
	defer yaml_parser_delete(&p)
	yaml_parser_set_input_string(&p, payload)
	if err := b.allocation("arity", maxNodes*4, 1); err != nil {
		return nil, nil, err
	}
	arities := make([]uint32, maxNodes)
	var parents [maxDepth]int
	docs, nodes, depth := 0, 0, 0
	nonempty := false
	for {
		var e yaml_event_t
		ok := yaml_parser_parse(&p, &e)
		if p.guardErr != nil {
			return nil, nil, p.guardErr
		}
		if !ok || p.error != yaml_NO_ERROR {
			return nil, nil, ErrSyntax
		}
		switch e.typ {
		case yaml_DOCUMENT_START_EVENT:
			docs++
			if docs > 1 {
				return nil, nil, ErrSyntax
			}
		case yaml_MAPPING_START_EVENT, yaml_SEQUENCE_START_EVENT, yaml_SCALAR_EVENT:
			if nodes == maxNodes {
				return nil, nil, ErrLimit
			}
			if depth > 0 {
				arities[parents[depth-1]]++
			}
			index := nodes
			nodes++
			if e.typ != yaml_SCALAR_EVENT {
				if depth == maxDepth {
					return nil, nil, ErrLimit
				}
				parents[depth] = index
				depth++
				nonempty = true
			} else if len(e.value) > 0 || e.style != yaml_style_t(yaml_PLAIN_SCALAR_STYLE) {
				nonempty = true
			}
		case yaml_MAPPING_END_EVENT, yaml_SEQUENCE_END_EVENT:
			if depth == 0 {
				return nil, nil, ErrSyntax
			}
			depth--
		case yaml_STREAM_END_EVENT:
			if docs != 1 || !nonempty || depth != 0 {
				return nil, nil, ErrSyntax
			}
			if err := b.allocation("statistics", 128, 1); err != nil {
				return nil, nil, err
			}
			return &statistics{arities: arities[:nodes:nodes]}, b, nil
		case yaml_NO_EVENT:
			return nil, nil, ErrSyntax
		}
	}
}
