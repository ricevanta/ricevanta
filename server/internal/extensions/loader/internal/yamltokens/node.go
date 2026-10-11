//
// Copyright (c) 2011-2019 Canonical Ltd
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package yamltokens

import (
	"go.yaml.in/yaml/v3"
	"unsafe"
)

// Decode preflights unchanged authenticated bytes before one arena construction.
// A failed call returns neither a partial tree nor a ledger.
func Decode(payload []byte) (*yaml.Node, *Budget, error) { return decodeBudget(payload, newBudget()) }
func decodeBudget(payload []byte, b *Budget) (*yaml.Node, *Budget, error) {
	s, _, err := prepare(payload, b)
	if err != nil {
		return nil, nil, err
	}
	n, err := construct(payload, s, b)
	if err != nil {
		return nil, nil, err
	}
	return n, b, nil
}

type nodeBuilder struct {
	parser     yaml_parser_t
	stats      *statistics
	next, edge int
}

func (p *nodeBuilder) event() (yaml_event_t, error) {
	var e yaml_event_t
	ok := yaml_parser_parse(&p.parser, &e)
	if p.parser.guardErr != nil {
		return e, p.parser.guardErr
	}
	if !ok || p.parser.error != yaml_NO_ERROR {
		return e, ErrSyntax
	}
	return e, nil
}
func construct(payload []byte, s *statistics, b *Budget) (*yaml.Node, error) {
	if err := b.begin(); err != nil {
		return nil, err
	}
	n := len(s.arities)
	if n == 0 || n > maxNodes {
		return nil, ErrLimit
	}
	if err := b.allocation("nodes", uint64(n+1)*uint64(unsafe.Sizeof(yaml.Node{})), 1); err != nil {
		return nil, err
	}
	s.nodes = make([]yaml.Node, n+1)
	if err := b.allocation("content", uint64(n)*uint64(unsafe.Sizeof((*yaml.Node)(nil))), 1); err != nil {
		return nil, err
	}
	s.content = make([]*yaml.Node, n)
	p := nodeBuilder{stats: s, next: 1, edge: 1}
	p.parser.budget = b
	if !yaml_parser_initialize(&p.parser) {
		return nil, p.parser.guardErr
	}
	defer yaml_parser_delete(&p.parser)
	yaml_parser_set_input_string(&p.parser, payload)
	e, err := p.event()
	if err != nil {
		return nil, err
	}
	if e.typ != yaml_STREAM_START_EVENT {
		return nil, ErrSyntax
	}
	e, err = p.event()
	if err != nil {
		return nil, err
	}
	if e.typ != yaml_DOCUMENT_START_EVENT {
		return nil, ErrSyntax
	}
	root := &s.nodes[0]
	*root = yaml.Node{Kind: yaml.DocumentNode, Line: e.start_mark.line + 1, Column: e.start_mark.column + 1, Content: s.content[:1:1]}
	e, err = p.event()
	if err != nil {
		return nil, err
	}
	child, err := p.child(e, 0)
	if err != nil {
		return nil, err
	}
	root.Content[0] = child
	e, err = p.event()
	if err != nil {
		return nil, err
	}
	if e.typ != yaml_DOCUMENT_END_EVENT {
		return nil, ErrSyntax
	}
	e, err = p.event()
	if err != nil {
		return nil, err
	}
	if e.typ != yaml_STREAM_END_EVENT || p.next != n+1 || p.edge != n {
		return nil, ErrSyntax
	}
	return root, nil
}
func (p *nodeBuilder) child(e yaml_event_t, depth int) (*yaml.Node, error) {
	if p.next >= len(p.stats.nodes) {
		return nil, ErrLimit
	}
	index := p.next
	p.next++
	n := &p.stats.nodes[index]
	n.Line = e.start_mark.line + 1
	n.Column = e.start_mark.column + 1
	arity := int(p.stats.arities[index-1])
	end := yaml_NO_EVENT
	switch e.typ {
	case yaml_SCALAR_EVENT:
		if arity != 0 {
			return nil, ErrSyntax
		}
		if err := p.parser.budget.allocation("string", uint64(len(e.value)), 1); err != nil {
			return nil, err
		}
		n.Kind = yaml.ScalarNode
		n.Value = string(e.value)
		switch e.scalar_style() {
		case yaml_DOUBLE_QUOTED_SCALAR_STYLE:
			n.Style = yaml.DoubleQuotedStyle
		case yaml_SINGLE_QUOTED_SCALAR_STYLE:
			n.Style = yaml.SingleQuotedStyle
		case yaml_LITERAL_SCALAR_STYLE:
			n.Style = yaml.LiteralStyle
		case yaml_FOLDED_SCALAR_STYLE:
			n.Style = yaml.FoldedStyle
		}
		if n.Style != 0 {
			n.Tag = strTag
		} else if n.Value == "<<" {
			n.Tag = mergeTag
		} else {
			var err error
			n.Tag, err = resolveImplicit(n.Value, p.parser.budget)
			if err != nil {
				return nil, err
			}
		}
		return n, nil
	case yaml_MAPPING_START_EVENT:
		n.Kind = yaml.MappingNode
		n.Tag = mapTag
		end = yaml_MAPPING_END_EVENT
		if e.mapping_style() == yaml_FLOW_MAPPING_STYLE {
			n.Style = yaml.FlowStyle
		}
		if arity%2 != 0 {
			return nil, ErrSyntax
		}
	case yaml_SEQUENCE_START_EVENT:
		n.Kind = yaml.SequenceNode
		n.Tag = seqTag
		end = yaml_SEQUENCE_END_EVENT
		if e.sequence_style() == yaml_FLOW_SEQUENCE_STYLE {
			n.Style = yaml.FlowStyle
		}
	default:
		return nil, ErrSyntax
	}
	if depth == maxDepth {
		return nil, ErrLimit
	}
	if arity > len(p.stats.content)-p.edge {
		return nil, ErrLimit
	}
	if arity > 0 {
		n.Content = p.stats.content[p.edge : p.edge+arity : p.edge+arity]
	}
	p.edge += arity
	for i := 0; i < arity; i++ {
		event, err := p.event()
		if err != nil {
			return nil, err
		}
		c, err := p.child(event, depth+1)
		if err != nil {
			return nil, err
		}
		n.Content[i] = c
	}
	event, err := p.event()
	if err != nil {
		return nil, err
	}
	if event.typ != end {
		return nil, ErrSyntax
	}
	return n, nil
}
