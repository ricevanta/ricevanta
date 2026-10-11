package yamltokens

import (
	"errors"
	"go.yaml.in/yaml/v3"
	"strings"
	"testing"
	"unsafe"
)

func scanOnly(payload string) error {
	var p yaml_parser_t
	yaml_parser_initialize(&p)
	defer yaml_parser_delete(&p)
	yaml_parser_set_input_string(&p, []byte(payload))
	for {
		var tok yaml_token_t
		ok := yaml_parser_scan(&p, &tok)
		if p.guardErr != nil {
			return p.guardErr
		}
		if !ok || p.error != yaml_NO_ERROR {
			return ErrSyntax
		}
		if tok.typ == yaml_STREAM_END_TOKEN {
			return nil
		}
	}
}

func TestScannerGrowthBounds(t *testing.T) {
	for name, s := range map[string]string{
		"flow": strings.Repeat("[", 65) + strings.Repeat("]", 65),
		"indent": func() string {
			var b strings.Builder
			for i := 0; i < 65; i++ {
				b.WriteString(strings.Repeat(" ", i) + "a:\n")
			}
			return b.String()
		}(),
		"tokens":    "[" + strings.Repeat("0,", 131104) + "0]",
		"scalar":    "\"" + strings.Repeat("\\L", 350000) + "\"",
		"aggregate": "[\"" + strings.Repeat("\\L", 175000) + "\",\"" + strings.Repeat("\\L", 175000) + "\"]",
	} {
		t.Run(name, func(t *testing.T) {
			if err := scanOnly(s); !errors.Is(err, ErrLimit) {
				t.Fatalf("got %v, want limit", err)
			}
		})
	}
}

func TestAggregateBeforeGrowth(t *testing.T) {
	p := yaml_parser_t{tokenBytes: maxBytes - 1}
	value := appendValue(&p, nil, 'a')
	if p.guardErr != nil || len(value) != 1 {
		t.Fatal("inclusive scalar budget")
	}
	value = appendValue(&p, value, 'b')
	if !errors.Is(p.guardErr, ErrLimit) || len(value) != 1 {
		t.Fatal("aggregate grew past limit")
	}
}

func TestParserStackGuards(t *testing.T) {
	for _, name := range []string{"states", "marks"} {
		t.Run(name, func(t *testing.T) {
			var p yaml_parser_t
			yaml_parser_initialize(&p)
			defer yaml_parser_delete(&p)
			yaml_parser_set_input_string(&p, []byte("[0]"))
			var tok yaml_token_t
			if !yaml_parser_scan(&p, &tok) {
				t.Fatal("stream start")
			}
			var e yaml_event_t
			if name == "states" {
				p.states = make([]yaml_parser_state_t, maxStack)
				yaml_parser_parse_document_start(&p, &e, true)
				if len(p.states) != maxStack {
					t.Fatal("states grew before rejection")
				}
			} else {
				p.marks = make([]yaml_mark_t, maxStack)
				yaml_parser_parse_flow_sequence_entry(&p, &e, true)
				if len(p.marks) != maxStack {
					t.Fatal("marks grew before rejection")
				}
			}
			if !errors.Is(p.guardErr, ErrLimit) {
				t.Fatalf("got %v", p.guardErr)
			}
		})
	}
}

func TestParserLayouts(t *testing.T) {
	t.Logf("token=%d comment=%d simple-key=%d mark=%d state=%d node=%d", unsafe.Sizeof(yaml_token_t{}), unsafe.Sizeof(yaml_comment_t{}), unsafe.Sizeof(yaml_simple_key_t{}), unsafe.Sizeof(yaml_mark_t{}), unsafe.Sizeof(yaml_parser_state_t(0)), unsafe.Sizeof(yaml.Node{}))
	t.Logf("parser=%d builder=%d budget=%d statistics=%d event=%d", unsafe.Sizeof(yaml_parser_t{}), unsafe.Sizeof(nodeBuilder{}), unsafe.Sizeof(Budget{}), unsafe.Sizeof(statistics{}), unsafe.Sizeof(yaml_event_t{}))
}
