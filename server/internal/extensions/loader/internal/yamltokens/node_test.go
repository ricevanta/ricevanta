package yamltokens

import (
	"bytes"
	"errors"
	"math"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func TestBudgetedNodeAgreement(t *testing.T) {
	for _, s := range []string{"a: [0, {}, null, true, 0b11, 0o77, 1.2, .inf, 2001-12-14]\n", "? a\n: b\n", "a: |+\n  #literal\n\n", "{a: 'x', b: \"\\L\", c: >-\n    text\n}", strings.Repeat("- {} #c\n", 65535)} {
		var want yaml.Node
		oracleErr := yaml.NewDecoder(bytes.NewReader([]byte(s))).Decode(&want)
		got, budget, err := Decode([]byte(s))
		if oracleErr != nil {
			if err != ErrSyntax || got != nil || budget != nil {
				t.Fatal("syntax agreement")
			}
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		clearComments(&want)
		if !reflect.DeepEqual(got, &want) {
			t.Fatal("complete tree disagreement")
		}
	}
}
func clearComments(n *yaml.Node) {
	n.HeadComment = ""
	n.LineComment = ""
	n.FootComment = ""
	for _, c := range n.Content {
		clearComments(c)
	}
}

func TestParserAllocationGuards(t *testing.T) {
	b := &Budget{}
	if b.Reserve(math.MaxUint64, 1) != ErrLimit || b.bytes != 0 || b.objects != 0 {
		t.Fatal("overflow charged")
	}
	if b.Reserve(1, math.MaxUint64) != ErrLimit || b.bytes != 0 {
		t.Fatal("object overflow charged")
	}
	if b.Reserve(64<<20, 1000000) != nil || b.Reserve(1, 0) != ErrLimit {
		t.Fatal("inclusive ceiling")
	}
	for _, family := range []string{"entry", "reader", "scratch", "tokens", "arity", "nodes", "content", "string", "resolver", "stack"} {
		for _, object := range []bool{false, true} {
			t.Run(family+map[bool]string{false: "/bytes", true: "/objects"}[object], func(t *testing.T) {
				b := &Budget{failFamily: family, failObjects: object}
				node, ledger, err := decodeBudget([]byte("{a: [2001-12-14, 123_bad, 0]}"), b)
				if !errors.Is(err, ErrLimit) || node != nil || ledger != nil || !b.injected {
					t.Fatalf("family %s: %v", family, err)
				}
			})
		}
	}
	s, b, err := prepare([]byte("[a,b,c]"), newBudget())
	if err != nil {
		t.Fatal(err)
	}
	before := b.bytes
	node, err := construct([]byte("[a,b,c]"), s, b)
	if err != nil || b.bytes <= before || len(node.Content) != 1 {
		t.Fatal("ledger refunded")
	}
	if len(s.arities) != 4 || cap(s.arities) != 4 {
		t.Fatal("arity size")
	}
	if len(s.nodes) != 5 || cap(s.nodes) != 5 || len(s.content) != 4 || cap(s.content) != 4 {
		t.Fatal("arena sizes")
	}
}

func TestCommentElision(t *testing.T) {
	for _, s := range []string{"a: value#tail\n", "a: value #tail\n", "a: 'quoted#text' #tail\n", "a: \"quoted#text\"\n", "a: |\n  #literal\n", "[ #head\n a, #line\n {} #foot\n] #end\n"} {
		for _, input := range []string{s, strings.ReplaceAll(s, "\n", "\r\n")} {
			var want yaml.Node
			if err := yaml.NewDecoder(strings.NewReader(input)).Decode(&want); err != nil {
				t.Fatal(err)
			}
			got, _, err := Decode([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			clearComments(&want)
			if !reflect.DeepEqual(got, &want) {
				t.Fatalf("comment context %q", input)
			}
		}
	}
}

func TestParserAllocationSites(t *testing.T) {
	payloads := []string{"[.bad, 1e999, 0b+1, 1_0]", "{a: [2001-12-14, 123_bad, 0]}", "a: >+\n  x\n\n  y\n", "a: 'multi\n  line'\n", "a: \"\\uFFFF \"\n"}
	for _, payload := range payloads {
		for _, family := range []string{"entry", "reader", "scratch", "tokens", "arity", "nodes", "content", "string", "resolver", "stack", "statistics"} {
			probe := &Budget{failFamily: family, failAt: -1}
			if _, _, err := decodeBudget([]byte(payload), probe); err != nil {
				t.Fatal(err)
			}
			for ordinal := 1; ordinal <= probe.hits; ordinal++ {
				for _, objects := range []bool{false, true} {
					b := &Budget{failFamily: family, failAt: ordinal, failObjects: objects}
					n, ledger, err := decodeBudget([]byte(payload), b)
					if err != ErrLimit || n != nil || ledger != nil || !b.injected {
						t.Fatalf("%s allocation %d: %v", family, ordinal, err)
					}
				}
			}
		}
	}
}
func TestBudgetedNodeResolver(t *testing.T) {
	forms := []string{"2001-12-14   1:2:3", "2000-2-29", "1900-2-29", "2001-12-14T1:2:3Z", "2001-12-14t1:2:3Z", "2001-12-14 1:2:3", "2001-12-14T21:59:43+24:60", "2001-12-14T21:59:43,1Z", "2001-12-14T21:59:43.123456789123Z", "2001-12-14T21:59:43.0+01:00"}
	for _, date := range []string{"0000-1-1", "9999-12-31", "2024-02-29", "2023-02-29", "2000-00-01", "2000-1-00", "2000-13-01", "2000-4-31"} {
		for _, suffix := range []string{"", "T01:02:03Z", "t1:2:3Z", " 1:2:3", "T24:0:0Z", "T1:60:0Z", "T1:2:60Z", "T1:2:3+25:00", "T1:2:3+01:61", "T1:2:3.1Z", "T1:2:3,1Z", "T1:2:3.\tZ", "T1:2:3"} {
			forms = append(forms, date+suffix)
		}
	}
	for _, s := range forms {
		var want yaml.Node
		if err := yaml.NewDecoder(strings.NewReader(s)).Decode(&want); err != nil {
			t.Fatal(err)
		}
		got, _, err := Decode([]byte(s))
		if err != nil {
			t.Fatal(err)
		}
		clearComments(&want)
		if !reflect.DeepEqual(got, &want) {
			t.Fatalf("resolver %q: got %s want %s", s, got.Content[0].Tag, want.Content[0].Tag)
		}
	}
}

func TestBudgetedNodeImplicitCapacity(t *testing.T) {
	for _, scalar := range []string{"0b2", "0o9", "-0b2", "1e999", ".bad", "0b+1", "0b-1", "+18446744073709551615", "18446744073709551615"} {
		t.Run(scalar, func(t *testing.T) {
			count := min(65535, (maxBytes-1)/(len(scalar)+1))
			input := []byte("[" + strings.Repeat(scalar+",", count-1) + scalar + "]")
			got, _, err := Decode(input)
			if err != nil {
				t.Fatal(err)
			}
			var oracle yaml.Node
			if err := yaml.NewDecoder(strings.NewReader(scalar)).Decode(&oracle); err != nil {
				t.Fatal(err)
			}
			if len(got.Content[0].Content) != count {
				t.Fatal("capacity")
			}
			for _, n := range got.Content[0].Content {
				if n.Tag != oracle.Content[0].Tag {
					t.Fatal("resolver capacity agreement")
				}
			}
		})
	}
}

func TestBudgetedNodeResolverDifferential(t *testing.T) {
	fixed := []string{"0b+1", "0b-1", "-0b+1", "-0b-1", "0o+7", "0o-7", "-0o7", "0Xff", "-0Xff", "0O77", "0B11", "0b", "0o", "0x", "+9223372036854775807", "+9223372036854775808", "-9223372036854775808", "-9223372036854775809", "18446744073709551615", "18446744073709551616", "01", "08", "1_0", "1__0", "_1", "+_1", "1.0", "1e2", "1e999", ".5", ".NaN", "-.inf", "2001-12-14   1:2:3"}
	state := uint64(0x6d7a5b)
	alphabet := "0123456789abcdefxobXOBeE+-. _TZ:"
	for i := 0; i < 2048; i++ {
		var b strings.Builder
		for j := 0; j < 1+i%28; j++ {
			state ^= state << 13
			state ^= state >> 7
			state ^= state << 17
			b.WriteByte(alphabet[int(state%uint64(len(alphabet)))])
		}
		fixed = append(fixed, b.String())
	}
	for _, s := range fixed {
		oracle := yaml.Node{Kind: yaml.ScalarNode, Value: s}
		want := oracle.ShortTag()
		got, err := resolveImplicit(s, newBudget())
		if err != nil || got != want {
			t.Fatalf("resolver %q: got %s/%v want %s", s, got, err, want)
		}
	}
}
func TestParserAllocationBeforeGrowth(t *testing.T) {
	for _, family := range []string{"scratch", "tokens", "stack"} {
		p := yaml_parser_t{budget: &Budget{failFamily: family}}
		switch family {
		case "scratch":
			s := appendBytes(&p, nil, 'x')
			if len(s) != 0 || cap(s) != 0 {
				t.Fatal("scratch grew")
			}
		case "tokens":
			s := boundedAppend(&p, family, []yaml_token_t(nil), yaml_token_t{}, 16)
			if len(s) != 0 || cap(s) != 0 {
				t.Fatal("tokens grew")
			}
		case "stack":
			s := boundedAppend(&p, family, []int(nil), 1, 16)
			if len(s) != 0 || cap(s) != 0 {
				t.Fatal("stack grew")
			}
		}
		if p.guardErr != ErrLimit {
			t.Fatal("growth exhaustion")
		}
	}
}
