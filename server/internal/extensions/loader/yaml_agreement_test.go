package loader

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
)

type commentCase struct {
	Name, Input string
	Error       error
}

func commentMatrix() []commentCase {
	return []commentCase{
		{"plain-hash", "a: value#tail\n", nil}, {"plain-comment", "a: value #tail\n", nil},
		{"token-hash", "# ! & * %\na: b\n", nil}, {"single-hash", "a: 'x#y' #c\n", nil}, {"double-hash", "a: \"x#y\" #c\n", nil},
		{"tab-separation", "a:\tb\t#c\n", nil}, {"tab-indentation", "a:\n\tb #c\n", yamltokens.ErrSyntax},
		{"tab-quoted", "a: \"x\ty\" #c\n", nil}, {"tab-block", "a: |\n  x\ty\n", nil}, {"tab-comment", "a: b #\ttext\n", nil},
		{"tab-flow", "[\ta,\t#c\n b\t]", nil}, {"leading-bom", "\ufeffa: !x b\n", yamltokens.ErrSyntax},
		{"repeated-bom", "\ufeff\ufeffa: b\n", yamltokens.ErrSyntax}, {"bom-whitespace", " \ufeffvalue #c\n", nil},
		{"bom-after-comment", "#c\n\ufeffvalue\n", nil}, {"bom-interior", "a: x\ufeffy\n", nil}, {"bom-token", "[a, \ufeffb] #c\n", nil},
		{"bang-separated", "a: ! #c\n b\n", yamltokens.ErrTag}, {"bang-attached", "a: !#c\n", yamltokens.ErrTag},
		{"tag-handle", "a: !!str #c\n b\n", yamltokens.ErrTag}, {"tag-verbatim", "a: !<tag:yaml.org,2002:str> #c\n b\n", yamltokens.ErrTag},
		{"tag-escaped", "a: !<tag:yaml.org,2002:%73tr> b #c\n", yamltokens.ErrTag},
		{"anchor-separated", "a: &x #c\n b\n", yamltokens.ErrSyntax}, {"anchor-attached", "a: &x#c\n", yamltokens.ErrSyntax},
		{"alias-separated", "a: *x #c\n", yamltokens.ErrSyntax}, {"alias-attached", "a: *x#c\n", yamltokens.ErrSyntax},
		{"control-text", "a: '! & * % --- ...' #c\n", nil}, {"control-plain", "a: value!&*#end #c\n", nil},
		{"flow-delimiters", "[ #a\n { #b\n x: #c\n y #d\n }, #e\n [] #f\n] #g\n", nil},
		{"empty-flow", "{ #a\n} #end\n", nil}, {"empty-flow-positions", "{a: #c\n, b: #d\n} #end\n", nil},
		{"explicit-eof-comment", "? \n#", nil},
		{"explicit-eof-text", "? \n#tail", nil},
		{"explicit-eof-inline", "? #tail", nil},
		{"explicit-eof-break", "? \n#tail\n", nil},
		{"explicit-eof-empty-lines", "? \n#one\n\n#two", nil},
		{"explicit-key-comment-break", "? a\n#c\n", nil},
		{"explicit-key-no-value", "? key\n#tail", nil},
		{"explicit-empty-value", "? key\n: #tail", nil},
		{"explicit-empty-next-comment", "? key\n:\n#tail", nil},
		{"nested-explicit-eof", "a:\n  ? \n  #tail", nil},
		{"flow-multiline-empty", "[  {00\n0},0: ] ", nil},
		{"flow-multiline-empty-comment", "[  {00\n0},0: #tail\n]", nil},
		{"flow-multiline-map-comment", "[  {00\n0} #map\n,0: ] #tail", nil},
		{"flow-multiline-key-comment", "[ {00\n0 #key\n}, 0: ]", nil},
		{"flow-multiline-value", "[ {key: one\ntwo}, 0: ]", nil},
		{"flow-multiline-two-breaks", "[ {00\n\n0}, 0: ]", nil},
		{"flow-empty-explicit", "[ {00\n0}, ? 0: ]", nil},
		{"explicit-key", "? #key\n a\n: #value\n b\n", nil}, {"explicit-empty", "? #key\n: #value\n", nil},
		{"nested-explicit-dedent", "a:\n  ? key\n  #inner\n#outer", nil},
		{"nested-explicit-comment-gap", "a:\n  ? key\n  #inner\n\n#outer\n", nil},
		{"nested-explicit-following-key", "a:\n  ? key\n  #inner\nb: c #tail", nil},
		{"nested-explicit-inline-boundary", "a:\n  ? key #inline\n  #inner\n#outer", nil},
		{"nested-explicit-three-levels", "a:\n  b:\n    ? key\n    #inner\n  #middle\n#outer", nil},
		{"explicit-comment-second-key", "? first\n#one\n? second\n#two", nil},
		{"explicit-comment-long", "? key\n#" + strings.Repeat("x", 600) + "\n#tail", nil},
		{"literal", "a: | #header\n  #literal\n", nil}, {"folded", "a: > #header\n  #literal\n  x\n", nil},
		{"literal-indent", "a: |2- #header\n  #literal\n", nil}, {"literal-keep", "a: |+2 #header\n  #literal\n\n", nil},
		{"folded-strip", "a: >- #header\n  #literal\n    #indent\n", nil}, {"block-tab-header", "a: |\t#header\n  x\n", nil},
		{"comments-only", "#c\n#tail\n", yamltokens.ErrSyntax}, {"comment-tail", "a: b\n#tail", nil},
		{"markers", "#head\n--- #start\na: b\n... #end\n#tail\n", nil},
		{"extra-start", "a: b\n#c\n--- #extra\n", yamltokens.ErrSyntax}, {"extra-end", "a: b\n... #end\n... #extra\n", yamltokens.ErrSyntax},
		{"after-end", "a: b\n... #end\nx: y #extra\n", yamltokens.ErrSyntax},
		{"quote-eof", "a: 'x #inside\n", yamltokens.ErrSyntax}, {"flow-eof", "[a, #tail\n", yamltokens.ErrSyntax},
		{"escape", "a: \"\\q\" #tail\n", yamltokens.ErrSyntax}, {"missing-delimiter", "[a #c\n b #d\n", yamltokens.ErrSyntax},
		{"indent", "a:\n  b: c\n d: e #c\n", yamltokens.ErrSyntax}, {"suffix", "a: b\n... #c\n[", yamltokens.ErrSyntax},
		{"directive", "%YAML 1.1 #c\n---\na: b\n", yamltokens.ErrSyntax},
		{"tag-before-syntax", "[!x a, \"\\q\"] #c\n", yamltokens.ErrTag},
		{"syntax-before-tag", "[\"\\q\", !x a] #c\n", yamltokens.ErrSyntax},
		{"limit-before-tag", strings.Repeat("[", 65) + "!x a #c\n", yamltokens.ErrLimit},
		{"tag-before-limit", "!x " + strings.Repeat("[", 65) + "a #c\n", yamltokens.ErrTag},
	}
}
func TestCommentElision(t *testing.T) {
	for _, c := range commentMatrix() {
		for _, crlf := range []bool{false, true} {
			name := c.Name
			input := c.Input
			if crlf {
				name += "/CRLF"
				input = strings.ReplaceAll(input, "\n", "\r\n")
			}
			t.Run(name, func(t *testing.T) {
				_, err := referenceAcceptance([]byte(input))
				if err != c.Error {
					t.Fatalf("independent assigned outcome %v, reference %v", c.Error, err)
				}
				assertAgreement(t, []byte(input))
			})
		}
	}
}
func TestBudgetedNodeAgreement(t *testing.T) {
	for _, c := range commentMatrix() {
		assertAgreement(t, []byte(c.Input))
	}
	for _, c := range parserCorpus(true) {
		t.Run(fmt.Sprintf("%s/%d", c.Name, c.Size), func(t *testing.T) { assertAgreement(t, parserPayload(c)) })
	}
	for _, s := range []string{"[null, Null, ~, true, TRUE, false, yes, no, on, off, 0, 01, -1, +1, 0xFF, 0b11, 0o77, 1_0, .inf, -.Inf, .nan, 1e3, 1e999, 1.2, <<]", "[2001-12-14, 2001-12-14T21:59:43Z, 2001-12-14t21:59:43.123+05:00, 2001-12-14 21:59:43, '123', \"\\u0031\"]", "a: b\n...\n!x c", "? [a, #key\n b]\n: c #value\n", "kind: a\n\"k\\u0069nd\": b\n", "[\"" + strings.Repeat("\\L", 350000) + "\", !x a]"} {
		assertAgreement(t, []byte(s))
	}
}
func FuzzParserQualification(f *testing.F) {
	for _, c := range commentMatrix() {
		f.Add([]byte(c.Input))
		f.Add([]byte(strings.ReplaceAll(c.Input, "\n", "\r\n")))
	}
	b, err := os.ReadFile("../../../../schemas/extension/v1alpha1/loader-vectors.json")
	if err != nil {
		f.Fatal(err)
	}
	var vectors struct{ Cases []struct{ YAML string } }
	if err := json.Unmarshal(b, &vectors); err != nil {
		f.Fatal(err)
	}
	for _, c := range vectors.Cases {
		f.Add([]byte(c.YAML))
	}
	for _, c := range parserCorpus(false) {
		f.Add(parserPayload(c))
	}
	f.Fuzz(func(t *testing.T, payload []byte) { assertAgreement(t, payload) })
}

// Exercise queue compaction at different offsets and scalar break lengths.
func TestFlowEmptyValueMarks(t *testing.T) {
	for prefix := 0; prefix <= 40; prefix++ {
		for breaks := 1; breaks <= 3; breaks++ {
			for _, tail := range []string{" ]", " #value\n]", " ] #sequence", " , next]"} {
				input := "[" + strings.Repeat("x,", prefix) + "{00" + strings.Repeat("\n", breaks) + "0},0:" + tail
				t.Run(fmt.Sprintf("prefix%d/breaks%d/tail%q", prefix, breaks, tail), func(t *testing.T) { assertAgreement(t, []byte(input)) })
			}
		}
	}
}

func TestExplicitKeyCommentMark(t *testing.T) {
	payload := []byte("? a\n#c\n")
	want, err := referenceAcceptance(payload)
	if err != nil {
		t.Fatal(err)
	}
	value := want.Content[0].Content[1]
	if value.Tag != "!!null" || value.Value != "" || value.Line != 2 || value.Column != 2 {
		t.Fatalf("oracle implicit null: %#v", value)
	}
	assertAgreement(t, payload)
}
