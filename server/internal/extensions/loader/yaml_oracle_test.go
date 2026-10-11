package loader

import (
	"bytes"
	"fmt"
	"io"
	"reflect"
	"testing"
	"unicode/utf8"

	"github.com/ricevanta/ricevanta/server/internal/extensions/loader/internal/yamltokens"
	"go.yaml.in/yaml/v3"
)

// referenceAcceptance uses pinned, comment-preserving scanner/events with
// separate profile checks. It never calls candidate code to classify input.
// The reference source and these rules require independent Gate A review.
func referenceAcceptance(payload []byte) (*yaml.Node, error) {
	if len(payload) > 1048576 {
		return nil, yamltokens.ErrLimit
	}
	if !utf8.Valid(payload) || bytes.HasPrefix(payload, []byte{239, 187, 191}) {
		return nil, yamltokens.ErrSyntax
	}
	var p yaml_parser_t
	yaml_parser_initialize(&p)
	defer yaml_parser_delete(&p)
	yaml_parser_set_input_string(&p, payload)
	documents, count, nesting := 0, 0, 0
	meaningful := false
	for {
		var event yaml_event_t
		ok := yaml_parser_parse(&p, &event)
		if p.referenceError != nil {
			return nil, p.referenceError
		}
		if !ok || p.error != yaml_NO_ERROR {
			return nil, yamltokens.ErrSyntax
		}
		switch event.typ {
		case yaml_DOCUMENT_START_EVENT:
			documents++
			if documents > 1 {
				return nil, yamltokens.ErrSyntax
			}
		case yaml_SCALAR_EVENT:
			count++
			meaningful = meaningful || len(event.value) != 0 || event.scalar_style() != yaml_PLAIN_SCALAR_STYLE
		case yaml_SEQUENCE_START_EVENT, yaml_MAPPING_START_EVENT:
			count++
			nesting++
			meaningful = true
		case yaml_SEQUENCE_END_EVENT, yaml_MAPPING_END_EVENT:
			nesting--
		case yaml_STREAM_END_EVENT:
			if documents != 1 || !meaningful || nesting != 0 {
				return nil, yamltokens.ErrSyntax
			}
			decoder := yaml.NewDecoder(bytes.NewReader(payload))
			var node, extra yaml.Node
			if decoder.Decode(&node) != nil || decoder.Decode(&extra) != io.EOF {
				return nil, yamltokens.ErrSyntax
			}
			return &node, nil
		case yaml_NO_EVENT:
			return nil, yamltokens.ErrSyntax
		}
		if count > 65536 || nesting > 16 {
			return nil, yamltokens.ErrLimit
		}
	}
}
func eraseComments(n *yaml.Node) {
	n.HeadComment = ""
	n.LineComment = ""
	n.FootComment = ""
	for _, c := range n.Content {
		eraseComments(c)
	}
}
func assertAgreement(t *testing.T, payload []byte) {
	t.Helper()
	want, wantErr := referenceAcceptance(payload)
	checkErr := yamltokens.Check(payload)
	got, b, err := yamltokens.Decode(payload)
	assertAgreementResults(t, want, wantErr, checkErr, got, b, err)
}

// Separate outcomes allow negative controls to exercise the agreement assertion.
func assertAgreementResults(t *testing.T, want *yaml.Node, wantErr, checkErr error, got *yaml.Node, b *yamltokens.Budget, err error) {
	t.Helper()
	if checkErr != wantErr || err != wantErr {
		t.Fatalf("acceptance/error disagreement: check=%v decode=%v reference=%v", checkErr, err, wantErr)
	}
	if wantErr != nil {
		if got != nil || b != nil {
			t.Fatal("partial result")
		}
		return
	}
	eraseComments(want)
	if !reflect.DeepEqual(got, want) {
		dumpNodeDifferences(t, "root", got, want)
		t.Fatal("Node kind/tag/value/style/marks/order disagreement")
	}
	gn, gd := nodeCounts(got)
	wn, wd := nodeCounts(want)
	if gn != wn || gd != wd {
		t.Fatal("Node count/depth disagreement")
	}
}

func referenceScalarAppend(p *yaml_parser_t, s []byte, values ...byte) []byte {
	if p.referenceError != nil {
		return s
	}
	if p.referenceText+len(s)+len(values) > 1048576 {
		p.referenceError = yamltokens.ErrLimit
		return s
	}
	return append(s, values...)
}
func referenceScalarRead(p *yaml_parser_t, s []byte) []byte {
	n := width(p.buffer[p.buffer_pos])
	if p.referenceText+len(s)+n > 1048576 {
		p.referenceError = yamltokens.ErrLimit
		skip(p)
		return s
	}
	return read(p, s)
}
func referenceScalarLine(p *yaml_parser_t, s []byte) []byte {
	n := 1
	if is_break(p.buffer, p.buffer_pos) && p.buffer[p.buffer_pos] == 0xe2 {
		n = 3
	}
	if p.referenceText+len(s)+n > 1048576 {
		p.referenceError = yamltokens.ErrLimit
		skip_line(p)
		return s
	}
	return read_line(p, s)
}

// dumpNodeDifferences reports all unequal fields without weakening tree equality.
func dumpNodeDifferences(t *testing.T, path string, got, want *yaml.Node) {
	t.Helper()
	if got == nil || want == nil {
		t.Logf("%s: candidate=%v oracle=%v", path, got, want)
		return
	}
	gv, wv := reflect.ValueOf(*got), reflect.ValueOf(*want)
	for i := 0; i < gv.NumField(); i++ {
		name := gv.Type().Field(i).Name
		if name == "Content" {
			continue
		}
		if !reflect.DeepEqual(gv.Field(i).Interface(), wv.Field(i).Interface()) {
			t.Logf("%s.%s: candidate=%#v oracle=%#v", path, name, gv.Field(i).Interface(), wv.Field(i).Interface())
		}
	}
	if len(got.Content) != len(want.Content) {
		t.Logf("%s.Content length: candidate=%d oracle=%d", path, len(got.Content), len(want.Content))
	}
	for i := 0; i < min(len(got.Content), len(want.Content)); i++ {
		dumpNodeDifferences(t, fmt.Sprintf("%s.Content[%d]", path, i), got.Content[i], want.Content[i])
	}
}
