package wire

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

type descriptorFixture struct {
	Class   string `json:"class"`
	Epoch   string `json:"epoch"`
	Segment string `json:"segment"`
	First   string `json:"first"`
	Last    string `json:"last"`
	Count   string `json:"count"`
}

type fixture struct {
	Name         string             `json:"name"`
	Values       []string           `json:"header_values"`
	Error        *string            `json:"expected_error"`
	Descriptor   *descriptorFixture `json:"expected_descriptor"`
	FrameHex     string             `json:"frame_hex"`
	Consumed     int                `json:"consumed_bytes"`
	Construction json.RawMessage    `json:"construction"`
}

func loadFixtures(t testing.TB, kind string) []fixture {
	t.Helper()
	data, err := os.ReadFile("../../../../schemas/events/v1/fixtures/" + kind + ".json")
	if err != nil {
		t.Fatal(err)
	}
	var container struct {
		Kind  string    `json:"kind"`
		Cases []fixture `json:"cases"`
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&container); err != nil {
		t.Fatal(err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		t.Fatalf("fixture must contain exactly one JSON value: %v", err)
	}
	if container.Kind != kind || len(container.Cases) == 0 {
		t.Fatal("invalid fixture container")
	}
	var fields struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool)
	for i, c := range container.Cases {
		required := []string{"name", "header_values", "expected_error"}
		if kind == "descriptor" {
			required = append(required, "construction", "frame_hex", "consumed_bytes")
		}
		for _, key := range required {
			raw, ok := fields.Cases[i][key]
			if !ok || (key != "expected_error" && string(raw) == "null") {
				t.Fatalf("fixture %d missing required %s", i, key)
			}
		}

		if c.Name == "" || names[c.Name] {
			t.Fatal("missing or duplicate fixture name")
		}
		names[c.Name] = true
		fixtureError(t, c.Error)
		if (c.Error == nil) != (c.Descriptor != nil) {
			t.Fatal("invalid fixture expectation")
		}
		if c.Descriptor != nil {
			fixtureDescriptor(t, c.Descriptor)
		}
	}
	return container.Cases
}

func fixtureError(t testing.TB, name *string) error {
	t.Helper()
	if name == nil {
		return nil
	}
	sentinels := map[string]error{
		"wire.ErrReaderBound": ErrReaderBound, "wire.ErrFrameRead": ErrFrameRead,
		"wire.ErrFrameMagic": ErrFrameMagic, "wire.ErrFrameSize": ErrFrameSize,
		"wire.ErrFrameReserved": ErrFrameReserved, "wire.ErrDescriptorMismatch": ErrDescriptorMismatch,
		"wire.ErrHeaderCount": ErrHeaderCount, "wire.ErrHeaderSize": ErrHeaderSize,
		"wire.ErrHeaderSyntax": ErrHeaderSyntax, "wire.ErrVersion": ErrVersion,
		"batch.ErrClass": batch.ErrClass, "batch.ErrStreamEpoch": batch.ErrStreamEpoch,
		"batch.ErrRecordCount": batch.ErrRecordCount, "batch.ErrSequenceRange": batch.ErrSequenceRange,
		"batch.ErrSequenceCount": batch.ErrSequenceCount,
	}
	err, ok := sentinels[*name]
	if !ok {
		t.Fatalf("unknown fixture sentinel %q", *name)
	}
	return err
}

func fixtureDescriptor(t testing.TB, f *descriptorFixture) batch.Descriptor {
	t.Helper()
	if f == nil {
		return batch.Descriptor{}
	}
	var class batch.SpoolClass
	for c := batch.ClassRaw; c <= batch.ClassAudit; c++ {
		if c.String() == f.Class {
			class = c
		}
	}
	parse := func(s string, bits int) uint64 {
		n, err := strconv.ParseUint(s, 10, bits)
		if err != nil || strconv.FormatUint(n, 10) != s {
			t.Fatalf("invalid fixture integer %q", s)
		}
		return n
	}
	d := batch.Descriptor{Class: class, StreamEpoch: parse(f.Epoch, 64), SegmentID: parse(f.Segment, 64), FirstSequence: parse(f.First, 64), LastSequence: parse(f.Last, 64), RecordCount: uint32(parse(f.Count, 32))}
	if err := d.Validate(); err != nil {
		t.Fatalf("invalid fixture descriptor: %v", err)
	}
	return d
}

func canonicalHeader(d batch.Descriptor) string {
	return fmt.Sprintf("v=1;class=%s;epoch=%d;segment=%d;first=%d;last=%d;count=%d", d.Class, d.StreamEpoch, d.SegmentID, d.FirstSequence, d.LastSequence, d.RecordCount)
}

func requireResult(t testing.TB, d batch.Descriptor, err, want error, expected batch.Descriptor) {
	t.Helper()
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if want != nil {
		expected = batch.Descriptor{}
	}
	if d != expected {
		t.Fatalf("descriptor = %+v, want %+v", d, expected)
	}
}

// The child uses a temporary repository layout so reviewed fixtures stay read-only.
func TestParseHeaderFixtureLoaderChild(t *testing.T) {
	if os.Getenv("RICEVANTA_WIRE_FIXTURE_CHILD") != "1" {
		return
	}
	loadFixtures(t, "header")
}

func TestParseHeaderMalformedFixtureFile(t *testing.T) {
	original, err := os.ReadFile("../../../../schemas/events/v1/fixtures/header.json")
	if err != nil {
		t.Fatal(err)
	}
	missingField := func(key string) []byte {
		var container struct {
			Kind  string                       `json:"kind"`
			Cases []map[string]json.RawMessage `json:"cases"`
		}
		if err := json.Unmarshal(original, &container); err != nil {
			t.Fatal(err)
		}
		delete(container.Cases[0], key)
		data, err := json.Marshal(container)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		name        string
		data        []byte
		wantFailure bool
	}{
		{"valid", original, false},
		{"missing expected error", missingField("expected_error"), true},
		{"missing header values", missingField("header_values"), true},
		{"trailing malformed bytes", append(append([]byte(nil), original...), 'x'), true},
		{"second object", append(append([]byte(nil), original...), []byte("{}")...), true},
	} {
		t.Run(c.name, func(t *testing.T) {
			root, err := os.MkdirTemp("/tmp", "ricevanta-wire-fixtures-")
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { os.RemoveAll(root) })
			cwd := filepath.Join(root, "server", "internal", "events", "wire")
			fixtureDir := filepath.Join(root, "schemas", "events", "v1", "fixtures")
			for _, dir := range []string{cwd, fixtureDir} {
				if err := os.MkdirAll(dir, 0700); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.WriteFile(filepath.Join(fixtureDir, "header.json"), c.data, 0600); err != nil {
				t.Fatal(err)
			}
			command := exec.Command(executable, "-test.run=^TestParseHeaderFixtureLoaderChild$")
			command.Dir = cwd
			command.Env = append(os.Environ(), "RICEVANTA_WIRE_FIXTURE_CHILD=1")
			output, err := command.CombinedOutput()
			if (err != nil) != c.wantFailure {
				t.Fatalf("fixture load error = %v, want failure %v; output: %s", err, c.wantFailure, output)
			}
		})
	}
}

// These checks exercise response vectors without adding a production response API.
func TestResponseFixtures(t *testing.T) {
	data, err := os.ReadFile("../../../../schemas/events/v1/fixtures/response.json")
	if err != nil {
		t.Fatal(err)
	}
	var container struct {
		Kind  string `json:"kind"`
		Cases []struct {
			Name          string             `json:"name"`
			Status        int                `json:"status"`
			Body          json.RawMessage    `json:"body"`
			SchemaValid   bool               `json:"schema_valid"`
			SemanticValid bool               `json:"semantic_valid"`
			Error         *string            `json:"expected_error"`
			Descriptor    *descriptorFixture `json:"request_descriptor"`
			RetryAfter    string             `json:"retry_after"`
		} `json:"cases"`
	}
	if err := json.Unmarshal(data, &container); err != nil {
		t.Fatal(err)
	}
	if container.Kind != "response" || len(container.Cases) == 0 {
		t.Fatal("invalid response fixture container")
	}
	schemaData, err := os.ReadFile("../../../../schemas/events/v1/response.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]responseFixtureSchema `json:"$defs"`
	}
	if err := json.Unmarshal(schemaData, &schema); err != nil {
		t.Fatal(err)
	}
	if len(schema.Defs) != 2 {
		t.Fatal("missing response schemas")
	}
	var fields struct {
		Cases []map[string]json.RawMessage `json:"cases"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		t.Fatal(err)
	}
	names := make(map[string]bool)
	for i, c := range container.Cases {
		required := []string{"name", "status", "body", "schema_valid", "semantic_valid", "expected_error"}
		for _, key := range required {
			raw, ok := fields.Cases[i][key]
			if !ok || (key != "expected_error" && key != "body" && string(raw) == "null") {
				t.Fatalf("fixture %d missing required %s", i, key)
			}
		}

		t.Run(c.Name, func(t *testing.T) {
			if c.Name == "" || names[c.Name] {
				t.Fatal("missing or duplicate response fixture name")
			}
			names[c.Name] = true
			var body any
			decoder := json.NewDecoder(bytes.NewReader(c.Body))
			decoder.UseNumber()
			if err := decoder.Decode(&body); err != nil {
				t.Fatal(err)
			}
			success := schema.Defs["success"].matches(t, body)
			failure := schema.Defs["error"].matches(t, body)
			schemaValid := success != failure
			result := ""
			if !schemaValid {
				result = "schema.invalid"
			} else {
				object := body.(map[string]any)
				if c.Status == 200 {
					if !success {
						result = "response.status"
					} else {
						if c.Descriptor == nil {
							t.Fatal("missing request descriptor")
						}
						d := fixtureDescriptor(t, c.Descriptor)
						if object["batch_id"] != d.BatchID() {
							result = "response.batch_id"
						} else {
							if !responseCountsWithin(object, d.RecordCount) {
								result = "response.counts"
							}
						}
					}
				} else {
					// The HTTP bindings come from the reviewed machine contract.
					var contract struct {
						Responses map[string]struct {
							Error string `json:"error"`
						} `json:"responses"`
					}
					contractData, err := os.ReadFile("../../../../schemas/events/v1/contract.json")
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(contractData, &contract); err != nil {
						t.Fatal(err)
					}
					binding, ok := contract.Responses[strconv.Itoa(c.Status)]
					if !failure || !ok || object["error"] != binding.Error {
						result = "response.status"
					}
				}
				if result == "" && (c.Status == 429 || c.Status == 503) {
					delay, err := strconv.ParseUint(c.RetryAfter, 10, 8)
					if err != nil || strconv.FormatUint(delay, 10) != c.RetryAfter || delay < 5 || delay > 60 {
						result = "response.retry_after"
					}
				}
			}
			expected := ""
			if c.Error != nil {
				expected = *c.Error
			}
			switch expected {
			case "", "schema.invalid", "response.status", "response.batch_id", "response.counts", "response.retry_after":
			default:
				t.Fatal("unknown response fixture sentinel")
			}
			if schemaValid != c.SchemaValid || (result == "") != c.SemanticValid || result != expected {
				t.Fatalf("schema valid %v, error %q; want %v, %q", schemaValid, result, c.SchemaValid, expected)
			}
		})
	}
}

func TestResponseIntegerCounts(t *testing.T) {
	data, err := os.ReadFile("../../../../schemas/events/v1/response.schema.json")
	if err != nil {
		t.Fatal(err)
	}
	var schema struct {
		Defs map[string]responseFixtureSchema `json:"$defs"`
	}
	if err := json.Unmarshal(data, &schema); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		stored, quarantined      string
		count                    uint32
		schemaValid, countsValid bool
	}{
		{"1", "0", 1, true, true},
		{"1.0", "0", 1, true, true},
		{"1e0", "0", 1, true, true},
		{"10e-1", "0.0", 1, true, true},
		{"1.000", "1e0", 1, true, false},
		{"0", "2.0", 1, true, false},
		{"9999.0", "1e0", 10000, true, true},
		{"1e4", "1.0", 10000, true, false},
		{"-0.0", "0e10", 1, true, true},
		{"0e9223372036854775808", "0", 1, true, true},
		{"0e-9223372036854775809", "0", 1, true, true},
		{"1.00000000000000000001", "0", 1, false, false},
		{"0", "1e-1", 1, false, false},
		{"10000.000000000000000001", "0", 10000, false, false},
		{"10001e0", "0", 10000, false, false},
		{"-1e0", "0", 1, false, false},
		{"9223372036854775808", "0", 1, false, false},
		{`"1"`, "0", 1, false, false},
	} {
		t.Run(c.stored+"/"+c.quarantined, func(t *testing.T) {
			body := fmt.Sprintf(`{"batch_id":"1-raw-0","result":"stored","stored":%s,"quarantined":%s}`, c.stored, c.quarantined)
			var value any
			decoder := json.NewDecoder(strings.NewReader(body))
			decoder.UseNumber()
			if err := decoder.Decode(&value); err != nil {
				t.Fatal(err)
			}
			valid := schema.Defs["success"].matches(t, value)
			if valid != c.schemaValid {
				t.Fatalf("schema valid %v, want %v", valid, c.schemaValid)
			}
			if valid {
				object := value.(map[string]any)
				if got := responseCountsWithin(object, c.count); got != c.countsValid {
					t.Fatalf("counts valid %v, want %v", got, c.countsValid)
				}
			}
		})
	}
}

// responseFixtureSchema handles only the keywords used by the reviewed response definitions.
// It is a test oracle, not a general JSON Schema validator.
type responseFixtureSchema struct {
	Type                 string                           `json:"type"`
	AdditionalProperties bool                             `json:"additionalProperties"`
	Required             []string                         `json:"required"`
	Properties           map[string]responseFixtureSchema `json:"properties"`
	Enum                 []string                         `json:"enum"`
	MaxLength            *int                             `json:"maxLength"`
	Pattern              string                           `json:"pattern"`
	Minimum              *int64                           `json:"minimum"`
	Maximum              *int64                           `json:"maximum"`
}

func (s responseFixtureSchema) matches(t *testing.T, value any) bool {
	t.Helper()
	if len(s.Enum) > 0 {
		text, ok := value.(string)
		if !ok {
			return false
		}
		found := false
		for _, v := range s.Enum {
			if text == v {
				found = true
			}
		}
		if !found {
			return false
		}
	}
	switch s.Type {
	case "object":
		object, ok := value.(map[string]any)
		if !ok {
			return false
		}
		for _, key := range s.Required {
			if _, ok := object[key]; !ok {
				return false
			}
		}
		for key, value := range object {
			property, ok := s.Properties[key]
			if !ok {
				if !s.AdditionalProperties {
					return false
				}
				continue
			}
			if property.Type == "integer" {
				n, ok := property.integer(value)
				if !ok {
					return false
				}
				// Keep the exact validated value for the later count sum.
				object[key] = n
			} else if !property.matches(t, value) {
				return false
			}
		}
	case "string":
		text, ok := value.(string)
		if !ok {
			return false
		}
		if s.MaxLength != nil && utf8.RuneCountInString(text) > *s.MaxLength {
			return false
		}
		if s.Pattern != "" {
			// Go's end anchor already requires physical end, unlike JavaScript's dollar anchor.
			pattern := s.Pattern
			if end := strings.Index(pattern, "$(?!"); end >= 0 {
				pattern = pattern[:end] + "$"
			}
			expression, err := regexp.Compile(pattern)
			if err != nil {
				t.Fatal(err)
			}
			if !expression.MatchString(text) {
				return false
			}
		}
	case "integer":
		if _, ok := s.integer(value); !ok {
			return false
		}
	case "":
	default:
		t.Fatalf("unsupported test schema type %q", s.Type)
	}
	return true
}

// integer checks mathematical integrality without rounding decimal or exponent notation.
func (s responseFixtureSchema) integer(value any) (*big.Int, bool) {
	var n *big.Int
	switch value := value.(type) {
	case json.Number:
		mantissa := string(value)
		if end := strings.IndexAny(mantissa, "eE"); end >= 0 {
			mantissa = mantissa[:end]
		}
		// Decoded JSON with a zero mantissa is zero regardless of exponent size.
		if strings.Trim(mantissa, "-0.") == "" {
			n = new(big.Int)
		} else {
			rational, ok := new(big.Rat).SetString(string(value))
			if !ok || !rational.IsInt() {
				return nil, false
			}
			n = new(big.Int).Set(rational.Num())
		}
	case *big.Int:
		n = value
	default:
		return nil, false
	}
	if s.Minimum != nil && n.Cmp(big.NewInt(*s.Minimum)) < 0 ||
		s.Maximum != nil && n.Cmp(big.NewInt(*s.Maximum)) > 0 {
		return nil, false
	}
	return n, true
}

func responseCountsWithin(object map[string]any, count uint32) bool {
	stored := object["stored"].(*big.Int)
	quarantined := object["quarantined"].(*big.Int)
	sum := new(big.Int).Add(stored, quarantined)
	return sum.Cmp(new(big.Int).SetUint64(uint64(count))) <= 0
}
