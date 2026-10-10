package body

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
)

type bodyFixture struct {
	Name       string                                                     `json:"name"`
	Descriptor struct{ Class, Epoch, Segment, First, Last, Count string } `json:"descriptor"`
	Device     string                                                     `json:"authenticated_device"`
	Plain      struct {
		Literal *string `json:"literal_base64"`
		Records *struct {
			Count      int
			First      string
			LineBytes  int `json:"line_bytes"`
			TotalBytes int `json:"total_bytes"`
			Extra      int `json:"extra_last_spaces"`
		} `json:"records"`
	} `json:"plain"`
	Encoder   string `json:"encoder"`
	Mutations []struct {
		Offset, Delete int
		Insert         string `json:"insert_base64"`
	} `json:"mutations"`
	Parts []struct {
		Base64 string
		Repeat int
	} `json:"body_parts"`
	BodyBytes  int    `json:"body_bytes"`
	BodySHA    string `json:"body_sha256"`
	PlainBytes int    `json:"plain_bytes"`
	PlainSHA   string `json:"plain_sha256"`
	Expected   struct {
		Error  *string `json:"batch_error"`
		Status *int
		Lines  []outcome
	} `json:"expected"`
}
type outcome struct {
	Count        int
	Error, Cause *string
	Mismatch     bool   `json:"device_mismatch"`
	UID          string `json:"event_uid"`
	First        string `json:"sequence_first"`
	Device       string `json:"device_uid"`
}
type fixtureFile struct {
	Kind     string
	Encoder  string `json:"reference_encoder"`
	Template string `json:"record_template"`
	Cases    []bodyFixture
}

func readFixtureFile() ([]byte, error) {
	return os.ReadFile("../../../../schemas/events/v1/fixtures/body.json")
}
func loadFixtures(t testing.TB) fixtureFile {
	t.Helper()
	data, err := readFixtureFile()
	if err != nil {
		t.Fatal(err)
	}
	f, err := parseFixtures(data)
	if err != nil {
		t.Fatal(err)
	}
	return f
}
func parseFixtures(data []byte) (fixtureFile, error) {
	var f fixtureFile
	schemaData, err := os.ReadFile("../../../../schemas/events/v1/body-fixture.schema.json")
	if err != nil {
		return f, err
	}
	var schema map[string]any
	if err = json.Unmarshal(schemaData, &schema); err != nil {
		return f, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	var value any
	if err = dec.Decode(&value); err != nil {
		return f, err
	}
	var tail any
	if dec.Decode(&tail) != io.EOF {
		return f, fmt.Errorf("trailing fixture data")
	}
	if !schemaMatches(schema, value) {
		return f, fmt.Errorf("fixture/schema disagreement")
	}
	if err = json.Unmarshal(data, &f); err != nil {
		return f, err
	}
	names := map[string]bool{}
	for _, c := range f.Cases {
		if names[c.Name] {
			return f, fmt.Errorf("duplicate fixture name")
		}
		names[c.Name] = true
		if _, err = c.descriptor(); err != nil {
			return f, err
		}
		if _, err = c.body(); err != nil {
			return f, err
		}
		if _, err = c.plain(f.Template); err != nil {
			return f, err
		}
		total := 0
		for _, r := range c.Expected.Lines {
			total += r.Count
			if r.Error == nil {
				n, e := strconv.ParseUint(r.First, 10, 64)
				if e != nil || uint64(r.Count-1) > ^uint64(0)-n {
					return f, fmt.Errorf("outcome overflow")
				}
			}
		}
		if c.Expected.Error == nil && total != int(mustCount(c.Descriptor.Count)) {
			return f, fmt.Errorf("outcome count")
		}
	}
	return f, nil
}
func mustCount(s string) uint64 { n, _ := strconv.ParseUint(s, 10, 64); return n }

// schemaMatches implements only the keywords in the approved fixture schema.
// Unsupported keywords fail closed so schema changes require a test-oracle update.
func schemaMatches(s map[string]any, v any) bool {
	for key, x := range s {
		switch key {
		case "$schema", "$id", "title", "contentEncoding":
		case "type":
			ok := false
			switch x {
			case "object":
				_, ok = v.(map[string]any)
			case "array":
				_, ok = v.([]any)
			case "string":
				_, ok = v.(string)
			case "boolean":
				_, ok = v.(bool)
			case "null":
				ok = v == nil
			case "integer":
				n, yes := v.(json.Number)
				if yes {
					_, e := strconv.ParseInt(string(n), 10, 64)
					ok = e == nil
				}
			}
			if !ok {
				return false
			}
		case "const":
			if !sameJSON(x, v) {
				return false
			}
		case "enum":
			ok := false
			for _, e := range x.([]any) {
				ok = ok || sameJSON(e, v)
			}
			if !ok {
				return false
			}
		case "required":
			if m, ok := v.(map[string]any); ok {
				for _, k := range x.([]any) {
					if _, yes := m[k.(string)]; !yes {
						return false
					}
				}
			}
		case "properties":
			if m, ok := v.(map[string]any); ok {
				for k, p := range x.(map[string]any) {
					if val, yes := m[k]; yes && !schemaMatches(p.(map[string]any), val) {
						return false
					}
				}
			}
		case "additionalProperties":
			if x == false {
				if m, ok := v.(map[string]any); ok {
					p, _ := s["properties"].(map[string]any)
					for k := range m {
						if _, yes := p[k]; !yes {
							return false
						}
					}
				}
			}
		case "minItems", "maxItems":
			if a, ok := v.([]any); ok {
				bound := int(x.(float64))
				if key == "minItems" && len(a) < bound || key == "maxItems" && len(a) > bound {
					return false
				}
			}
		case "items":
			if a, ok := v.([]any); ok {
				for _, e := range a {
					if !schemaMatches(x.(map[string]any), e) {
						return false
					}
				}
			}
		case "minimum", "maximum":
			if n, ok := v.(json.Number); ok {
				a, e := strconv.ParseInt(string(n), 10, 64)
				if e != nil {
					return false
				}
				b := int64(x.(float64))
				if key == "minimum" && a < b || key == "maximum" && a > b {
					return false
				}
			}
		case "minLength":
			if a, ok := v.(string); ok && len(a) < int(x.(float64)) {
				return false
			}
		case "pattern":
			if a, ok := v.(string); ok && !regexp.MustCompile(x.(string)).MatchString(a) {
				return false
			}
		case "oneOf", "allOf", "anyOf":
			n := 0
			items := x.([]any)
			for _, e := range items {
				if schemaMatches(e.(map[string]any), v) {
					n++
				}
			}
			if key == "oneOf" && n != 1 || key == "allOf" && n != len(items) || key == "anyOf" && n == 0 {
				return false
			}
		case "not":
			if schemaMatches(x.(map[string]any), v) {
				return false
			}
		case "if":
			branch := "else"
			if schemaMatches(x.(map[string]any), v) {
				branch = "then"
			}
			if b, ok := s[branch]; ok && !schemaMatches(b.(map[string]any), v) {
				return false
			}
		case "then", "else":
		default:
			return false
		}
	}
	return true
}
func sameJSON(a, b any) bool {
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
func (c bodyFixture) descriptor() (batch.Descriptor, error) {
	var d batch.Descriptor
	for v := batch.ClassRaw; v <= batch.ClassAudit; v++ {
		if v.String() == c.Descriptor.Class {
			d.Class = v
		}
	}
	vals := []string{c.Descriptor.Epoch, c.Descriptor.Segment, c.Descriptor.First, c.Descriptor.Last, c.Descriptor.Count}
	nums := make([]uint64, 5)
	for i, s := range vals {
		n, e := strconv.ParseUint(s, 10, 64)
		if e != nil || strconv.FormatUint(n, 10) != s {
			return d, fmt.Errorf("invalid descriptor integer")
		}
		nums[i] = n
	}
	if nums[4] > 1<<32-1 {
		return d, fmt.Errorf("descriptor count overflow")
	}
	d.StreamEpoch = nums[0]
	d.SegmentID = nums[1]
	d.FirstSequence = nums[2]
	d.LastSequence = nums[3]
	d.RecordCount = uint32(nums[4])
	return d, d.Validate()
}
func digestOK(b []byte, n int, digest string) bool {
	return len(b) == n && fmt.Sprintf("%x", sha256.Sum256(b)) == digest
}
func (c bodyFixture) body() ([]byte, error) {
	b := make([]byte, 0, c.BodyBytes)
	for _, p := range c.Parts {
		part, e := base64.StdEncoding.Strict().DecodeString(p.Base64)
		if e != nil {
			return nil, e
		}
		if p.Repeat < 1 || len(part) > 0 && p.Repeat > (5000001-len(b))/len(part) {
			return nil, fmt.Errorf("fixture expansion cap")
		}
		for range p.Repeat {
			b = append(b, part...)
		}
	}
	if !digestOK(b, c.BodyBytes, c.BodySHA) {
		return nil, fmt.Errorf("body length/digest")
	}
	return b, nil
}
func (c bodyFixture) plain(template string) ([]byte, error) {
	var b []byte
	if c.Plain.Literal != nil {
		var e error
		b, e = base64.StdEncoding.Strict().DecodeString(*c.Plain.Literal)
		if e != nil {
			return nil, e
		}
	} else {
		r := c.Plain.Records
		if r == nil {
			return nil, fmt.Errorf("missing recipe")
		}
		first, e := strconv.ParseUint(r.First, 10, 64)
		if e != nil || uint64(r.Count-1) > ^uint64(0)-first {
			return nil, fmt.Errorf("recipe sequence")
		}
		b = make([]byte, 0, c.PlainBytes)
		for i := 0; i < r.Count; i++ {
			line := strings.ReplaceAll(template, "SEQUENCE", strconv.FormatUint(first+uint64(i), 10))
			size := len(line) + 1
			if r.LineBytes != 0 {
				size = r.LineBytes
			}
			if r.TotalBytes != 0 {
				size = min(1048576, r.TotalBytes-len(b))
			}
			if i == r.Count-1 {
				size += r.Extra
			}
			if size < len(line)+1 || size > 1048578 || len(b)+size > 67108865 {
				return nil, fmt.Errorf("recipe length")
			}
			b = append(b, line...)
			b = append(b, bytes.Repeat([]byte{' '}, size-len(line)-1)...)
			b = append(b, '\n')
		}
	}
	if !digestOK(b, c.PlainBytes, c.PlainSHA) {
		return nil, fmt.Errorf("plain length/digest")
	}
	return b, nil
}
func fixtureBytes(t testing.TB, c bodyFixture, template string) ([]byte, []byte, batch.Descriptor) {
	t.Helper()
	b, e := c.body()
	if e != nil {
		t.Fatal(e)
	}
	p, e := c.plain(template)
	if e != nil {
		t.Fatal(e)
	}
	d, e := c.descriptor()
	if e != nil {
		t.Fatal(e)
	}
	return b, p, d
}
func errorName(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
func expectedMessage(p *string) string {
	if p == nil {
		return ""
	}
	s := strings.TrimPrefix(*p, "body.Err")
	if s == "EventID" {
		return "event body event id"
	}
	if strings.HasPrefix(s, "JSON") {
		if s == "JSON" {
			return "event body JSON"
		}
		return "event body JSON " + strings.ToLower(s[4:])
	}
	return "event body " + strings.ToLower(regexp.MustCompile(`([a-z])([A-Z])`).ReplaceAllString(s, "$1 $2"))
}
