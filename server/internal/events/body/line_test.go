package body

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ricevanta/ricevanta/server/internal/events/batch"
	"github.com/ricevanta/ricevanta/server/internal/events/eventid"
)

func descriptor(first uint64, count uint32) batch.Descriptor {
	return batch.Descriptor{Class: batch.ClassRaw, StreamEpoch: 1, FirstSequence: first, LastSequence: first + uint64(count-1), RecordCount: count}
}

const uid = "017f22e2-79b0-7cc3-98c4-dc0c0c07398f"

func record(seq string, device string) []byte {
	return []byte(fmt.Sprintf(`{"metadata":{"uid":%q,"sequence":%s},"device":{"uid":%q}}`, uid, seq, device))
}
func assertLine(t testing.TB, got Line, raw []byte, number uint32, r outcome, offset int) {
	t.Helper()
	if !bytes.Equal(got.Raw, raw) || got.Number != number || !errors.Is(got.Err, lineSentinel(r.Error)) || got.DeviceMismatch != r.Mismatch {
		t.Fatalf("line %d: err=%v mismatch=%v want=%+v", number, got.Err, got.DeviceMismatch, r)
	}
	if r.Error != nil {
		if got.EventID != (eventid.ID{}) || got.Sequence != 0 || got.DeviceUID != "" {
			t.Fatal("partial identity")
		}
		if r.Cause != nil {
			causes := map[string]error{"eventid.ErrFormat": eventid.ErrFormat, "eventid.ErrNonCanonical": eventid.ErrNonCanonical, "eventid.ErrVersion": eventid.ErrVersion, "eventid.ErrVariant": eventid.ErrVariant}
			if !errors.Is(got.Err, causes[*r.Cause]) {
				t.Fatalf("missing cause %v", got.Err)
			}
		}
	} else if got.EventID.String() != r.UID || got.Sequence != mustCount(r.First)+uint64(offset) || got.DeviceUID != r.Device {
		t.Fatalf("identity=%+v", got)
	}
}
func TestExtractLineFixtures(t *testing.T) {
	f := loadFixtures(t)
	for _, c := range f.Cases {
		if c.Expected.Error != nil {
			continue
		}
		t.Run(c.Name, func(t *testing.T) {
			_, p, d := fixtureBytes(t, c, f.Template)
			raw := bytes.Split(p[:len(p)-1], []byte{'\n'})
			i := 0
			for _, r := range c.Expected.Lines {
				for j := 0; j < r.Count; j++ {
					assertLine(t, extractLine(raw[i], uint32(i+1), d, c.Device), raw[i], uint32(i+1), r, j)
					i++
				}
			}
		})
	}
}
func TestExtractLinePrecedence(t *testing.T) {
	for _, c := range []struct {
		raw  string
		want error
	}{
		{`{"device":{"uid":"b"},"metadata":{"uid":"x","sequence":1}}`, ErrEventID},
		{string(record("1", "b")), ErrSequenceRange},
		{`{"a":1,"a":2,`, ErrJSON},
		{`{"metadata":{},"device":{"uid":"a","uid":"b"}}`, ErrJSONKeys},
		{`{"metadata":{},"device":{"uid":"b"},"unknown":[{"a":1,"a":2}]}`, ErrJSONKeys},
		{`{"METADATA":{}}`, ErrJSONKeys},
	} {
		got := extractLine([]byte(c.raw), 1, descriptor(0, 1), "device-a")
		if !errors.Is(got.Err, c.want) {
			t.Fatalf("%s: %v want %v", c.raw, got.Err, c.want)
		}
	}
	got := extractLine(record("0", "b"), 2, descriptor(0, 2), "a")
	if !errors.Is(got.Err, ErrSequencePosition) || !got.DeviceMismatch {
		t.Fatal(got)
	}
}
func TestExtractLineDeviceEvidence(t *testing.T) {
	for _, c := range []struct {
		raw      string
		want     error
		mismatch bool
	}{
		{`{"device":{"uid":"b"}}`, ErrFields, true},
		{`{"metadata":[],"device":{"uid":""}}`, ErrFields, true},
		{`{"device":{"uid":"b","UID":"b"}}`, ErrJSONKeys, false},
		{`{"device":{"uid":null}}`, ErrFields, false},
		{`{"device":[]}`, ErrFields, false},
		{`{"device":{"uid":"b"},"x":"\ud800"}`, ErrJSON, false},
	} {
		got := extractLine([]byte(c.raw), 1, descriptor(0, 1), "a")
		if !errors.Is(got.Err, c.want) || got.DeviceMismatch != c.mismatch {
			t.Fatal(got)
		}
	}
}
func TestExtractLineDepth(t *testing.T) {
	base := string(record("0", "device-a"))
	for _, depth := range []int{128, 129} {
		raw := []byte(base[:len(base)-1] + `,"x":` + strings.Repeat("[", depth-1) + "0" + strings.Repeat("]", depth-1) + "}")
		got := extractLine(raw, 1, descriptor(0, 1), "device-a")
		if (got.Err == nil) != (depth == 128) {
			t.Fatalf("depth=%d err=%v", depth, got.Err)
		}
	}
	for _, value := range []string{`"\ud83d\ude00"`, `"�"`, `"\\ud800"`} {
		raw := []byte(base[:len(base)-1] + `,"x":` + value + "}")
		if got := extractLine(raw, 1, descriptor(0, 1), "device-a"); got.Err != nil {
			t.Fatal(got.Err)
		}
	}
	for _, value := range []string{`"\ud800"`, `"\udfff"`, `"\ud800x"`, `"\ud800\ud800"`, `[]`, `null`} {
		raw := []byte(base[:len(base)-1] + `,"x":` + value + "}")
		if value == "[]" || value == "null" {
			raw = []byte(value)
		}
		if got := extractLine(raw, 1, descriptor(0, 1), "device-a"); !errors.Is(got.Err, ErrJSON) {
			t.Fatal(got.Err)
		}
	}
}
func TestExtractLineMaxSequence(t *testing.T) {
	for _, n := range []uint64{0, 1<<53 + 1, ^uint64(0)} {
		got := extractLine(record(fmt.Sprint(n), "device-a"), 1, descriptor(n, 1), "device-a")
		if got.Err != nil || got.Sequence != n {
			t.Fatal(got)
		}
	}
	for _, n := range []string{"-0", "-1", "0.0", "0e0", `"0"`, "18446744073709551616"} {
		if got := extractLine(record(n, "device-a"), 1, descriptor(0, 1), "device-a"); !errors.Is(got.Err, ErrFields) {
			t.Fatalf("%s: %v", n, got.Err)
		}
	}
}
func FuzzExtractLine(f *testing.F) {
	fixtures := loadFixtures(f)
	seen := make(map[string]bool)
	for _, c := range fixtures.Cases {
		if c.PlainBytes > MaxLineBytes {
			continue
		}
		p, e := c.plain(fixtures.Template)
		if e != nil {
			f.Fatal(e)
		}
		rawLines := bytes.Split(bytes.TrimSuffix(p, []byte{'\n'}), []byte{'\n'})
		for i, raw := range rawLines {
			// Generated runs need endpoint positions, not thousands of equivalent seeds.
			if c.Plain.Records != nil && i != 0 && i != len(rawLines)-1 {
				continue
			}
			first := mustCount(c.Descriptor.First)
			selector := uint32(i)
			key := fmt.Sprintf("%x/%d/%d", sha256.Sum256(raw), first, selector)
			if !seen[key] {
				f.Add(raw, first, selector)
				seen[key] = true
			}
		}
	}
	f.Add([]byte(`{"metadata":{"uid":"017f22e2-79b0-7cc3-98c4-dc0c0c07398f","sequence":0},"device":{"uid":"device-a"},"unknown":{"a":1,"a":2}}`), uint64(0), uint32(0))
	f.Fuzz(func(t *testing.T, raw []byte, first uint64, selector uint32) {
		if len(raw) > MaxLineBytes {
			return
		}
		count := uint32(1 + selector%10000)
		if uint64(count-1) > ^uint64(0)-first {
			first = 0
		}
		number := 1 + selector%count
		got := extractLine(raw, number, descriptor(first, count), "device-a")
		if !bytes.Equal(got.Raw, raw) || got.Number != number {
			t.Fatal("raw/number changed")
		}
		assertReferenceLine(t, got, raw, number, descriptor(first, count), "device-a")
	})
}

func lineSentinel(name *string) error {
	if name == nil {
		return nil
	}
	return map[string]error{"body.ErrJSON": ErrJSON, "body.ErrJSONKeys": ErrJSONKeys, "body.ErrFields": ErrFields, "body.ErrEventID": ErrEventID, "body.ErrSequenceRange": ErrSequenceRange, "body.ErrSequencePosition": ErrSequencePosition, "body.ErrDeviceBinding": ErrDeviceBinding}[*name]
}
