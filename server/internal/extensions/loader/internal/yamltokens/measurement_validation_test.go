package yamltokens

import (
	"encoding/json"
	"math"
	"os"
	"os/exec"
	"strings"
	"testing"
)

func validMeasurementReport(t *testing.T) map[string]any {
	t.Helper()
	m := parserMeasurement{Mode: "combined", Status: "preflight-rejected", Size: 64, Sample: 1, Alloc: 10, Objects: 2, LedgerBytes: 10, LedgerObjects: 2, ProcsBefore: 1, ProcsAfter: 1, MemoryLimitBefore: math.MaxInt64, MemoryLimitAfter: math.MaxInt64, GCPercentBefore: math.MaxUint64, GCPercentAfter: math.MaxUint64, GCBefore: 3, GCAfter: 3}
	data, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]any
	// Preserve integer precision, including MaxUint64.
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.UseNumber()
	if err := decoder.Decode(&fields); err != nil {
		t.Fatal(err)
	}
	return fields
}

func TestParserMeasurementValidation(t *testing.T) {
	check := func(t *testing.T, fields map[string]any, wantFailure bool) {
		t.Helper()
		data, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		_, err = decodeParserMeasurement(data)
		if (err != nil) != wantFailure {
			t.Fatalf("validation error = %v, want failure %v", err, wantFailure)
		}
	}
	t.Run("valid", func(t *testing.T) { check(t, validMeasurementReport(t), false) })
	for _, field := range []string{"ProcsBefore", "ProcsAfter", "MemoryLimitBefore", "MemoryLimitAfter", "GCPercentBefore", "GCPercentAfter", "GCBefore", "GCAfter"} {
		t.Run(field+"/wrong", func(t *testing.T) {
			fields := validMeasurementReport(t)
			switch field {
			case "ProcsBefore", "ProcsAfter":
				fields[field] = 2
			case "MemoryLimitBefore", "MemoryLimitAfter":
				fields[field] = 1 << 20
			case "GCPercentBefore", "GCPercentAfter":
				fields[field] = 1
			case "GCBefore":
				fields[field] = 2
			case "GCAfter":
				fields[field] = 4
			}
			check(t, fields, true)
		})
	}
	for field := range validMeasurementReport(t) {
		t.Run(field+"/missing", func(t *testing.T) { fields := validMeasurementReport(t); delete(fields, field); check(t, fields, true) })
	}
	for field := range validMeasurementReport(t) {
		t.Run(field+"/null", func(t *testing.T) { fields := validMeasurementReport(t); fields[field] = nil; check(t, fields, true) })
	}
	for _, field := range []string{"GCBefore", "GCAfter"} {
		t.Run(field+"/missing-zero", func(t *testing.T) {
			fields := validMeasurementReport(t)
			fields["GCBefore"], fields["GCAfter"] = 0, 0
			check(t, fields, false)
			delete(fields, field)
			check(t, fields, true)
		})
	}
	for _, field := range []string{"Alloc", "Objects"} {
		t.Run("rejected-combined-ledger/"+field, func(t *testing.T) { fields := validMeasurementReport(t); fields[field] = 11; check(t, fields, true) })
	}
	for name, value := range map[string]any{"zero": 0, "negative": -1, "fraction": 1.5, "text": "1"} {
		t.Run("sample/"+name, func(t *testing.T) {
			fields := validMeasurementReport(t)
			fields["Sample"] = value
			check(t, fields, true)
		})
	}
	t.Run("negative-nanoseconds", func(t *testing.T) {
		fields := validMeasurementReport(t)
		fields["Nanoseconds"] = -1
		check(t, fields, true)
	})
}

func TestRejectedCombinedMeasurementLedger(t *testing.T) {
	cmd := exec.Command(os.Args[0], "-test.run=^TestParserMeasurementChild$", "-test.v")
	cmd.Env = append(os.Environ(), "RICEVANTA_PARSER_RECIPE=tags", "RICEVANTA_PARSER_SIZE=64", "RICEVANTA_PARSER_MODE=combined", "RICEVANTA_PARSER_ACCEPTED=false", "RICEVANTA_PARSER_ERROR=YAML tag", "RICEVANTA_PARSER_SAMPLE=1")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child: %v\n%s", err, out)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if data, ok := strings.CutPrefix(line, "PARSER_MEASUREMENT "); ok {
			m, err := decodeParserMeasurement([]byte(data))
			if err != nil {
				t.Fatal(err)
			}
			if m.LedgerBytes == 0 || m.LedgerObjects == 0 {
				t.Fatalf("rejected combined sample lost ledger: %+v", m)
			}
			for _, field := range []string{"LedgerBytes", "LedgerObjects"} {
				t.Run(field+"/below-raw", func(t *testing.T) {
					tampered := m
					if field == "LedgerBytes" {
						tampered.LedgerBytes = m.Alloc - 1
					} else {
						tampered.LedgerObjects = m.Objects - 1
					}
					report, err := json.Marshal(tampered)
					if err != nil {
						t.Fatal(err)
					}
					if _, err := decodeParserMeasurement(report); err == nil {
						t.Fatal("rejected combined raw excess passed validation")
					}
				})
			}
			t.Log(data)
			return
		}
	}
	t.Fatal("missing measurement")
}
