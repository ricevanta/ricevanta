package batch

import (
	"errors"
	"math"
	"testing"
)

func validDescriptor() Descriptor {
	return Descriptor{Class: ClassRaw, StreamEpoch: 1, RecordCount: 1}
}

func requireError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func TestSpoolClassString(t *testing.T) {
	tests := []struct {
		class SpoolClass
		want  string
	}{
		{ClassRaw, "raw"},
		{ClassContext, "context"},
		{ClassLineage, "lineage"},
		{ClassFindings, "findings"},
		{ClassAudit, "audit"},
		{0, ""},
		{6, ""},
		{math.MaxUint8, ""},
	}
	for _, tt := range tests {
		if got := tt.class.String(); got != tt.want {
			t.Errorf("SpoolClass(%d).String() = %q, want %q", tt.class, got, tt.want)
		}
	}
}

func TestDescriptorValidate(t *testing.T) {
	for _, class := range []SpoolClass{ClassRaw, ClassContext, ClassLineage, ClassFindings, ClassAudit} {
		d := Descriptor{Class: class, StreamEpoch: 1, RecordCount: 1}
		if err := d.Validate(); err != nil {
			t.Errorf("class %q: Validate() error = %v", class.String(), err)
		}
	}
}

func TestDescriptorBoundaryCounts(t *testing.T) {
	tests := []struct {
		name string
		d    Descriptor
		want error
	}{
		{"zero", Descriptor{Class: ClassRaw, StreamEpoch: 1}, ErrRecordCount},
		{"one", validDescriptor(), nil},
		{"ten thousand", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 5, LastSequence: 10004, RecordCount: 10000}, nil},
		{"ten thousand and one", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 5, LastSequence: 10005, RecordCount: 10001}, ErrRecordCount},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { requireError(t, tt.d.Validate(), tt.want) })
	}
}

func TestDescriptorMaxUint64Sequences(t *testing.T) {
	tests := []Descriptor{
		{Class: ClassRaw, StreamEpoch: 1, FirstSequence: math.MaxUint64, LastSequence: math.MaxUint64, RecordCount: 1},
		{Class: ClassRaw, StreamEpoch: 1, FirstSequence: math.MaxUint64 - 9999, LastSequence: math.MaxUint64, RecordCount: 10000},
	}
	for _, d := range tests {
		if err := d.Validate(); err != nil {
			t.Errorf("Validate(%+v) error = %v", d, err)
		}
	}
}

func TestBatchID(t *testing.T) {
	tests := []struct {
		name string
		d    Descriptor
		want string
	}{
		{"zero segment", validDescriptor(), "1-raw-0"},
		{"maximum values", Descriptor{Class: ClassAudit, StreamEpoch: math.MaxUint64, SegmentID: math.MaxUint64, FirstSequence: math.MaxUint64, LastSequence: math.MaxUint64, RecordCount: 1}, "18446744073709551615-audit-18446744073709551615"},
		{"invalid descriptor", Descriptor{}, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.d.BatchID(); got != tt.want {
				t.Fatalf("BatchID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestValidateBatchID(t *testing.T) {
	tests := []struct {
		class SpoolClass
		want  string
	}{
		{ClassRaw, "9-raw-42"},
		{ClassContext, "9-context-42"},
		{ClassLineage, "9-lineage-42"},
		{ClassFindings, "9-findings-42"},
		{ClassAudit, "9-audit-42"},
	}
	for _, tt := range tests {
		d := Descriptor{Class: tt.class, StreamEpoch: 9, SegmentID: 42, FirstSequence: 5, LastSequence: 10004, RecordCount: 10000}
		if err := ValidateBatchID(tt.want, d); err != nil {
			t.Errorf("ValidateBatchID(%q) error = %v", tt.want, err)
		}
	}
}

func TestDescriptorRejectsClass(t *testing.T) {
	for _, class := range []SpoolClass{0, 6, math.MaxUint8} {
		d := validDescriptor()
		d.Class = class
		requireError(t, d.Validate(), ErrClass)
	}
}

func TestDescriptorRejectsZeroEpoch(t *testing.T) {
	d := validDescriptor()
	d.StreamEpoch = 0
	requireError(t, d.Validate(), ErrStreamEpoch)
}

func TestDescriptorRejectsCount(t *testing.T) {
	for _, count := range []uint32{0, 10001, math.MaxUint32} {
		d := validDescriptor()
		d.RecordCount = count
		requireError(t, d.Validate(), ErrRecordCount)
	}
}

func TestDescriptorRejectsReversedRange(t *testing.T) {
	d := validDescriptor()
	d.FirstSequence = 5
	d.LastSequence = 4
	requireError(t, d.Validate(), ErrSequenceRange)
}

func TestDescriptorRejectsCountMismatch(t *testing.T) {
	tests := []Descriptor{
		{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 0, LastSequence: 1, RecordCount: 1},
		{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 10, LastSequence: 10, RecordCount: 2},
		{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 0, LastSequence: 10000, RecordCount: 10000},
	}
	for _, d := range tests {
		requireError(t, d.Validate(), ErrSequenceCount)
	}
}

func TestDescriptorErrorPrecedence(t *testing.T) {
	tests := []struct {
		name string
		d    Descriptor
		want error
	}{
		{"every field omitted", Descriptor{}, ErrClass},
		{"only class valid", Descriptor{Class: ClassRaw}, ErrStreamEpoch},
		{"class and epoch valid", Descriptor{Class: ClassRaw, StreamEpoch: 1}, ErrRecordCount},
		{"range before agreement", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 2, LastSequence: 1, RecordCount: 1}, ErrSequenceRange},
		{"agreement last", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 1, LastSequence: 2, RecordCount: 1}, ErrSequenceCount},
		{"class before later errors", Descriptor{Class: 6, FirstSequence: math.MaxUint64, RecordCount: 10001}, ErrClass},
		{"epoch before later errors", Descriptor{Class: ClassRaw, FirstSequence: math.MaxUint64, RecordCount: 10001}, ErrStreamEpoch},
		{"count before range", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: math.MaxUint64, RecordCount: 10001}, ErrRecordCount},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := tt.d.Validate(); err != tt.want {
				t.Fatalf("Validate() error = %v, want exact sentinel %v", err, tt.want)
			}
		})
	}
}

func TestDescriptorMaxUint64Boundaries(t *testing.T) {
	tests := []struct {
		name string
		d    Descriptor
		want error
	}{
		{"maximum singleton", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: math.MaxUint64, LastSequence: math.MaxUint64, RecordCount: 1}, nil},
		{"maximum ten thousand", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: math.MaxUint64 - 9999, LastSequence: math.MaxUint64, RecordCount: 10000}, nil},
		{"reversed maximum to zero", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: math.MaxUint64, LastSequence: 0, RecordCount: 1}, ErrSequenceRange},
		{"maximum count mismatch", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: math.MaxUint64, LastSequence: math.MaxUint64, RecordCount: 2}, ErrSequenceCount},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) { requireError(t, tt.d.Validate(), tt.want) })
	}
}

func TestValidateBatchIDRejectsNonCanonical(t *testing.T) {
	d := Descriptor{Class: ClassRaw, StreamEpoch: 9, SegmentID: 42, FirstSequence: 5, LastSequence: 5, RecordCount: 1}
	for _, claimed := range []string{"09-raw-42", "9-RAW-42", "9-context-42", "9-raw-042", "9-raw-43", " 9-raw-42", "9-raw-42 ", ""} {
		requireError(t, ValidateBatchID(claimed, d), ErrBatchID)
	}
}

func TestValidateBatchIDPrefersDescriptorError(t *testing.T) {
	tests := []struct {
		name string
		d    Descriptor
		want error
	}{
		{"class", Descriptor{}, ErrClass},
		{"epoch", Descriptor{Class: ClassRaw}, ErrStreamEpoch},
		{"count", Descriptor{Class: ClassRaw, StreamEpoch: 1}, ErrRecordCount},
		{"range", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 1, LastSequence: 0, RecordCount: 1}, ErrSequenceRange},
		{"sequence count", Descriptor{Class: ClassRaw, StreamEpoch: 1, FirstSequence: 0, LastSequence: 1, RecordCount: 1}, ErrSequenceCount},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := ValidateBatchID("mismatched", tt.d); err != tt.want {
				t.Fatalf("ValidateBatchID() error = %v, want exact descriptor sentinel %v", err, tt.want)
			}
		})
	}
}

func FuzzDescriptor(f *testing.F) {
	seeds := []struct {
		class   uint8
		epoch   uint64
		segment uint64
		first   uint64
		last    uint64
		count   uint32
		claimed string
	}{
		// Valid classes, ordinary count boundaries, and zero sequence values.
		{uint8(ClassRaw), 1, 0, 0, 0, 1, "1-raw-0"},
		{uint8(ClassContext), 2, 3, 5, 10004, 10000, "2-context-3"},
		{uint8(ClassLineage), 3, 4, 0, 0, 1, "3-lineage-4"},
		{uint8(ClassFindings), 4, 5, 0, 0, 1, "4-findings-5"},
		{uint8(ClassAudit), 5, 6, 0, 0, 1, "5-audit-6"},

		// Invalid fields and ordinary range errors.
		{0, 1, 0, 0, 0, 1, "1-raw-0"},
		{6, 1, 0, 0, 0, 1, "1-unknown-0"},
		{uint8(ClassRaw), 0, 0, 0, 0, 1, "0-raw-0"},
		{uint8(ClassRaw), 1, 0, 0, 0, 0, "1-raw-0"},
		{uint8(ClassRaw), 1, 0, 0, 10000, 10001, "1-raw-0"},
		{uint8(ClassRaw), 1, 0, 5, 4, 1, "1-raw-0"},
		{uint8(ClassRaw), 1, 0, 0, 1, 1, "1-raw-0"},

		// Maximum sequence boundaries.
		{uint8(ClassLineage), 1, math.MaxUint64, math.MaxUint64, math.MaxUint64, 1, "1-lineage-18446744073709551615"},
		{uint8(ClassFindings), math.MaxUint64, 7, math.MaxUint64 - 9999, math.MaxUint64, 10000, "18446744073709551615-findings-7"},
		{uint8(ClassRaw), 1, 0, math.MaxUint64, 0, 1, "1-raw-0"},
		{uint8(ClassRaw), 1, 0, math.MaxUint64, math.MaxUint64, 2, "1-raw-0"},

		// Validation precedence, from no valid fields through count agreement.
		{0, 0, 0, 0, 0, 0, ""},
		{6, 0, 0, math.MaxUint64, 0, 10001, "mismatched"},
		{uint8(ClassRaw), 0, 0, math.MaxUint64, 0, 10001, "mismatched"},
		{uint8(ClassRaw), 1, 0, math.MaxUint64, 0, 10001, "mismatched"},
		{uint8(ClassRaw), 0, 0, 0, 0, 0, "mismatched"},
		{uint8(ClassRaw), 1, 0, 0, 0, 0, "mismatched"},
		{uint8(ClassRaw), 1, 0, 2, 1, 1, "mismatched"},
		{uint8(ClassRaw), 1, 0, 1, 2, 1, "mismatched"},

		// Canonical and alternate claimed IDs for the same valid descriptor.
		{uint8(ClassRaw), 9, 42, 5, 5, 1, "9-raw-42"},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, "09-raw-42"},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, "9-RAW-42"},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, "9-context-42"},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, "9-raw-042"},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, "9-raw-43"},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, " 9-raw-42"},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, "9-raw-42 "},
		{uint8(ClassRaw), 9, 42, 5, 5, 1, ""},
	}
	for _, seed := range seeds {
		f.Add(seed.class, seed.epoch, seed.segment, seed.first, seed.last, seed.count, seed.claimed)
	}

	f.Fuzz(func(t *testing.T, class uint8, epoch, segment, first, last uint64, count uint32, claimed string) {
		d := Descriptor{Class: SpoolClass(class), StreamEpoch: epoch, SegmentID: segment, FirstSequence: first, LastSequence: last, RecordCount: count}
		err := d.Validate()
		batchID := d.BatchID()
		if err != nil {
			if batchID != "" {
				t.Fatalf("invalid descriptor produced BatchID %q", batchID)
			}
			if got := ValidateBatchID(claimed, d); got != err {
				t.Fatalf("ValidateBatchID() error = %v, want exact validation error %v", got, err)
			}
			return
		}
		if batchID == "" {
			t.Fatal("valid descriptor produced an empty BatchID")
		}
		if got := ValidateBatchID(batchID, d); got != nil {
			t.Fatalf("ValidateBatchID(canonical) error = %v", got)
		}
		got := ValidateBatchID(claimed, d)
		if claimed == batchID {
			if got != nil {
				t.Fatalf("ValidateBatchID(%q) error = %v", claimed, got)
			}
		} else {
			requireError(t, got, ErrBatchID)
		}
	})
}
