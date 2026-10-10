// Package batch validates decoded event batch descriptors and their canonical identities.
package batch

import (
	"errors"
	"strconv"
)

var (
	ErrClass         = errors.New("invalid spool class")
	ErrStreamEpoch   = errors.New("invalid stream epoch")
	ErrRecordCount   = errors.New("invalid record count")
	ErrSequenceRange = errors.New("invalid sequence range")
	ErrSequenceCount = errors.New("sequence range does not match record count")
	ErrBatchID       = errors.New("invalid batch ID")
)

// SpoolClass identifies an independent event spool.
type SpoolClass uint8

const (
	ClassRaw SpoolClass = iota + 1
	ClassContext
	ClassLineage
	ClassFindings
	ClassAudit
)

// String returns the canonical name of c, or an empty string for an unknown class.
func (c SpoolClass) String() string {
	switch c {
	case ClassRaw:
		return "raw"
	case ClassContext:
		return "context"
	case ClassLineage:
		return "lineage"
	case ClassFindings:
		return "findings"
	case ClassAudit:
		return "audit"
	default:
		return ""
	}
}

// Descriptor identifies a contiguous sequence of records from one event spool.
type Descriptor struct {
	Class         SpoolClass
	StreamEpoch   uint64
	SegmentID     uint64
	FirstSequence uint64
	LastSequence  uint64
	RecordCount   uint32
}

// Validate checks the descriptor fields in their canonical validation order.
func (d Descriptor) Validate() error {
	if d.Class.String() == "" {
		return ErrClass
	}
	if d.StreamEpoch == 0 {
		return ErrStreamEpoch
	}
	if d.RecordCount == 0 || d.RecordCount > 10000 {
		return ErrRecordCount
	}
	if d.LastSequence < d.FirstSequence {
		return ErrSequenceRange
	}
	if d.LastSequence-d.FirstSequence != uint64(d.RecordCount-1) {
		return ErrSequenceCount
	}
	return nil
}

// BatchID returns the descriptor's canonical identity, or an empty string when invalid.
func (d Descriptor) BatchID() string {
	if d.Validate() != nil {
		return ""
	}
	return strconv.FormatUint(d.StreamEpoch, 10) + "-" + d.Class.String() + "-" + strconv.FormatUint(d.SegmentID, 10)
}

// ValidateBatchID checks that claimed is the canonical identity for d.
func ValidateBatchID(claimed string, d Descriptor) error {
	if err := d.Validate(); err != nil {
		return err
	}
	if claimed != d.BatchID() {
		return ErrBatchID
	}
	return nil
}
