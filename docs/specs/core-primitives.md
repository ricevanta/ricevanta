# Core event primitives

Two standard-library-only Go packages establish small, reusable checks for the event path. They implement settled invariants from `design/events.md` sections 2.3, 2.4, 3.1 and 3.2 without depending on the absent compiled OCSF schemas. They do not make event ingest complete.

## 1. Toolchain and location

- Module: `server/`, with module path `github.com/ricevanta/ricevanta/server`.
- `server/go.mod` starts with `module github.com/ricevanta/ricevanta/server`, then `go 1.27.1`. The directive sets the minimum Go version. The file has no `toolchain` directive.
- The design is tested locally with Go 1.27.1. CI pins Go 1.27.1.
- Dependencies: Go standard library only.

The packages are `server/internal/events/eventid` and `server/internal/events/batch`. Keeping both under `internal/events` prevents a premature public API.

## 2. UUIDv7 event identifiers

`eventid` validates `metadata.uid` before schema-generated event types exist.

```go
package eventid

type ID [16]byte

func Parse(text string) (ID, error)
func (id ID) String() string
```

`Parse` accepts exactly 36 ASCII bytes in the `8-4-4-4-12` hex-and-dash form. It requires lowercase hexadecimal, version bits `0111`, and variant bits `10`. `String` always formats the receiver's 16 raw bytes in lowercase `8-4-4-4-12` form. It does not validate version or variant, so every `ID`, including zero and values callers construct directly, has a deterministic string. `Parse` reports errors that work with `errors.Is`:

```go
var (
    ErrFormat       = errors.New("event id format")
    ErrNonCanonical = errors.New("event id is not lowercase canonical text")
    ErrVersion      = errors.New("event id is not UUIDv7")
    ErrVariant      = errors.New("event id has an unsupported UUID variant")
)
```

RFC 9562 permits mixed-case text. Ricevanta's lowercase-only form is a new internal contract. One accepted textual form makes logs, fixtures, duplicate analysis and byte comparisons consistent. Error checks run in this order: length and dash positions return `ErrFormat`; any uppercase `A` through `F` returns `ErrNonCanonical`, even when another position is not hexadecimal; any remaining non-hexadecimal byte returns `ErrFormat`; then version and variant return their specific errors. `Parse` returns the zero `ID` on every error.

Required vectors:

| Input | Result |
|---|---|
| `017f22e2-79b0-7cc3-98c4-dc0c0c07398f` | Accept; RFC 9562 UUIDv7 example and exact round trip |
| `017F22E2-79B0-7CC3-98C4-DC0C0C07398F` | `ErrNonCanonical` |
| `017f22e279b07cc398c4dc0c0c07398f` | `ErrFormat` |
| `017f22e2-79b0-6cc3-98c4-dc0c0c07398f` | `ErrVersion` |
| `017f22e2-79b0-7cc3-78c4-dc0c0c07398f` | `ErrVariant` |

Precedence vectors are also required: bad dash placement plus uppercase returns `ErrFormat`; correct shape with uppercase plus another invalid hexadecimal byte returns `ErrNonCanonical`; correct shape with a non-ASCII byte or invalid UTF-8 returns `ErrFormat`; invalid hexadecimal plus wrong version bits returns `ErrFormat`; and wrong version plus wrong variant returns `ErrVersion`. `String` must format zero as `00000000-0000-0000-0000-000000000000`, `ID{6: 0x60, 8: 0x80}` as `00000000-0000-6000-8000-000000000000`, and `ID{6: 0x70, 8: 0x70}` as `00000000-0000-7000-7000-000000000000`.

The parser does not generate UUIDs, check timestamp plausibility, prove uniqueness, enforce monotonic generation, or validate `metadata.correlation_uid`.

`FuzzParse` supplies arbitrary strings. It asserts no panic and, on success, an exact `String` and `Parse` round trip.

## 3. Event batch descriptors

`batch` validates a descriptor after a future transport layer decodes it.

```go
package batch

type SpoolClass uint8

const (
    ClassRaw SpoolClass = iota + 1
    ClassContext
    ClassLineage
    ClassFindings
    ClassAudit
)

type Descriptor struct {
    Class         SpoolClass
    StreamEpoch   uint64
    SegmentID     uint64
    FirstSequence uint64
    LastSequence  uint64
    RecordCount   uint32
}

func (d Descriptor) Validate() error
func (d Descriptor) BatchID() string
func ValidateBatchID(claimed string, d Descriptor) error
func (c SpoolClass) String() string
```

Canonical class names are `raw`, `context`, `lineage`, `findings` and `audit`. The numeric values, short class names and rules below are new internal contracts. They make the existing five spool classes exact for code without defining the missing `Ricevanta-Batch` wire schema.

Validation applies in this order:

1. `Class` is one of the five constants.
2. `StreamEpoch` is nonzero. Zero is reserved to catch an uninitialized random epoch.
3. `RecordCount` is from 1 through 10,000 inclusive. An agent segment contains at least one record, and server admission caps a batch at 10,000 lines.
4. `LastSequence` is at least `FirstSequence`.
5. `LastSequence - FirstSequence == uint64(RecordCount - 1)`. The subtraction occurs only after step 4, so hostile bounds cannot wrap. This enforces the segment's contiguous per-class sequence.

`SegmentID`, `FirstSequence` and `LastSequence` may be zero. The current contracts do not state a starting counter. Reserving those zero values would add no safety because the class, epoch and count already detect a zero descriptor.

`SpoolClass.String` returns the canonical name, or the empty string for an unknown value. `BatchID` returns the empty string when `Validate` fails. Otherwise it returns `<stream epoch>-<class>-<segment id>` with base-10 unsigned integers without leading zeroes. `ValidateBatchID` first calls `d.Validate` and returns that validation error unchanged. For a valid descriptor, it requires byte equality with `d.BatchID` and returns `ErrBatchID` on inequality. It does not parse a claimed ID into a descriptor.

Errors are stable sentinels for `errors.Is`: `ErrClass`, `ErrStreamEpoch`, `ErrRecordCount`, `ErrSequenceRange`, `ErrSequenceCount` and `ErrBatchID`. No function panics for any value.

Required vectors include each valid class; counts 1 and 10,000; sequence range `0..0` for count 1; range `5..10004` for count 10,000; unknown classes 0 and 6; zero epoch; counts 0 and 10,001; reversed ranges; mismatched counts; leading-zero IDs; wrong class names; and valid descriptor ID round trips.

Boundary vectors include `MaxUint64..MaxUint64` with count 1 as valid; `MaxUint64-9999..MaxUint64` with count 10,000 as valid; `MaxUint64..0` as `ErrSequenceRange`; and `MaxUint64..MaxUint64` with count 2 as `ErrSequenceCount`. Multi-invalid descriptors must prove every step of the stated validation order. `ValidateBatchID` with both an invalid descriptor and a mismatched claimed ID returns the descriptor's first validation error, never `ErrBatchID`.

The multi-invalid table starts with every omitted field. It then makes one field valid at a time: unknown class returns `ErrClass`; valid class with zero epoch returns `ErrStreamEpoch`; valid class and epoch with zero count returns `ErrRecordCount`; valid class, epoch and count with `FirstSequence > LastSequence` returns `ErrSequenceRange`; and otherwise valid fields whose range disagrees with count return `ErrSequenceCount`.

`FuzzDescriptor` supplies arbitrary field values and claimed IDs. It asserts no panic. Every valid descriptor must produce a nonempty ID that `ValidateBatchID` accepts, and every invalid descriptor must produce an empty ID.

## 4. Trust boundary and non-goals

Both packages process attacker-controlled agent input. They bound work to fixed-size values, allocate no input-sized collections, use no regular expressions and never panic on malformed input. Callers must still cap compressed and decompressed bytes before these checks.

This slice does not define or parse the `Ricevanta-Batch` header, zstd skippable frame, or NDJSON body. The machine wire schema remains absent. It does not count body lines, compare event sequences with the descriptor, validate JSON or OCSF, bind a device, authenticate a sender, verify extension provenance, deduplicate data, write a ledger or database, quarantine an event, or acknowledge a batch. Descriptor validity supplies no authenticity or ingest guarantee.

## 5. Benefits, trade-offs and alternatives

The packages isolate cheap checks that later transport and schema code can call without a database. Typed errors support metrics and precise rejection tests. The cost is two small packages before their callers exist.

A general UUID dependency would add a dependency for four bit and shape checks. Accepting every RFC text spelling would preserve equivalent strings in raw events. Parsing the unspecified batch header now would freeze a wire format without a machine-readable contract. These alternatives are outside this slice.

Source: [RFC 9562 sections 4, 4.1, 4.2, 5.7 and Appendix A.6](https://www.rfc-editor.org/rfc/rfc9562).
