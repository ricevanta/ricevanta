# Event upload wire contract

This specification defines the descriptor prefix for `POST /agent/v1/events` and its response bodies. The implementation slice parses the header and descriptor frame only. It builds on [core primitives](core-primitives.md#3-event-batch-descriptors); it does not make ingest ready.

## 1. Scope and contract files

`schemas/events/v1/` owns the transport contract because the version belongs to the event upload protocol, independently of OCSF and the product release. `header.abnf` defines accepted header syntax, `response.schema.json` defines response bodies, `contract.json` describes framing and HTTP status bindings, and `fixtures/` contains conformance vectors. `fixture.schema.json` validates the fixture containers. The prose owns semantics and error precedence; the machine files must agree with it.

The decoder uses Go 1.27.1, module `github.com/ricevanta/ricevanta/server`, and the standard library only. The [Go package inventory](https://pkg.go.dev/std@go1.27.1) and installed `go list std` show no public zstd decoder. [`internal/zstd`](https://pkg.go.dev/internal/zstd@go1.27.1) is not importable by this module. NDJSON decompression needs a separate reviewed decision and a dependency row in `docs/licensing.md`; this slice adds neither.

Decision: [EV-08](../decisions.md#ev-08-event-upload-descriptor-wire-contract).

## 2. Request header

The request carries `Content-Type: application/x-ndjson`, `Content-Encoding: zstd`, and exactly one `Ricevanta-Batch` field in the initial header section. No trailer may supply or override it. HTTP field names are case-insensitive; descriptor keys and class names are case-sensitive. The canonical value is:

```text
v=1;class=raw;epoch=1;segment=0;first=0;last=0;count=1
```

Keys occur exactly once, in that order, with no optional keys. `v` is wire version 1. `class` uses the names in the core-primitives contract. `epoch`, `segment`, `first` and `last` map to the four `uint64` fields of `batch.Descriptor`; `count` maps to `RecordCount`, a `uint32`. Integers use unsigned ASCII decimal, with `0` as the only zero spelling and no leading zeros. Descriptor validation, including the nonzero epoch and contiguous sequence range, is exactly `batch.Descriptor.Validate`.

The maximum field value length is 139 bytes, excluding the name, colon and HTTP framing whitespace. This fits all valid descriptors, including four 20-digit integers, `findings`, and `count=10000`. There is no separate claimed batch ID. Derive it with `Descriptor.BatchID`, which agrees with `batch.ValidateBatchID`.

The HTTP parser removes outer HTTP whitespace before calling the decoder. The decoder accepts no whitespace in the value it receives, including outer whitespace. It rejects signs, alternate bases, quotes, commas, escapes, non-ASCII bytes, NUL, CR, LF, missing or extra keys, wrong key order or case, empty tokens and numeric overflow. It never trims or normalizes values. HTTP-level outer whitespace removed by the server cannot be detected here and is not claimed to be rejected on the socket.

Repeated field lines are invalid even if identical. Pass every value to `ParseHeader`; never use a first-value accessor or join values. A comma-coalesced value is also invalid. A trusted HTTP adapter must preserve repeated values; middleware must not discard duplicates. These rules follow the single-value field model in [RFC 9110 sections 5.1 to 5.5](https://www.rfc-editor.org/rfc/rfc9110.html#section-5). HTTP supplies no fixed field-size ceiling; 139 is a Ricevanta limit, independent of the future listener's aggregate header cap.

Rejected alternatives: arbitrary key order and optional whitespace create equivalent byte strings; JSON or base64 makes routine diagnosis harder; Structured Fields adds a general parser where this contract needs only seven fixed fields. This contract does not use RFC 8941 syntax. A separate batch ID repeats derivable data and introduces another mismatch case.

## 3. Descriptor frame

The uploaded body is the sealed file: exactly this descriptor frame, followed by one ordinary zstd frame of NDJSON. All offsets below count from body byte zero. There is no alignment padding beyond the explicit reserved bytes.

| Offset | Bytes | Encoding | Meaning |
|---|---|---|---|
| 0 | 4 | Little-endian u32, `0x184D2A50` | Magic, bytes `50 2a 4d 18` |
| 4 | 4 | Little-endian u32, 40 | Payload size, bytes `28 00 00 00` |
| 8 | 1 | u8, 1 | Wire version |
| 9 | 1 | u8 | `batch.SpoolClass`, values 1 through 5 |
| 10 | 2 | Both zero | Reserved, must be checked |
| 12 | 8 | Little-endian u64 | `StreamEpoch` |
| 20 | 8 | Little-endian u64 | `SegmentID` |
| 28 | 8 | Little-endian u64 | `FirstSequence` |
| 36 | 8 | Little-endian u64 | `LastSequence` |
| 44 | 4 | Little-endian u32 | `RecordCount` |

The total frame is 48 bytes. Its version is independent of the active spool file version. No device ID, checksum, batch ID string or extra payload field is present. Require magic equality, not merely membership in the skippable range. Reject a size other than 40 before reading payload bytes or allocating storage. No extension bytes or second descriptor frame are accepted by the full upload contract.

[RFC 8878 section 3.1.2](https://www.rfc-editor.org/rfc/rfc8878#section-3.1.2) permits magic values `0x184D2A50` through `0x184D2A5F`. Its little-endian unsigned 32-bit size excludes the eight framing bytes and permits at most 4,294,967,295 payload bytes. The chosen magic identifies Ricevanta metadata only within this protocol, not a registered global format. A generic zstd decoder skips the payload, so descriptor validation must precede decompression.

Rejected alternatives: encoding the header text or JSON inside the frame adds variable-length parsing; native struct serialization exposes padding and host endianness; accepting every skippable magic hides foreign metadata; using the RFC maximum as an allocation size lets an attacker demand gigabytes.

### 3.1 Following zstd frame, enforced by a later slice

The ordinary frame starts with magic `0xFD2FB528`. Require `Content_Checksum_Flag` (bit 2) set and a present `Frame_Content_Size`. Presence means bits 7 to 6 are nonzero **or** `Single_Segment_Flag` (bit 5) is set. A zero size flag with bit 5 set is valid for small content. The two-byte content-size form adds 256 to its encoded value. These are [RFC 8878 section 3.1.1](https://www.rfc-editor.org/rfc/rfc8878#section-3.1.1) rules, not a new single-bit size flag.

The Ricevanta profile requires reserved bit 3 and unused bit 4 zero, dictionary flag bits 1 to 0 zero, and no external dictionary. Bound the advertised window and content size to 67,108,864 bytes before allocation. Verify the checksum, actual decompressed size, exactly one ordinary frame, and physical end of body. Reject extra ordinary or skippable frames and trailing bytes. Reject checksum errors and malformed framing as 400; reject resource ceilings as 413. The checksum detects corruption, not forgery.

This decoder leaves byte 48 unread and checks none of these conditions. A prefix-only fixture is valid for `Decode`, not a complete upload. Requiring a specific content-size flag or single-segment encoding would exclude valid small frames; accepting concatenation or external dictionaries adds ambiguity and state.

## 4. Consistency and trust

The authenticated context is authoritative for device identity. The header carries no device identity. The handler checks the certificate, authorization lease, device state and update-only mode before reading the body, under [backend section 3](../design/backend.md#3-agent-facing-handler-rules). Neither descriptor changes those facts.

The header supplies a tentative class for admission; it cannot authorize storage or acknowledgement. Parse and validate both descriptors, then compare all six typed fields. Any difference returns `ErrDescriptorMismatch` and ultimately 400, with no storage, ledger hit acknowledgement or quarantine. Neither descriptor wins. On success return the header descriptor, whose identity is also the frame's identity. Equality catches corruption and conflicting routing metadata; it does not prove that a hostile agent told the truth in both copies.

Future ingestion must use `(authenticated device, descriptor.BatchID())` for ledger lookup, including duplicate responses. The full request must pass transport and framing checks before any 200. Event `device.uid` mismatches remain per-event quarantine and a security finding under [events section 3.2](../design/events.md#32-validation-and-binding), not a new identity source. Future validation checks actual line count against `RecordCount` and sequence membership; the descriptor decoder cannot inspect these facts.

Rejected alternatives: preferring the header allows the compressed file to describe another stream; preferring the frame changes an admitted class after admission; accepting a device ID in either copy creates a caller-controlled identity path. No stream epoch is an authorization or recovery epoch.

## 5. Response bodies and status binding

All listed application responses have `Content-Type: application/json` and `Cache-Control: no-store`. JSON object order is immaterial; fields are required, unknown fields and duplicate JSON member names are forbidden. The schema validates parsed values; the future response consumer must reject duplicate members while parsing. There is no free-text error detail or echoed input.

| HTTP status | Exact body shape | Meaning |
|---|---|---|
| 200 | `{ "batch_id": "1-raw-0", "result": "stored", "stored": 1, "quarantined": 0 }` | First committed ledger result |
| 200 | `{ "batch_id": "1-raw-0", "result": "duplicate", "stored": 1, "quarantined": 0 }` | Replay of the committed counts, not new writes |
| 400 | `{ "error": "malformed_batch" }` | Header, descriptor or full-body framing failure |
| 413 | `{ "error": "batch_too_large" }` | Compressed, decompressed, line-count or line-size ceiling exceeded |
| 403 | `{ "error": "update_only" }` | Authenticated device can only update or renew |
| 429 | `{ "error": "rate_limited" }` | Request rate exceeds admission allowance |
| 503 | `{ "error": "unavailable" }` | Queue, store, ledger, authority snapshot or acknowledgement fence unavailable |

`batch_id` must equal the request descriptor's canonical ID. Counts are JSON integers from 0 through 10,000. `stored` counts valid input records newly persisted or routed to their designated durable store in the original batch commit; it does not count copies across stores. Event-UID conflict skips are excluded. `quarantined` counts rejected event records persisted in quarantine. Thus `stored + quarantined <= RecordCount`; the difference is event-UID skips. A `stored` result with both counts zero is valid when all records already exist. `duplicate` repeats the original counts, even when the retry would encounter different validation state. The ledger must retain those counts. A changed descriptor under an existing device/batch ID is 400; its detection needs the future ledger to retain the complete descriptor.

The schema checks individual count bounds and canonical uint64 ID components. Cross-field sums, equality with the request, ledger comparisons and duplicate-member detection are semantic checks outside JSON Schema. Fixtures name these layers so a schema-valid but semantically invalid body cannot be mistaken for an acknowledgement.

429 and 503 require exactly one `Retry-After` field using canonical decimal delay-seconds from 5 through 60 inclusive, after server jitter and rounding. The 503 range follows events section 3.7; v1 uses the same range for 429. No HTTP-date or body delay field is emitted. [RFC 9110 section 10.2.3](https://www.rfc-editor.org/rfc/rfc9110.html#section-10.2.3) permits delay-seconds. Client retry behavior stays in events section 2.4. A malformed 200, mismatched batch ID or impossible counts never permits deletion. 413 keeps the file in `rejected/` and emits the same rejected-drop record as 400; retrying the unchanged oversized file cannot succeed.

Only a successful current-primary acknowledgement fence permits either 200 ([events section 3.5](../design/events.md#35-write-and-acknowledgement)). This slice produces no response. HTTP parser failures before the application, generic 401/403 authorization failures and other 5xx bodies belong to the handler slice.

Rejected alternatives: zeroing duplicate counts loses the persisted result; counting UID skips as new writes misstates storage; returning a detailed parser error exposes input; acknowledging before durability breaks EV-04. Encoding integers as JSON strings adds work for bounded counts without a precision benefit.

## 6. Go API and error precedence

Create `server/internal/events/wire`. It imports only `batch` and the standard library. `wire` has no downstream consumer imports; `batch` remains transport-independent. Adding HTTP parsing to `batch` would couple primitive validation to transport. Keeping the API below `internal/` avoids a public compatibility promise.

```go
package wire

const (
    MaxHeaderBytes = 139
    DescriptorFrameBytes = 48
    MaxCompressedBytes int64 = 5_000_000
)

func ParseHeader(values []string) (batch.Descriptor, error)
func Decode(values []string, body *io.LimitedReader) (batch.Descriptor, error)

var (
    ErrHeaderCount = errors.New("event batch header count")
    ErrHeaderSize = errors.New("event batch header size")
    ErrHeaderSyntax = errors.New("event batch header syntax")
    ErrVersion = errors.New("event batch wire version")
    ErrReaderBound = errors.New("event batch reader bound")
    ErrFrameRead = errors.New("event batch frame read")
    ErrFrameMagic = errors.New("event batch frame magic")
    ErrFrameSize = errors.New("event batch frame size")
    ErrFrameReserved = errors.New("event batch frame reserved bytes")
    ErrDescriptorMismatch = errors.New("event batch descriptor mismatch")
)
```

Every failure returns the zero descriptor. Match sentinels with `errors.Is`, not message text. Return `batch` validation errors unchanged; do not replace or alias them. No exported frame encoder, HTTP adapter, response type or response encoder is needed in this slice.

`ParseHeader` applies these stages, stopping at the first failure:

1. `len(values) != 1`: `ErrHeaderCount`, before inspecting any value.
2. Value longer than `MaxHeaderBytes`: `ErrHeaderSize`. An empty value reaches syntax validation.
3. Check the entire lexical shape and representability: seven exact ordered keys, lowercase ASCII alphabetic class token, canonical unsigned decimal values. Parse `v` as uint8, four counters as uint64, count as uint32. Any overflow or malformed token is `ErrHeaderSyntax`, even with an unsupported version or unknown class. This stage admits unknown lowercase class tokens for the next checks.
4. A representable `v` other than 1: `ErrVersion`.
5. Map an unknown class to zero and call `Descriptor.Validate`. Its precedence remains class, epoch, count, sequence range, sequence count.

The ABNF describes **accepted** values. Stages 3 to 5 classify invalid values outside that language, including `v=2`, unknown classes, and zero epoch. Do not let a grammar library erase the error distinction.

`Decode` first calls `ParseHeader`; no body read or reader validation precedes it. Then:

1. Require a non-nil `body`, non-nil `body.R` interface, and `0 <= body.N <= MaxCompressedBytes + 1`; otherwise `ErrReaderBound`. A caller must provide a usable reader, not a typed-nil interface or a reader that violates `io.Reader`. Deadlines and cancellation belong to that reader.
2. `io.ReadFull` four magic bytes, then check magic. Read failure is `ErrFrameRead`; wrong magic is `ErrFrameMagic` without reading size.
3. `io.ReadFull` four size bytes, then check size equals 40; otherwise `ErrFrameSize` without reading payload.
4. `io.ReadFull` the fixed 40-byte payload. Incomplete payload is `ErrFrameRead`, even when a received version or reserved byte is invalid.
5. Check payload version, then both reserved bytes, then `Descriptor.Validate`; return `ErrVersion`, `ErrFrameReserved` or the first `batch` error.
6. Compare the complete valid descriptors; return `ErrDescriptorMismatch` on any inequality.

Wrap `ErrFrameRead` and its underlying I/O error so `errors.Is` matches both, including `io.EOF` and `io.ErrUnexpectedEOF`. Other errors match only the selected wire or batch sentinel. Do not expose parsed fragments. `Decode` neither closes nor drains the reader. On success it consumes exactly 48 bytes and decrements `N` by 48; on failure it consumes only the bytes of the stages reached, at most 48. It must not buffer or prefetch later bytes.

A fresh caller uses `N = MaxCompressedBytes + 1`, including the descriptor, reserving one overflow probe byte. The future body consumer uses the same reader and tracks total consumption from the initial budget; reaching 5,000,001 means 413. It must prove real end-of-body before success rather than treating budget exhaustion as valid EOF. A successful prefix decode establishes no whole-body size bound. The caller must not reset the budget or discard the descriptor's consumed bytes.

Use fixed arrays, `encoding/binary.LittleEndian`, bounded string splitting and decimal parsing. Production standard-library imports are [`encoding/binary`](https://pkg.go.dev/encoding/binary@go1.27.1), [`errors`](https://pkg.go.dev/errors@go1.27.1), [`fmt`](https://pkg.go.dev/fmt@go1.27.1), [`io`](https://pkg.go.dev/io@go1.27.1), [`strconv`](https://pkg.go.dev/strconv@go1.27.1) and [`strings`](https://pkg.go.dev/strings@go1.27.1). `io.ReadFull` distinguishes empty from partial reads; `LimitedReader` bounds reads through `N`; `fmt.Errorf` can wrap both sentinels and causes. Avoid regular expressions, reflection, `io.ReadAll` and allocation from frame sizes. Malformed bytes never panic; a broken caller-supplied reader is outside that guarantee.

## 7. Limits and ownership

| Check | Exact limit | Enforcement |
|---|---|---|
| Header value | 139 bytes | This slice |
| Descriptor frame | 40-byte payload, 48 total | This slice |
| Declared records | 1 through 10,000 | This slice through `batch.Validate` |
| Compressed body | 5 MB = 5,000,000 bytes, descriptor included | Future body reader; this slice only bounds its reader budget and prefix work |
| Streamed decompressed NDJSON | 64 MiB = 67,108,864 bytes | Future decompressor, including line terminators |
| Actual lines | 1 through 10,000, equal to `RecordCount` | Future NDJSON reader |
| Line payload | 1 MiB = 1,048,576 bytes, excluding LF | Future NDJSON reader |
| OCSF fields and lists | `schemas/ocsf/limits.yaml` | Future generated validation; no substitution by the line cap |

The complete NDJSON body uses UTF-8 JSON objects, one per LF-terminated line, no blank lines, BOM or CRLF. Each payload must fit the line limit. Count mismatch or missing final LF is malformed (400); any resource ceiling exceeded is 413. Invalid event objects within valid line framing follow per-event quarantine. Future checks must count bytes, not Unicode characters, and must apply decompression and window limits before trusting advertised content size.

Header and frame failures map to 400, including invalid declared count; actual excessive line count maps to 413. `ErrReaderBound` is caller misuse and has no client status mapping. `ErrFrameRead` with EOF indicates malformed input; cancellation, timeout and connection failure do not warrant a synthetic 400. The future handler controls their transport outcome and must never emit 200.

Authentication refusal precedes body work. Capacity refusal may return 429 or 503 without reading a frame. On an admitted request, parser errors follow section 6; a declared compressed length over the ceiling may yield 413 before parsing. There is no global precedence over defects in unread body bytes. Aggregate headers, read deadlines, streaming budgets and full-ingest gates remain handler responsibilities.

## 8. Threat trace, benefits and dependencies

| Attacker | Boundary and remaining ability |
|---|---|
| Stolen enrollment token | The upload handler needs a valid device certificate, not the token. If enrollment issues one, the attacker can upload as that enrolled device; wire parsing grants no wider identity. |
| Compromised agent host | Can fabricate matching descriptors and events, replay its own batch IDs and consume bounded parsing work. mTLS scopes identity; later ledger, event binding and admission checks limit effects. Checksums and matching copies do not prove truthful telemetry. |
| Compromised console session | A console session is not an agent certificate. The wire decoder accepts no session or device override; protected enrollment changes remain outside this slice. |
| Rogue extension publisher | Publication supplies no upload credential. The core owns transport; future event provenance checks bind grants. This decoder proves neither publisher trust nor extension provenance. |
| Network position | mTLS with the pinned root and server TLS termination protects request and response bytes. The prefix itself is unsigned; if transport trust is broken, equal descriptors and checksums offer no authenticity. Truncation yields a read error and never an acknowledgement. |
| Database writer without signing keys | Cannot gain transport identity from these bytes. Can corrupt unprotected event or ledger data; this decoder provides no database integrity. A ledger row alone must not bypass the acknowledgement fence. |
| Server restored from backup | Stream epochs cannot prove current authority or revive a certificate. BE-12 sealed recovery and the live authorization snapshot remain required; this decoder restores no counters, ledger entries or authority. |

Benefits: one canonical header, fixed parsing cost, portable binary fields and shared Rust/Go fixtures. Trade-offs: duplicate metadata costs 48 body bytes and requires a comparison; strict v1 fields require an explicit protocol revision for extensions. Dependencies: the existing `batch` package and standard library only. Limits: no decompression, JSON/OCSF validation, authentication, storage, deduplication, signing, acknowledgement or OS qualification. The byte contract applies equally to macOS ARM64, Windows x64 and Linux x64; this design claims no platform test result.

## 9. Required vectors and review focus

`fixtures/descriptor.json` covers every class, zero counters where allowed, 10,000 records, uint64 maxima, all truncation lengths 0 through 47, every alternate skippable magic, endian mistakes, maximum frame size, version and reserved bytes, semantic descriptor failures, mismatches, and combined defects. It records expected sentinel names and bytes consumed. Hex encodes descriptor bytes only; appended suffix probes test that byte 48 stays unread.

`fixtures/header.json` covers header count, byte limit, lexical variants, numeric width boundaries, version precedence and every `batch` semantic error. `fixtures/response.json` covers each status, unknown fields, type and bound errors, and schema-valid semantic failures. Descriptor integers in fixture metadata are decimal strings so JavaScript readers preserve all uint64 values. Hex is lowercase, even-length, without separators. Fixture containers are data, never an instruction to allocate a claimed frame size.

Review focus:

- Distinguish HTTP field normalization from decoder strictness and retain duplicate values.
- Preserve zero-on-error and precedence across header, reader, frame and `batch` defects.
- Bound reads and allocations even for an RFC-maximum payload claim or truncated reader.
- Compare every descriptor field before a ledger acknowledgement can be considered.
- Keep declared counts, actual body checks and durable acknowledgement separate.
- Validate fixtures independently, including full-width integers and response semantics.
- Keep independent design approval as a code prerequisite.
