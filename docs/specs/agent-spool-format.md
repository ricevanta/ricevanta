# Agent spool segment format

`ricevanta-spool` encodes and recovers uncompressed v1 segment bytes without file access. It is the first Rust library slice, not an operational spool. [AG-10](../decisions.md#ag-10-spool-format-library) records the boundary. [Events section 2](../design/events.md#2-agent-pipeline) owns the pipeline; [the implementation plan](../plans/agent-spool-format.md) owns construction and checks.

## 1. Location and dependencies

The virtual Cargo workspace is `agent/`; its sole initial member is `crates/spool`, package `ricevanta-spool`, Rust import `ricevanta_spool`. The future core's `events` module calls this leaf crate. It imports no core, runtime, OS adapter, transport or database code. This fits [the repository layout](../architecture.md#6-repository-layout) without creating absent component directories.

[instructions/rust.md](../../instructions/rust.md) owns toolchain, package metadata and lint rules. The only direct crate dependency is `crc32c = "=0.6.8"`, default features enabled. Its build dependency is `rustc_version` 0.4.1, whose dependency is `semver` 1.0.27; lock these exact versions in `agent/Cargo.lock`. There are no dev dependencies. The [crc32c manifest](https://docs.rs/crate/crc32c/0.6.8/source/Cargo.toml) declares its build dependency; [rustc_version](https://docs.rs/rustc_version/0.4.1/rustc_version/) and [semver](https://docs.rs/semver/1.0.27/semver/) document the selected versions. The plan requires license records for the complete closure before code uses it; verify the exact release license texts and resolved closure before implementation.

## 2. Exact byte contract

Offsets are zero-based bytes. Integers are unsigned and little-endian, independent of host architecture. Encode fields explicitly; Rust struct layout, alignment and native-endian casts are not the format. There is no footer or record padding.

| Header offset | Bytes | Value |
|---|---|---|
| 0 | 4 | ASCII `RVSP`, hex `52565350` |
| 4 | 2 | Format version u16, exactly 1 |
| 6 | 1 | Class u8, table below |
| 7 | 1 | Reserved, exactly zero |
| 8 | 8 | Stream epoch u64, nonzero |
| 16 | 8 | Segment id u64, zero allowed |
| 24 | 8 | First sequence u64, zero allowed |

The reserved byte makes the header exactly 32 bytes. Unsupported versions or classes are fatal errors; never reinterpret them as v1, skip them, or recommend truncation. Nonzero reserved bytes are also fatal. Headers carry no checksum. Epoch creation and counter persistence belong to the spool manager, not this library.

| Rust variant | Number | `as_str()` | Go constant |
|---|---|---|---|
| `Raw` | 1 | `raw` | `batch.ClassRaw` |
| `Context` | 2 | `context` | `batch.ClassContext` |
| `Lineage` | 3 | `lineage` | `batch.ClassLineage` |
| `Findings` | 4 | `findings` | `batch.ClassFindings` |
| `Audit` | 5 | `audit` | `batch.ClassAudit` |

These values match [core primitives section 3](core-primitives.md#3-event-batch-descriptors) and `server/internal/events/batch/descriptor.go`. The [upload descriptor frame](event-upload-wire.md#3-descriptor-frame) is a different format, with a one-byte version and two reserved bytes. Never emit a spool header as an upload prefix.

For a record starting at offset `r`:

| Offset | Bytes | Value |
|---|---|---|
| r | 4 | Payload length u32, excludes all 16 framing bytes |
| r + 4 | 4 | CRC32C u32 |
| r + 8 | 8 | Per-class sequence u64 |
| r + 16 | Length | Exact payload bytes |

CRC32C covers the eight stored little-endian sequence bytes followed by the payload. It excludes the length, stored checksum and header. Use `crc32c::crc32c_append(crc32c::crc32c(&sequence.to_le_bytes()), payload)` without concatenating an allocated buffer. The [crate API](https://docs.rs/crc32c/0.6.8/crc32c/) defines checksum continuation. The fixture oracle uses reflected Castagnoli polynomial `0x82f63b78`, initial register `0xffffffff`, final XOR `0xffffffff`; ASCII `123456789` has checksum `0xe3069283`.

`MAX_PAYLOAD_LEN` is 1,048,576 bytes, matching the server's [line payload ceiling](event-batch-body.md#5-ndjson-framing). Zero-length payloads are legal framing. The codec accepts arbitrary bytes, including invalid UTF-8, literal newline and non-JSON. The event producer must supply OCSF JSON without a line terminator and bind `metadata.sequence`; the codec does not establish either property. Framing-valid empty or non-JSON payloads do not qualify for upload.

## 3. Public Rust API

All items below live at the crate root. No other public API is required. Value types derive `Debug, Clone, Copy, PartialEq, Eq`; `Recovery` derives `Debug` only. `Error` implements `Display` and `std::error::Error`, with `source()` returning `None`. Display text is diagnostic, not a stable machine contract; match variants and fields instead of strings, the Rust equivalent of the Go sentinel checks.

```rust
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 32;
pub const RECORD_HEADER_LEN: usize = 16;
pub const MAX_PAYLOAD_LEN: usize = 1_048_576;

#[repr(u8)]
pub enum SpoolClass { Raw = 1, Context = 2, Lineage = 3, Findings = 4, Audit = 5 }
impl TryFrom<u8> for SpoolClass {
    type Error = Error;
    fn try_from(value: u8) -> Result<Self, Self::Error>;
}
impl SpoolClass { pub const fn as_str(self) -> &'static str; }

pub struct Header {
    pub class: SpoolClass,
    pub stream_epoch: u64,
    pub segment_id: u64,
    pub first_sequence: u64,
}
pub struct Record<'a> { pub sequence: u64, pub payload: &'a [u8] }
pub enum TailKind { Incomplete, Checksum }
pub struct TailIssue { pub offset: usize, pub kind: TailKind }
pub enum Error {
    HeaderTooShort { actual: usize },
    Magic,
    Version { found: u16 },
    Class { found: u8 },
    Reserved { found: u8 },
    StreamEpoch,
    PayloadTooLarge { length: usize },
    OutputTooSmall { needed: usize, actual: usize },
    Sequence { offset: usize, expected: Option<u64>, found: u64 },
}

pub fn encode_header(header: Header) -> Result<[u8; HEADER_LEN], Error>;
pub fn encode_record(record: Record<'_>, output: &mut [u8]) -> Result<usize, Error>;
pub fn recover(input: &[u8]) -> Result<Recovery<'_>, Error>;

pub struct Recovery<'a> { /* private validated prefix and summary */ }
impl<'a> Recovery<'a> {
    pub fn header(&self) -> Header;
    pub fn valid_len(&self) -> usize;
    pub fn record_count(&self) -> usize;
    pub fn next_sequence(&self) -> Option<u64>;
    pub fn tail(&self) -> Option<TailIssue>;
    pub fn records(&self) -> impl Iterator<Item = Record<'a>> + 'a;
}
```

`TryFrom<u8>` returns `Error::Class` for every value except 1 through 5. There is no invalid enum sentinel or unchecked numeric conversion. `encode_header` rejects a zero epoch and otherwise emits canonical v1 bytes. It has no configurable version or reserved byte.

`encode_record` first rejects oversized payloads, then rejects output shorter than `16 + payload.len()`. Either error leaves the entire output unchanged. On success it returns that exact encoded length and leaves bytes beyond it unchanged. It neither assigns nor checks sequence continuity because one record has no segment context. It performs no I/O, allocation, append or sync.

`recover` borrows immutable input. Success holds only a borrowed prefix and constant-size summary, not a vector of records. `records()` returns records in stored order, with payloads borrowing the original input. Iteration over the validated prefix repeats length/offset reads but need not recompute CRCs. Repeated iteration returns identical values. No returned reference points into the rejected suffix. The private state prevents callers from changing the validated bounds.

There is no global input-byte or record-count ceiling in this format library. Recovery is linear in supplied bytes up to the first bad record; iteration is linear in the accepted record count. Auxiliary memory is constant. The caller owns and bounds the input allocation and concurrent scans. Loading arbitrary files wholesale is not a production integration approved by this slice. The manager's 4 MiB/5,000-record sealing policy is not a format validity test.

## 4. Recovery and error precedence

Header checks run before any record access, in this order: fewer than 32 bytes gives `HeaderTooShort`, then magic, version, class, reserved byte, and nonzero epoch. A fatal error returns no `Recovery`, prefix, records or truncation recommendation. The input never changes.

After a valid header, start at offset 32 with expected sequence `Some(header.first_sequence)`. At each record boundary apply exactly this order:

1. No remaining bytes: succeed with no tail issue. A header-only segment is valid with count zero, `valid_len = 32` and `next_sequence = Some(first_sequence)`.
2. Fewer than four remaining bytes: succeed with `Incomplete` at the current offset.
3. Read length. If greater than `MAX_PAYLOAD_LEN`, return `PayloadTooLarge`, even if the record is also incomplete. This refuses unsupported framing without treating it as a repairable write.
4. If fewer than `16 + length` bytes remain, succeed with `Incomplete`. This includes a torn checksum, sequence or payload. Compare remaining lengths before slicing; never add an unchecked hostile offset.
5. Compute CRC. A mismatch succeeds with `Checksum` at the current offset, even if that record's sequence is wrong.
6. Compare sequence with the expected value. Inequality, or any complete checksum-valid record when expected is `None`, returns `Sequence`. Do not hide a gap, duplicate, reversal or wrap as a torn tail.
7. Accept the record; advance by `16 + length`, increment count, and set expected to `sequence.checked_add(1)`. Continue.

On a tail issue, `valid_len` equals the bad record's start and includes every preceding complete good record. `next_sequence` is the expected sequence at that offset. Stop immediately: never search for another magic, salvage later records, or inspect defects in the discarded suffix. An interior corrupt record discards the entire suffix under the same rule as a final corrupt record.

A good record at `u64::MAX` is legal and makes `next_sequence = None`; exhaustion is not zero. A partial or bad-checksum suffix after it still follows steps 2 through 5. A further checksum-valid record returns `Sequence { expected: None, ... }`. The later manager must refuse another append in that stream and specify the epoch transition separately.

A torn final record loses that record only. The later manager must hold exclusive ownership of the active segment, truncate to `valid_len`, establish native durability, then resume at `next_sequence`. Recovery alone neither truncates nor makes reuse durable. A completely missing final record is indistinguishable from clean EOF. Neither a checksum nor an in-memory scan proves a record ever reached stable storage.

Required combined defects: short header plus bad magic; bad magic plus unknown version; unknown version plus class; unknown class plus reserved; reserved plus zero epoch; over-limit length plus incomplete body; incomplete body plus wrong checksum; wrong checksum plus sequence gap; checksum-valid gap before a later checksum failure. The earlier check wins. Unknown headers and fatal sequence errors must never become automatic file deletion or truncation.

## 5. Fixtures and tests

`schemas/agent/spool/v1/fixtures.json` contains complete hex-encoded segment inputs and exact expected results. `fixture.schema.json` validates the container; prose owns semantic precedence. Hex is lowercase, even-length, without separators. Every u64 is a canonical decimal string to preserve precision in JavaScript; `null` means exhausted sequence. Offsets and lengths are byte counts. Expected `record_count()` is the length of the `records` array. Error objects carry the exact fields of their Rust variant; successful results carry the header, ordered records, valid length, next sequence and optional tail issue.

[Schema validation cases](../../schemas/agent/spool/v1/schema-cases.json) each supply a complete fixture container as `instance` and its expected validation result as `valid`. Validate each instance against `fixture.schema.json`. Negative cases reject trailing newlines in hex, fixture IDs and every u64 field, including `stream_epoch` set to `"0\n"`.

The final-record truncation family uses a complete first record and a second record with a nonempty payload. It includes every retained byte count from zero through the full second record. Zero retained bytes is clean EOF; partial counts are `Incomplete`; the full record succeeds. Header truncations cover all lengths 0 through 31. Additional fixtures cover every class, empty segment and payload, binary payload, asymmetric multi-byte integers, uint64 maxima, checksum corruption in sequence and payload, an interior failure with a valid suffix, unknown versions/classes, reserved bytes, zero epoch, oversized lengths, first-record mismatch, gaps, duplicate/reversed sequences, exhaustion and combined defects.

Tests also construct payload sizes 1,048,575, 1,048,576 and 1,048,577 in memory, full scans above both sealing thresholds, short/exact/oversized output buffers, and all 256 class bytes. Boundary payloads are generated in tests to avoid megabytes of repeated fixture hex. A Python standard-library generator produces checked-in Rust fixture data from JSON; CI checks exact regeneration. Do not add a production or handwritten JSON parser just to load fixtures.

The std-only `fuzz_recover` test mutates shared seeds, scans arbitrary bytes, and checks successful prefixes and encode/recover round trips. It runs a fixed budget in normal CI and an explicit larger ignored budget before review. [The plan](../plans/agent-spool-format.md#task-4-bounded-fuzz-like-tests) fixes the budgets and invariants. This gives reproducible coverage on all three stable targets, but no coverage-guided exploration. [cargo-fuzz](https://rust-fuzz.github.io/book/cargo-fuzz/setup.html) needs a separate toolchain/runtime setup; it is an alternative for a separately reviewed fuzzing expansion.

## 6. Threat trace and deferred gates

CRC detects accidental corruption, not forgery. Length checks bound each checksum operation; borrowed prefixes prevent allocations based on hostile lengths. Sequence checks prevent accepting structurally inconsistent runs. None of these mechanisms authenticates a producer or protects a header, and changing bytes plus CRC can pass them.

| Attacker | Path through this slice and remaining ability |
|---|---|
| Stolen enrollment token | The codec accepts bytes, not enrollment credentials. Token possession alone grants no local file access through this API. If enrollment creates a device identity, later transport must bind that identity; this codec cannot distinguish its fabricated events. |
| Compromised agent host | A privileged writer can rewrite the header, payload, sequence and CRC, delete records or roll back a whole segment. Recovery can accept the forged run. Root/LocalSystem storage permissions and truthful telemetry are outside this library. |
| Compromised console session | No console/session input or administrative action enters the codec. A session cannot acquire local spool authority here; policy and enrollment authorization stay in their own consumers. |
| Rogue extension publisher | A package signature does not grant a spool handle. The future core owns event construction and extension provenance before encoding; if hostile bytes reach recovery, the same structural bounds apply without proving provenance. |
| Network position between agent and server | This slice has no network API. Reusing CRC bytes over an untrusted channel provides no authenticity. Upload mTLS and acknowledgement binding remain required before the manager deletes any segment. |
| Database writer without signing keys | No database state enters recovery. Such a writer may corrupt ledger data but cannot obtain local file authority from this API; ledger and acknowledgement integrity remain external gates. |
| Server restored from backup | A spool epoch is a telemetry namespace, not an authority recovery epoch. Recovery cannot detect server rollback, authorize an old certificate or establish a durable acknowledgement; BE-12 and ingest recovery stay mandatory. |

Later slices must specify file creation/opening, permissions, exclusive ownership, read bounds, short writes, physical truncation, rename/delete ordering and crash consistency. **Durable sync is a platform gate:** verify exact pinned-Rust behavior and error handling for macOS `F_FULLFSYNC`, Windows `FlushFileBuffers` and Linux `fdatasync`, including directory persistence and power-loss tests. This library does not call or certify any of them.

Sealing at the byte/count/age thresholds, NDJSON conversion, zstd compression and its expansion bound, upload descriptors, acknowledgements, deletion, shared spool caps, drops, counter persistence, epoch creation/transition, disk encryption and OCSF validation remain separate slices. The existing full v1.0.0 support requirement on macOS ARM64, Windows x64 and Linux x64 is unchanged. Hosted codec checks do not establish native spool durability or sensor support.

## 7. Benefits, trade-offs and alternatives

Benefits: a byte-exact portable format, typed failures, deterministic recovery and shared vectors allow the first Rust code to proceed without assuming native durability. Zero allocation inside the codec keeps malformed lengths from becoming allocation requests.

Trade-offs: callers retain the input while reading borrowed records; a future bounded file reader needs its own contract. CRC excludes the header and length, and cannot prove authenticity or detect every accidental corruption. A strict sequence error preserves evidence but needs later manager handling. A format-valid segment can exceed sealing thresholds because format and scheduling are separate concerns.

Alternatives considered: a file-owning writer couples the first slice to unproved sync and crash ordering; a record vector copies or allocates per record; serde-based tests add dependencies only to load fixtures; accepting sequence gaps contradicts the Go descriptor invariant; silently truncating an unsupported version risks losing readable data after an update; cargo-fuzz adds a separate toolchain and does not replace the stable cross-platform checks. The selected choices reject those costs for this slice.

## 8. Unresolved questions and review focus

The byte/API choices are complete proposals, pending independent approval. Review these questions before implementation:

- Does `agent/crates/spool` as a leaf workspace member fit the core events dependency better than embedding the codec in the future core crate?
- Does the explicit reserved zero byte and little-endian layout fit interoperability better than native struct serialization?
- Does the 1 MiB opaque payload ceiling fit the server contract better than unbounded records or JSON validation inside the codec?
- Does the borrowed, file-free API fit the first slice better than a file-owning writer whose native durability contract is unresolved?
- Is refusing oversized lengths and checksum-valid sequence gaps preferable to truncating them and hiding unsupported framing or sequence defects?
- Is stable std-only mutation testing sufficient for this bounded codec, with coverage-guided cargo-fuzz reserved for a separate expansion?
- Can the selected dependency closure and CI pins pass the plan's license and target checks without changing the reviewed contract?

Review focus: class parity with Go; every byte offset and endian rule; unchecked offset/sequence arithmetic; no output mutation on encode failure; tail versus fatal-error precedence; no suffix salvage; header-only and exhausted-stream behavior; borrowed lifetime and constant auxiliary memory; fixture independence; and the separation of framing from authenticity, OCSF validity and native durability.
