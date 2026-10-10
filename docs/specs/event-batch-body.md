# Event batch body decoder

Decode the single zstd NDJSON frame after the descriptor, enforce body limits, and return raw lines with preliminary identity checks. This is a design for `server/internal/events/body`, not complete ingest. [The wire spec](event-upload-wire.md) owns the descriptor and HTTP contract; [events sections 3.2 to 3.5](../design/events.md#3-server-ingestion) own quarantine, storage and acknowledgement. Decision: EV-09.

## 1. Toolchain, dependencies and alternatives

Use Go 1.27.1, module `github.com/ricevanta/ricevanta/server`, the existing `batch`, `eventid` and `wire` packages, and the standard library except `github.com/klauspost/compress/zstd` at **v1.20.1**. Add that exact module requirement and its checksums during implementation. Do not change the Go directive or add a toolchain directive. Go's [zstd reader is internal](https://go.dev/src/internal/zstd/zstd.go), not a public import.

| Candidate | Benefit | Choice and cost |
|---|---|---|
| [Klauspost v1.20.1](https://pkg.go.dev/github.com/klauspost/compress@v1.20.1/zstd) | Pure Go; explicit window, concurrency and checksum controls | Selected; adds a pinned module and requires our own total-output counter and single-frame check |
| [DataDog/zstd](https://github.com/DataDog/zstd/blob/1.x/zstd.go) | Wraps the C reference codec | Rejected; `import "C"` adds a C build and native boundary without a need in this slice |
| [valyala/gozstd](https://pkg.go.dev/github.com/valyala/gozstd) | Streaming wrapper around libzstd | Rejected; requires cgo and a cross-compiler for cross-builds |
| Copy Go's internal decoder or write a codec | No external module | Rejected; owns codec maintenance and security fixes instead of a small protocol adapter |

The pinned [LICENSE](https://github.com/klauspost/compress/blob/v1.20.1/LICENSE) assigns BSD-3-Clause to the zstd code; module paths outside this import also carry Apache-2.0 and MIT. Preserve applicable notices in distribution and include the module in the release SBOM. The existing licensing row is made exact rather than duplicated. No encoder or reference CLI ships with the server.

A separate `body` package keeps prefix parsing reusable. Folding this into `wire` would mix its fixed 48-byte contract with decompression and event interpretation. Buffer at most the compressed budget, preflight exactly one frame, then stream its output. Fully streaming compressed input would save under 5 MB but require a frame-limiting reader resistant to codec read-ahead. `DecodeAll` would delay line-limit rejection and allocate from the entire output. Both alternatives are rejected.

## 2. Exact Go API and ownership

```go
package body

const (
    MaxDecodedBytes int64 = 64 << 20
    MaxWindowBytes uint64 = 64 << 20
    MaxLineBytes = 1 << 20
    MaxLines = 10_000
    MaxJSONDepth = 128
)

type Line struct {
    Number uint32
    Raw []byte
    EventID eventid.ID
    Sequence uint64
    DeviceUID string
    Err error
    DeviceMismatch bool
}

func Decode(r *io.LimitedReader, d batch.Descriptor, authenticatedDevice string) ([]Line, error)
```

`Number` is one-based. `Raw` preserves the exact payload bytes without LF, including whitespace and invalid UTF-8. Every returned line owns its bytes; no line aliases another line, a pooled buffer, or decoder memory. Callers may retain and mutate one line independently. `Err == nil` means only that the checks in this spec passed. It never means OCSF-valid, stored or acknowledged.

Any line failure zeros `EventID`, `Sequence` and `DeviceUID`. `DeviceMismatch` is true when an unambiguous string `device.uid` differs from the supplied identity, even if another field fails first. It is false for invalid JSON, ambiguous keys, missing/wrong-type device uid, or no mismatch. Later ingestion emits the required security finding when true. Do not let the primary line error hide an independently established device mismatch.

Every batch error returns a **nil slice**, discarding provisional successes and quarantine candidates. There are no callbacks, partial yields, counters to commit, database writes or logging. A callback alternative risks side effects before the checksum or count is known. The caller owns and closes the request reader; `Decode` never closes it. It closes its own zstd decoder on every path. Do not pool decoders in this slice.

The caller first authenticates and admits the request, creates `io.LimitedReader{R: requestBody, N: wire.MaxCompressedBytes + 1}`, and calls `wire.Decode`. On success it passes that same reader and descriptor here, without another read, buffer, replacement or budget reset. `wire.Decode` returns the descriptor and leaves the reader positioned after byte 47. The caller supplies the uid from its authenticated device record, never an event or header field. Accepting arbitrary remaining budgets is rejected because this API carries no initial-budget parameter; a caller must use the canonical handoff.

## 3. Batch errors and precedence

Declare each name below as a distinct `errors.New` sentinel; messages are the lowercase space-separated name after removing `Err`, prefixed by `event body` (for example `ErrContentSize` is `event body content size`). Callers use `errors.Is`, never messages. Return `d.Validate()` errors unchanged. The decoder is transport-free; the status column guides the later handler.

| Sentinel | Meaning | HTTP mapping |
|---|---|---|
| `ErrReaderBound` | Nil reader, nil `R`, or remaining `N` not exactly 4,999,953 | Caller bug; no client status |
| `ErrDevice` | Empty or invalid-UTF-8 authenticated uid | Caller bug; no client status |
| `ErrRead` | Underlying compressed-body read failed | Transport outcome; never success |
| `ErrCompressedLimit` | Descriptor plus consumed body exceeds 5,000,000 bytes | 413 |
| `ErrFrame` | Invalid/truncated magic, header, blocks or checksum bytes | 400 |
| `ErrChecksumRequired` | Checksum flag is clear | 400 |
| `ErrContentSizeRequired` | Frame_Content_Size is absent | 400 |
| `ErrDecodedLimit` | Claimed or observed output exceeds 67,108,864 bytes | 413 |
| `ErrWindowLimit` | Effective window exceeds 67,108,864 bytes | 413 |
| `ErrTrailingData` | Any byte after the first data frame | 400 |
| `ErrContentSize` | Declared size differs from actual decoded size | 400 |
| `ErrChecksum` | Content checksum does not match | 400 |
| `ErrLineLimit` | Payload exceeds 1,048,576 bytes | 413 |
| `ErrLineCountLimit` | A 10,001st line starts | 413 |
| `ErrLineFraming` | Blank line, literal CR, BOM, or missing final LF | 400 |
| `ErrRecordCount` | Completed line count differs from descriptor | 400 |

Stop at the first failed stage:

1. `d.Validate()`, reader precondition, authenticated uid precondition, in that order. No reads on failure. Typed-nil or contract-violating `io.Reader` implementations are caller bugs.
2. Read the remaining compressed input in bounded chunks until genuine EOF. Count returned bytes before handling a simultaneous error: filling the overflow byte wins as `ErrCompressedLimit`; otherwise a non-EOF error is `ErrRead`, wrapping both sentinel and cause. Short reads with nil errors continue. EOF with data completes the buffer. Never read `r.R` directly. At most 4,999,953 bytes are consumed here. Budget exhaustion is overflow, not proof of EOF. A correctly bounded body leaves `N >= 1`. Use one fixed buffer of 4,999,953 bytes and reads of at most 32 KiB, slicing to received length. After 100 consecutive `(0, nil)` reads, return `ErrRead` wrapping `io.ErrNoProgress`; a positive read resets that counter.
3. Preflight the frame in section 4. Its ordered stages select one sentinel before any decompression.
4. Stream-decode and frame lines in section 5. Resource limits stop immediately in output-byte order. For the same byte: total-output limit, line-count limit, then line-size limit. Process bytes returned with an error before handling that error. Remember a framing failure but continue bounded decoding to verify integrity; do not parse or retain further lines after a framing failure.
5. Handle a codec failure: size mismatch/exceeded is `ErrContentSize`, checksum mismatch is `ErrChecksum`, window/decoder-size ceiling is `ErrWindowLimit`, all other codec failures are `ErrFrame`. Use the pinned exported `zstd.ErrFrameSizeMismatch`, `ErrFrameSizeExceeded`, `ErrCRCMismatch`, `ErrWindowSizeExceeded` and `ErrDecoderSizeExceeded`, never error-string matching. These errors match only the selected body sentinel, not a codec API.
6. At clean codec EOF compare total output with declared size, then report remembered framing failure or a nonempty unfinished line, then record-count mismatch. Only then return line results.

There is no precedence over bytes the codec did not return. A lying size may cause `ErrContentSize` before the output counter sees an overflow; that is a bounded 400 rejection, not a successful bomb. The [pinned synchronous decoder](https://github.com/klauspost/compress/blob/v1.20.1/zstd/decoder.go) checks size before checksum. A resource failure in delivered bytes wins over a simultaneous codec error. Batch errors always supersede line errors. Missing LF plus count mismatch returns `ErrLineFraming`; checksum corruption plus bad uid returns `ErrChecksum`; trailing bytes plus checksum corruption returns `ErrTrailingData`; compressed overflow plus bad magic returns `ErrCompressedLimit`.

## 4. Single-frame preflight and codec controls

Apply these checks to the bounded compressed bytes without allocating from a claimed size. RFC 8878 [sections 3.1 and 3.1.1](https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1) define frame concatenation and fields. Ricevanta permits exactly one ordinary frame here and no skippable frame.

1. Require four-byte little-endian magic `0xFD2FB528`. An incomplete magic, another magic, or an empty body is `ErrFrame`.
2. Read the descriptor byte and all fields its flags imply; incomplete header is `ErrFrame`. Determine content-size width as 0/1, 2, 4 or 8 bytes; flag zero with Single_Segment set has a present one-byte size and is allowed. Add 256 for the two-byte form. Use uint64 arithmetic.
3. Reject reserved bit 3, unused bit 4, and any nonzero Dictionary_ID_Flag as `ErrFrame`, even an encoded dictionary id of zero. Bit 4 rejection is a Ricevanta profile restriction, not an RFC decoder requirement. No dictionary is registered.
4. Require checksum flag, then present content size. Return `ErrChecksumRequired` before `ErrContentSizeRequired` when both are absent.
5. Reject declared output over `MaxDecodedBytes`, then effective window over `MaxWindowBytes`. For Single_Segment use content size; otherwise compute `base = uint64(1) << (10 + (wd >> 3))`, `window = base + (base / 8) * uint64(wd & 7)`. Do not silently shrink the advertised window. Size zero is structurally allowed and ultimately fails record count.
6. Walk three-byte little-endian block headers until Last_Block. Type 3 is invalid. Bound block size by `min(window, 128 KiB)`; an empty single-segment frame permits a zero-length raw last block. Raw and compressed blocks occupy Block_Size bytes; RLE occupies one byte. Check remaining bytes before advancing. Missing bytes, an oversize block, or no final block is `ErrFrame`. The codec still validates compressed block contents.
7. Require four checksum bytes after the last block. Any suffix, including another ordinary frame, an empty frame, zero padding or a skippable frame, is `ErrTrailingData`. The [reference format](https://github.com/facebook/zstd/blob/v1.5.7/doc/zstd_compression_format.md) documents these block boundaries; no scanning for magic inside block payloads is allowed.

RFC 8878 [Window_Descriptor](https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1.1.1.2) describes a minimum history allocation, not a total process-memory ceiling. Frame size and checksum are optional in the RFC; both are mandatory here. Checksum detects corruption and supplies no authenticity. Accepting all RFC concatenations or optional fields would weaken the one-segment upload contract and is rejected.

Create one decoder over `bytes.NewReader(frame)` with these explicit options. The [pinned option documentation](https://pkg.go.dev/github.com/klauspost/compress@v1.20.1/zstd#DOption) and [implementation](https://github.com/klauspost/compress/blob/v1.20.1/zstd/decoder_options.go) own their semantics.

| Option | Value | Purpose |
|---|---|---|
| `WithDecoderConcurrency` | `1` | Synchronous stream decoding; no async block pipeline |
| `WithDecoderMaxMemory` | `uint64(MaxDecodedBytes)` | Streaming window guard, not a total-output guard |
| `WithDecoderMaxWindow` | `MaxWindowBytes` | Explicit maximum history window |
| `WithDecoderLowmem` | `true` | Lower decoder memory use |
| `WithDecodeBuffersBelow` | `0` | Disable implicit whole-buffer decompression |
| `IgnoreChecksum` | `false` | Verify the required checksum |

Do not use `DecodeAll`, `WriteTo`, `io.Copy` fast paths or `WithDecodeAllCapLimit` as a streaming output limit. Read through the explicit output counter. Use a fixed 32 KiB output buffer and request at most `remaining + 1` bytes, shrinking to a one-byte probe at the ceiling. Stop on the first overflow byte and close. A codec can internally decode a bounded block ahead of that probe; concurrency one and the window cap bound that work. Never allocate an output array from Frame_Content_Size.

A 64 MiB window admits single-segment frames throughout the output allowance. An 8 MiB window would use less memory but reject otherwise admissible single-segment uploads; leaving the library default would permit excess history allocation. Both alternatives are rejected.

The output ceiling is not a 64 MiB resident-memory promise. Live memory includes under 5 MB compressed input, at most 64 MiB raw-line bytes, one line scratch buffer capped at 1 MiB plus one byte, the bounded decoder window/block state, and bounded per-line JSON bookkeeping. Avoid retaining decoded JSON trees, duplicate raw-body copies, or key maps across lines. Aggregate request concurrency, read deadlines and process memory qualification remain handler gates.

## 5. NDJSON framing

Retain the wire spec's LF-only rule. Each line ends in byte `0x0a`; require the final LF. A line consists of 1 through `MaxLineBytes` payload bytes, excluding LF, and must contain a byte other than space or tab. Literal CR anywhere, including CRLF and JSON whitespace, is a framing error; escaped `\r` is ordinary JSON text. A UTF-8 BOM at the start of any line is a framing error. UTF-8 validity itself is a per-line JSON check, so its bytes remain available for quarantine.

Count every completed line, including quarantined events. After 10,000 LFs, any next output byte is `ErrLineCountLimit`. Permit exactly 1 MiB followed by LF; the next non-LF byte is `ErrLineLimit`. No trimming, Unicode newline splitting, Scanner default token size or CRLF normalization is allowed. Zero output reaches `ErrRecordCount`; one LF is `ErrLineFraming`. Rejecting the batch for invalid UTF-8 would defeat event quarantine; accepting missing LF, CRLF or blank records would change EV-08 framing.

Actual line count must equal `d.RecordCount`. Otherwise segment accounting cannot describe the batch, so reject the whole batch. Within that framing, line `i` must carry `d.FirstSequence + uint64(i-1)`, as well as lie in the descriptor range. Check range before position. Compute the expected value only for `i <= d.RecordCount`; extra lines are counted for the batch error without field extraction or unsafe addition. Valid descriptors make this addition safe even at MaxUint64.

Sequence defects quarantine only that line. Do not require the surviving subset to remain contiguous after quarantine. Rejecting the whole batch on an event sequence defect conflicts with section 3.2; accepting merely in-range values would admit duplicate or reordered positions. Duplicate event UUIDs are allowed by this slice and remain a deduplication gate.

## 6. Strict field extraction and line errors

Declare distinct `errors.New` sentinels `ErrJSON`, `ErrJSONKeys`, `ErrFields`, `ErrEventID`, `ErrSequenceRange`, `ErrSequencePosition` and `ErrDeviceBinding`, with the same message convention as section 3 (`JSON` stays uppercase). They are **line results**, never batch 400/413 responses. `ErrEventID` wraps both itself and the precise `eventid.Parse` cause; other line errors match only their selected sentinel. Error messages contain no event text or attacker-supplied key names.

Validate and extract one line without a compiled schema:

1. Require `utf8.Valid(raw)`, valid JSON syntax, exactly one top-level object and maximum container depth 128 (root depth 1). Reject unpaired `\uD800` through `\uDFFF` escapes, including in unknown fields; paired surrogate escapes are valid. Use a bounded string-escape pass, not replacement-character detection, since literal U+FFFD is valid. Any of these failures is `ErrJSON` and precedes all other line checks.
2. Walk `encoding/json.Decoder.Token` with `UseNumber` and a bounded explicit container stack. Inspect every object, including objects in unknown arrays. Track each object's decoded member names; exact duplicates, including escaped spellings such as `uid` and `u\u0069d`, are `ErrJSONKeys`. Compare recognized names by exact case. Any unequal name for which `strings.EqualFold` matches a recognized name is also `ErrJSONKeys`, even if the exact name is absent. Recognized names are `metadata` and `device` at root, `uid` and `sequence` directly in metadata, and `uid` directly in device. Unknown non-colliding names are allowed; their OCSF validity is a later gate. Do not reject case differences among unrelated unknown names here.
3. Require object-valued metadata and device, string-valued metadata.uid and device.uid, and a `json.Number` metadata.sequence. Missing, null or wrong-type values return `ErrFields`. Parse sequence from its original token using lexical `[0-9]+` with no leading zeros except `0`, then `strconv.ParseUint(..., 10, 64)`. Negative zero, negative, fractional, exponent, quoted and overflowing sequences are `ErrFields`. Never pass through float64 or signed int64.
4. Independently set `DeviceMismatch` once steps 1 and 2 succeed and device.uid is an unambiguous string. Empty device.uid is a mismatch against the nonempty caller value. Retain that flag even on `ErrFields` for another field.
5. Parse uid with `eventid.Parse`, then check sequence range, sequence position, and exact decoded device string equality, in that order. Return the first line sentinel. No case, Unicode or whitespace normalization applies to values. If all pass, fill all three extracted fields.

A whole-line syntax/depth prepass ensures a duplicate key cannot mask malformed trailing JSON. The token pass avoids a full generic map. [Go encoding/json](https://pkg.go.dev/encoding/json@go1.27.1#Unmarshal) otherwise accepts duplicate keys, uses case-insensitive struct matching and repairs invalid UTF-8/surrogates. [`UseNumber`](https://pkg.go.dev/encoding/json@go1.27.1#Decoder.UseNumber) preserves number tokens. Direct struct unmarshalling, last-key-wins maps and `DisallowUnknownFields` alone are rejected: none enforces this contract, and unknown OCSF fields must survive for later validation.

Depth 128 bounds the token stack and nested-key state; relying on the JSON library's larger syntax limit is rejected. One primary line error gives stable diagnostics. Joining every line error is rejected because parser defects can make later fields ambiguous; `DeviceMismatch` preserves the one independently meaningful security fact. Returning partially validated ids is rejected to prevent accidental promotion.

Raw bytes and extracted ids are inputs for the later generated validator. That validator must preserve these exact bindings and strict key semantics, not re-extract with permissive rules. The decoder neither validates UUID timestamps nor authenticates uid values. The [OCSF profile sections 3 and 6](ocsf-profile.md) and `schemas/ocsf/limits.yaml` remain required for full event validation; the 1 MiB cap does not replace individual field/list limits.

## 7. Threat trace, benefits and later gates

| Attacker | Mechanism, result and remaining ability |
|---|---|
| Stolen enrollment token | Handler requires a device certificate before decoding. If enrollment grants one, exact device binding confines uploads to that device; token policy remains outside this package. |
| Compromised agent host | Can forge all its own event content and descriptors. Input, window, line, depth and output bounds limit one decode; exact binding quarantines other-device claims. Count and positional sequences constrain format, not truth or replay. |
| Compromised console session | Supplies no upload identity. Caller must derive uid from mTLS, not session-controlled parameters; the package itself cannot prove caller authentication. |
| Rogue extension publisher | Has no transport credential from publication. The agent core owns upload. Unknown provenance fields survive untouched; current grant/epoch validation is a later gate and these results grant no extension authority. |
| Network position | mTLS protects transport. Single-frame, size and checksum checks reject damaged bodies, but an attacker who breaks TLS can recompute all these fields. No checksum substitutes for authentication. |
| Database writer without signing keys | This package reads no database and grants no authority. Altered stored/quarantined events and ledger entries are outside its integrity boundary; later durable acknowledgement and authorization fences still apply. |
| Server restored from backup | Stateless decoding restores no high-water mark, credential or consumed authorization. BE-12 sealed recovery and current authentication must gate callers; replay/deduplication remain outside this slice. |

Benefits: deterministic admission, bounded decode work, exact raw quarantine evidence and a shared byte contract for producers. Costs: bounded compressed buffering and retention of up to 64 MiB of provisional raw lines; strict keys and positional sequences quarantine nonconforming producers. The three v1.0.0 targets share this byte contract. Pure parser fixtures establish no OS qualification.

Later gates: compiled OCSF decoding and validation; field/list bounds; extension provenance and recovery epochs; device authentication and admission concurrency; deduplication and sequence high-water marks; quarantine persistence and device-binding findings; enrichment; stores, ledger and durability fence; HTTP responses and acknowledgement. None is implemented or bypassed by a successful `Decode`.

## 8. Machine fixtures and review focus

`schemas/events/v1/body-fixture.schema.json` defines `fixtures/body.json`. The fixture format owns no alternate protocol. Each case supplies a validated descriptor with uint64 fields as decimal strings, authenticated uid, frame bytes, reconstruction recipe, SHA-256 digests, and expected batch sentinel/status and line outcomes. Null batch status means no batch rejection, not HTTP 200. Reconstruct input before creating the canonical remaining reader budget. Do not use its byte length as `N`.

Input bytes are standard padded base64 parts with repeat counts. Concatenate expanded parts in order, with a hard fixture expansion cap of 5,000,001 bytes. Most frames have one part; raw-block compressed-boundary cases encode long space runs as repeated single-byte parts. Recipes describe plaintext literal bytes or generated records, encoder mode and ordered byte mutations. Generated records use the exact compact object shown in the fixture's `record_template`, substituting decimal `sequence`. Optional `line_bytes` includes LF and pads each record with ASCII spaces before LF. `total_bytes` distributes bytes across records in order, at most 1,048,576 bytes per line including LF; the last record takes the remainder. `extra_last_spaces` adds that many spaces before the last LF. The plaintext SHA-256 includes LF; compare each returned Raw against the reconstructed payload without LF. Outcome runs expand in line order; successful sequences advance by one from `sequence_first`, while failed lines have no extracted ids and preserve `device_mismatch`.

Reference frames use `zstd` CLI **1.5.7**, `-q -3 --single-thread --check --stream-size=<plain length> -c`, including `--stream-size=0` for an empty frame. The `raw` mode uses RFC raw blocks of at most 131,072 bytes, a single-segment header with an eight-byte content size, and the reference encoder's four checksum bytes. Each ordered mutation removes `delete` bytes at zero-based `offset` and inserts `insert_base64` there, after the preceding mutation. This expresses header/checksum changes, truncation and suffixes. Rebuild from recipes in a fresh process, compare every encoded part's expanded bytes and both digests, and reference-decode every valid envelope. Corrupt frames must fail reference integrity; profile-only rejections can remain RFC-valid.

Required fixtures include both size ceilings and their adjacent values; claimed and lying bombs; full-width sequences; mixed good/quarantined lines; all frame flags and size widths; malformed/truncated blocks; checksum absence/corruption; extra/skippable frames; framing and count limits; duplicate/case/escaped keys; invalid UTF-8 and surrogates; numeric forms; uid, range, position and device failures; combined-defect precedence. Implementation adds caller-misuse and injected-read-error tests that JSON cannot express.

Review focus:

- Prove genuine compressed EOF without resetting or spending the descriptor budget twice.
- Bound window allocation independently of declared and observed content size; disable implicit `DecodeAll`.
- Find the last block structurally, including RLE size semantics; never accept an empty trailing frame.
- Discard every provisional line on batch failure, including late checksum/count failures.
- Preserve exact uint64 values, strict decoded keys, raw bytes and independent device-mismatch evidence.
- Enforce positional sequences without making a quarantined line reject good neighbors.
- Keep this preliminary parser and fixtures independent of absent OCSF, storage and acknowledgement guarantees.
