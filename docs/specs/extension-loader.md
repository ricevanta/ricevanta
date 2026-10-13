# Extension package loader

The loader authenticates a bounded package and returns byte evidence for admission. It grants no installation authority. EXT-08 covers the manifest boundary; [the implementation plan](../plans/extension-loader.md) requires independent approval before code. Production consumers require both qualification approvals under section 6.

## 1. Boundary and dependencies

Create `server/internal/extensions/loader` above `manifest` and `signing/dsse` in `github.com/ricevanta/ricevanta/server`. Use Go 1.27.1, `go.yaml.in/yaml/v3` v3.0.4 and `github.com/klauspost/compress` v1.20.1 exactly. Both dependencies are in [licensing](../licensing.md). No database, path extraction, network, component execution or signing belongs here. Keep dependency direction from loader to the two existing leaf packages.

Retain the zstd-compressed tar format in [extension design section 1](../design/extensions.md#1-package-and-manifest). This slice selects a strict USTAR subset, one zstd frame, and memory-owned bytes. ZIP introduces a second archive format; generic tar extraction admits metadata, links and filesystem races; both are rejected. [Go's USTAR layout](https://raw.githubusercontent.com/golang/go/go1.27.1/src/archive/tar/format.go) cannot represent every 240-byte manifest path: the name must fit 100 bytes, or split at a slash into a prefix of at most 155 bytes and a nonempty name of at most 100 bytes. Authors must use representable paths. PAX support requires a separate reviewed widening, not silent truncation.

[The manifest contract](extension-manifest.md) owns the five kinds, field inventory, canonical paths, identity, ownership and decoded tree limits. [The runtime contract](extension-agent-runtime.md) owns agent execution. Loading a module, connector descriptor, browser adapter, console asset or content file treats its bytes as opaque. A matching hash does not validate that component's format or safety.

## 2. Exact Go API

```go
package loader

type Options struct {
    AllowReservedID bool
    MaxTotalFileBytes uint64 // Zero selects manifest.DefaultMaxTotalFileBytes.
}

type File struct {
    Path string
    Size uint64
    SHA256 [32]byte
    Bytes []byte
}

type Package struct {
    Archive []byte
    Manifest []byte
    Envelope []byte
    Document map[string]any
    Files []File
    PackageSHA256 [32]byte
    ManifestSHA256 [32]byte
    EnvelopeSHA256 [32]byte
    PublisherFingerprint string
}

func Load(body *io.LimitedReader, authorizedKey ed25519.PublicKey,
    options Options) (Package, error)
```

`body.N` must equal the effective compressed ceiling plus one on entry; `body` and `body.R` must be non-nil. The caller owns transport cancellation, deadlines, concurrency and reader correctness. An arbitrary reader that blocks cannot be interrupted by this bounded local API. The loader does not close it. One hundred consecutive `(0, nil)` reads return `ErrRead` wrapping `io.ErrNoProgress`; positive reads reset that counter. Read chunks are at most 32 KiB. Stop at the extra byte without draining the source.

The caller supplies a currently authorized, non-revoked key whose canonical encoding and rejection of small-order points passed the separate key-admission slice. Length alone is insufficient. This slice checks length defensively but does not implement point validation. No manifest field or DSSE hint selects that key. `AllowReservedID` derives only from that key's current project-publisher authority. Authorization must be rechecked at admission's publication fence.

On success, retain exact compressed archive, manifest and envelope bytes. Hash these independently; `PackageSHA256` hashes the compressed input including its zstd header and checksum. `EnvelopeSHA256` equals the DSSE result's exact received-envelope hash. Return files in bytewise path order. `Document` contains only the types accepted by `manifest.Validate`; no `yaml.Node` escapes. The payload and archive member equality check makes `Manifest` the exact verified payload.

Return independently owned slices and tree data, with no mutable alias between exported slices, file bodies or caller inputs. The caller must not mutate inputs during a call. The trusted consumer owns the result and must not mutate it during admission. A public Go value is evidence, not an unforgeable authority token; network handlers must invoke `Load` themselves and cannot deserialize a claimed `Package`. Return `Package{}` on every error, without partial files or bytes. Calls share no mutable cache or decoder pool.

## 3. Budgets and archive profile

Let `F` be the effective listed-file ceiling from `manifest.Options`: default 67,108,864 bytes, positive override at most 1,073,741,824. These are file bytes, not total tar bytes. Define `T = F + 8,388,608` as the decompressed tar ceiling and `C = T + 1,048,576` as the compressed ceiling. All arithmetic uses checked `uint64`; validate before converting to `int` or `int64`.

| Resource | Ceiling, inclusive |
|---|---|
| Received compressed archive | `C`; observe at most `C+1` bytes |
| Decompressed tar including headers and padding | `T` |
| Zstd window | 8,388,608 bytes |
| Regular members | 4,098, including the two control members |
| `extension.yaml` | 1,048,576 bytes |
| `envelope.json` | 2,097,152 bytes |
| Other member body sum | `F`, enforced before YAML or signature processing |
| Individual other member | `min(F, 1,073,741,824)` bytes |
| Physical tar block | 512 bytes; at most 511 padding bytes per member |
| End marker | Exactly two zero blocks, then end of decoded bytes |

The overhead allowance exceeds both control members, 4,098 headers, maximum per-member padding and the end marker. Bounds are product choices, not measured peak-memory guarantees. The compressed ceiling deliberately rejects unusually inefficient but otherwise valid compression.

Read a bounded compressed snapshot before any parser. An extra byte takes precedence over a read error returned with that byte. Otherwise a non-EOF read error wins over parsing; bytes returned with EOF count. Do not allocate `C` immediately for a tiny input; bounded geometric growth must never reserve more than `C+1`.

Inspect zstd framing before invoking the decoder: require ordinary magic, no reserved header bits, no dictionary-id field, explicit frame content size at most `T`, window at most 8 MiB, and the content checksum flag. Walk bounded block headers to the last block and checksum with checked offsets; reject reserved block types, oversize blocks, truncation, a second frame, skippable frames and any suffix. Require the measured output length to equal the declared content size. [RFC 8878 sections 3 and 4](https://www.rfc-editor.org/rfc/rfc8878.html) define the framing; these single-frame restrictions are Ricevanta rules.

Use `zstd.NewReader(nil, zstd.WithDecoderConcurrency(1), zstd.WithDecoderLowmem(true), zstd.WithDecoderMaxMemory(T), zstd.WithDecoderMaxWindow(8<<20), zstd.WithDecodeAllCapLimit(true))`. Preallocate exactly the checked content-size capacity and call `DecodeAll` once. Keep checksum verification enabled and close the decoder on all paths. [The pinned decoder options](https://raw.githubusercontent.com/klauspost/compress/v1.20.1/zstd/decoder_options.go) distinguish output-size and window limits; neither alone caps total Go heap. Do not import the events decoder, whose wire profile and ceilings differ.

Inspect physical tar headers before handing any header to `archive/tar`. For each nonzero 512-byte header, require `ustar\x00` magic and `00` version, regular type `0` or NUL, empty link target, no GNU/PAX/sparse extensions and valid unsigned octal numeric fields. Accept leading/trailing ASCII space or NUL padding around octal digits; an all-padding numeric field means zero. Reject embedded padding between digits, base-256 and negative numbers. Require the unsigned header checksum, summing bytes with offsets 148 through 155 treated as spaces. Require bytes 500 through 511 to be zero, excluding STAR trailers. Require NUL-terminated text fields, or a full field with no NUL; after a NUL only NUL padding is allowed. Ignore bounded owner, group, mode and time metadata as authority; never apply permissions or timestamps. Require device major/minor to be zero. After raw integrity, size and member checks, use `archive/tar.Reader` on that one regular header and its bounded body to cross-check standard header interpretation; never feed it unchecked extension headers. [Go's tar API](https://pkg.go.dev/archive/tar@go1.27.1) supports formats beyond this profile, so its acceptance alone is insufficient.

Form the member name from the literal USTAR prefix and name, inserting one `/` only when the prefix is nonempty. Validate that result against the manifest path grammar, with only the exact control names exempt from reserved-root rejection. Empty paths, control-name descendants, directory entries, hard links, symlinks, device nodes, FIFOs, absolute paths, dot segments, uppercase, backslashes and reserved device stems fail. Do not clean, fold, decode or normalize names. Different prefix/name representations of the same full path are duplicates. Reject file/directory prefix collisions across every member, including controls. Bytewise path equality is sufficient after the portable ASCII restrictions; this is not a filesystem extraction guarantee.

Require exactly one of each control member and no more than 4,096 other members, in any order. Check each declared header size against its role ceiling and remaining bytes before slicing, skipping or copying; verify zero member padding and exact end framing. No member data becomes externally visible yet. After manifest validation and publisher binding, the non-control name set must equal `files[]` exactly, including attestations. Compare all sizes before any digest comparison; then compare SHA-256 of each exact body. Empty bodies use SHA-256 of empty bytes. A filename prefix never authorizes an extra file.

## 4. Signature, YAML and binding order

1. Validate options, reader contract and key length without reading. Load and frame-check the bounded archive under section 3.
2. Apply the limits-only envelope preflight below, then call `dsse.Verify(envelope, dsse.TypeExtensionManifest, authorizedKey)`. Propagate its sentinel unchanged. Never call a YAML scanner, decoder or validator on an unauthenticated payload, including when a control file contains obvious malformed YAML.
3. Check the verified payload's actual byte length against 1 MiB, then require byte equality with `extension.yaml`. The DSSE API has a larger generic payload cap, so the envelope preflight must bound decoded payload length before verification allocates payload/PAE bytes. The post-verification length check is defense in depth. There is one signature verification and one base64 payload decode.
4. Call the single two-pass parser on these same bytes through the [accounted converter](#qualification-observation-boundary); `Decode` and `DecodeAccounted` share that parser (section 6.1). It checks UTF-8/BOM, runs the token-aware preflight, then makes exactly one budgeted Node construction pass. The preflight proves single-document framing through stream end; do not call Decode a second time to look for EOF.
5. Inspect the bounded node tree, reject duplicate decoded keys, apply section 4.3's per-mapping conversion bound, and convert manually to `map[string]any`, `[]any`, `string`, `bool` and `json.Number`. Run `manifest.Validate` once with explicit caller options. Propagate its sentinel unchanged.
6. Require `metadata.publisher.key == "sha256:" + lowercaseHex(SHA256(authorizedKey))`, hashing exactly the 32 raw public-key bytes. Then check the file set, sizes and digests. Id-prefix authority is an input to the next slice, not an inferred property of the fingerprint.

Before DSSE verification, make a bounded JSON token walk solely to measure every root `payload` string, including duplicate occurrences. Count the decoded JSON string's base64 characters, without base64 decoding or using its contents as authority. Reject more than 1,398,104 characters, or exactly that many without two trailing `=` characters, as `ErrPayloadLimit`. These conditions bound any canonical base64 payload to 1 MiB; malformed shorter values remain DSSE errors. JSON string storage remains inside the 2 MiB envelope budget; base64 output capacity may include two padding bytes beyond the semantic payload ceiling. Use `encoding/json.Decoder.Token` with a fixed depth ceiling of four, no generic tree and a complete scan through JSON EOF. On JSON syntax or excessive nesting return `dsse.ErrEnvelope`; other DSSE shape, Unicode and base64 checks remain in `dsse.Verify`. This preflight has no exported parse-only API. Within the walk, the first syntax/depth or payload-limit failure wins in source order. It never scans YAML, selects a key or reports signature success.

The [DSSE protocol](https://github.com/secure-systems-lab/dsse/blob/master/protocol.md) binds type and payload through pre-authentication encoding. `KeyID` remains an opaque unauthenticated hint under [the Ricevanta DSSE profile](dsse-envelope.md). The loader neither requires it to equal the publisher fingerprint nor invents a publisher certificate or signing-hint contract.

### 4.1 Token-aware preflight

The public [v3.0.4 API](https://pkg.go.dev/go.yaml.in/yaml/v3@v3.0.4) has no token stream API. Implement a package-private scanner adapter from the exact v3.0.4 reader/scanner/event-parser sources in `loader/internal/yamltokens`, preserving both license notices and source provenance. Use the pinned [scanner](https://github.com/yaml/go-yaml/blob/v3.0.4/scannerc.go), [reader](https://raw.githubusercontent.com/yaml/go-yaml/v3.0.4/readerc.go) and [event parser](https://raw.githubusercontent.com/yaml/go-yaml/v3.0.4/parserc.go). Keep those files and required support types; section 6.1 adds only the pinned Node builder and resolver portions needed for the budgeted fallback. No emitter, reflection decoder or alternate tree representation belongs here. Observe raw tokens before the event parser normalizes tags. Consume events through stream end without constructing a tree. Count document events, scalar/key events and collection starts to enforce one document, 65,536 nodes and container depth 16 before Node allocation. An empty implicit scalar still counts as a node. Audit event lookahead before growth. This is a reviewed adaptation of the pinned dependency, not a regex or an independently invented YAML lexer. Audit and instrument every buffer, token queue, indentation stack and flow stack before growth. Both passes use this same adapted scanner; the unmodified module decoder is a test-only agreement oracle. Keep the exact module pin for `yaml.Node` types and oracle tests.

The preflight consumes the full bounded payload and classifies YAML tokens using lexical context. Reject every tag token, including bare `!`, named handles, `!!` and verbatim forms. Reject anchors, aliases and directives, including `%TAG` and `%YAML`; no custom tag handle is admitted. Preserve literal `!`, `&`, `*`, `---`, `...` and `#` inside plain, quoted and block scalar content. A comment cannot create a token. Handle double-quote escapes, doubled single quotes, flow collections, indentation, block scalar indentation/chomping and CRLF without rewriting the signed input. [YAML 1.2.2 sections 6 through 9](https://yaml.org/spec/1.2.2/) define those contexts.

Permit one optional leading document-start marker and one optional trailing document-end marker. Require exactly one nonempty document; reject a second start marker even for an empty document, or tokens after the end marker other than stream end. A payload containing only comments or markers fails. Comments after the document are allowed. The event parser proves complete document framing, including malformed trailing tokens without a second start marker. The budgeted Node builder still validates syntax; a line-based marker search is not framing proof.

Use at most 262,208 emitted tokens, at most 1,048,576 aggregate token-value bytes, and at most 64 entries in each scanner indentation/flow stack. These are additional conservative parser-work ceilings, distinct from the accepted tree's limits. Stop before the next allocation or stack growth exceeds a ceiling. The adapter owns fixed counters and bounded queues plus the cumulative allocation ledger in section 6.1; section 6 must prove that scanner lookahead and scalar buffers cannot allocate outside these bounds. A malformed or over-budget lexical stream may stop without examining its suffix.

### 4.2 Node inspection and conversion

The document wrapper must contain one root mapping. Ignore the wrapper when counting the manifest tree. Enforce the exact node, text-byte and container-depth accounting from [manifest section 6](extension-manifest.md#6-exact-go-api-and-error-precedence), including key nodes, before allocating the output map or slices. Traverse with a bounded explicit stack. Anchors, alias nodes, explicit-tag style and merge keys fail even if the preflight misses them. Reject every decoded mapping key equal to `<<`, including quoted spelling.

Accept only mapping, sequence and scalar node kinds with implicit `!!map`, `!!seq`, `!!str`, `!!bool` or `!!int` tags as appropriate. A string key must be a scalar with `!!str`. Reject complex keys, nulls, binary, timestamps and floats. A boolean's node text must be exactly `true` or `false`. An integer must be `0` or `[1-9][0-9]*`, at most 20 digits and fit `uint64`; preserve its lexeme in `json.Number`. Reject plus signs, negatives, leading zeroes, underscores, hexadecimal and octal. Quoted numbers remain strings. Plain `yes`, `no`, `on` and `off` remain strings when the pinned resolver identifies them as strings; they never satisfy boolean fields.

Decoded strings must be valid UTF-8; no coercion or case folding occurs. Detect duplicate keys per mapping on decoded string values, including `"kind"` beside `"k\u0069nd"`, before building any Go map. Keep duplicate detection separate from tree/profile checks to preserve section 5 precedence. Do not use `Node.Decode`, struct decoding, map decoding or YAML reserialization. The [pinned Node parser](https://raw.githubusercontent.com/yaml/go-yaml/v3.0.4/decode.go) erases bare `!` as an explicit-tag distinction, so Node checks cannot replace the preflight.

### 4.3 Native map allocation bound

Convert only mappings with at most 896 decoded key/value pairs. After complete tree/profile inspection and the complete duplicate-key pass, reject a larger mapping anywhere with `ErrYAMLLimit`, before allocating any output map or slice. Inspection may record the largest arity, but must not reject for this bound early. This is a conversion resource bound, not a schema check or a parser limit. Keep one `manifest.Validate` call after conversion; do not prune unknown subtrees or skip their profile, text, node, depth or duplicate checks.

All 27 object shapes in [the manifest schema](../../schemas/extension/v1alpha1/manifest.schema.json) have `additionalProperties: false`; none has pattern properties. The largest declares 13 properties, the collector capabilities object. Thus no schema-valid manifest reaches this bound. Keep every schema cardinality, the aggregate 25,040-entry maximum-valid witness, all tree/text/payload limits and every permitted YAML presentation. Schema revisions must recheck this closed-object proof. Mappings of 14 through 896 entries still convert and receive the existing manifest error; larger profile-valid, duplicate-free mappings receive `ErrYAMLLimit` instead of reaching schema validation. Earlier error stages retain precedence.

The bound excludes hash-dependent growth in Go 1.27.1 for every seed, rather than estimating its probability:

- [Map construction](https://raw.githubusercontent.com/golang/go/go1.27.1/src/internal/runtime/maps/map.go) treats a capacity hint as an average-case estimate in general. For `9 <= n <= 896`, however, `target = floor(8*n/7)` is at most 1024, so the directory contains exactly one table. Its rounded capacity `c = nextPowerOfTwo(target)` satisfies `n <= 7*c/8` for every integer in this interval.
- [Table initialization and insertion](https://raw.githubusercontent.com/golang/go/go1.27.1/src/internal/runtime/maps/table.go) give that table `7*c/8` insertions before growth. Construction inserts exactly the checked distinct keys with no deletions, clearing, extra keys or concurrent mutation. Collisions change probing, not the remaining capacity. For `1 <= n <= 8`, the small-map path uses one eight-slot group; `n = 0` needs no group. [String-key insertion](https://raw.githubusercontent.com/golang/go/go1.27.1/src/internal/runtime/maps/runtime_faststr.go) therefore reaches neither table growth nor a directory split for an admitted mapping.
- At 897 entries, a table can exceed 896 occupied slots under an unfavorable hash prefix. Splits allocate replacement tables and can repeatedly double the directory. Pre-sizing alone does not bound cumulative allocations by a linear per-entry constant. A controlled-seed source experiment selects 897 keys sharing ten high hash bits: one run allocates 934,992 bytes and 57 objects against the candidate's 344,576-byte reservation. It uses test-only runtime seed access, not an end-to-end attacker payload. The experiment proves an insufficient bound; it does not prove that a remote publisher can predict a production seed.

Before each `make(map[string]any, n)`, reserve the following map-owned allocations in the shared ledger. Let `R(s) = 2*s + 32` below 32,768 requested bytes, and `R(s) = s + 8,192` at or above that size. These conservative bounds cover size-class/header or page rounding in the pinned [allocator](https://raw.githubusercontent.com/golang/go/go1.27.1/src/runtime/malloc.go), [rounding rules](https://raw.githubusercontent.com/golang/go/go1.27.1/src/runtime/msize.go) and [size classes](https://raw.githubusercontent.com/golang/go/go1.27.1/src/internal/runtime/gc/sizeclasses.go). Round each allocation separately; never apply one rounding charge to an aggregate.

| Checked arity | Byte reservation | Object reservation |
|---|---|---|
| `n = 0` | `R(48)` | 1 |
| `1 <= n <= 8` | `R(48) + R(264)` | 2 |
| `9 <= n <= 896` | `R(48) + R(8) + R(32) + R(264*c/8)` | 4 |

The [compiler layouts](https://raw.githubusercontent.com/golang/go/go1.27.1/src/cmd/compile/internal/reflectdata/map.go) and [runtime groups](https://raw.githubusercontent.com/golang/go/go1.27.1/src/internal/runtime/maps/group.go) give a 48-byte map header, an 8-byte directory entry, a 32-byte table and a 264-byte group on the required 64-bit targets. String and interface slots are each 16 bytes, below the [128-byte indirect-storage thresholds](https://raw.githubusercontent.com/golang/go/go1.27.1/src/internal/abi/map.go); insertion copies headers without allocating key bytes or indirect slot objects. Charge scalar interface boxes, slice headers/backings, traversal and duplicate scratch, and any other allocating helper separately. Immutable Node string storage may be shared; no Node pointer or mutable alias may escape. Reserve even when the compiler places an object on the stack. No runtime seed access, unsafe map construction, custom runtime or alternate public map type belongs in production.

These charges cover map storage, not the entire converter or loader. Task 3 must complete the source audit for helper/runtime work and each remaining allocation family; Gate B must prove their combined bound with the parser on Linux x64, Windows x64 and macOS ARM64. A runtime, compiler-layout or map-operation change requires a fresh source audit and native evidence. Keep the 64 MiB, 1,000,000-object and stack ceilings unchanged. Gate A's parser acceptance is unchanged, including inputs that conversion later rejects.

Alternatives: checking closed schema shapes on Nodes could retain `manifest.ErrShape` for oversized objects, but duplicates shape logic and changes the validator boundary. A 13-property guard needlessly narrows profile-valid conversion below the runtime's proven limit. A custom temporary map still has to construct the exact native map result. Larger linear constants, random-seed retries, process memory limits and panic recovery cannot prevent directory growth outside the reservation before a ledger check. The selected guard preserves valid capacity and the native API with one resource check; its trade-off is the explicit error change for oversized, schema-invalid mappings.

## 5. Errors and precedence

Declare these exact `errors.New` sentinels in `loader`. Static context may wrap one with `%w`; error strings must not contain member names, YAML excerpts, fingerprints or parser diagnostics controlled by the publisher.

| Sentinel | Message |
|---|---|
| `ErrOptions` | `extension loader options` |
| `ErrReader` | `extension loader reader` |
| `ErrKey` | `extension loader key length` |
| `ErrCompressedLimit` | `extension compressed limit` |
| `ErrRead` | `extension read` |
| `ErrCompression` | `extension compression` |
| `ErrArchiveLimit` | `extension archive limit` |
| `ErrArchive` | `extension archive format` |
| `ErrMember` | `extension archive member` |
| `ErrMemberDuplicate` | `extension duplicate member` |
| `ErrControls` | `extension control members` |
| `ErrPayloadLimit` | `extension payload limit` |
| `ErrPayloadMismatch` | `extension payload mismatch` |
| `ErrYAML` | `extension YAML profile` |
| `ErrYAMLLimit` | `extension YAML limit` |
| `ErrExplicitTag` | `extension YAML explicit tag` |
| `ErrDuplicateKey` | `extension YAML duplicate key` |
| `ErrPublisher` | `extension publisher binding` |
| `ErrFileSet` | `extension file set` |
| `ErrFileSize` | `extension file size` |
| `ErrFileDigest` | `extension file digest` |

Apply stages in this order. Each completed stage dominates every later stage, independent of manifest map order. Bounds and structural parse failures have the local short-circuit rules below; do not keep parsing dangerous input to discover a preferred later error.

| Stage | Checks and internal order |
|---|---|
| 1 | Options outside the hard ceiling: `ErrOptions`; reader contract: `ErrReader`; key length: `ErrKey` |
| 2 | Extra compressed byte: `ErrCompressedLimit`; otherwise source failure: `ErrRead` |
| 3 | Invalid zstd framing: `ErrCompression`; during the frame-header walk, a valid declared size above `T` or window above 8 MiB: `ErrArchiveLimit`; decoder/checksum/size disagreement: `ErrCompression` |
| 4 | Physical tar walk in archive order: header/framing/padding/truncation defects: `ErrArchive`; size/count/sum ceiling: `ErrArchiveLimit`; type or path violation: `ErrMember`; duplicate or prefix collision: `ErrMemberDuplicate`; after full traversal missing controls: `ErrControls` |
| 5 | Envelope budget walk in source order: `dsse.ErrEnvelope` or `ErrPayloadLimit`; then `dsse.Verify` failure with its exact sentinel and internal precedence |
| 6 | Verified payload over 1 MiB: `ErrPayloadLimit`; unequal control bytes: `ErrPayloadMismatch` |
| 7 | Invalid UTF-8/BOM: `ErrYAML`; token scan stops at first encountered syntax/profile defect (`ErrYAML`), limit (`ErrYAMLLimit`) or tag (`ErrExplicitTag`); missing/extra document: `ErrYAML` |
| 8 | Budgeted Node allocation failure: `ErrYAMLLimit`; other single Node decode failure: `ErrYAML`; bounded Node traversal stops on first tree budget (`ErrYAMLLimit`) or profile defect (`ErrYAML`) in source order |
| 9 | Duplicate decoded key anywhere: `ErrDuplicateKey`; then section 4.3's per-mapping bound: `ErrYAMLLimit`; then manual conversion; allocation exhaustion during duplicate detection or conversion: `ErrYAMLLimit` before growth |
| 10 | `manifest.Validate` failure: its exact sentinel and whole-tree precedence |
| 11 | Publisher fingerprint mismatch: `ErrPublisher` |
| 12 | Any missing/extra member: `ErrFileSet`; any size mismatch: `ErrFileSize`; any digest mismatch: `ErrFileDigest` |

Within each physical tar header, check header integrity, then size/count/sum, then type/path, then duplicate/prefix collision, then body extent and padding. Unknown member names cannot evade size checks. The first failing header wins; reordering broken tar members may change its error. Token errors likewise follow source order. These local rules do not promise whole-stream prioritization before safe framing exists.

`ErrRead` additionally wraps the original I/O cause for `errors.Is`; every other loader error matches exactly one loader sentinel. Propagated DSSE and manifest errors match only the owning package's sentinel, without a generic loader wrapper. Do not expose raw zstd, tar or YAML errors. Combined cases: bad signature plus tag returns `dsse.ErrSignature`; mismatched manifest plus duplicate key returns `ErrPayloadMismatch`; validly signed unknown field plus false publisher returns `manifest.ErrShape`; false publisher plus wrong file digest returns `ErrPublisher`; size mismatch in one file plus digest mismatch in another returns `ErrFileSize` regardless of member order.

## 6. Parser and complete-loader qualification

Use the budgeted v3.0.4 adaptation in section 6.1. [The qualification artifact](../../server/internal/extensions/loader/GATE_A_REVIEW.md) owns the candidate identity, Gate A outcome, independent review and native evidence. The unmodified v3.0.4 Node decoder is a rejected alternative. For the accepted parser input `strings.Repeat("- {} #c\n", 65535)` (524,280 bytes, 65,536 nodes and depth 2), unmodified Node decode allocates 78,958,448 bytes; the combined call allocates 105,189,016 bytes. These exceed 67,108,864 bytes by 11,849,584 and 38,080,152 respectively. The later root-shape rejection does not excuse the excess: Gate A includes inputs that later validation rejects. The unmodified decoder cannot satisfy the allocation contract.

Retain the 1 MiB payload, 65,536 tree nodes, depth 16, token/value/stack ceilings and all schema cardinalities. Qualification requires source review and native measurements for the exact candidate; selecting an adaptation alone cannot qualify it.

Gate A qualifies the parser in plan Task 1 before Task 2 starts. Gate B qualifies conversion and the complete loader after Task 4, using Task 5's harness. Tasks 2 through 4 may build the candidate pipeline only after Gate A approval; only loader tests and qualification harnesses may call it until both reviews pass. No production consumer, handler wiring or admission integration may import or invoke the candidate before both approvals. An exported `Load` declaration in the isolated candidate is not permission for production use. Requiring complete-loader evidence before building the candidate is rejected because that evidence needs the archive reader, converter and assembled pipeline.

### 6.1 Fallback decision and parser contract

Lower structural caps cannot supply measured headroom while preserving the manifest contract. The counterexample's observed combined rate is `105,189,016 / 65,536 = 1,605.0570068359375` allocated bytes per node; Node-only is `78,958,448 / 65,536 = 1,204.810302734375`. A linear estimate gives `floor(67,108,864 / 1,605.0570068359375) = 41,810` nodes with no reserve, or 33,448 nodes with a 20% reserve. These are screening estimates, not upper bounds: fixed costs, comment layout and slice capacity steps defeat linear proof. A 32,768-node cap projects 52,594,508 bytes on this recipe, but is too small for legitimate manifests.

The largest semantically valid tree has 62,437 nodes, below the existing 65,536 ceiling. Its construction uses 64 service connectors, each with 64 distinct outbound tuples, all four connector interfaces, 4,096 listed files, exactly one owner per file and the optional homepage. The accounting is:

| Part | Nodes |
|---|---:|
| Root, metadata including publisher, spec, requires with four interfaces, and outer arrays | 37 |
| 64 connectors excluding owned path elements | `64 * (15 + 64 * 7) = 29,632` |
| Owned file path elements, summed across components | 4,096 |
| `files[]` records, each one map plus three keys and three scalars | `4,096 * 7 = 28,672` |
| Total | `37 + 29,632 + 4,096 + 28,672 = 62,437` |

This maximum follows the closed schema and ownership rule. Excluding owned path elements, each connector costs at most 463 nodes; the largest other branch, a browser adapter, costs 227. Adding every other requires kind can add only 15 nodes, less than even one 236-node component loss. Attestations cannot increase the ownership total. The same construction uses `16 + 64 * (6 + 1 + 64 * 3) + 4,096 * 3 = 25,040` mapping entries; it also maximizes that count because each other component branch has fewer entries even after requires keys are added.

A reproducible compact JSON-form YAML witness uses paths `f0000` through `f4095`, names `c0` through `c63`, 64 consecutive owned paths per connector, its first path as `file`, and cycles the schema's four connector interfaces. Each outbound array lists `h0.x` through `h63.x`, port 1 and transport `tcp`. Use zero-size files with the SHA-256 of empty bytes, id `a.b`, version `1.0.0`, publisher name `a`, a `sha256:` fingerprint with 64 zero digits, license `MIT`, and source/homepage `https://a.b`. With compact JSON separators and no final newline it is 639,793 bytes. The fingerprint is validator data only; a signed load test substitutes its fixture key's equal-length fingerprint. A trailing YAML comment can pad it to exactly 1,048,576 bytes without changing its tree. The harness must check schema and `manifest.Validate` success, ownership, byte length and node count, not infer validity from node counts alone.

At the observed rate, 62,437 nodes project 100,214,944.33581543 bytes, already above the gate; no claim is made that this valid witness has that measured cost. A file-only calculation misses 4,096 ownership references and capability trees. Reducing mapping entries does not reject the empty-mapping counterexample, which has zero entries. Reducing input below 524,280 bytes excludes the 639,793-byte witness and permitted comments up to 1 MiB. Joint caps still cannot replace a source allocation bound. Clamped growth does not satisfy a generic less-than-twice-capacity bound: token capacities `16, 32, ..., 262,144, 262,208` sum to 786,480 slots, or 113,253,120 bytes at 144 bytes each, before allocator rounding. The final clamp adds another backing allocation. The analogous less-than-`2B` byte-buffer claim also fails for capacities starting at 33 then doubling and clamping to 1,048,576: their sum is 2,129,887, above 2,097,152. Reachability needs a separate proof; neither that sequence nor the artifact's comment-record bound below 352,321,536 bytes establishes 64 MiB.

A direct valid-manifest counterexample removes reliance on that projection. Insert ` #c\n` after every comma and colon token outside JSON strings in the compact witness. The result is 855,713 bytes, 62,437 nodes, depth 7 and 477,323 decoded text bytes; preflight, pinned Node decode and `manifest.Validate` accept it. A fresh Go 1.27.1 Linux x64 combined measurement using the unmodified Node decoder allocates 93,661,808 bytes and 478,779 objects, exceeding the ceiling by 26,552,944 bytes. Independent reviewer reproduction records 93,661,792 bytes; the 16-byte variation does not affect failure. These finite measurements support the fallback decision, not universal bounds or native Gate A approval. The commented payload SHA-256 is `af263524ee80433b68ef296023ef57e099d23d5f08fe3237c384f82738ca30bb`. Retain this exact recipe in the maintained Task 1 harness. Any structural/work cap low enough to reject this manifest cuts currently supported capacity or YAML presentation.

Rejected alternatives: lower node, aggregate mapping-entry or byte caps cut supported manifest capacity without proving Gate A; raising allocation limits weakens the security budget; dropping comment cases or banning comment placement changes the YAML profile. A different parser or pin adds unnecessary grammar and dependency risk. JSON-only input, `GOMEMLIMIT`, recovery from panic and goroutine timeouts supply neither the required YAML support nor a pre-allocation bound.

The fallback extends `loader/internal/yamltokens` with the Node-building portion of pinned `decode.go` and the implicit resolver portion of `resolve.go`, using the exact module's `yaml.Node` type. Keep the existing scanner/event adaptation and one complete preflight followed by exactly one Node construction on the same immutable bytes. Do not call the unmodified `yaml.Decoder`, `Node.Decode`, a reflection decoder or a second tree builder in the candidate path. Keep syntax, kind, tag, scalar value/style, marks and source child order equal to pinned Node behavior; profile rejection and duplicate detection remain later stages.

Use these allocation rules in both passes:

- Consume comments using the pinned lexical contexts and mark advancement, but discard presentation comment text before buffer growth. Do not queue comment records, join event comments or populate Node comment fields. Preserve every signed payload byte separately, and never strip or rewrite the input. Literal `#` in scalar content still belongs to the scalar. Compare trees to the oracle ignoring only `HeadComment`, `LineComment` and `FootComment`; comment elision must not change framing, scalar folding or accepted syntax.
- Preflight records checked node count and container arities in bounded flat storage, not a second tree. Let `N` be the checked node count for this input, excluding the document wrapper. Allocate one exact Node arena of `N+1` elements and one exact Content-pointer arena of `N` elements, including the document edge. Carve each container's Content slice from its recorded arity; reserve space before writing. Check count and depth before each Node creation/descent even after preflight, and fail on any disagreement. No append may silently grow either arena.
- Replace the simple-key map with bounded slots keyed by live flow level, preserving token lookup and stale-key semantics; at most 64 live levels exist. Compact token storage and reuse scratch capacity. Every reader/scanner buffer, token queue, arity record, parser state/mark/indent/flow stack, scalar string, resolver temporary and Node/Content allocation must have a check before growth. Removing comment storage alone is not an allocation proof.
- Use one monotonic per-call allocation ledger across preflight and Node construction; Gate B continues that ledger through inspection, duplicate detection and conversion. Charge cumulative allocation, including abandoned backing arrays and copied strings, without refunds on reuse or release. Before `make`, `new`, copying conversion, append growth or an allocating helper, reserve a source-derived upper bound on allocator-rounded bytes and allocation objects, with checked arithmetic. Never charge only logical length or live heap. Reserve audited fixed runtime/helper overhead at entry. Limits remain 67,108,864 bytes and 1,000,000 objects for the whole YAML path, with 8 MiB stack growth verified separately. A helper without a defensible bound prevents Gate A qualification and must be replaced; sampled allocator deltas cannot define its charge.
- Preserve pinned implicit scalar resolution, including rejected scalar classes; account for `strconv`, timestamp and regexp work before calls, or use an independently reviewed allocation-bounded equivalent with differential tests. Use static internal errors; exhaustion returns `ErrLimit` before allocation, maps to `ErrYAMLLimit` in the current stage, and returns no tree. Syntax returns `ErrSyntax`, explicit tags `ErrTag`. Preserve first-error source order, full preflight before Node/profile errors, and duplicate checks before conversion.

The internal API is `Check(payload []byte) error` for standalone preflight tests and `Decode(payload []byte) (*yaml.Node, *Budget, error)` for the complete two-pass parser. `Decode` creates the ledger, runs preflight itself and performs one Node construction; callers must not run `Check` first. `Budget.Reserve(bytes, objects uint64) error` charges caller-proved allocation upper bounds; its counters are private and cannot be reset or refunded. Successful Decode returns the cumulative ledger for Task 3; any failure returns nil Node and nil Budget. Gate B's [qualification observation boundary](#qualification-observation-boundary) retains that same ledger internally on failures without changing `Decode`'s result contract. Node-only harness mode invokes a test-only construction entry with preflight statistics prepared before measurement and a fresh ledger; combined mode measures `Decode`, including its preflight and ledger initialization.

Parser/API changes and source/licensing provenance require approval from the design author and independent reviewer before implementation. Preserve both notices, upstream checksums, copied source ranges and a deterministic patch digest, including resolver adaptations. No new public loader API, dependency pin, schema or byte vector is required. The allocation charges and comment-elision semantics need source proof and tests; the fallback must accept the maximum valid witness and the commented-empty-mapping parser counterexample within budget, not hide a regression by exhausting its ledger. Prove coverage of legitimate manifests under the existing limits, including permitted comment placement and scalar forms, before Gate A approval. If a bound cannot be proved, stop dependent work and revise the adaptation through independent review.

### Gate A: parser qualification before Task 2

1. Audit every growth site in the adapted scanner, reader, parser, resolver and Node builder, against their pinned sources. Derive upper bounds from payload bytes, emitted tokens and the scanner stack caps for lookahead, comments, scalar accumulation, parser states, Node allocations and recursion. Include rejected inputs, empty implicit scalars and parser work before the first returned token. Map each bound to a check or a finite input-derived proof; a benchmark is not proof for all input.
2. Build a test-only isolated subprocess harness. Inputs include maximum comments, escaped and block scalars, dense empty flow collections, many tiny keys, indentation and flow nesting, explicit-key syntax, repeated tag/anchor attempts, missing delimiters at EOF and 1 MiB malformed suffixes. Vary sizes geometrically through the cap, plus cap-1/cap/cap+1. Measure preflight and budgeted Node construction separately, then their combined call without map conversion. Retain the failing recipe unchanged, add the maximum valid witness with interleaved comments and 1 MiB padding, and exercise allocator boundaries and rejection paths. The unmodified Node decoder runs only as an isolated test oracle, outside candidate measurements. Do not install a production consumer for the harness.
3. Record raw `runtime.MemStats.TotalAlloc` and `Mallocs` deltas with one operation per fresh process, using the measurement isolation rule below for both gates and decoder tests. Build inputs and classify them in the parent before measurement; the child constructs its input before its initial snapshot, prepares only the runtime, forces GC once, performs no candidate warmup, sets `debug.SetMemoryLimit(math.MaxInt64)` before preparation so an inherited `GOMEMLIMIT` cannot trigger collection, and holds `debug.SetGCPercent(-1)` from before the initial snapshot until after the final snapshot to retain transient allocations and stacks. Rejected preflight inputs never reach Node construction, including Node-only mode. Keep payload and Node live through the final snapshot; walk the tree after measurement. Retained heap includes transients; peak resident memory includes process startup and input generation and is not incremental heap. Native measurement API failure fails the child. Record `StackInuse`, live heap with the result retained, wall time and peak resident memory in native CI. The scanner plus Node decode must allocate at most 64 MiB and 1,000,000 objects, and grow stack memory by at most 8 MiB per call, including failures. These are preliminary ceilings within Gate B's combined budget, not an extra allowance for conversion. Source reasoning must support the finite bounds, not just the sampled maximum.
4. Require independent `code_reviewer` review of the source bound, corpus coverage, measured results and scanner/Node agreement before Task 2. Success requires no acceptance disagreement within the restricted profile, no panic and no missing pre-allocation bound. Compare complete tree values, tags, styles, marks and child order as well as node/depth counts, excluding only discarded comment fields. The maximum valid witness must pass without allocation exhaustion. CI runs parser-harness timed fuzzing and native Go 1.27.1 measurements on Linux x64, Windows x64 and macOS ARM64; local work runs only the finite smoke corpus. Gate A requires no archive reader, map converter or `Load` implementation.

#### Measurement isolation and runtime activity

Use runtime preparation with conservative raw counters for acceptance, plus separate allocation-profile diagnostics. OS-thread creation can contribute process-wide allocations without loader or adapted-parser frames. A raw count signature alone does not attribute those allocations; attribution requires complete native stacks for the measured child. Thread creation is process-wide activity, not a platform-specific parser charge. Empirical trace evidence belongs in [the qualification artifact](../../server/internal/extensions/loader/GATE_A_REVIEW.md).

In every fresh measurement child, set `runtime.GOMAXPROCS(1)` before setup. Exercise scheduler handoff and OS-thread creation outside the interval with two runtime-only helper goroutines: each locks its OS thread, signals readiness and parks at a release barrier; release both after both are ready, require each to unlock before exit, and join both. Prepare snapshot storage and measurement helpers, then perform the single pre-snapshot GC. No helper remains runnable during measurement. Never invoke the parser, converter, loader, decoder, resolver or their lazy initialization during preparation; never grow the measuring goroutine's stack deliberately. Only runtime/thread preparation is warm. Production scheduling is unchanged. This reduces scheduler noise; it is not a proof that Go cannot create another thread.

Use raw bytes and objects without subtraction for every pass/fail comparison. The YAML ledger bounds all allocations caused by the measured parser/conversion call, including synchronous runtime/helper work, cold initialization, failed calls and abandoned storage. Require its raw byte/object deltas at most the same-call cumulative ledger charges and unchanged YAML ceilings. Full `Load` has the separately source-audited allocation envelope in Gate B; it is not compared with a YAML-only ledger. Its audit covers every loader/dependency allocation, including failures, and its raw byte delta must fit that envelope; record full-call object and stack counts and prove their finite source bounds. An excess fails qualification even if diagnostics identify unrelated runtime work; fix measurement isolation and rerun the complete required batch, never retry until a passing sample or select a minimum. Source audit must also cover loader-caused asynchronous work even when a profile lacks a loader frame. Keep native retained heap, stack growth, resident-memory peaks, normal-GC ownership tests and serial/two-call tests intact; run concurrency/ownership checks under normal scheduling as well as isolated allocation measurements.

For diagnostics, use a separate fresh child for the same recipe/mode with `runtime.MemProfileRate=1` set before setup and held constant. Preallocate profile buffers; report cumulative `AllocBytes`/`AllocObjects` record deltas with stacks, not live-object counts. Audit the pinned runtime's profile publication delay and tiny-allocation accounting; flush profiles outside the raw interval and label flush/setup records separately. Truncated stacks, buffer exhaustion, missing records or an unexplained counter mismatch fail the diagnostic. Preserve raw counters, ledger charges, candidate-attributed records and every unattributed record. Loader, `yamltokens` and synchronous dependency frames always count as candidate work, including allocations reached through runtime frames. Absence of those frames alone never proves an allocation unrelated.

The only diagnostic runtime-thread classification is the source-checked chain `wakep -> startm -> newm -> allocm`, with allocation sites in `allocm`, `malg` (including the OS-specific `mpreinit` path), `newMWeakPointer`, or `makeProfStackFP` through `mProfStackInit`/`mcommoninit`. Require the complete runtime-only ancestry through `resetspinning`, `schedule`, `park_m` and `mcall`, exact pinned source sites and native OS verification. Unknown stacks remain unexplained failures, never a generic `runtime.*` exclusion. A profile from another run cannot excuse an excess in the measured child.

No fixed runtime allowance is acceptable in Gate A or Gate B: the extra allowance is zero bytes and zero objects. An allocation-count signature is not a bound on thread creation count or an OS-independent allocation layout. Named, source-bounded runtime/helper work on the YAML path belongs in its shared ledger before allocation; other loader stages belong in the full-load source bound. Both stay within their existing ceilings, and process-wide activity cannot justify increasing either bound. Reject fixed object padding, per-OS slack, subtraction of a baseline or profile totals, and candidate warmup because they can conceal loader allocations. Reject stack-filtered totals as the acceptance metric because profile publication, tiny allocations, truncated stacks and asynchronous ancestry require more proof than these traces provide. `MemProfileRate=1` supplies diagnostic evidence, not the source bound. See [Go's memory-profile contract](https://pkg.go.dev/runtime@go1.27.1#MemProfile).

Gate A qualification applies only to the exact reviewed candidate, harness and native evidence named in [the qualification artifact](../../server/internal/extensions/loader/GATE_A_REVIEW.md). It does not prove that every raw process-wide sample is free of scheduler noise. Parser or measurement-method changes require fresh `loader-gate-a` results and independent confirmation on Linux x64, Windows x64 and macOS ARM64. Require 50 fresh-child repetitions of the affected parser recipe/mode in Gate A on each target, with every sample retained, alongside each gate's complete native suite. Gate A approval does not wait for Gate B assembly. Gate B requires its own reviewed source bounds and native evidence.

Qualification must demonstrate that runtime preparation keeps raw allocations within the applicable YAML ledger or full-load source envelope and unchanged ceilings on every target while all candidate work stays cold. Use the raw-counter method with zero allowance; any excess, including residual runtime noise, fails qualification. Profile-filtered acceptance requires a separate reviewed proof and is not an implementer fallback.

#### Independent acceptance and error agreement

Before running candidate preflight on any fixture or fuzz input, determine expected preflight and Decode acceptance and the sanitized error class independently. Use the isolated, unmodified v3.0.4 oracle for syntax and Node semantics, with separately reviewed test-only checks for sections 4.1 and 5's framing, lexical restrictions, structural/work limits and first-error source order. Those checks must not call or reuse candidate preflight, comment elision or classification code. Fixed cases carry reviewed expected outcomes; generated cases use the same independent reference rules. Oracle YAML acceptance alone does not imply profile acceptance. Later Node inspection, duplicate-key and manifest validation errors remain outside Gate A's Decode result.

Compare expected and candidate acceptance in both directions for every input, including candidate preflight rejections. Expected acceptance plus candidate rejection, expected rejection plus candidate acceptance, and rejection with a different sanitized class all fail qualification. Compare `ErrSyntax`, `ErrTag` and `ErrLimit`, including their section 5 loader mappings and precedence, without comparing or exposing raw oracle diagnostics. Unclassified inputs or reference failures cannot be skipped or counted as agreement; they block qualification until resolved. Only tree comparison depends on successful Decode: compare complete kind, tag, value, style, marks, child order and node/depth counts, ignoring only `HeadComment`, `LineComment` and `FootComment`. Candidate preflight rejection still prevents candidate Node construction, but never prevents the independent acceptance/error comparison.

Keep deliberately injected allocation exhaustion separate from normal-budget agreement. Each injected case specifies the allocation family and expected `ErrLimit` before candidate execution and checks nil Node/Budget from the legacy parser entry and rejection before growth. Under normal budgets, required-profile acceptance loss remains a failure even when the candidate returns `ErrLimit`.

`TestCommentElision`, agreement tests and fuzz seeds must cover this comment-context matrix. Give every case an independent expected acceptance or sanitized rejection before candidate execution. Cross applicable contexts with LF/CRLF, stream end and collection boundaries, and include valid and malformed neighbors.

| Context | Required cases |
|---|---|
| Whitespace-sensitive `#` | Plain scalar `value#tail` versus `value #tail`; `#` at token start; single/double-quoted `#`; block-scalar literal `#`; spaces versus tabs before `#` |
| Tabs | Tabs in indentation, legal separation, quoted/block scalar content and comment text; tabs before/after flow delimiters and comment starts |
| Byte-order mark (BOM) | One leading UTF-8 BOM, repeated leading BOM, BOM after whitespace/comment, and interior BOM at token/scalar boundaries; apply section 5's BOM rule before lexical errors |
| Tags, anchors and aliases | Bare/named/verbatim tags, anchors and aliases adjacent to `#` with/without separation; the same spellings inside comments and scalar content; comment-separated properties and values |
| Flow and explicit keys | Comments before/after commas, colons, brackets, braces and explicit-key indicators; empty collections and missing key/value positions |
| Block scalars | Comments on headers, indentation indicators, folding/chomping variants, and literal `#` at differing content indentation |
| Document framing | Comment-only input/tails, comments around start/end markers, extra markers/documents and tokens after an end marker |
| Malformed comment-bearing input | Unterminated quotes/flow collections, invalid escapes, missing delimiters, invalid indentation and malformed EOF/suffixes; combine tag/limit/syntax defects in both source orders to check sanitized precedence |

### Gate B: complete-loader qualification after Task 4

1. Extend the source-bound audit and subprocess harness to Task 3's tree inspection, duplicate detection and map conversion, and Task 4's complete `Load` pipeline. Reuse Gate A's corpus and measurement method. The scanner plus Node decode plus inspection, duplicate detection and map conversion together must allocate at most 64 MiB and 1,000,000 objects, and grow stack memory by at most 8 MiB per call, including failures. Recheck scanner/Node agreement against the assembled path.
2. Measure full-load incremental allocation against `4*C + 4*T + 128 MiB`, including DSSE, decoder and independent output copies, on success and failure. Reject a candidate that exceeds this envelope; do not call it a hard process limit. CI records serial and two-call peaks on Go 1.27.1 for Linux x64, Windows x64 and macOS ARM64. The later handler defaults to one in-flight load and must budget concurrency separately before adoption. Wall time is reported for comparison, not promised as an interruptible library deadline.
3. Require independent `code_reviewer` review of the complete source bounds, corpus coverage, native measurements and assembled-path agreement, plus Task 5's race and timed-fuzz results. Both Gate A and Gate B approvals are required before production consumers may use the loader. Neither approval replaces key admission or stateful admission.

[CI hardening's loader qualification inventory](ci-hardening.md#loader-qualification-inventory) owns Task 5's exact native jobs, check IDs, receipt units, fuzz inventory and evidence retention. Gate B adds its three native receipts under the existing `loader` route while preserving Gate A. The existing server-wide race job covers this package. The selected-output wrapper remains a separate CI hardening task; neither step-success receipts nor design approval replace Gate B's source and measurement review.

#### Qualification observation boundary

Task 5 adds only these internal observation interfaces. No metrics field or option enters `Load`, `Options`, `Package`, errors, signed bytes or admission. Production wrappers and qualification use one shared parser and one shared converter; measuring a copied pipeline, another invocation's charges or only the YAML ceiling is insufficient.

| Owned source | Exact interface and rule |
|---|---|
| `loader/internal/yamltokens/node.go` | `DecodeAccounted(payload []byte) (*yaml.Node, *Budget, error)` creates one fresh ledger and invokes the existing private `decodeBudget` once. It retains its local ledger even when `decodeBudget` returns nil results. Every return supplies that same non-nil ledger; failure still returns nil Node. `Decode` delegates to `DecodeAccounted`, discards the ledger on failure, and retains its existing three-result contract. |
| `loader/internal/yamltokens/budget.go` | `func (b *Budget) Usage() (bytes, objects uint64)` copies the two cumulative counters from a non-nil ledger, with no allocation, mutation, refund or reset. Reservation and limit behavior stay unchanged. |
| `loader/yaml.go` | Private `type yamlUsage struct { bytes, objects uint64 }` and `decodeVerifiedYAMLAccounted(payload []byte) (map[string]any, yamlUsage, error)` own the existing conversion pipeline. Call `DecodeAccounted` once, continue its ledger through inspection, duplicate checks, map guard and conversion, and copy `Usage()` after all work on every return. Failure returns nil map, the final counters and the unchanged sanitized error. Existing `decodeVerifiedYAML` delegates once and discards only the value snapshot. |

The shared routines allocate and initialize their ledger inside the measured call. Accounting includes any new wrapper, return or escape-related allocation with a source-derived reservation before it occurs, within existing ceilings. Prove value snapshots and reads allocate nothing; do not assume a compiler optimization. Preserve failed reservations' unchanged counters, monotonic successful charges and nil partial data. Usage is diagnostic output only: no caller-supplied metric, budget or observer can alter parsing, validation or authority. No process-global hook, mutable function variable, allocator interception or shared ledger is permitted.

Qualification uses three fresh-child modes, each with section 6's cold runtime preparation, raw counters, liveness and zero allowance:

1. Combined YAML: snapshot immediately around one `decodeVerifiedYAMLAccounted` call. Compare raw bytes/objects with its returned same-call usage and the 64 MiB/1,000,000-object ceilings; apply the 8 MiB stack bound. Preserve success and failure snapshots, including parser, profile, duplicate, map-guard and conversion failures. Wrapper delegation and source audit establish this is the production conversion path.
2. Assembled YAML: call Task 4's existing `loadWithDependencies` once with a per-call test-only `decode` closure and the real `manifest.Validate`. The closure snapshots around one `decodeVerifiedYAMLAccounted` call, copies its usage and raw counters into preallocated per-call storage, then returns its unmodified map/error. It changes no argument or control flow. Pre-verification/equality failures must invoke it zero times; later stages invoke it exactly once. Compare that interval against its own ledger, not the whole-load delta. Keep observation setup, formatting and assertions outside the interval; no second parse, preflight or warmup is allowed. Retain these records even when a later loader stage returns a zero `Package` with an error.
3. Full loader: snapshot around one exported `Load` call using its normal production dependencies, with no observation closure. Compare raw total bytes with `4*C + 4*T + 128 MiB`, retain raw objects, stack, heap, resident memory and elapsed time, and run the required serial/two-call cases. Derive the envelope from all bounded archive, DSSE, YAML, validation, commitment and result-copy allocation families in the source audit. YAML charges already fall inside this envelope and are not an additional allowance; no new full-process ledger or allocation hook is required. Assembled-YAML observations cannot substitute for this direct `Load` measurement.

[Go's `ReadMemStats` contract](https://pkg.go.dev/runtime#ReadMemStats) and [pinned runtime implementation](https://raw.githubusercontent.com/golang/go/go1.27.1/src/runtime/mstats.go) supply the raw snapshots; they do not isolate allocations to a subsystem. Apply the existing zero-subtraction/noise-failure rules to each interval. No mode may subtract observation costs or add fixed runtime slack. All candidate work remains cold; necessary archive/signature work before the assembled converter is the normal pipeline, not preparation.

These interfaces require source, provenance and independent review plus fresh complete native Gate A results, including the required 50 repetitions, before Gate B acceptance. Preserve parser semantics, corpus and ceilings. A missing bound or failed observation check blocks qualification. The seven attacker paths in section 7 are unchanged: this per-call numeric evidence travels only to test assertions/logs, grants no authority and changes no production result. Retaining failed-call counters adds a small internal API and audit burden; it avoids shared observers and a second pipeline. A public metrics option or a global allocation hook widens runtime surfaces without supplying stronger evidence and is rejected.

If the budgeted adaptation cannot satisfy either gate, stop dependent implementation and production integration. The design author and independent reviewer must approve any further parser/API or provenance change before implementation resumes; rerun Gate A before dependent work and Gate B after assembly. A different upstream parser pin requires the same review. A Gate B failure outside the parser requires a fix to that stage and fresh Gate B evidence; rerun Gate A too if its reviewed parser changes. Neither a ledger-only rejection of required valid manifests nor weakened tests can establish qualification.

## 7. Admission handoff and attacker paths

The next slice consumes the exact `Package`, the verifying key identity, current trust/revocation and allowed-prefix evidence, caller principal and install intent, served interface catalogue, component validators, committed id ownership and tombstones, requested grants/approvals and recovery fence inputs. It rechecks current key and prefix authority before publication uses file evidence. A loader success does not freeze trust or reserve an id.

That slice returns either a rejection, an approval request, an identical retry result or a committed installation identity bound to package/manifest/envelope hashes, publisher, component grants and recovery epoch/generations. Only its fenced commit permits blob publication, enabling or compilation. This spec defines no storage, journal protocol or component-digest encoding. Restored or cached loader results must repeat admission, never become authority by reuse.

| Attacker | Path through this slice, boundary and remaining power |
|---|---|
| Stolen enrollment token | Submission still requires an independently authorized publisher key; signature and schema checks give the token no install or grant authority. Enrollment and install permissions remain caller gates. |
| Compromised agent host | Local package bytes and forged uploads pass no server signature boundary. An intact signed package can be replayed; current admission and organization-signed bundles control deployment. Host compromise can still falsify local execution. |
| Compromised console session | Upload reaches byte caps before parsing and cannot select a key through YAML. A session can submit valid requests within its rights or cause bounded load; protected trust/install/grant approval remains necessary. |
| Rogue extension publisher | A signature permits bounded YAML processing, not links, ambiguous keys, unknown fields or mismatched files. The per-mapping guard excludes native-map splits for every seed, including signed unknown subtrees. A trusted rogue can sign malicious but well-formed component bytes; component validators, grants and runtime isolation remain required. |
| Network position between agent and server | Changed manifest or file bytes fail signature/equality/digest checks. Recompression or hint changes can retain a valid signature but change package/envelope identity. The attacker retains replay/drop power; TLS, tombstones and assignments supply later controls. |
| Database writer without signing keys | Replaced bytes fail when the caller reloads and verifies them under independently established current key authority. A forged trust row or manufactured Package is outside this library's authority proof; admission must use committed journal-fenced authority. Valid old packages remain replayable inputs. |
| Server restored from backup | Deterministic loading can accept authentic old bytes. No loader return unseals the server or revives grants; recovery reconciliation and current tombstones remain mandatory before publication. |

## 8. Fixtures and qualification cases

[loader-vectors.json](../../schemas/extension/v1alpha1/loader-vectors.json) supplies the existing raw YAML token controls. Its claimed fingerprint uses arbitrary test public bytes, not an admitted signing key. For end-to-end tests only, replace that one fingerprint with the deterministic signing fixture's fingerprint and sign the resulting exact bytes; token-only tests keep the original bytes.

[package-loader-vectors.json](../../schemas/extension/v1alpha1/package-loader-vectors.json) and [its schema](../../schemas/extension/v1alpha1/package-loader-vectors.schema.json) supply exact public key, payload, archive-manifest and envelope strings, expected signature validity, decoded documents, hashes and outcomes. The public test seed is bytes `00` through `1f`; it is fixture material only. Python cryptography 50.0.0 generates Ed25519 signatures; a separate Go 1.27.1 standard-library script independently reconstructs PAE, signatures and hashes. Validate documents with the existing manifest schema using Python jsonschema 4.25.1. File bytes `abc` are opaque integrity test data, not a classification-content example.

Do not commit binary archives. The plan's test generator builds strict tar/zstd fixtures deterministically from these bytes, then applies named physical mutations. Tests must not regenerate expected signed bytes with the implementation under test.

Required cases:

- All raw tag and literal-exclamation controls; comments, block indentation/chomping, escaped quotes, CRLF, flow/explicit keys, document markers in scalar content, one optional start/end pair, empty input and a second empty document.
- UTF-8 errors, BOM, directives, anchors/aliases, merge keys, escaped duplicate keys at every nesting level, complex/non-string keys, null, binary, timestamp, float, numeric spelling/overflow and quoted-number rejection. JSON syntax must produce the same accepted tree.
- Mapping arities 0/1/8/9/13/14/895/896/897 and every hinted-capacity transition; oversized root and nested mappings; duplicates and profile defects before/after an oversized mapping. Require zero output-container allocations on the oversized-map path, boundary conversion success at 896, and the expected later schema error. Keep all maximum-valid witness presentations and a schema closure/cardinality assertion.
- Tree depth 15/16/17, nodes 65,535/65,536/65,537 and decoded text cap-1/cap/cap+1; scanner tokens and stacks at limit and limit+1. An unknown subtree tests tree-limit precedence before schema shape.
- C and T at cap-1/cap/cap+1; window at 8 MiB and above; all role size/count limits, F near default and hard bounds, arithmetic overflow attempts, short/zero-progress/failing readers and bytes-plus-error reads.
- Truncated/bad checksum zstd, missing size/checksum, dictionaries, reserved bits, concatenated/skippable frames and suffixes. USTAR checksum/size corruption, GNU/PAX/sparse headers, every nonregular type, missing/extra zero blocks and nonzero padding.
- Both controls in all member positions; duplicate controls; aliasing USTAR splits; missing/extra files; path, reserved-root and prefix collisions; zero-length files and exact set equality; size and digest defects across different files.
- Wrong authorized key, invalid key length, wrong DSSE type, bad signature plus tagged YAML, escaped base64 characters, duplicate payload fields across the cap, payload cap and equality failures, changed hint that still verifies, signed wrong publisher and all combined-defect precedence examples in section 5.
- Result ownership, zero result on every failure, sanitized errors, repeatability, unknown component content accepted only as opaque bytes, and no filesystem writes or premature callbacks.

`FuzzLoad` mutates bounded archive bytes/options with a fixed valid public key and asserts no panic, zero result on failure and exact hashes/file commitments on success. `FuzzVerifiedYAML` targets the private post-verification routine using arbitrary bounded bytes; its direct use is test-only. `FuzzTar` targets physical framing without compression. Seed each with small positive and negative fixtures. CI alone runs timed fuzzing and race tests.

## 9. Assessment and review focus

Benefits: one loader preserves signed bytes, parser evidence and file commitments without storage authority. Memory-owned snapshots avoid file replacement and extraction races. Narrow framing makes hidden metadata and trailing archives visible.

Trade-offs and limits: bounded in-memory copies cost memory proportional to archive size. USTAR excludes some manifest-valid long paths and ordinary tool defaults that emit PAX. A 2 MiB envelope ceiling narrows DSSE whitespace/escaping freedom. Scanner adaptation adds maintenance and source-audit work; signatures do not make publisher YAML benign. Production consumers require both qualification approvals, key admission and stateful admission; the loader alone establishes no OS runtime support.

Review focus:

- Does any path tokenize YAML before signature success and exact payload equality?
- Can hidden tar metadata, framing suffixes or alternative prefix/name splits bypass member checks?
- Do scanner lookahead and Node allocations stay inside the reviewed bound on failing input?
- Can string decoding merge two keys, or scalar conversion erase a type defect?
- Can key hints, fingerprints, mutable results or stale trust state be mistaken for admission authority?
- Do combined defects follow the stated whole-stage and local short-circuit rules?

## 10. Unresolved questions

Selected rules apply until an independently reviewed change replaces them.

- Can the assembled loader meet Gate B's allocation bounds and scanner/Node agreement requirements across the complete pipeline while preserving all legitimate manifests? Lower tree, text and payload caps are rejected by section 6.1. Apply section 4.3's conversion-only mapping bound, retain every valid-manifest capacity and require native measurements and independent `code_reviewer` approval before production use; Gate A evidence does not qualify Gate B.
- Do real extension paths require bounded PAX support, instead of the selected USTAR representability restriction?
- Do real package measurements require higher byte ceilings or disk staging, instead of the selected bounded memory snapshots?
- What exact key-admission API will supply the required canonical, non-small-order authorized key without moving that concurrent slice into this loader?
