# Agent sealed batch writer

`ricevanta-batch` turns one complete v1 spool segment into the canonical `Ricevanta-Batch` value and sealed upload body. It rechecks record CRCs, preserves payload bytes and emits the EV-08 descriptor followed by one EV-09 zstd frame. This is a file-free library design, not a durable spool or uploader. Decision: [AG-11](../decisions.md#ag-11-sealed-batch-writer). [The plan](../plans/agent-batch-writer.md) owns implementation tasks and checks.

## 1. Boundary, dependencies and alternatives

Create `agent/crates/batch`, package `ricevanta-batch`, import `ricevanta_batch`, in the existing virtual workspace. The library depends only on `ricevanta-spool` through `path = "../spool", version = "=0.1.0"`, the standard library and `zstd = { version = "=0.13.3", default-features = false }`. It imports no core, OS adapter, async runtime, HTTP, database, JSON or signing package. No dev dependency is needed. Inherit metadata and lints from [Rust instructions](../../instructions/rust.md), including the unsafe-code prohibition.

Use the [zstd 0.13.3 manifest](https://raw.githubusercontent.com/gyscos/zstd-rs/v0.13.3/Cargo.toml) and its safe bulk API over the bundled reference library. Default features are off: no legacy decoder, arrays, dictionary builder, bindgen, experimental API, multithreaded encoder, system `pkg-config` selection or LTO feature. The dependency enables `zstd-safe/std`; [zstd-safe 7.2.2](https://raw.githubusercontent.com/gyscos/zstd-rs/v0.13.3/zstd-safe/Cargo.toml) forwards `std` to `zstd-sys`. Do not enable any additional feature.

Pin this complete added Cargo lockfile closure. Direct dependencies use exact requirements; transitive pins live in `agent/Cargo.lock`, not unused direct dependencies:

| Crate | Exact version | Role |
|---|---|---|
| zstd | 0.13.3 | Safe bulk encoder |
| zstd-safe | 7.2.2 | Safe reference-codec wrapper |
| zstd-sys | 2.0.16+zstd.1.5.7 | Bundled zstd 1.5.7 and supplied bindings |
| cc | 1.4.5 | Native build, `parallel` feature from zstd-sys |
| pkg-config | 0.3.34 | Build dependency, system-library selection disabled |
| find-msvc-tools | 0.1.12 | cc tool discovery |
| shlex | 2.0.1 | cc argument handling |
| jobserver | 0.1.35 | cc build concurrency |
| libc | 0.2.189 | Unix build support |
| getrandom | 0.4.3 | Windows jobserver support |
| cfg-if | 1.0.4 | getrandom configuration |
| r-efi | 6.0.0 | Target-specific lockfile closure, not a v1 host build input |

The existing spool closure stays pinned under AG-10. The [zstd-sys manifest](https://docs.rs/crate/zstd-sys/2.0.16%2Bzstd.1.5.7/source/Cargo.toml) requests cc with parallel build support and pkg-config even without the system-library feature. Its [build script](https://docs.rs/crate/zstd-sys/2.0.16%2Bzstd.1.5.7/source/build.rs) can select a system library through `ZSTD_SYS_USE_PKG_CONFIG`; require that variable unset. C build workers do not enable runtime codec workers. The remaining helper manifests are present in the installed Cargo registry. Verify the resolved closure and release license files before implementation; dependency download is not established by this design. Any different version or feature requires a design correction and review, not an implicit update.

[The licensing row](../licensing.md#libraries-named-in-the-architecture) records the selected license branches. The binding is MIT; the safe/sys wrappers and build helpers permit MIT; bundled zstd uses BSD-3-Clause, not its GPL alternative. Retain notices and include the closure in the release software bill of materials. A native C compiler is required on each build host; exact compiler identity and native build results are qualification evidence, not inferred from a Rust build on Linux.

| Alternative | Benefit | Choice and cost |
|---|---|---|
| zstd 0.13.3 binding | Explicit profile controls and the reference encoder | Selected; adds C compilation and dependency-internal unsafe code |
| Pure Rust ruzstd | Avoids the C boundary | Rejected for this slice: its [maintainer README](https://raw.githubusercontent.com/KillingSpark/zstd-rs/master/Readme.md) lists level 3 compression as unfinished and documents reduced encoder configurability |
| Hand-written raw zstd frames | Small encoder with predictable expansion | Rejected: forfeits event compression and makes the project own checksum/frame construction |
| Streaming encoder | Avoids the contiguous plaintext allocation | Rejected for this file-free slice: one-shot compression gives an explicit input length and documented worst-case bound; durable streaming needs its own resource design |
| Extend ricevanta-spool | Avoids another crate | Rejected: compression and upload framing would widen the segment codec and its dependency closure |

## 2. Exact Rust API and ownership

All public items live at the crate root. `SealedBatch` has private fields and derives `Debug` only through a redacted implementation that reports lengths, not header/body bytes. `Error` derives `Debug`, implements `Display` and `std::error::Error`, and exposes the cause for `Spool` and `Compression`. Match variants and fields, never display text. This is the Rust equivalent of Go `errors.Is` sentinel checks; do not invent Go sentinels for the writer.

```rust
pub const MAX_RECORDS: usize = 5_000;
pub const MAX_NDJSON_BYTES: usize = 4_194_304;
pub const MAX_SEGMENT_BYTES: usize = 4_269_336;

pub enum LineFraming { Blank, Bom, Lf, Cr }
pub enum Error {
    SegmentTooLarge { length: usize },
    Spool(ricevanta_spool::Error),
    Tail(ricevanta_spool::TailIssue),
    Empty,
    RecordCount { count: usize },
    LineFraming { index: usize, kind: LineFraming },
    DecodedLimit { index: usize },
    Compression(std::io::Error),
    CompressedLimit { length: usize },
}

pub struct SealedBatch { /* private String and Vec<u8> */ }
impl SealedBatch {
    pub fn header_value(&self) -> &str;
    pub fn body(&self) -> &[u8];
    pub fn into_parts(self) -> (String, Vec<u8>);
}
pub fn seal(segment: &[u8]) -> Result<SealedBatch, Error>;
```

`LineFraming` derives `Debug, Clone, Copy, PartialEq, Eq`. Indices are zero-based record positions. Error text contains no payload or attacker-controlled key/value text. `Compression` retains the codec's `io::Error` through `source()`; no codec error-string matching. All other errors have no source except `Spool`, which exposes the unchanged spool cause.

`segment` is exactly one raw spool segment, including its 32-byte header and every record frame. `seal` calls `ricevanta_spool::recover` itself, so CRC and contiguous stored-sequence checks cannot be bypassed with caller-constructed records. A borrowed immutable slice stays unchanged for the entire call. No successful result contains input borrows. The returned header and body describe the same records; accessors do not permit changing one independently. `into_parts` transfers ownership to a later file/transport caller, which must preserve their association.

No header-only batch, partial result, callback, log event, counter increment or filesystem side effect occurs. On failure the caller retains the complete original segment. A returned `TailIssue` is an error here, even when recovery found a nonempty valid prefix. Only the later spool manager may durably repair a raw file and call `seal` on the repaired segment. An arbitrary-record iterator or `Recovery` argument would either bypass CRC validation or let a caller silently discard a tail; both are rejected.

## 3. Sealing limits and error precedence

[Events section 2.4](../design/events.md#24-sealing-upload-and-acknowledgement) owns age scheduling and the count trigger. The byte trigger means emitted NDJSON bytes, `sum(payload.len() + 1)`, including every LF and excluding spool framing. The future manager seals the nonempty segment before appending a record that would exceed either writer limit; it seals immediately when a limit is reached. Each legal spool payload fits an empty batch. No overshoot exception, segment splitting, new segment id or record reassignment occurs in this library. A caller may seal a smaller batch for its class age limit. Empty devices require no call or timer here.

`MAX_SEGMENT_BYTES = 32 + MAX_NDJSON_BYTES + 15 * MAX_RECORDS`. Each raw record has 16 framing bytes while NDJSON adds one LF. Thus this input bound rejects no segment otherwise admissible here. The server's larger limits are admission ceilings, not permission for the agent to make larger batches.

Run exactly these stages, stopping at the first failure:

1. Input longer than `MAX_SEGMENT_BYTES`: `SegmentTooLarge`, before inspecting even the spool magic.
2. Call `recover` over the complete supplied slice. Return fatal errors as `Spool(cause)`, preserving [AG-10 precedence](agent-spool-format.md#4-recovery-and-error-precedence). A later fatal record error wins over an earlier record's bad NDJSON framing because recovery precedes payload checks.
3. If recovery reports a tail: `Tail(issue)`. Never compress its valid prefix. Otherwise reject zero records as `Empty`, then more than `MAX_RECORDS` as `RecordCount`.
4. Walk records in order. For each payload, check all-space/tab or empty (`Blank`), initial bytes `ef bb bf` (`Bom`), any literal LF (`Lf`), then any literal CR (`Cr`), in that order. Return `LineFraming` at the first failing record. Spool recovery has already imposed the 1 MiB payload ceiling.
5. Immediately after that record's framing passes, add `payload.len() + 1` to the running total. Compare against the remaining allowance before addition. Overflow of the allowance returns `DecodedLimit` at that record; do not inspect later payloads. No arithmetic can wrap.
6. Allocate exactly sized plaintext, append each unchanged payload and one LF. Build the descriptor from the recovered header and count; take last sequence from the final validated record. Recovery guarantees `last - first == count - 1` without sequence overflow. Create and configure the encoder in section 5 in listed order. The first constructor, setter or compression error becomes `Compression`.
7. If the complete sealed body would exceed 5,000,000 bytes: `CompressedLimit`, returning nothing. Otherwise return the canonical header and completed body. This defense must remain even with the proven bound.

The input is bounded before any scan; recovery and two payload walks are linear in at most that input size. Host allocation failure follows standard Rust allocation behavior; the API does not promise to recover from process-wide out-of-memory failure. No compression occurs before all record checks pass.

Combined-defect vectors: oversized input plus bad magic gives `SegmentTooLarge`; bad CRC plus stored sequence gap gives `Tail(Checksum)`; fatal stored sequence gap plus an earlier blank payload gives `Spool(Sequence)`; header-only plus incomplete record suffix gives `Tail(Incomplete)`; 5,001 records plus blank first payload gives `RecordCount`; BOM plus LF gives `Bom`; LF plus CR gives `Lf`; invalid framing plus total overflow in the same record gives `LineFraming`; total overflow before a later bad payload gives `DecodedLimit`. A final stored sequence of `u64::MAX` is legal; a checksum-valid successor is a spool error.

## 4. NDJSON and descriptor bytes

Payloads remain opaque except for section 3's batch framing checks. Do not trim, reserialize, repair UTF-8, normalize CRLF, append a missing JSON field or rewrite `metadata.sequence`. Escaped `\n` and `\r` are ordinary payload bytes. A producer supplies OCSF JSON, event identifiers and device binding. An invalid JSON value, invalid UTF-8 or mismatched JSON sequence can still seal and reach EV-09 per-line quarantine. Success means batch framing acceptance by the Go decoder with a valid authenticated-device argument, not that every returned line has `Err == nil` or that ingest stores it.

[EV-08 section 2](event-upload-wire.md#2-request-header) owns the exact header grammar. Emit its canonical ordered decimal value, without the field name, whitespace or newline. Use the spool class's `as_str()`. Counts and all counters are unsigned decimal without leading zeros. Derive all fields from the same recovered segment; callers supply no overrides. Future upload sets `Content-Type: application/x-ndjson`, `Content-Encoding: zstd` and exactly one initial `Ricevanta-Batch` field.

For class raw, epoch 1, segment 0, first 0 and one record:

```text
v=1;class=raw;epoch=1;segment=0;first=0;last=0;count=1
```

The exact 48-byte descriptor is the existing `valid-raw` vector in `schemas/events/v1/fixtures/descriptor.json`:

```text
502a4d182800000001010000010000000000000000000000000000000000000000000000000000000000000001000000
```

Emit the offsets from [EV-08 section 3](event-upload-wire.md#3-descriptor-frame) explicitly in little-endian order. Do not serialize Rust memory or copy the spool header. Reserve 48 bytes at the start of the output vector, encode the descriptor there, then place the ordinary frame at offset 48. The body contains no filename, spool CRC, record length, device field, padding, additional frame or trailing byte. The descriptor has no cryptographic authenticity. Its repeated header representation only lets the receiver detect disagreement.

## 5. Compression profile and bounds

Use one fresh `zstd::bulk::Compressor::new(3)` per call and release its context on every exit. Call these setters before compression, in order: `window_log(22)`, `include_checksum(true)`, `include_contentsize(true)`, `include_dictid(false)`, `long_distance_matching(false)`. Do not change level or dictionary afterward. Never provide a dictionary or prefix. Runtime worker count remains zero with `zstdmt` disabled.

The [binding's parameter documentation](https://raw.githubusercontent.com/gyscos/zstd-rs/v0.13.3/src/stream/mod.rs) defines the window as `2^window_log`, checksum inclusion, content-size inclusion and dictionary-id suppression. Its streaming API requires a pledged size; that streaming requirement is not a reason to omit size here. The [bulk implementation](https://raw.githubusercontent.com/gyscos/zstd-rs/v0.13.3/src/bulk/compressor.rs) calls `CCtx::compress2` with the complete input slice. The [reference API](https://raw.githubusercontent.com/facebook/zstd/v1.5.7/lib/zstd.h) documents one-shot source-size knowledge and that `compress2` honors advanced parameters. Do not substitute `compressCCtx`, which resets those parameters.

Allocate output length `48 + zstd::zstd_safe::compress_bound(plain.len())`, initialized to zero. Pass only `&mut output[48..]` to `compress_to_buffer`; truncate to `48 + returned_length` after success. This uses no second compressed-body allocation and keeps the descriptor outside the checksum. `compress2` completes exactly one frame; there is no finish-on-drop path. Inspect the completed length before publication. No frame surgery, flush boundaries or manual checksum construction is allowed.

The [zstd 1.5.7 bound formula](https://raw.githubusercontent.com/facebook/zstd/v1.5.7/lib/zstd.h) gives `compressBound(4_194_304) = 4_210_688`; adding the descriptor gives **4,210,736**, below 5,000,000. The formula is nondecreasing throughout this input range. One-shot compression with that destination capacity has sufficient room even for incompressible data. Tests compare the library bound with the independently calculated value.

The requested window is at most 4 MiB. A single-segment frame instead uses its content size as the effective window, also at most 4 MiB. Both are below EV-09's 64 MiB ceiling. The [zstd frame format](https://www.rfc-editor.org/rfc/rfc8878.html#section-3.1.1) permits both forms. The encoder may choose either form and any valid content-size width; tests require a present exact size, not a fixed flag pattern. Require ordinary magic, checksum flag, zero dictionary/reserved/unused bits, no dictionary, structurally bounded blocks, one checksum and physical EOF under EV-09. Native output across compiler builds need not be byte-identical; decoded bytes, descriptor and profile must be identical.

Caller input, plaintext and output can occupy 12,674,376 bytes at their combined maxima, excluding allocator overhead and the compression context. Release plaintext before returning and hold only one context per call. The library does not impose global concurrency. Verify context memory, total active footprint and latency on all three targets before the core integrates this API. This design does not establish the smaller operational events budget in section 2.6; durable streaming or buffer ownership changes need a reviewed follow-on slice if the measured budget fails.

## 6. Cross-language tests and required vectors

Use live Rust output in a Go integration test, with the existing fixtures as the oracle. A Rust-only round trip could share codec mistakes; committed compressed golden files could become stale without exercising the writer. No new fixture schema or copied corpus is needed. Go's standard JSON/base64/CRC libraries can reconstruct the existing recipes without adding Rust test dependencies.

Add a test-only Cargo example `seal-vector` and a Go test under `server/internal/events/body` guarded by build tag `rustinterop`. The example reads one raw segment from stdin, bounded to `MAX_SEGMENT_BYTES + 1`; it calls `seal`, writes the canonical header plus one LF then the exact body, and exits zero. On failure it writes no stdout and exits nonzero with a variant name only on stderr. It is an example, not a shipped agent binary or file writer. The Go test obtains its absolute path from `RICEVANTA_BATCH_VECTOR`; a missing path fails the tagged test, never skips it. Bound captured output to 5,000,141 bytes and each child to 30 seconds.

For every body fixture whose `expected.batch_error` is null and whose plaintext/count fit the writer limits, reconstruct the exact recipe, verify its existing plaintext digest, split its final-LF-terminated lines, and build a spool segment with positional stored sequences and a Go `hash/crc32` Castagnoli oracle over little-endian sequence plus payload. Keep JSON sequence values untouched. Run the example and feed its result to `wire.Decode`, then `body.Decode`, using the same `io.LimitedReader` initialized with `wire.MaxCompressedBytes + 1` and the fixture's authenticated device. Compare every descriptor field, raw line, error sentinel with `errors.Is`, parsed identity, sequence and device-mismatch flag against existing expectations. No batch error is allowed. This exercises good events and quarantine, including invalid UTF-8, duplicate keys and sequence swaps. Shared cases beyond agent limits remain server decoder tests, not weakened writer limits.

For each successful header/descriptor fixture within writer count limits, build contiguous synthetic records. Compare the writer header and first 48 body bytes exactly with the fixture's canonical values, then run the full Go decoder. Check all five classes, zero counters and full-width counters. Header-only fixtures cannot prove full-body acceptance alone. Run the unchanged server fixture suite as well; it retains every malformed-frame and 64 MiB case the writer cannot emit.

Additional Rust and live Go vectors:

- Empty segment; every AG-10 header/record error and tail kind; all precedence pairs in section 3; input length at and one past `MAX_SEGMENT_BYTES`.
- Counts 1, 4,999, 5,000 and 5,001; NDJSON totals 4 MiB minus one, exactly 4 MiB and plus one; payload sizes 1 MiB minus one, exactly 1 MiB and plus one. Compute totals including LF, not spool framing.
- Minimum one-byte nonblank payload; empty and whitespace-only records; BOM in first and later payloads; literal CR/LF anywhere; escaped CR/LF; trailing spaces/tabs; non-ASCII and invalid UTF-8. Preserve bytes exactly on success.
- Sequence zero, one record at `u64::MAX`, multiple records ending there and an extra record after exhaustion. Metadata sequence mismatch seals but Go quarantines it.
- Plaintext sizes 255, 256, 65,791 and 65,792; inspect content size independent of encoding width. Tiny single-segment output must pass Go preflight.
- Four MiB of low-compressibility non-CR/LF bytes divided into legal records; a highly compressible four-MiB input; 5,000 tiny records; maximum descriptor counters. Each successful output passes Go preflight, checksum and count checks.
- Corrupt a Rust-produced checksum, append another frame, remove content size or checksum, change the advertised window and mismatch the descriptor/header. Assert the applicable EV-08/EV-09 sentinel using `errors.Is` and no provisional lines on batch failure. Construct mutations structurally, not by assuming a fixed frame header width.

`fuzz_seal` is a stable, std-only deterministic mutation test: xorshift64 seed `0x5249564241544348`, 2,000 cases normally and an ignored 20,000-case extended test. Its recurrence is `x ^= x << 13; x ^= x >> 7; x ^= x << 17` on u64. Mutate bounded segment bytes, headers, lengths, CRCs, stored sequences and payload framing; also rebuild CRC-valid records so validation reaches later stages. Limit ordinary generated inputs to 64 KiB; run maximum-boundary vectors separately. Assert no panic, unchanged input, repeatable error variants and, on success, exact decompression plus header/descriptor consistency. Do not log payloads. The Go interop suite independently validates the fixed success vectors and 128 deterministic small generated segments; it need not spawn a child per Rust mutation.

### 6.1. CI ownership and scope

The slice implementer owns `.github/workflows/agent.yml`. Its native matrix builds and tests the workspace, including `ricevanta-batch` and bundled libzstd, on `macos-15` / `aarch64-apple-darwin`, `windows-2025` / `x86_64-pc-windows-msvc` and `ubuntu-24.04` / `x86_64-unknown-linux-gnu`. Keep the exact dependency-set and package-count assertions: the four spool packages plus `ricevanta-batch` 0.1.0 and the twelve section 1 pins total 17 packages. Unset `ZSTD_SYS_USE_PKG_CONFIG` in every Cargo step, assert that it is absent rather than empty, and record the selected C compiler/version and verbose bundled-source build evidence on each native host. Cache downloaded dependencies, not compiled target artifacts, so each host qualifies C compilation.

Run Rust-to-Go interoperability in one separate `rustinterop` job on `ubuntu-24.04`, without a matrix. Place the job in `agent.yml` because that workflow owns the Rust toolchain and dependency policy; the job adds Go setup without widening `server.yml` or duplicating interoperability on three hosts. The native matrix establishes Rust/C portability. The Linux job establishes the shared wire/body contract. Local macOS and Windows interop commands remain available for diagnosis, not additional CI jobs.

For both push and pull-request events, the interop job matches exactly `agent/crates/batch/**`, `agent/crates/spool/**`, `server/internal/events/wire/**`, `server/internal/events/body/**` and `schemas/events/v1/**`. Add only the three server/schema patterns to the workflow-level paths, since `agent/**` covers the two crate paths. A cheap Linux `changes` job emits separate `native` and `interop` booleans from changed paths. The native predicate retains exactly `agent/**`, `schemas/agent/**` and `.github/workflows/agent.yml`; the interop predicate uses only the five listed patterns. Both jobs depend only on `changes`, with job-level conditions on their own outputs, so decoder/fixture-only edits run interop without the native matrix. Manual dispatch retains native validation and sets interop false. Preserve branch restrictions, read-only permissions, pinned actions, dependency caches and cancellation of superseded runs.

The interop job installs the pinned Rust toolchain and Go from `server/go.mod`, builds `seal-vector` with `--locked` and bundled zstd, and passes the freshly built executable's absolute path in `RICEVANTA_BATCH_VECTOR`. It runs the Task 3 tagged Go commands with and without `-race`, including all three `TestRustWriter` suites. A missing binary, build failure or failed test fails the job. [Plan Task 4](../plans/agent-batch-writer.md#task-4-native-build-and-linux-interop-workflow) owns filter semantics, workflow edits and their checks.

## 7. Threat trace and later gates

| Attacker | End-to-end effect within this slice |
|---|---|
| Stolen enrollment token | The writer consumes no token and grants no credential. Later enrollment and mTLS must establish device identity; a sealed body alone gives no upload authority. |
| Compromised agent host | Can forge CRCs, sequence fields, JSON and both descriptors. Bounded recovery/framing limits work for supplied slices; Go repeats wire/body checks and quarantines foreign device claims. Neither layer proves event truth. |
| Compromised console session | Has no writer or upload credential through this API. A later caller must keep transport identity in the core and authenticate independently of console-supplied metadata. |
| Rogue extension publisher | Publication grants no direct writer access. The core's producer/provenance checks precede spool append; opaque preservation grants no extension authority. Go's later provenance validation remains required. |
| Network position | Spool CRC covers stored sequence and payload; zstd checksum covers emitted NDJSON; duplicate descriptors detect disagreement. None prevents recomputed forgery. Later mTLS protects the complete header/body and authenticates the device. |
| Database writer without signing keys | No database value enters this function. Altered ledgers or acknowledgements remain outside its guarantees; EV-04 durability and authorization fences still gate deletion. |
| Server restored from backup | Stream epoch is not the BE-12 recovery epoch. Sealing restores no authority or high-water mark. Replay handling, sealed server recovery and a valid durable acknowledgement remain mandatory before deletion. |

Benefits: one narrow adapter connects the existing Rust codec to the fixed Go contract, with no native file-ordering assumption. Costs: bounded whole-batch allocations, a C dependency and cross-language test tooling. Limits: no UTF-8/JSON/OCSF validation, scheduling, durable writes, rename/sync/delete, upload, response handling, retry, epoch generation, deduplication or admission concurrency. Portable tests must pass on macOS ARM64, Windows x64 and Linux x64; codec acceptance establishes none of those later guarantees.

## 8. Review focus and unresolved questions

Review focus:

- Does recovery precede line checks and refuse every tail without losing the original bytes?
- Do the 4 MiB accounting and pre-append rule prevent a largest-record overshoot?
- Does one-shot compression preserve all profile flags and stay within the complete-body bound?
- Do both descriptors derive from stored sequences while JSON defects remain quarantine candidates?
- Does the live interop test consume existing fixtures and the actual Rust library, with no silent skip?
- Are dependency features, native notices and measured memory kept separate from portability claims?

Open qualification questions, with the selected choice and rejected alternative stated above:

- Does independent review approve the dedicated crate, complete-segment byte API and live Go fixture tests? Extending the spool codec, accepting arbitrary record iterators and relying only on Rust round trips are rejected in this design.

- Does the exact dependency closure resolve with the stated features and complete release license texts on all three targets? Verify before code relies on it; the selected binding remains fixed pending that check.
- Does the measured whole-batch allocation and level-3 context fit the active core budget, or must the durable-file slice adopt streaming? The file-free API selects whole-batch ownership; production integration remains gated.
- Does the future manager enforce the selected NDJSON-inclusive pre-append threshold and preserve a failed raw segment through durable recovery? Allowing one-record overshoot is rejected; the manager's crash protocol remains outside this slice.
