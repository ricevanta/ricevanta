# Event batch body implementation plan

> **For agentic workers:** Use superpowers:subagent-driven-development or superpowers:executing-plans task by task. Checkboxes record evidence, not intent.

**Goal:** Decode the event batch's one zstd frame and return bounded raw lines with preliminary identity checks.

**Architecture:** A private `body` package consumes the reader left by `wire.Decode`. It bounds compressed input, preflights the frame, streams decompression and retains provisional line results until all batch checks pass.

**Tech stack:** Go 1.27.1, standard library, existing event packages and the single approved exception `github.com/klauspost/compress/zstd` v1.20.1.

**Spec:** [Event batch body decoder](../specs/event-batch-body.md), EV-09, `schemas/events/v1/body-fixture.schema.json` and `fixtures/body.json`.

## Global constraints

- An independent Sol xhigh review must approve the spec, plan and fixtures before code. This plan records no approval or implementation result.
- A separate Sol medium implementer owns the code paths below. Designer and reviewer never implement this slice. Use `gpt-6.1-sol` at `medium` for implementation and `gpt-6.1-sol` at `xhigh` for every review and independent fix confirmation.
- Keep module `github.com/ricevanta/ricevanta/server`, Go 1.27.1 and no toolchain directive. Standard library only except the exact dependency approved in spec section 1. The explicit decompression requirement is the exception to the core-primitives plan's no-dependency rule.
- Implementation may change `server/internal/events/body/`, add the one pinned requirement to `server/go.mod` and its checksums to `server/go.sum`, add the two fuzz commands to `instructions/testing.md`, and add required attribution to `NOTICE`. In `.github/workflows/server.yml`, only set `cache: true` and `cache-dependency-path: server/go.sum` in the existing setup-go step. No other dependency, server package or CI change is authorized by this plan.
- Treat the spec and `schemas/events/v1/` as read-only. Contract fixes return to design and independent review. Do not loosen expected errors to make a test pass.
- Use a separate implementation worktree. These tasks share files and run sequentially. The primary agent owns Git, integration and final verification; workers never commit or push.
- Write tests first, observe the intended failure, then add the least implementation that passes. Compile failures count only for the planned missing API. Record dependency/setup failures separately.
- The final slice needs independent Sol xhigh code review with hostile-input and resource analysis. Signing or authentication additions require a separate design and adversarial review; neither belongs here.
- No HTTP handler, authentication, full OCSF types, schema generation, deduplication, storage, enrichment, findings, ledger or acknowledgement implementation. A returned line remains provisional for those consumers.

## Review focus

- An exact 5,000,000-byte request must prove real EOF; the descriptor's 48 bytes remain charged.
- A decoder option alone cannot enforce streaming output size; large windows and forged small sizes remain bounded.
- Valid RFC concatenations and skippable suffixes still fail Ricevanta's one-frame rule.
- A late checksum or count failure returns no lines, including no quarantine candidates.
- Decoded duplicate names, Unicode case-fold collisions and full-width uint64 numbers cannot change field binding.
- Device mismatch evidence survives another field's error without exposing partially validated ids.
- Positional sequences quarantine bad rows without invalidating good neighbors or overflowing MaxUint64.

### Task 1: Bounded input and single-frame envelope

**Owned files:** create `server/internal/events/body/frame.go`, `errors.go`, `frame_test.go`, `fixtures_test.go`; modify `server/go.mod`, `server/go.sum` and the dependency notice in `NOTICE` only as allowed above.

**Consumes:** canonical remaining `*io.LimitedReader`, spec sections 3 and 4, and the reference frame fixtures.

**Produces:** private `readCompressed(r *io.LimitedReader) ([]byte, error)` and `inspectFrame(frame []byte) (uint64, error)`, where the uint64 is declared content size and is zero on error. Public constants and batch sentinels match the spec. Keep descriptor/caller validation for `Decode` in Task 3.

- [x] Add `TestReadCompressed`, `TestReadCompressedIO`, `TestInspectFrameFixtures`, `TestInspectFramePrecedence` and `TestFixtureLoaderRejectsInvalid` before implementation. Read `../../../../schemas/events/v1/fixtures/body.json` from the package directory. Expand base64 parts under the fixture cap, verify lengths/digests and descriptor integer bounds, and reject missing fields, unknown sentinel names, duplicate case names and malformed outcome runs.
- [x] Test remaining lengths 4,999,951, 4,999,952 and 4,999,953. Count underlying reads. Assert correct EOF handling for one-byte readers, short reads, `(n > 0, io.EOF)`, injected errors and an error accompanying the overflow byte. A read after consuming the probe must fail the test. Preserve `errors.Is(err, cause)` for `ErrRead`. A reader returning `(0, nil)` 100 times must produce `ErrRead` and `io.ErrNoProgress`; progress resets the counter.
- [x] Test every preflight fixture, all four content-size widths, the two-byte offset, single-segment zero/small windows, explicit windows at 64 MiB and the next representable value, header truncations, dictionary flags, both profile-rejected bits, raw/RLE/compressed block boundaries and huge block claims. Assert no claimed-size allocation. RLE's payload occupies one byte, regardless of its decoded block size.
- [x] Add combined defects: absent size and checksum selects checksum-required; oversize content and window selects decoded-limit; trailing plus checksum corruption selects trailing; a truncated header precedes its flag defects. Assert structural traversal, never magic searching, with magic bytes embedded inside raw blocks.
- [x] Run `cd server && go test ./internal/events/body -run 'Test(ReadCompressed|InspectFrame|FixtureLoader)'`. Record the intended missing-function failure.
- [x] Add `require github.com/klauspost/compress v1.20.1` via `cd server && go get github.com/klauspost/compress/zstd@v1.20.1`. Inspect the module diff: no Go/toolchain bump or unrelated requirement. Add applicable license notices from the exact module and run `cd server && go mod verify`.
- [x] Implement capped compressed buffering and the private frame inspection functions. Use fixed-size header arithmetic and remaining-length checks. Return only body sentinels for frame faults. Do not decompress in this task.
- [x] Run the focused command again and require PASS. An independent Sol xhigh reviewer approves these boundaries before Task 3 consumes them. The implementer fixes findings; another Sol xhigh reviewer confirms fixes.

### Task 2: Strict line extraction

**Owned files:** create `server/internal/events/body/line.go` and `line_test.go`; extend `errors.go` and fixture helpers.

**Consumes:** a bounded raw payload, descriptor, one-based line position and authenticated uid. **Produces:** `Line` and private `extractLine(raw []byte, number uint32, d batch.Descriptor, authenticatedDevice string) Line` with the exact section 6 semantics. The helper receives owned bytes and does not copy them; Task 3 establishes ownership.

- [x] Add `TestExtractLineFixtures`, `TestExtractLinePrecedence`, `TestExtractLineDeviceEvidence`, `TestExtractLineDepth`, `TestExtractLineMaxSequence` and `FuzzExtractLine` first. Reconstruct plaintext recipes and outcome runs; compare raw bytes directly, not re-encoded JSON. Assert successful ids and sequence values, exact line errors and wrapped eventid causes, and zero extracted fields on every error.
- [x] Exercise all fixture line failures, missing/null/wrong-type parents and fields, duplicate names in unknown nested arrays, escaped exact names, case variants both alone and beside canonical names, Unicode long-s in sequence, and unrelated unknown case differences. Include invalid syntax after a duplicate key to prove the syntax prepass wins.
- [x] Test paired and unpaired surrogate escapes, literal U+FFFD, invalid UTF-8, depth 128/129 and top-level scalars/arrays. Escape-looking text preceded by an escaped backslash must not be mistaken for a surrogate escape. Unknown fields remain available in Raw.
- [x] Test 0, 2^53+1, MaxUint64, overflow, fractions, exponents, quoted integers and negative zero. Test range before position, UUID error before sequence, sequence before device, and DeviceMismatch on another missing/invalid field. Ambiguous device keys cannot set that flag.
- [x] Run `cd server && go test ./internal/events/body -run 'TestExtractLine'` and record the intended missing-helper failure.
- [x] Implement bounded syntax/UTF-8/surrogate/depth checks, the token walk with `UseNumber`, duplicate tracking and scoped `strings.EqualFold` checks, followed by typed binding checks. Release per-line key state. No generated OCSF structs, raw-content logging or generic retained object trees.
- [x] Run the focused command again and require PASS. Obtain independent Sol xhigh review and independent fix confirmation before integration into `Decode`.

### Task 3: Streamed decompression and complete batch results

**Owned files:** create `server/internal/events/body/decode.go`, `decode_test.go`, `limits_test.go`, `limits_norace_test.go`; extend fixture helpers and errors only as needed.

**Consumes:** Tasks 1 and 2. **Produces:** `Decode(r *io.LimitedReader, d batch.Descriptor, authenticatedDevice string) ([]Line, error)` and private `consume(decoded io.Reader, size uint64, d batch.Descriptor, authenticatedDevice string) ([]Line, error)`. `consume` owns output counting, framing, provisional raw bytes and final checks; the decoder adapter maps codec errors before returning them to `consume`.

- [x] Write `TestDecodeFixtures`, `TestDecodeCallerPrecedence`, `TestDecodeWireHandoff`, `TestDecodeNoPartialResults`, `TestDecodeRawOwnership`, `TestConsumeLimits`, `TestDecodeCodecOptions` and `FuzzDecode` first.
- [x] Execute every body fixture with `N = wire.MaxCompressedBytes + 1 - wire.DescriptorFrameBytes`. Test the real `wire.Decode` handoff with a descriptor prefix and header. Reduced/reset budgets, nil reader, nil `R`, empty device, invalid device UTF-8 and invalid descriptors fail without reads, in the spec's order. Valid caller uid is opaque, not assumed UUID-shaped.
- [x] Test LF split across reads, exact/overlong payloads, a 10,001st starting byte, CRLF, blank lines, BOM on a later line, missing final LF, exact and mismatched counts, all-quarantined and mixed batches. Include repeated event UUIDs with correct sequences as accepted here.
- [x] Run the exact 64 MiB output fixture through the real codec. For `consume`, use a synthetic reader to deliver 64 MiB plus one with a simultaneous error and assert `ErrDecodedLimit`, never retention of the overflow byte. Bound each read request to remaining output plus one and ensure no further reads after an immediate limit failure. This test directly exercises the guard even when the pinned codec detects a lying size first.
- [x] Test honest oversized size rejection before codec construction, forged small size bombs, excessive window rejection, bad checksum after valid lines, and size mismatch plus bad checksum. Test limits in delivered bytes against simultaneous codec errors. Framing errors remain provisional until integrity is known; checksum plus malformed line framing selects checksum if no resource limit fires first.
- [x] Assert no aliases among Raw slices or decoder storage. Mutate one result after return and confirm neighbors remain intact. Require a nil slice for every batch error; no partially parsed ids on a quarantined line. A decoder factory used only for tests can record the selected options and close calls; do not export configuration that weakens the fixed contract.
- [x] Run `cd server && go test ./internal/events/body -run 'Test(Decode|Consume)'` and record the expected missing-API failure.
- [x] Implement caller checks, compressed buffering, preflight, the exact six decoder options and the 32 KiB output loop. Close the decoder with deferred cleanup after creation. Avoid pools, `DecodeAll`, `WriteTo`, `io.Copy`, callbacks and allocation from content size. Attach line results only after all batch checks pass.
- [x] Run `cd server && go test ./internal/events/body` and require PASS. Measure allocations for the ceiling and bomb cases with `cd server && go test ./internal/events/body -run '^$' -bench BenchmarkDecodeLimits -benchmem`; add `BenchmarkDecodeLimits` covering those inputs.
- [x] Add `TestDecodePeakMemory` in `limits_norace_test.go` with the build constraint `//go:build !race` for the same ceiling and bomb cases. Keep only this test and its exclusive helpers in the guarded file; all other tests remain enabled during race runs. Run each case alone in a fresh test subprocess using `os/exec`. Prepare compressed input, release plaintext fixture buffers, run `runtime.GC()`, then record baseline `HeapInuse` with `runtime.ReadMemStats`. Sample `HeapInuse` immediately before `Decode`, every 1 ms during decoding, and immediately after return; keep returned lines alive through the final sample with `runtime.KeepAlive`. Use normal garbage collection (`GOGC=100`), no soft memory limit (`GOMEMLIMIT=off`) and no race instrumentation. Require the separate non-race command `cd server && GOGC=100 GOMEMLIMIT=off go test ./internal/events/body -run '^TestDecodePeakMemory$' -count=1 -v` to pass. Pass only if every case returns its expected result and `max(sampled HeapInuse) <= baseline HeapInuse + 512*1024*1024`; log baseline, maximum and delta for each case. This is a sampled peak-live-heap check using [Go's heap-span metric](https://pkg.go.dev/runtime#MemStats), which includes unused space in occupied spans and can miss peaks between samples. The bound is a test budget, not a total-process memory guarantee. Record measurements without claiming a 64 MiB total-memory ceiling or platform qualification.

### Task 4: Fuzzing, module checks and review

**Owned files:** body tests and minimized corpus entries; only the two command additions to `instructions/testing.md`; only the two setup-go cache settings in `.github/workflows/server.yml` authorized above.

- [x] Add missing invariant tests first, observe their failure, and fix through the implementer. `FuzzExtractLine` accepts arbitrary bytes and bounded valid descriptor/position selectors; seed binding, escape, duplicate, numeric and depth cases. Bound inputs to `MaxLineBytes`. Assert no panic, exact Raw, zero fields on error, and re-parse successful ids with `eventid.Parse`.
- [x] `FuzzDecode` accepts arbitrary compressed bytes and a valid descriptor selector. Cap test input at 5,000,001 bytes. Seed every frame family, including the bomb and checksum mutations. Assert no panic, no returned lines on batch error, correct count and raw limits on success, and bounded compressed consumption. Reader faults and exact precedence remain unit tests, not fuzz-only properties.
- [x] Add and run these commands from `server/`:

```sh
go test ./internal/events/body -fuzz=FuzzExtractLine -fuzztime=5s -parallel=2
go test ./internal/events/body -fuzz=FuzzDecode -fuzztime=5s -parallel=2
```

- [x] Run `cd server && gofmt -w internal/events/body` and `cd server && gofmt -l .`; the second prints no files.
- [x] Run `cd server && go mod verify`, `cd server && go test ./...`, `cd server && go test -race ./...` and `cd server && go vet ./...`; require PASS and exit 0. The race run skips `TestDecodePeakMemory` because of `//go:build !race`. Final verification must also run the separate non-race command `cd server && GOGC=100 GOMEMLIMIT=off go test ./internal/events/body -run '^TestDecodePeakMemory$' -count=1 -v` and require PASS and exit 0.
- [x] Set `cache: true` and `cache-dependency-path: server/go.sum` in the existing setup-go step in `.github/workflows/server.yml`. Inspect the workflow diff and require that only these two settings change.
- [x] Run the existing bounded fuzz targets from `server/`:

```sh
go test ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s -parallel=2
go test ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s -parallel=2
go test ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzParseHeader -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzDecode -fuzztime=5s -parallel=2
```

- [x] Ordinary tests consume static frames without a zstd executable or Python package. Add a Go test that validates fixture structure, reconstructs plaintext recipes and expands stored input parts; reference regeneration remains a separate design verification step. Do not assert that the Go encoder reproduces reference-compressor bytes. Fail on fixture/schema disagreement, never silently skip missing vectors.
- [x] Run `git diff --check` and inspect the full diff, exact dependency pin, checksums and notices. Report failed checks as failed. Verify the implementation adds no ingest or platform-support claim.
- [x] Obtain independent Sol xhigh review against the entire spec and fixture set, including adversarial input/resource analysis. Resolve findings through the implementer and obtain independent Sol xhigh fix confirmation. The primary agent inspects changes and runs required checks before accepting the slice.

## Handoff evidence

Report changed files, intended failing-test commands and output, dependency verification, passing checks, resource measurements, fuzz durations/corpus changes and unresolved findings. Design approval, implementation results and code review are separate evidence. No decoder success authorizes quarantine persistence, storage or acknowledgement.
