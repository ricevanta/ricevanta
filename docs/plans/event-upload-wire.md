# Event upload wire implementation plan

Add a bounded Go decoder for the header and leading descriptor frame defined in [the wire spec](../specs/event-upload-wire.md). The decoder returns a validated `batch.Descriptor` and leaves the NDJSON zstd frame unread.

## Global constraints

- An independent Sol xhigh review must approve the spec, plan and machine contract before code.
- A separate Sol medium implementer owns the code paths below. The designer and reviewer never implement this slice. Dispatch implementation on `gpt-6.1-sol` at `medium` and reviews and fix confirmations on `gpt-6.1-sol` at `xhigh`.
- Keep Go 1.27.1 and module `github.com/ricevanta/ricevanta/server`. Do not change `go.mod`, add a `toolchain` directive or introduce dependencies.
- Use only the existing `batch` package and the standard library imports named in the spec. Do not change `batch` or `eventid`.
- No HTTP handler, decompressor, response writer, authentication, database, ledger or acknowledgement code belongs here. The response schema is a contract for a later slice.
- Write each test first and observe the expected failure before adding the least implementation that passes it. Compile failures count only when caused by the planned missing API.
- The primary agent owns Git operations, integration and final checks. Workers never commit or push. Use a separate worktree for an implementer; these tasks share files and run sequentially.
- An independent Sol xhigh code review checks the final slice, including hostile input and resource use. Signing or authentication additions are out of scope; any authorized scope change adding them requires an adversarial review.
- The implementer may change only `server/internal/events/wire/` and the two fuzz command additions to `instructions/testing.md`. Treat reviewed `schemas/events/v1/` as read-only input. Contract fixes return to design and independent review.

## Review focus

- Header cardinality and byte length precede syntax and version checks.
- Numeric overflow is syntax failure; semantic errors preserve `batch` sentinels.
- Frame reads stop at the first failing stage, never at a hostile declared size.
- Every error returns a zero descriptor; read errors preserve the I/O cause.
- Reader budget includes the descriptor and overflow probe; prefix success is not body admission.
- Header/frame equality checks all fields, not only `BatchID`.
- Fixtures are shared without lossy JSON number conversion or copied expectations.

### Task 1: Header parsing

**Owned files:** create `server/internal/events/wire/header.go`, `errors.go`, `header_test.go` and `fixtures_test.go`.

**Consumes:** all values from the HTTP adapter, without first-value selection. **Produces:** the exact constants, sentinels and `ParseHeader` API in spec section 6.

- [x] Write `TestParseHeaderFixtures`, `TestParseHeaderErrorPrecedence`, `TestParseHeaderNumericBounds`, `TestParseHeaderZeroOnError` and `FuzzParseHeader` first. Load `../../../../schemas/events/v1/fixtures/header.json` relative to the package directory. Resolve decimal fixture strings with uint64-aware parsing; fail on a missing or malformed fixture file or an unknown sentinel name.
- [x] Cover every provided vector. Add invalid UTF-8 byte strings in Go tests, class case changes, NUL and CR/LF, 139 and 140 byte values, uint8/uint32/uint64 overflow, every reordered key pair and signed/hex/scientific notation. Prove unsupported version plus numeric overflow returns syntax failure, unknown class plus zero epoch returns `batch.ErrClass`, and multiple fields plus oversize returns header-count failure.
- [x] Run `cd server && go test ./internal/events/wire -run 'TestParseHeader'` and record the expected missing-API failure.
- [x] Implement exact parsing stages with a length check before splitting, fixed token count, ASCII checks, explicit base 10 and widths, then `Descriptor.Validate`. Keep error messages free of raw header text.
- [x] Run `cd server && go test ./internal/events/wire -run 'TestParseHeader'` and require PASS.
- [x] Have an independent Sol xhigh reviewer inspect Task 1 before Task 2 depends on it. The implementer fixes findings; a separate Sol xhigh reviewer confirms fixes.

### Task 2: Descriptor prefix decoding

**Owned files:** create `server/internal/events/wire/decode.go`, `decode_test.go`; extend `errors.go` and `fixtures_test.go` only as needed.

**Consumes:** parsed header values and a caller-owned `*io.LimitedReader`. **Produces:** `Decode` with no reads after byte 47 and no stateful consumer.

- [x] Write `TestDecodeFixtures`, `TestDecodeReadBoundaries`, `TestDecodeReaderBounds`, `TestDecodeIOErrors`, `TestDecodeErrorPrecedence`, `TestDecodeZeroOnError`, `TestDecodeLeavesSuffix` and `FuzzDecode` first. Load the descriptor fixtures by the same repository-relative method as Task 1. Assert exact consumption, error sentinel, zero result on failure and descriptor equality on success.
- [x] Cover every truncation length, payload byte order, unsupported magic and size, reserved bytes, version and descriptor validation, all six mismatch fields, and header defects combined with body defects. Test `N` values -1, 0, 47, 48, 49, 5,000,000, 5,000,001 and 5,000,002, nil reader and nil `R`. Never allocate a buffer matching a fixture's advertised size.
- [x] Add one-byte-at-a-time readers, `(n > 0, io.EOF)` readers, injected non-EOF failures in each read stage and a reader that fails if called after byte 48. Assert `errors.Is` for the wire error and I/O cause. A complete `ReadFull` remains successful even if its final read also reports EOF, per the standard library contract.
- [x] Use a suffix containing arbitrary bytes and another descriptor frame. Prefix decoding must leave both untouched; the full-body slice will reject illegal suffixes. Header failure must leave the reader and its budget unchanged.
- [x] Run `cd server && go test ./internal/events/wire -run 'TestDecode'` and record the expected missing-API failure.
- [x] Implement only the staged fixed-array reads and comparisons in spec section 6. Do not add buffering, decompression, drains, closes or a read of the following magic.
- [x] Run `cd server && go test ./internal/events/wire` and require PASS.

### Task 3: Fuzzing and integration checks

**Owned files:** extend the tests from Tasks 1 and 2; add only the fuzz command entries below to `instructions/testing.md`.

- [x] Write any missing invariant assertions first, run `cd server && go test ./internal/events/wire` and record the failure before fixing implementation. Do not change semantics to satisfy a fixture without design review.
- [x] `FuzzParseHeader` accepts an arbitrary string and a small value-count selector covering missing, singleton and repeated fields. Seed every header fixture. Assert no panic, zero result on failure, valid descriptor on success, input equality with the canonical test formatter, and `batch.ValidateBatchID(d.BatchID(), d) == nil`.
- [x] `FuzzDecode` accepts an arbitrary string and arbitrary byte slice. Wrap the bytes in a counting reader and bounded reader; seed every descriptor fixture. Assert no panic, at most 48 bytes consumed, zero result on failure, equality with `ParseHeader` on success and an unchanged suffix. Use fixture tests, not only fuzzing, for exact combined-defect precedence and injected I/O errors.
- [x] Add these exact bounded commands to `instructions/testing.md`, alongside the existing primitive targets. Run them from `server/` and retain useful minimized cases in the target's seed corpus:

```sh
go test ./internal/events/wire -fuzz=FuzzParseHeader -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzDecode -fuzztime=5s -parallel=2
```

- [x] Run `cd server && gofmt -w internal/events/wire` followed by `cd server && gofmt -l .`; the second command must print no files.
- [x] Run `cd server && go test ./...`, `cd server && go test -race ./...` and `cd server && go vet ./...`; require PASS and exit 0.
- [x] Run the two new fuzz commands and the existing targets: `cd server && go test ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s -parallel=2` and `cd server && go test ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s -parallel=2`. Each run must pass for five seconds with two workers. Ordinary `go test` runs seeds in CI; do not add timed CI fuzzing.
- [x] Run `git diff --check`. Inspect the full diff for ownership, no dependencies and no HTTP/storage claims. Record failures as failures, not skipped successes.
- [x] Obtain independent Sol xhigh code review against the complete spec, contract and vectors. Resolve findings through the implementer and obtain independent Sol xhigh fix confirmation before integration.

## Handoff evidence

The implementer reports changed files, focused expected failures, passing command output, fuzz durations and corpus changes, and any unresolved findings. The primary agent inspects the edits and runs the required checks before accepting them. Pure parser checks establish neither complete upload acceptance nor authentication, database durability, decompression or platform support.
