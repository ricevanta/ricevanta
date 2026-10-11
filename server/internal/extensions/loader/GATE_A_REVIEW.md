# Gate A parser qualification

Gate A remains unqualified until the syntax-before-tag candidate and corrected harness have fresh native `loader-gate-a` evidence on Linux x64, Windows x64 and macOS ARM64 and independent confirmation on the new head. Local checks do not establish native qualification. No production consumer imports the candidate. Gate B remains unqualified.

The candidate reads the unchanged payload twice, discards presentation comment storage, records flat arities, builds exact Node/Content arenas and retains a cumulative allocation ledger. Production Decode failure returns no partial tree or ledger. The measurement harness retains its own budget for every measured parser call, including rejected combined calls. Explicit tags return ErrTag; anchors, aliases and directives return ErrSyntax under the profile mapping.

## Source bounds

[The allocation audit](internal/yamltokens/ALLOCATION_AUDIT.md) identifies every reachable allocation family, rounding rule, clamp, abandoned buffer, helper and recursion bound. [Provenance](internal/yamltokens/PROVENANCE.md) identifies selected upstream ranges, complete-file checksums, preserved notices and the deterministic patch digest.

- Payload and aggregate token values: 1,048,576 bytes. Tokens: 262,208. Live simple-key/indent/state/mark slots: 64. Nodes: 65,536 excluding the wrapper. Container depth: 16.
- The ledger checks each rounded backing allocation before growth and never refunds it. Its cumulative ceilings are 67,108,864 bytes and 1,000,000 objects. Reserve rejects overflow requests before changing either counter.
- A successful tree allocates exactly N+1 Nodes and N Content pointers. Capacities cannot grow. Linux Node size is 152 bytes; charges use unsafe.Sizeof for all required 64-bit targets. At N=65,536, logical Node/Content storage totals 10,485,912 bytes before rounding.
- Comment storage contributes zero candidate allocations. Simple-key lookup has no map. Scalar whitespace/break scratch reuses capacity within each pass. Both passes' allocations remain charged.
- Integer/timestamp/float-pattern classification uses allocation-free tag-only equivalents. Underscore replacement and ParseFloat reserve helper copies/objects first. Fixed overhead reserves 16,640 bytes and eight objects once at entry.
- Node construction has at most 16 container frames plus scalar/caller frames. Native CI must confirm the 8 MiB StackInuse ceiling. Local growth measurements are listed below.

Astra xhigh reviewed the fixed-overhead/escape allowance, allocator source reasoning, resolver equivalents and independent reference classification against Go 1.27.1. No source bound is claimed for the unmodified oracle, which remains isolated in test code and outside candidate measurements. Passing finite samples do not establish universal profile acceptance or qualify Gate A.

## Syntax and independent agreement

Before classifying the next token, the candidate expires live simple keys through its fixed-slot validity check. A required key that lacks a colon fails with ErrSyntax before a later tag. The independent reference separately checks line breaks and the 1024-character boundary, returns ErrSyntax for a required expired key, and removes expired token-number entries. It calls no candidate classifier.

The production precedence hunks and provenance remain unchanged by the harness fixes. `TestRequiredKeyExpiryBoundary` locks down ErrTag at 1023 and 1024 key characters and ErrSyntax at 1025; required keys expire only beyond 1024 characters. Each case checks the independent reference, candidate preflight and Decode, including nil Node/Budget on rejection. The retained fuzz files are `4122f76a6bf0b3f8`, `687be868109012a0`, `7e17a2392a971d03` and `f5bbf3fd3c98d3eb`. The comment matrix includes lone CR, all CR, CR comments, EOF, explicit values, comments, empty keys and an earlier tag. LF/CRLF variants preserve source-order precedence.

The root classifies each recipe with the separate comment-preserving scanner/event reference and unmodified Node oracle before candidate execution. Check and Decode compare acceptance in both directions and sanitized rejection classes. Successful Decode compares complete kind, tag, value, style, marks, child order and node/depth counts. Only presentation comments are excluded. Deliberate allocation exhaustion remains separate from normal-budget agreement.

## Measurement method

Each operation runs in a fresh parser test child. The root supplies independent outcomes, arities and complete-tree paths in temporary files. Every child sets `runtime.GOMAXPROCS(1)` before input setup and `debug.SetMemoryLimit(math.MaxInt64)` before preparation. Production scheduling and ordinary ownership tests retain normal scheduling.

Runtime preparation uses two helper goroutines. Each locks its OS thread, signals readiness and parks at a shared release barrier. The measuring goroutine releases both only after both are ready. Both unlock and join before measurement. Preparation invokes no candidate parser, resolver, decoder or lazy initialization and does not deliberately grow the measuring goroutine's stack.

The child prepares snapshot storage and metric samples outside the interval, forces GC once, and holds `debug.SetGCPercent(-1)` from before the initial snapshot through the final snapshot. No candidate warmup runs. Node-only mode loads independent arities before the initial snapshot and does not run candidate preflight. Rejected inputs never reach Node construction. Payload and tree remain live through the final snapshot; tree comparison runs after allocation, timing and peak RSS measurement.

Raw TotalAlloc and Mallocs deltas determine acceptance. No subtraction, retry, selected minimum or runtime allowance applies. Raw allocations must stay within the source ledger and the unchanged 64 MiB, 1,000,000-object and 8 MiB stack-growth ceilings. Retained HeapAlloc includes transient allocations. Native peak RSS includes startup and input generation. Linux uses Getrusage KiB converted to bytes; macOS uses Getrusage bytes; Windows uses GetProcessMemoryInfo. Native API failures fail the child.

The parent validates every reported field and requires GOMAXPROCS 1, memory limit MaxInt64 and GC percent -1 at both snapshots, with unchanged NumGC. Missing fields fail validation. Negative controls use that same validation path for each setting, missing fields and raw allocations above the ledger. `TestParserMeasurementIsolation` launches accepted and rejected inputs in all three modes with inherited `GOMAXPROCS=2`, `GOMEMLIMIT=1MiB` and `GOGC=1`. The accepted case supplies independent tree and arity metadata so node and combined modes construct and compare a tree.

## Trace evidence

The runtime-preparation rationale uses native traces for `comment-collections/262144/combined`. Five of 50 Linux raw samples recorded 31 objects against a 30-object ledger, with the same 25 parser-attributed objects as the other samples. Six objects came from OS-thread creation under `runtime.newm`; those stacks contained no loader or adapted-parser frame. All 50 macOS raw samples recorded 25 objects; profile totals also included work after the interval. A macOS 31-object raw failure shares the count signature but requires its own stacks for attribution. The six-object signature supplies neither a thread-count bound nor an OS-independent allocation layout. The allowance remains zero bytes and zero objects.

The independent review of `c53ba92` found that rejected combined samples skipped the ledger comparison: `tags/64/combined` reported 267,728 bytes and seven objects with zero reported charges. Synthetic reports with wrong or omitted runtime settings also passed. Native passes at that head therefore do not establish qualification under the corrected validation path.

## Verification

Local checks run from `server/` with `GOPROXY=off GOFLAGS=-mod=mod GOCACHE=/tmp/ricevanta-loaderfix-gocache`. The local toolchain is Go 1.27.1 on Linux amd64. The results below cover the current working-tree fixes only. Native cross-OS measurements, the extended batch, race tests and timed fuzzing are not run locally.

The `loader-gate-a` repetition step retains all 50 `comment-collections/262144/combined` fresh-child samples in each native target's verbose log. Every sample must pass raw ledger, ceiling and runtime-setting validation with zero allowance. Fresh results on Linux x64, Windows x64 and macOS ARM64 and independent confirmation on the new head remain required.

The validate job timeout is 15 minutes. [PR CI at `c53ba92`](https://github.com/ricevanta/ricevanta/actions/runs/38118193413) completed validate in 8m28s, including 6m49s of race tests, as recorded by the independent review. That duration supports the timeout choice; those results do not verify the current fixes. No archive reader, zstd, Load or dependency change enters this fix.

| Check | Exact command | Result |
|---|---|---|
| Focused suite and fuzz seeds | `go test -count=1 ./internal/extensions/loader/... -run 'Test(Token\|YAMLFraming\|Preflight\|ParserBudgetSmoke\|ParserBudgetRepeatFlags\|ParserMeasurementIsolation\|CommentElision\|FlowEmptyValueMarks\|Rejection)\|^FuzzParserQualification$'` | PASS; loader 19.918s, yamltokens 0.078s |
| New regression tests and accepted isolation | `go test -count=1 ./internal/extensions/loader/... -run '^(TestParserMeasurementValidation\|TestRejectedCombinedMeasurementLedger\|TestParserMeasurementIsolation\|TestRequiredKeyExpiryBoundary)$' -v` | PASS; loader 0.002s, yamltokens 0.075s; six isolation cases |
| Vet | `go vet ./internal/extensions/...` | PASS; exit 0, no output |
| Formatting | `gofmt -l .` | PASS; exit 0, no output |
| Whitespace, repository root | `git diff --check` | PASS; exit 0, no output |

The rejected `tags/64/combined` sample records 267,728 raw bytes and seven objects against retained ledger charges of 292,768 bytes and 13 objects. Both below-raw ledger tampering controls fail validation. Wrong settings at either snapshot, changed NumGC, missing fields and null fields fail the same parent validation path. Zero NumGC remains valid only when both fields are present and equal.

Test-first verification ran `go test -count=1 ./internal/extensions/loader/internal/yamltokens -run '^(TestParserMeasurementValidation\|TestRejectedCombinedMeasurementLedger)$'`: FAILED as intended before the fix, exposing unchecked settings and raw excess plus the real rejected sample's zero reported ledger. The first implementation rerun FAILED to compile because `qualification_test.go:322` declared an unused `m`; removing that obsolete local resolved the failure. The next run PASSED in 0.006s.

Additional worker checks used the same environment:

| Exact command | Result |
|---|---|
| `go test -count=1 ./internal/extensions/loader -run '^TestRequiredKeyExpiryBoundary$' -v` | PASS; 0.003s, all three boundaries on the unchanged parser |
| `go test -count=1 ./internal/extensions/loader/internal/yamltokens -run '^(TestParserMeasurementValidation\|TestRejectedCombinedMeasurementLedger\|TestParserMeasurementIsolation)$' -v` | PASS; 0.076s |
| `go test -count=1 ./internal/extensions/loader/... -run '^(TestParserMeasurementValidation\|TestRejectedCombinedMeasurementLedger\|TestParserMeasurementIsolation\|TestRequiredKeyExpiryBoundary)$'` | PASS; loader 0.004s, yamltokens 0.073s |

No design assumptions were needed. GC percent -1 appears as MaxUint64 in the runtime metric, preserving the existing report representation. The accepted isolation fixture uses the unmodified decoder for the expected scalar tree and its zero child arity. Independent Astra xhigh review of the working-tree fixes reports no actionable findings. Native CI and independent confirmation on the new head remain unverified.

Production parser sources and provenance are unchanged. The recorded deterministic patch digest remains `8fa86e54a3b4175985e846f573d7fcba79f8e49a0d9bb6a5df1ae2fac6491df7`; this task does not recompute upstream source checksums. Gate B remains unqualified.
