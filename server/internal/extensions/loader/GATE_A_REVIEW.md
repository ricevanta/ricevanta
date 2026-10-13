# Gate A parser qualification

The Task 5 accounted parser has independent Gate A source/API/allocation/provenance approval for the source at `a19cc54`, with passing native evidence on Linux x64, Windows x64 and macOS ARM64. Gate A permits isolated work under the [loader plan](../../../../docs/plans/extension-loader.md). Production consumers require both qualification gates and stateful admission. DSSE already validates canonical prime-subgroup keys; publisher authorization remains a separate caller obligation.

## Candidate and source identity

The candidate uses Go 1.27.1 and `go.yaml.in/yaml/v3` v3.0.4. The module checksum is `h1:tfq32ie2Jv2UxXFdLJdh3jXuOzWiL1fo0bu/FbuKpbc=`; the metadata checksum is `h1:DhzuOOF2ATzADvBadXxruRBLzYTpT36CKvDb3+aBEFg=`. [Provenance](internal/yamltokens/PROVENANCE.md) identifies all 16 source rows, exact upstream ranges, complete-file checksums, preserved notices and reproducible patch construction.

The current deterministic patch SHA-256 is `39db62ed7caf0b73be9b767546211d66c30271c457a3a8b33c2fcd4bfc1e0154`. Project-owned `budget.go`, outside that patch, has SHA-256 `03ccddb6d86daa47cdf09de9330ec4f54be9648aff7d7d89703764ce61310aa1`.

`DecodeAccounted` owns one fresh ledger and invokes the existing `decodeBudget` body once. It returns cumulative usage on every error. Legacy `Decode` delegates once and preserves nil Node/Budget failure results. `Budget.Usage` and `usageYAML` return scalar copies without mutation. The converter continues the same ledger through inspection, duplicate detection, mapping guards and concrete-tree conversion. Scanner, reader, Node construction and resolver semantics remain unchanged.

Native compiler artifacts match all 78 selected repository Go source hashes at `a19cc54`. The accounted entry has a 48-byte frame on Linux/Windows and a 64-byte frame on macOS ARM64. The same 64-byte Budget allocation remains; the scalar usage adapters add no escaping receiver, helper call or heap family. All three complete artifacts are in [diagnosis run 38362276804](https://github.com/ricevanta/ricevanta/actions/runs/38362276804), which builds diagnostic head `b825cb5` after checking its server tree against source candidate `a19cc54`. Source hashes bind the candidate; diagnostic jobs supply compiler evidence and do not replace required CI.

## Source bounds and agreement

[The parser audit](internal/yamltokens/ALLOCATION_AUDIT.md) owns every reachable allocation family, allocator rounding, abandoned backing, helper and recursion bound. The payload and aggregate token values are at most 1 MiB; nodes are at most 65,536 excluding the wrapper, container depth is at most 16, and live simple-key/indent/state/mark slots are at most 64. The ledger reserves before each growth and never refunds cumulative charges. Its ceilings remain 64 MiB and 1,000,000 objects; stack growth remains at most 8 MiB.

The parser reads the unchanged payload twice, discards presentation comment storage, records flat arities and constructs exact Node/Content arenas. Comment elimination retains mark and lookahead behavior. Simple-key lookup uses bounded slots and preserves flow-pop lookup deletion independently of key validity. Required keys expire only beyond 1,024 characters or at a line break, before a later token changes the error class. Scalar whitespace/break scratch is reused within each pass; both passes remain charged. Resolver helper allocations are reserved before use. The fixed entry reservation remains 16,640 bytes and eight objects.

Before any candidate trial, the parent independently determines expected acceptance and sanitized rejection using the separate comment-preserving scanner/event reference and unmodified pinned Node oracle. Candidate code does not classify the reference result. Both acceptance directions and error classes must agree. Successful trees compare kind, tag, value, style, marks, child order and node/depth counts; only presentation comments are excluded. Injected allocation exhaustion is checked separately from normal-budget acceptance.

Retained regressions cover comment contexts, CR/LF/CRLF, flow-pop key lookup, empty-value marks, malformed suffixes and the 1,023/1,024/1,025-character key boundary. The corpus input `065d6ae9e1509d82` must reject as syntax before its later tag. Focused observation tests demonstrate missing-accounting and wrong-failure-ledger failures before the adapter; current tests require exact same-call usage, zero/one YAML calls and unchanged legacy failure results. No corpus or independent oracle is weakened by the adapter.

## Measurement method

Every parser operation runs in a fresh child. The parent supplies independently constructed outcomes, arities and tree data. The child sets `GOMAXPROCS(1)` and memory limit `MaxInt64`, prepares runtime threads with two helper goroutines, then joins both before measurement. Each helper locks its thread, signals readiness, waits at the release barrier and unlocks before exit. This preparation invokes no parser, converter, decoder, resolver or dependency initialization, and does not deliberately grow the measuring goroutine's stack.

Snapshot storage and input setup precede one GC. GC stays disabled from the initial snapshot through the final snapshot. Node-only mode loads reference arities without invoking candidate preflight. Rejected preflight never reaches Node construction. Inputs and results stay live through the final snapshot; semantic comparison follows measurement.

Raw `TotalAlloc` and `Mallocs` deltas must fit the same-call ledger and unchanged ceilings, including rejected combined calls. No baseline subtraction, selected minimum, retry, warmup or runtime allowance applies. Each report must include validated runtime controls at both snapshots with unchanged GC count. Negative controls reject missing fields, wrong settings and raw values exceeding the ledger.

Runtime-only thread preparation addresses observed process-wide OS-thread allocations: a diagnostic batch included five Linux samples with 31 objects against a 30-object ledger, and complete stacks attributed six objects to `wakep -> startm -> newm -> allocm`. Those failed raw samples remain failures. Count signatures alone do not establish attribution or an allowance; current qualification still requires every raw sample to pass with zero exclusions.

Retained heap includes transient allocations, and process peak resident memory includes startup/input setup. Linux converts `Getrusage` KiB to bytes; macOS reports bytes; Windows uses `GetProcessMemoryInfo`. A native API failure fails the child. Normal scheduling/GC ownership and concurrency tests remain separate from the isolated allocation interval.

## Native evidence

[CI run 38362466507](https://github.com/ricevanta/ricevanta/actions/runs/38362466507) passes all 49 jobs for head `a19cc54e4748ff0c26379d634c3cb3f3581394ce`, testing PR integration commit `ded2b717aeb7ecfe3e4f2943132c6564e07b2413`. Each native Gate A job passes the extended corpus, 50 fresh-child repetitions of `comment-collections/262144/combined`, and anchored 60-second/two-worker parser fuzzing. Server race and required receipt aggregation pass in the same run.

| Target | Extended records | Repetitions | Largest raw bytes | Largest raw objects | Largest stack growth |
|---|---:|---:|---:|---:|---:|
| Linux x64 | 816 | 50 | 19,171,616 | 327,712 | 32,768 |
| macOS ARM64 | 816 | 50 | 19,171,616 | 327,712 | 0 |
| Windows x64 | 816 | 50 | 19,171,616 | 327,712 | 32,768 |

The primary checks all 2,598 retained records against their own ledger, ceilings and runtime controls. The table contains field maxima, not a selected sample or allowance. All 150 repeat records allocate 5,535,728 bytes and 25 objects. Raw `extended.log` and `repeat.log` files are retained in the run's per-host Gate A measurement artifacts; complete agreement and fuzz output remains in its job logs.

## Verification and remaining gate

Focused observation/accounting tests, ordinary parser/loader integration tests, formatting and vet pass locally. Race, timed fuzzing, extended measurements and the native matrix run only in CI. Source identity and allocation reasoning must pass independent review together with these native results; finite passing samples alone do not renew Gate A.

Independent renewal review confirms the single ledger/delegation path, all 16 provenance rows, native adapter escapes/frames and all 2,598 raw records. The separate final-head implementation review and CI remain required before landing. [Gate B](GATE_B_REVIEW.md) separately records complete-loader qualification and production prerequisites. Any candidate parser or measurement-method change requires fresh three-host native evidence and independent confirmation.
