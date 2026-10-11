# Extension Package Loader Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Return authenticated, bounded package bytes and decoded manifest evidence for a separate admission slice.

**Architecture:** A leaf loader imports the existing manifest and DSSE packages. It owns zstd/USTAR framing, a bounded token/event preflight, one budgeted YAML Node construction, conversion and file commitments. It performs no extraction or stateful admission.

**Tech Stack:** Go 1.27.1, `go.yaml.in/yaml/v3` v3.0.4 and `github.com/klauspost/compress` v1.20.1.

**Spec:** [Extension package loader](../specs/extension-loader.md). Numeric limits and error precedence have one home there.

## Global constraints

- An independent Sol xhigh reviewer approves spec and plan before code. Dispatch `gpt-6.1-sol` at `xhigh`; the design author cannot supply that approval.
- A separate Sol medium implementer, `gpt-6.1-sol` at `medium`, owns the code paths below. The design author and reviewer do not implement them.
- Astra xhigh, `gpt-6-astra` at `xhigh`, independently reviews the code and confirms fixes, including an adversarial pass for untrusted archive/YAML parsing and authentication; a model never reviews code it wrote (`instructions/workflow.md`, Reviews). No implementer reviews their own changes.
- Installed tools: Go 1.27.1; Rust 1.99.0 with cargo 1.99.0; Node 24.21.0 with pnpm 11.18.0. Rust and Node do not enter this Go dependency closure. Keep `go 1.27.1` without a toolchain directive.
- Pin both Go dependencies exactly as above; no new unpinned module. Preserve copied YAML notices and provenance under the existing licensing row. The selected budgeted v3.0.4 fallback in spec section 6.1 needs independent design/API and source/licensing approval before implementation.
- Failing test first: write tests, observe and record their intended failure, implement the smallest change, then rerun them. A compile failure establishes only a missing API; later tasks must demonstrate a behavioral failure too.
- The primary agent owns Git and checks each diff. Workers never add, commit or push. Use this isolated worktree; concurrent editing workers require separate worktrees and nonoverlapping owned paths. Tasks below are sequential because they share one boundary.
- Task 1 qualifies the isolated parser under spec section 6 Gate A before Task 2 starts. After Gate A approval, Tasks 2 through 4 build an isolated candidate pipeline; only loader tests and qualification harnesses may call it. Task 5 qualifies the complete loader under Gate B after Task 4. No production consumer, handler wiring or admission integration may import or invoke the candidate until both independent reviews pass. Production use also depends on canonical/non-small-order key admission from its concurrent slice.
- No trust-list storage, id ownership, tombstones, grants, recovery protocol, publication, component execution or HTTP handler belongs here. Unknown component bytes remain opaque.
- Local checks: formatting, vet and focused ordinary tests only. Race, timed fuzzing, extended allocation measurements and native matrices run in CI. Full v1.0.0 support remains required on macOS ARM64, Windows x64 and Linux x64.

## Review focus

- Bad signatures and mismatched control bytes must prevent any token/event/Node processing, including validly signed tagged YAML with a different archive member.
- Hidden tar metadata, concatenated frames, duplicate USTAR representations and malicious suffixes must fail without extraction or input-sized allocations beyond the stated bounds.
- Scanner lookahead, event queues and Node construction must be bounded on failures as well as valid documents; a post-decode node count is insufficient.
- Duplicate escaped keys, complex keys and resolver coercions must retain the intended error and cannot silently overwrite fields.
- Key hints, mutable Go evidence and stale key authorization must never become installation authority.
- Cross-file combined defects must prefer set, then size, then digest, while physical framing and token failures follow the specified local order.

## Owned implementation files

Task 0 and the Task 1 qualification harness exist. Gate A fails; dependent code remains blocked. This design task changes only the spec and plan.

| Path | Responsibility |
|---|---|
| `server/internal/extensions/loader/loader.go`, `errors.go` | Public API, pipeline, results and sentinels |
| `server/internal/extensions/loader/frame.go`, `tar.go` | Bounded read, zstd frame and physical USTAR checks |
| `server/internal/extensions/loader/yaml.go`, `tree.go` | Preflight bridge, one Node decode, tree checks and conversion |
| `server/internal/extensions/loader/internal/yamltokens/` | Exact-pin reader/scanner/event parser, budgeted Node builder/resolver, allocation ledger, license texts and `PROVENANCE.md` |
| `server/internal/extensions/loader/*_test.go` | Fixtures, boundary tests, qualification harness and fuzz seeds |
| `server/internal/extensions/loader/testdata/` | Small minimized regression inputs only |
| `server/go.mod`, `server/go.sum` | Exact YAML dependency pin and resolved checksums |
| `schemas/extension/v1alpha1/package-loader-vectors*.json` | Reviewed signed inputs and corpus schema; changes require independent regeneration |
| `scripts/ci/validate_contracts.py`, `scripts/ci/test_validate_contracts.py` | Task 0 implementer's scoped checker fix and regression tests |

The primary agent separately owns CI wiring in `instructions/testing.md` and `.github/workflows/server.yml`. Task 0 assigns the checker and its test file to the implementer through the explicit scope below; the design task does not edit either file. Preserve the registered `package-loader-vectors.schema.json` pairing and add embedded-manifest validation before fixture integration. Do not change `manifest` or `dsse` contracts, or merge the concurrent key-admission slice into this one.

### Task 0: Validate every embedded package manifest

**Files and owner:** The Sol medium implementer modifies only `scripts/ci/validate_contracts.py` and creates `scripts/ci/test_validate_contracts.py` for this task. No schema or vector change is needed.

**Interfaces:** Preserve `instances(schema, fixture, data)` yielding `(label, instance, expected_schema_validity)` and the existing manifest-fixture behavior. Negative loader outcomes do not imply schema-invalid documents.

- [x] Write `unittest` regressions named `test_package_manifest_pair_registered`, `test_package_manifest_instances` and `test_invalid_package_manifest_rejected`. Assert the manifest/corpus pair exists, every case yields `(case["name"], case["decoded_document"], True)`, and `main()` rejects each case in turn when only its in-memory `decoded_document` becomes `{"unexpected": true}`. Patch `load()` for that corpus only; do not alter fixtures on disk. Include negative-signature and negative-binding cases, and retain a passing check of the unmodified corpus and existing manifest fixtures.
- [x] From the repository root run `/home/danny/.cache/ricevanta-validation/bin/python -m unittest discover -s scripts/ci -p 'test_validate_contracts.py' -v`. Record the intended missing-pair, wrong-instance and accepted-invalid-document failures before changing the checker.
- [x] Add `("schemas/extension/v1alpha1/manifest.schema.json", "schemas/extension/v1alpha1/package-loader-vectors.json")` to `CONTRACTS`. In `instances()`, within the manifest-schema branch, distinguish this exact corpus path from `fixtures.json`; for every package case yield `case["name"], case["decoded_document"], True`. Preserve the existing `case["manifest"]` and `case["schema_valid"]` path for manifest fixtures. Never filter package cases by `signature_valid` or `result`.
- [x] Rerun the exact unittest command and require PASS. Then run `/home/danny/.cache/ricevanta-validation/bin/python scripts/ci/validate_contracts.py` from the repository root and require PASS: 11 schemas, 16 pairs, 223 instances for the checked-in inventory. The eight additional instances must be the eight embedded manifests.
- [x] Obtain independent review and fix confirmation before accepting the fixture checks. The primary agent inspects the diff and runs both commands; this plan step does not authorize the design worker to edit checker code.

### Task 1: Qualify bounded YAML under Gate A

**State:** Gate A is approved for the budgeted candidate. The unmodified Node decoder failed the allocation ceiling; the budgeted adaptation passes the finite and extended harnesses, the native `loader-gate-a` CI job on Linux x64, Windows x64 and macOS ARM64, and an independent Astra xhigh review of source bounds, scanner/Node agreement and measurements. `GATE_A_REVIEW.md` records the evidence. Task 2 may start; production consumers still wait for Gate B.

**Files:** Modify `internal/yamltokens/`, `yaml_qualification_test.go` and `yaml_tokens_test.go` under the loader. Add `internal/yamltokens/node.go`, `resolve.go` and focused budget/agreement tests. Retain `yaml_rss_linux_test.go`, `yaml_rss_darwin_test.go`, `yaml_rss_windows_test.go`, `TestParserBudgetExtended` and `-loader-budget-extended`. Update `PROVENANCE.md` and `GATE_A_REVIEW.md` with reviewed source bounds and fresh measurements. The implementer owns these code/artifact changes; this design revision edits none of them.

**Interfaces:** Preserve `yamltokens.Check(payload []byte) error` and static `ErrSyntax`, `ErrLimit`, `ErrTag`. Add internal `Decode(payload []byte) (*yaml.Node, *Budget, error)` and `Budget.Reserve(bytes, objects uint64) error` as specified in section 6.1. Decode owns the preflight, ledger and exactly one Node construction; only authenticated bytes reach it in the eventual loader. Node-only measurements use a test-only entry. No handler or public Load entry point exists for Task 1.

- [x] Obtain independent Sol xhigh approval of the revised spec/plan and fallback API/source/licensing scope. Independent Astra xhigh review confirms the failing Gate A evidence. Adapted source and updated provenance still require implementation review; neither design approval nor confirmation of failure approves Gate A.
- [x] Retain `TestTokenVectors`, `TestYAMLFraming`, `TestTokenLimits`, `TestPreflightNodeBounds`, all scanner growth/aggregate/parser-stack guards and every smoke recipe. Reproduce `comment-collections/524280` under the unmodified Node oracle. Record its Node-only and combined allocation failures; do not change expected acceptance or hide the test with a skip.
- [x] Add `TestBudgetedNodeAgreement`, `TestParserAllocationGuards`, `TestCommentElision` and `TestMaximumManifest`. Record intended failures before fallback implementation. Test raw/escaped tag controls, implicit scalar classes, malformed suffixes, full source-order errors, framing, node/depth/text/token boundaries, exact arena sizes and zero partial results. Exhaust byte/object budgets at each allocation family and assert rejection before growth, checked arithmetic and no ledger refunds between passes. Require the spec's [comment-context matrix](../specs/extension-loader.md#independent-acceptance-and-error-agreement), with independently assigned acceptance and sanitized errors for every case, in comment-elision tests, agreement tests and fuzz seeds.
- [x] Generate the spec's 62,437-node witness at runtime, including 4,096 `files[]` records and ownership references. Require schema/`manifest.Validate` success, exact counts and 639,793 compact JSON bytes. Add the exact ` #c\n` insertion after every comma/colon token outside strings (855,713 bytes), comments around collection boundaries, 1 MiB comment padding, and a case for each other component branch at its schema limits. Required valid cases and the exact commented-empty-mapping parser regression must succeed within budget, not return `ErrLimit` to pass qualification.
- [x] Implement the section 6.1 adaptation. Elide presentation comments in the scanner before storage, preserve scalar bytes and lexical marks, bound live simple-key slots, reuse scratch and compact tokens. Add the pinned Node-building and resolver portions only; no emitter or reflection decoder. Preflight records arities; construction uses exact Node/Content arenas and checks before descent. Route every allocating operation, including resolver helpers, through cumulative pre-allocation accounting; retain all structural caps. Preserve sanitized error precedence.
- [x] Extend `PROVENANCE.md` with exact upstream source ranges/checksums, both notices and deterministic patch digest. Audit every adapted allocation against the pinned Go 1.27.1 allocator/helper behavior, including rejected inputs, capacity rounding, the final clamped growth allocation, abandoned buffers, comments, simple keys, resolver temporaries and fixed overhead. Record source-backed upper bounds for bytes, objects and recursion; mark any missing bound as a Gate A blocker.
- [x] Update the harness to measure standalone preflight, budgeted Node construction and `Decode` separately in fresh children. Keep input generation before measurement, no warmup, one GC before the initial snapshot, GC disabled only during measurement, payload/Node liveness, post-measurement walking, and every existing metric/native RSS implementation. Classify rejection explicitly; rejected preflight inputs must never reach construction. Do not include oracle allocations in candidate deltas or pre-run the candidate inside a measured child.
- [x] Extend `FuzzParserQualification` and agreement tests using the spec's [independent acceptance and error rules](../specs/extension-loader.md#independent-acceptance-and-error-agreement). Establish expected preflight/Decode acceptance and sanitized rejection class before candidate preflight, using the pinned oracle and separately reviewed reference checks that do not reuse candidate code. Compare both acceptance directions on every input, including candidate rejections, and require rejected-input class/precedence equivalence. Compare complete Node kind, tag, value, style, marks, child order and node/depth counts on successful Decode, ignoring only presentation comment fields. Keep injected exhaustion separate from normal-budget agreement; any required-profile acceptance loss, unexpected acceptance, error mismatch, unclassified input, panic or allocation-bound gap fails qualification. Keep the oracle isolated and out of production imports/calls.
- [x] From `server/`, run `go test -count=1 ./internal/extensions/loader/... -run 'Test(Token|YAMLFraming|Preflight|ParserBudgetSmoke|BudgetedNode|ParserAllocation|CommentElision|MaximumManifest|ScannerGrowthBounds|AggregateBeforeGrowth|ParserStackGuards|ParserLayouts)'`, `go test -count=1 ./internal/extensions/loader -run '^FuzzParserQualification$'`, `go vet ./internal/extensions/loader/...` and `gofmt -l internal/extensions/loader`. Require PASS and no formatting output. Publish the finite measurement table and source audit, including headroom against 67,108,864 bytes; passing finite samples alone do not qualify Gate A.
- [x] Have the primary agent wire and run Gate A CI from `server/`: `go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetExtended$' -args -loader-budget-extended` and `go test -count=1 ./internal/extensions/loader -fuzz='^FuzzParserQualification$' -fuzztime=60s -parallel=2`. Preserve verbose measurement logs and failing fuzz inputs. Require Go 1.27.1 native measurements on Linux x64, Windows x64 and macOS ARM64. Independent Astra xhigh review must approve the source bounds, corpus, complete tree agreement, full-capacity valid manifests and measured headroom before Task 2. Failure keeps dependent work blocked and returns the adaptation to design review.

### Task 2: Frame and inventory a bounded archive

**Files:** Create `frame.go`, `tar.go`, `errors.go`, `frame_test.go`, `tar_test.go` and `archive_generator_test.go` under the loader.

**Interfaces:** Produce private `readArchive(body *io.LimitedReader, fileLimit uint64) (archive []byte, members []member, err error)` and `type member struct { path string; body []byte }`. This routine assumes validated options/reader contract. Returned member bodies may reference its private decoded snapshot; only Task 4 copies exported results.

- [ ] Write `TestReadArchive`, `TestReadBoundaries`, `TestFrameProfile`, `TestTarMembers`, `TestTarAliases` and `TestArchivePrecedence`. Cover every archive/vector class in spec section 8, bytes-plus-EOF/error, 100 zero-progress reads, declared size overflow, hidden PAX/GNU metadata, controls last, USTAR split aliases, malformed trailers and exact file totals. Assert sentinels and consumed byte counts, including no reads past `C+1`.
- [ ] Run from `server/`: `go test -count=1 ./internal/extensions/loader -run 'Test(Read|Frame|Tar|Archive)'`. Record the expected failure.
- [ ] Implement the bounded read and checked frame walk. Configure the pinned decoder exactly as the spec requires. Implement the physical tar walk before generic header interpretation, with all member metadata discarded as authority. Do not reuse the events body decoder.
- [ ] Build archives at test time with Go 1.27.1 `archive/tar` using `FormatUSTAR`, regular files, fixed zero uid/gid/time, mode 0644, empty owner/group and exact input order. Use the pinned zstd writer with concurrency 1, checksum on and 8 MiB window; encode a complete slice so frame content size is present. Valid fixtures end at exactly two zero blocks. Mutation helpers edit physical headers, checksum, lengths and trailers directly, then recompress when the defect belongs inside tar.
- [ ] Rerun the focused command and require PASS. Cross-check the valid tar inventory with an independent test reader; production parsing must still reject every prohibited format. Generated compression bytes are test transport, not a portable golden encoding or tombstone identity.
- [ ] Obtain independent review of checked arithmetic, pre-allocation ceilings and the framing/member precedence before Task 3 consumes member bytes.

### Task 3: Convert verified YAML without losing evidence

**Files:** Create `yaml.go`, `tree.go`, `yaml_test.go` and `tree_test.go` under the loader.

**Interfaces:** Consume `yamltokens.Decode` and its shared allocation ledger; produce private `decodeVerifiedYAML(payload []byte) (map[string]any, error)`. The name expresses a required call-site precondition, not a signature check inside the routine. Only `Load` calls it in production.

- [ ] Write `TestDecodeVerifiedYAML`, `TestScalarProfile`, `TestDuplicateKeys`, `TestTreeBudgets` and `TestYAMLPrecedence`. Add ordinary YAML, JSON syntax and all optional document-marker cases. Assert escaped duplicates at nested levels, quoted merge keys, complex keys, unsigned lexemes through MaxUint64, legacy boolean strings, quoted numbers, and every forbidden scalar tag. Assert exact `json.Number` spelling and that no Node or native integer enters the map.
- [ ] Run from `server/`: `go test -count=1 ./internal/extensions/loader -run 'Test(DecodeVerified|Scalar|DuplicateKeys|TreeBudgets|YAMLPrecedence)'`. Record the failure.
- [ ] Call `yamltokens.Decode` once; its internal preflight must complete before its one Node construction. Continue its allocation ledger through inspection, duplicate detection and conversion, reserving source-derived allocation upper bounds before every growth or helper call. Check node/profile budgets in source order, then scan for duplicate decoded keys, then allocate the map tree. Never call `Node.Decode`, a second Decoder.Decode, struct decoding or reserialization. Preserve full-source framing evidence from Task 1.
- [ ] Rerun the focused command and require PASS. Add a test-only call counter around the private decoder dependency to prove one call and no second EOF decode; do not expose a production injection option.
- [ ] Obtain independent review of scalar resolution, budget accounting and duplicate detection before assembly.

### Task 4: Verify and bind the complete package

**Files:** Create `loader.go`, `envelope.go`, `loader_test.go`, `vectors_test.go` and `ownership_test.go`; extend `errors.go` under the loader.

**Interfaces:** Implement the exact exported API and sentinels in spec sections 2 and 5, consuming Tasks 2 and 3, `dsse.Verify` and `manifest.Validate` unchanged. The candidate `Load` is callable only by loader tests and qualification harnesses until Task 5 obtains Gate B approval; do not wire a production consumer.

- [ ] Write `TestLoadVectors`, `TestLoadOrder`, `TestPublisherBinding`, `TestFileCommitments`, `TestLoadPrecedence`, `TestLoadResultOwnership` and `TestLoadZeroOnError`. Use every signed fixture as bytes, not a reconstructed envelope. Assert invalid signature plus tag returns only `dsse.ErrSignature`; payload mismatch prevents all YAML processing; schema errors precede publisher errors; set/size/digest precedence holds across reordered files. Use private test counters to prove zero YAML calls on verification failure.
- [ ] Run from `server/`: `go test -count=1 ./internal/extensions/loader -run 'Test(Load|PublisherBinding|FileCommitments)'`. Record the expected failure.
- [ ] Implement private `checkPayloadBudget(envelope []byte) error` in `envelope.go` and the pipeline in spec order. Test maximum base64 length/padding, escaped characters, duplicate root payloads and excessive JSON nesting before calling DSSE; no payload decode belongs in the preflight. Pass `dsse.TypeExtensionManifest` from caller intent. Bind the raw public-key fingerprint after structural validation. Copy exact bytes into independent exported storage only after every check succeeds. Do not parse KeyID to select a key or retain it as authority.
- [ ] Test changed valid hints, same manifest with different archive encoding, signed wrong publisher, zero-length bodies, control-member substitution, small key lengths and caller options. Exercise all five manifest kinds using valid decoded fixtures rendered into JSON syntax and signed by the fixed fixture key. Opaque body files need matching commitments, not valid runtime content.
- [ ] Rerun the focused command and require PASS. Assert no output slice aliases another output slice or input; mutate each independently and check peers. Assert `errors.Is` for each loader/DSSE/manifest failure and absence of publisher-controlled text. I/O failures additionally preserve their cause.
- [ ] Obtain independent adversarial review and fix confirmation. Review admission handoff explicitly: callers still need current prefix, ownership, tombstone, grant and recovery checks; no persistence or publication occurs here.

### Task 5: Qualify the complete loader under Gate B and pin CI coverage

**Files:** Create `fuzz_test.go`, `loader_qualification_test.go` and extend the qualification tests under the loader. The primary agent owns CI/test-instruction wiring through a separate scoped task. Task 4's assembled candidate must exist before this task measures it.

**Interfaces:** Add `FuzzLoad`, `FuzzVerifiedYAML` and `FuzzTar` as described in the spec. The direct YAML fuzz entry is test-only and cannot become a public unauthenticated parser.

- [ ] Add failing regression seeds for any review finding first. Cover every adjacent pipeline stage with combined defects, and local source-order failures separately. Test result hashes against standard-library SHA-256 over exact bytes, using signed goldens from the independently generated corpus.
- [ ] Add `TestLoaderBudgetSmoke` and `TestLoaderBudgetExtended` for Gate B. Extend the source-bound audit and reuse Task 1's measurement method for scanner, Node decode, tree inspection, duplicate detection and map conversion together, then full `Load` including DSSE, archive decoding and independent output copies. Exercise successes and failures, the spec's archive/manifest limits and serial/two-call peaks. Run `go test -count=1 ./internal/extensions/loader -run '^TestLoaderBudgetSmoke$'` from `server/`; record each budget defect's failure before fixing it, then require PASS. Keep extended measurements in CI.
- [ ] Run from `server/`: `go test -count=1 ./internal/extensions/loader/...`. Record each regression's failure before the implementer fixes it, then require PASS including the seed corpus.
- [ ] Run from `server/`: `gofmt -l internal/extensions/loader` and require no output; `go vet ./internal/extensions/loader/...` and require exit 0. Run `go test -count=1 ./internal/extensions/manifest ./internal/signing/dsse ./internal/extensions/loader/...` once for integration.
- [ ] The primary agent adds CI entries for `go test -race -count=1 ./internal/extensions/loader/...` and each command below, from `server/`. CI anchors each fuzz name and archives failures. No local timed fuzzing or race run.

```sh
go test -count=1 ./internal/extensions/loader -fuzz='^FuzzLoad$' -fuzztime=60s -parallel=2
go test -count=1 ./internal/extensions/loader -fuzz='^FuzzVerifiedYAML$' -fuzztime=60s -parallel=2
go test -count=1 ./internal/extensions/loader -fuzz='^FuzzTar$' -fuzztime=60s -parallel=2
go test -count=1 ./internal/extensions/loader -run '^TestParserBudgetExtended$' -args -loader-budget-extended
go test -count=1 ./internal/extensions/loader -run '^TestLoaderBudgetExtended$' -args -loader-budget-extended
```

- [ ] Both extended budget tests skip unless Task 1's named custom flag is true. Each launches one fresh child per input and measurement mode and publishes allocation, object, stack, retained-heap, peak-resident-memory and elapsed-time data with toolchain/OS/architecture. Ordinary `TestParserBudgetSmoke` and `TestLoaderBudgetSmoke` are finite and serial; no measurement substitutes for source-bound review.
- [ ] Require native Go 1.27.1 results on Linux x64, Windows x64 and macOS ARM64. Tests qualify this portable loader only, not endpoint runtime isolation or complete platform support.
- [ ] Obtain independent Gate B review and fix confirmation of the complete source bounds, corpus coverage, native measurements, assembled-path scanner/Node agreement, race tests and timed fuzzing. Retain Gate A approval too. A failed Gate B keeps the candidate isolated; parser changes require fresh Gate A evidence before dependent work resumes.
- [ ] The primary agent inspects every diff, `git diff --check`, focused results, both qualification approvals, independent review and required CI results before any Git integration. Report failed checks as failed. Do not claim production readiness while either qualification gate, key admission or stateful admission remains unresolved.

## Fixture regeneration contract

The committed JSON corpus records byte evidence. Do not commit archive binaries or fixture-generation scripts in this design slice. The implementation's `archive_generator_test.go` owns archive recipes; temporary signing/check scripts stay in `/tmp`.

1. Derive the public key from the fixed public test seed `000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`. Hash the raw public key for the publisher field. Use the existing untagged raw YAML vector with only that fingerprint replaced, then apply each corpus case's explicit byte rule.
2. Compute DSSE PAE with the exact extension payload type, decimal byte lengths and unchanged payload. Sign with Python cryptography 50.0.0; use the fixed zero hint and compact JSON field order from the DSSE spec. A changed-hint case uses 64 `f` characters. No hint represents an actual certificate.
3. Validate the corpus schema and every recorded decoded document against `manifest.schema.json` using jsonschema 4.25.1. Negative binding/equality/signature cases still carry schema-valid documents; record signature validity separately from loader outcome. Validate raw token vectors against their existing schema.
4. In a separate Go 1.27.1 standard-library script, derive the key, reconstruct PAE, recompute signatures and every digest, compare payload/envelope bytes and check signature-valid expectations. Re-run generation in a fresh `/tmp` directory and require byte equality. Do not use `dsse.Sign` or the loader to bless goldens.
5. Any fixture change needs a reviewer to check the generator rule, independent result and error-stage expectation. Larger boundary inputs stay runtime recipes, outside the small fuzz seeds.

## Handoff questions

- Can the selected budgeted adaptation prove every allocation charge and comment-elision rule while retaining full manifest capacity, then pass Gate A before Task 2 and Gate B after Task 4? Lower structural caps are rejected in spec section 6.1. Keep the current limits and corpus, independent reviews and native CI; no fallback qualification is implied by this plan.
- Which admitted-key API does the concurrent key-validation slice expose to the eventual caller?
- Do package measurements justify revisiting the selected USTAR and in-memory limits through a separate reviewed contract change?
