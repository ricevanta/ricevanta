# Permission catalogue implementation plan

Add a standard-library-only catalogue library under `server/internal/authz/catalogue`. The library validates exact permission names and bounded catalogue JSON, serves immutable metadata, and embeds a checked copy of the canonical catalogue. The contract is [the permission catalogue spec](../specs/permission-catalogue.md); the permission inventory and schema live under `schemas/permissions/v1/`.

## Global constraints

- An independent Sol xhigh review approves both spec and plan before code starts. Unresolved design findings are implementation blockers for the affected contract.
- A separate Sol medium implementer, `gpt-6.1-sol` at `medium`, owns the code paths below. The design author and reviewer do not implement them. Dispatch with explicit model and effort.
- Sol `gpt-6.1-sol` at `xhigh` reviews all code and makes an adversarial pass over untrusted JSON, names, error precedence and metadata delivery. A separate independent Sol xhigh reviewer confirms fixes. Reviewers never edit the implementation.
- Each task starts with failing tests. Record the expected failure before adding the least implementation needed for the contract. A compile failure is sufficient for a missing API, but later mutation and drift checks must fail for the intended behavior.
- The primary agent inspects changes, runs required checks, integrates work and owns Git. Workers never add, commit or push. No Git operation belongs to this design task.
- Use one implementation worktree for the sequential tasks because they share a package. Other slices use separate worktrees. Do not revert another worker's changes.
- Preserve module `github.com/ricevanta/ricevanta/server` with `go 1.27.1`; no `toolchain` directive. Go 1.27.1 is installed and required. No third-party Go dependency is permitted.
- Installed auxiliary tools: Rust 1.99.0, cargo 1.99.0, Node 24.21.0 and pnpm 11.18.0. They are not needed by the package. Schema validation uses installed Python `jsonschema==4.25.1`; require that exact version. Cryptography 50.0.0 is unused.
- Keep runtime packages leaf-only: standard library imports, no database, transport, identity evaluator, role model, command dispatch or module-private dependency. Add no server executable, HTTP route, console code, signing code or deployment change.
- The canonical JSON, schema and fixtures are design artifacts. Changes to their semantics require renewed design review and catalogue revision handling, not a test update that blesses changed behavior.
- Keep native, authority-journal, command-schema and OpenAPI gates intact. Successful validation does not authorize an action or qualify an OS.

## Ownership and handoff

The implementer owns the new package files below and the bounded workflow edit specified after the table. The primary agent coordinates any other expansion before a worker touches another slice:

| Path under `server/internal/authz/catalogue/` | Purpose |
|---|---|
| `name.go`, `name_test.go` | Grammar, name lookup vectors and `FuzzValidateName` |
| `errors.go` | Exact sentinels from spec section 6 |
| `parse.go`, `parse_test.go` | Strict wire parsing, schema parity, semantic phases and `FuzzParse` |
| `catalogue.go`, `catalogue_test.go` | Immutable storage, public API and concurrency checks |
| `builtin.go`, `builtin_test.go` | Embedded copy, cached initialization and drift tests |
| `catalogue.json` | Exact copy of canonical JSON, never independently edited |
| `schema_test.py` | Offline JSON Schema checks, fixture validation and coverage checks; test utility only |
| `testdata/fuzz/` | Useful minimized fuzz regressions only |

The same implementer owns `.github/workflows/server.yml` only to add `schemas/permissions/**`, `docs/design/**` (including `docs/design/console.md`) and `docs/specs/**` to both `push.paths` and `pull_request.paths`, and to add the one Python validation step in Task 4. Keep all existing triggers and steps. Preserve the exact setup-go action, `go-version-file: server/go.mod`, `cache: true` and `cache-dependency-path: server/go.sum`. Every file read by drift or coverage checks must match both filters; expand both filters if a test gains another input. This design task does not edit the workflow.

The primary agent supplies the reviewed documents and `schemas/permissions/v1/` in that worktree. A worker report names changed paths, tests, observed failures, passing checks, unresolved findings and any contract ambiguity. Reports do not claim API authorization or OS support. The primary agent reads the diff and reruns the required checks before accepting the report.

## Review focus

- All seven explicitly named permissions, every console operation, every swept action in `fixtures/coverage.json` and all response commands remain covered; proposed operation selectors remain semantic until OpenAPI review.
- No generic scope or approval default, namespace alias, wildcard, direct-approver role grant, connector-to-user grant or mutable shared slice slips through. Device update and label changes cannot bypass the organization group permission and group_change predicate.
- Grammar validation stays separate from catalogue membership. Unknown and retired names fail lookup with different sentinels.
- Whole-document phases win over earlier entry defects. Error matching is exactly one `errors.Is` sentinel; partial output never escapes.
- JSON decoding rejects repeated decoded keys, malformed UTF-8, unpaired surrogates and case aliases. Container and byte bounds hold before proportional allocations.
- Fixed direct authority approval and immediate revocation remain consumer requirements; catalogue metadata is not an evaluator.
- The embedded bytes match `schemas/` exactly; tests fail on a missing canonical source and retain permanent tombstones.

## Task 1: Fixture harness and name grammar

Consumes: spec sections 2, 6 and 7; `fixtures/names.json`, catalogue fragments and all three schemas. Produces: schema-validation utility, fixture-loading helpers, exact name grammar and sentinels. Later tasks own lookup assertions.

- [ ] Create `schema_test.py` as a test utility with an exact `importlib.metadata.version('jsonschema') == '4.25.1'` check. Use `Draft202012Validator.check_schema` on all three schemas, validate the complete catalogue and all four fixture wrappers, then compare each fragment's schema acceptance with `schema_valid`. Decode hex cases and report that byte-profile validation belongs to Go. Disable remote reference retrieval; these schemas use local references only.
- [ ] The same utility checks unique names, ASCII sorting, revision relations and the seven fixed names in the complete catalogue. Extract the operation IDs in console sections 5.1 through 5.16 and compare them with `uses` base selectors. Expand the console's “same set” for baselines and exceptions explicitly. Subject/protocol exemptions must be an explicit reviewed set, never ignored unmatched operations. Validate `coverage.schema.json` and `fixtures/coverage.json`. Check every action's exact name/selector, owner, note, scope, rule, derived approval/protection, active role grant, required composed names and source anchor inside its named section. Check the sorted unique path inventory and SHA-256 source digests against every `docs/design/*.md` and `docs/specs/*.md`, including the permission spec; added, removed or changed sources fail until independent review updates coverage. Read every source in the sweep, not just lines containing console operation IDs. Verify that every JSON row's source file exists; section-reference accuracy also gets manual review. Keep coverage expectations independent of the catalogue under test; never generate expected rows from that catalogue during validation.
- [ ] Prove the utility fails when a temporary copy of a schema-valid fragment expects schema rejection, when an explicit name is missing, and when a console operation is removed from all row uses. For every swept action, also remove its entry, remove/rename its exact selector, alter owner/note/scope/rule/protection/approval/grant/status and remove each composed permission; each mutation must fail for its intended coverage defect. Mutate source anchors, source digests and the source file inventory. Exercise every exemption explicitly. Keep mutation copies in a temporary directory and restore no repository file from a stale copy.
- [ ] Check the six exclusive revocation/trust bindings in spec section 7 independently of base-operation coverage. Require the publisher-key branch on `extensions.trust.revoke` with no approval, id and version branches and their API selectors on `extensions.packages.revoke` with `extension_dependency`, and removal through `extensions.trust.update` with `always`. Reject bare, generic and unknown `updateTrustList` selectors and duplicate bindings anywhere in the catalogue. Validate every `fixtures/revocations.json` fragment against the catalogue schema, then compare the separate branch-check result with `coverage_valid`. Prove rejection for missing id/version branches, branches moved or duplicated onto the immediate permission, unprotected package revocation, held publisher-key revocation and removal on the immediate permission. Mutate the coverage manifest too: removing or misbinding any required branch must fail even when the catalogue still covers the base operation.
- [ ] Write `TestValidateName` from every name fixture, including expected unknown names that remain syntactically valid. Add byte-grammar boundary and invalid UTF-8 cases; Go string literals or byte conversions carry invalid UTF-8 because JSON strings cannot faithfully carry it. Add `FuzzValidateName` with an independent byte-scanning oracle in the test.
- [ ] Run from the root: `python server/internal/authz/catalogue/schema_test.py`. Expected: schema cases pass and each harness self-test observes its intended failure.
- [ ] Run `cd server && go test ./internal/authz/catalogue -run '^TestValidateName$'`. Expected initial failure: API absent. Record the output.
- [ ] Implement `ValidateName` and `errors.go` exactly as specified. Avoid regex normalization, Unicode folding or namespace checking inside this function.
- [ ] Repeat the focused command. Expected: PASS, without module downloads.

## Task 2: Strict catalogue parser

Consumes: reviewed schema and fixture wrappers. Produces: `Parse`, private parsed representation and every parse sentinel. Do not expose partially decoded entries.

- [ ] Write `TestParseFixtures`, `TestParseWireProfile`, `TestParseShape`, `TestParseEntryMetadata`, `TestParseRevision`, `TestParseBounds` and `TestParsePrecedence`. The tests decode fixture objects into JSON bytes and `wire_hex` into exact bytes. A successful fragment must yield a usable catalogue; each failure must yield nil and exactly one sentinel.
- [ ] Add every generated boundary from spec section 7, including byte padding, container depth, entry counts, metadata lengths and numeric spellings. Build the 2,048-name input in tests without a checked-in giant fixture. Use the independent fixture expectation table, not implementation helper functions, to compute the wanted error.
- [ ] Combine each neighboring validation phase's defects. Test duplicate decoded keys including `name` versus an escaped spelling, invalid UTF-8, paired and unpaired surrogates, case aliases and trailing values. Ensure errors omit attacker input.
- [ ] Run `cd server && go test ./internal/authz/catalogue -run '^TestParse'`. Expected initial failure: parser absent or a behavioral assertion fails. Record it.
- [ ] Implement a bounded strict JSON scan and exact field decoding. Standard `encoding/json` typed decoding alone cannot enforce the wire contract. Use separate phase passes for shape, version, every name, every entry, duplicate names, sorting and revision relations.
- [ ] Keep the Go metadata vocabulary identical to the schema. Add parity vectors for every enum value and namespace/owner restriction, including the fixed direct and connector grant rows. Do not depend on Python at runtime.
- [ ] Add `FuzzParse`: arbitrary byte input, no panic, nil on failure and one sentinel. Task 3 adds exact accepted byte copies, repeat parse and active/retired lookup invariants after those APIs exist. Seed with every wire case and valid fragment.
- [ ] Repeat `cd server && go test ./internal/authz/catalogue -run '^TestParse'`. Expected: PASS. Run the Python utility again and require PASS.
- [ ] The primary agent inspects the parser diff against the error phases and allocation bounds before dependent code starts.

## Task 3: Immutable metadata and embedded catalogue

Consumes: parser and the exact canonical catalogue. Produces: the public `Catalogue` methods and `Builtin`. It adds no permission-checking function or transport handler.

- [ ] Write `TestLookupFixtures`, `TestLookupPrecedence`, `TestZeroCatalogue`, `TestDefensiveCopies`, `TestConcurrentReads`, `TestBuiltin`, `TestBuiltinDrift` and `TestBuiltinFailure`. Test all active names and tombstones, nil receivers, zero values, unknown names and malformed names on unavailable catalogues.
- [ ] Test copy isolation by mutating input bytes, `Permission.Uses`, the outer and nested `Entries` slices and returned JSON bytes, then re-reading. Race many lookups, enumeration and returned-copy mutations. Use a private loader seam to test malformed embedded-equivalent bytes without changing the production embedded string or global cache after use.
- [ ] Run `cd server && go test ./internal/authz/catalogue -run '^Test(Lookup|Zero|Defensive|Concurrent|Builtin)'`. Expected initial failure: methods and embedded asset absent. Record it.
- [ ] Implement the exact API and `sync.Once` initialization. Return typed errors to callers; no panic, empty fallback or mutable exported state. `Entries` includes tombstones; `Lookup` excludes them. Nil receiver semantics follow the spec.
- [ ] From the repository root run `cp schemas/permissions/v1/catalogue.json server/internal/authz/catalogue/catalogue.json`. Add `//go:embed catalogue.json` in `builtin.go`. Embed a string; keep it unexported.
- [ ] Implement `TestBuiltinDrift` using the relative path in spec section 5. Require a full repository checkout; failure to read canonical JSON is a test failure. Compare raw bytes including whitespace and final newline. Test comparison helpers with a one-byte difference and missing source.
- [ ] Repeat the focused command and `cd server && go test ./internal/authz/catalogue`. Expected: PASS.
- [ ] Run `cmp schemas/permissions/v1/catalogue.json server/internal/authz/catalogue/catalogue.json` from the root. Expected: exit 0, no output.
- [ ] Compare name metadata against the primary agent's reviewed base revision. No name deletion, reuse or semantic mutation under an existing name may pass merely by copying new bytes. For the first catalogue, record that there is no earlier catalogue baseline.

## Task 4: CI integration and independent security review

- [ ] Edit only the authorized workflow triggers and add one step before the existing Go tests, named `Validate permission catalogue`, with `working-directory: .` and the commands below. The job defaults to `server`, so the explicit root override is required. The temporary virtual environment avoids changing the runner's system Python. The exact package version is also asserted inside `schema_test.py`.

  ```sh
  python3 -m venv "$RUNNER_TEMP/permission-schema-venv"
  "$RUNNER_TEMP/permission-schema-venv/bin/python" -m pip install 'jsonschema==4.25.1'
  "$RUNNER_TEMP/permission-schema-venv/bin/python" server/internal/authz/catalogue/schema_test.py
  ```

- [ ] Keep `TestBuiltinDrift` in the normal `go test ./...` run with no skip or build tag. The existing Test and Test with race detector steps execute it on every filtered run; no separate Go step is needed.
- [ ] Verify both path filters cover the canonical JSON, all three schemas and fixtures, embedded copy, test utility and every source document read by coverage. Compare each input path to each filter and prove a catalogue-only change and a console-design-only change match. [GitHub path filters](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-syntax#onpushpull_requestpull_request_targetpathspaths-ignore) require a matching changed path. Check the setup-go block byte-for-byte against the input workflow.
- [ ] Run the Python step's commands in a temporary environment, then mutate only a temporary canonical copy by one byte and prove the drift comparison fails. Remove an action binding in a temporary fixture and prove coverage fails. Validate the workflow syntax and root working directory. Report local checks separately from a hosted CI run; no hosted run is claimed without its result.


- [ ] The primary agent sends a self-contained review brief to an independent `gpt-6.1-sol` `xhigh` reviewer: spec and plan as authorities, all implementation paths read-only, no Git mutations, required adversarial parser and authority-boundary pass, and findings with file/line, severity, failing vector and suggested contract resolution.
- [ ] The reviewer checks schema parity, combined defects, bounded allocation, mutable slices, singleton failure handling, special grant kinds, operation coverage and drift enforcement. A valid catalogue must not make unknown HTTP operations or extension bridge operations callable.
- [ ] The separate implementer fixes findings with a failing regression test first. A different independent Sol xhigh reviewer confirms each fix. The primary agent inspects the entire resulting diff and verifies no edits outside approved ownership.
- [ ] Run all commands in Final verification, capture outputs and report any failure as failed. Do not describe unrun commands as checks performed.

## Final verification

Run these from the repository root unless `cd server` is included. Task 4 installs automatic drift and coverage enforcement in the existing server workflow. These commands remain required locally.

```sh
python server/internal/authz/catalogue/schema_test.py
cmp schemas/permissions/v1/catalogue.json server/internal/authz/catalogue/catalogue.json
cd server && gofmt -w internal/authz/catalogue/*.go
cd server && gofmt -l internal/authz/catalogue
cd server && go test ./...
cd server && go test -race ./...
cd server && go vet ./...
cd server && go test ./internal/authz/catalogue -fuzz=FuzzValidateName -fuzztime=5s -parallel=2
cd server && go test ./internal/authz/catalogue -fuzz=FuzzParse -fuzztime=5s -parallel=2
git diff --check
```

Each `cd server` command is independent, not a script that repeatedly descends into `server/`. Formatting lists no paths; all other commands exit 0. Preserve useful minimized fuzz failures. Ordinary tests execute fuzz seeds; timed fuzzing runs locally before review.

Also run the existing bounded fuzz targets required by `instructions/testing.md`, from `server/`:

```sh
go test ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s -parallel=2
go test ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s -parallel=2
go test ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzParseHeader -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzDecode -fuzztime=5s -parallel=2
go test ./internal/events/body -fuzz=FuzzExtractLine -fuzztime=5s -parallel=2
go test ./internal/events/body -fuzz=FuzzDecode -fuzztime=5s -parallel=2
```

The final report names files, observed failing-test-first results, exact successful and failed commands, both fuzz durations, independent review status and remaining consumer gates. Passing library tests establishes name and metadata validation only.
