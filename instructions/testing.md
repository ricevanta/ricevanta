# Testing

Before review, run light checks for the touched component. For the Go server, run from `server/`:

```sh
gofmt -l .
go vet ./internal/path/to/touched/package
go test -count=1 ./internal/path/to/touched/package
```

`-count=1` prevents cached Go test results from hiding changes to fixtures outside `server/`.

`gofmt -l .` must print no files. Replace the example package path with the touched packages. Fix formatting with `gofmt -w` on the touched files.

CI runs the full ordinary suite, race tests and timed fuzzing on the pushed `wip/**` branch. Ordinary `go test -count=1 ./...` keeps running every fuzz target's seed corpus. The primary agent reads the CI results before merging and does not merge failed checks.

The following commands are the CI fuzz target list. Each target gets one matrix entry and runs for 60 seconds from `server/`:

```sh
go test -count=1 ./internal/events/eventid -fuzz=FuzzParse -fuzztime=60s -parallel=2
go test -count=1 ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=60s -parallel=2
go test -count=1 ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=60s -parallel=2
go test -count=1 ./internal/events/wire -fuzz=FuzzParseHeader -fuzztime=60s -parallel=2
go test -count=1 ./internal/events/wire -fuzz=FuzzDecode -fuzztime=60s -parallel=2
go test -count=1 ./internal/events/body -fuzz=FuzzExtractLine -fuzztime=60s -parallel=2
go test -count=1 ./internal/events/body -fuzz=FuzzDecode -fuzztime=60s -parallel=2
go test -count=1 ./internal/policy/celdecl -fuzz=FuzzParse -fuzztime=60s -parallel=2
go test -count=1 ./internal/policy/celdecl -fuzz=FuzzLoad -fuzztime=60s -parallel=2
go test -count=1 ./internal/authz/catalogue -fuzz=FuzzValidateName -fuzztime=60s -parallel=2
go test -count=1 ./internal/authz/catalogue -fuzz=FuzzParse -fuzztime=60s -parallel=2
go test -count=1 ./internal/extensions/manifest -fuzz=FuzzValidate -fuzztime=60s -parallel=2
go test -count=1 ./internal/events/exportdest -fuzz=FuzzValidate -fuzztime=60s -parallel=2
go test -count=1 ./internal/events/exportdest -fuzz=FuzzDecoded -fuzztime=60s -parallel=2
go test -count=1 ./internal/mdm/resourcevalidate -fuzz=FuzzValidate -fuzztime=60s -parallel=2
go test -count=1 ./internal/mdm/resourcevalidate -fuzz=FuzzBudget -fuzztime=60s -parallel=2
```

Keep the single target list in `.github/workflows/server.yml` aligned with these commands. CI anchors the target names to select exactly one fuzz target. CI uploads the target's corpus on failure, including new failing entries. Commit useful minimized inputs to the target's seed corpus. Report the command, duration and result from CI.

Race tests, timed fuzzing, extended property tests, browser tests and the cross-OS matrix belong in CI on the pushed `wip/**` branch. Browser checks start with the first reviewed console slice; no browser test suite exists yet.

The initial server packages have pure unit and fuzz tests. They do not establish PostgreSQL, network, process, operating-system or platform support. Add integration and platform checks with the first code that crosses those boundaries, following its reviewed design and the qualification gates in `docs/specs/platform-qualification.md`.

## Rust agent

The first Rust slice follows [instructions/rust.md](rust.md) and [the spool implementation plan](../docs/plans/agent-spool-format.md). Run fixture drift checks from the repository root:

```sh
python agent/tools/generate-spool-fixtures.py --check
```

Before review, run Cargo formatting, Clippy and ordinary tests for touched crates from `agent/`:

```sh
cargo fmt --all -- --check
cargo clippy --locked -p ricevanta-spool --all-targets -- -D warnings
cargo test --locked -p ricevanta-spool
cargo tree --locked --edges normal,build,dev
```

Select the touched crates with `-p`; `ricevanta-spool` is the current crate.

CI also runs the extended property test on every native matrix entry:

```sh
cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact
```

The ordinary suite runs every shared fixture and the deterministic `fuzz_recover` target. The ignored extended target runs in CI; report its seed, case count, elapsed time and result. The plan fixes both budgets and mutation invariants. Tests match error variants and fields, check combined defects and use an independent CRC oracle. A failed check stays failed in the report.

CI runs fixture regeneration, fmt, Clippy, ordinary tests and the extended property test natively on macOS ARM64, Windows x64 and Linux x64 with the exact Rust pin. These checks establish portable codec behavior, not file permissions, power-loss durability, sensors, resource budgets or full platform support. Add native integration checks only with their reviewed slice and [platform qualification](../docs/specs/platform-qualification.md).

No releasable binary exists, so the repository has no binary, installer, container or upgrade test yet.
