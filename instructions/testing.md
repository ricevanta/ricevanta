# Testing

Run checks from the component directory. For the Go server, run:

```sh
gofmt -w .
go test ./...
go test -race ./...
go vet ./...
```

`gofmt -l .` must print no files in continuous integration. The race run is required even when the ordinary test run passes.

Run every Go fuzz target for a bounded interval before review. The initial server targets require:

```sh
go test ./internal/events/eventid -fuzz=FuzzParse -fuzztime=5s -parallel=2
go test ./internal/events/batch -fuzz=FuzzDescriptor -fuzztime=5s -parallel=2
go test ./internal/signing/dsse -fuzz=FuzzVerify -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzParseHeader -fuzztime=5s -parallel=2
go test ./internal/events/wire -fuzz=FuzzDecode -fuzztime=5s -parallel=2
go test ./internal/events/body -fuzz=FuzzExtractLine -fuzztime=5s -parallel=2
go test ./internal/events/body -fuzz=FuzzDecode -fuzztime=5s -parallel=2
```

Run those commands from `server/`. Commit useful minimized inputs to the target's seed corpus. Report the command, duration and result. Ordinary continuous integration runs each fuzz target's seed corpus through `go test`; it does not run timed fuzzing.

The initial server packages have pure unit and fuzz tests. They do not establish PostgreSQL, network, process, operating-system or platform support. Add integration and platform checks with the first code that crosses those boundaries, following its reviewed design and the qualification gates in `docs/specs/platform-qualification.md`.

## Rust agent

The first Rust slice follows [instructions/rust.md](rust.md) and [the spool implementation plan](../docs/plans/agent-spool-format.md). Run fixture drift checks from the repository root:

```sh
python agent/tools/generate-spool-fixtures.py --check
```

Run the Rust checks from `agent/`:

```sh
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
cargo test --locked -p ricevanta-spool --test fuzz_recover fuzz_recover_extended -- --ignored --exact
cargo tree --locked --edges normal,build,dev
```

The ordinary suite runs every shared fixture and the deterministic `fuzz_recover` target. The ignored extended target runs before review; report its seed, case count, elapsed time and result. The plan fixes both budgets and mutation invariants. Tests match error variants and fields, check combined defects and use an independent CRC oracle. A failed check stays failed in the report.

CI runs fixture regeneration, fmt, Clippy and ordinary tests natively on macOS ARM64, Windows x64 and Linux x64 with the exact Rust pin. These checks establish portable codec behavior, not file permissions, power-loss durability, sensors, resource budgets or full platform support. Add native integration checks only with their reviewed slice and [platform qualification](../docs/specs/platform-qualification.md).

No releasable binary exists, so the repository has no binary, installer, container or upgrade test yet.
