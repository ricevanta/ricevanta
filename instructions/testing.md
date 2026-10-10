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
```

Run those commands from `server/`. Commit useful minimized inputs to the target's seed corpus. Report the command, duration and result. Ordinary continuous integration runs each fuzz target's seed corpus through `go test`; it does not run timed fuzzing.

The initial server packages have pure unit and fuzz tests. They do not establish PostgreSQL, network, process, operating-system or platform support. Add integration and platform checks with the first code that crosses those boundaries, following its reviewed design and the qualification gates in `docs/specs/platform-qualification.md`.

No releasable binary exists, so the repository has no binary, installer, container or upgrade test yet.
