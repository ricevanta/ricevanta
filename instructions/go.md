# Go development

The Go module is `github.com/ricevanta/ricevanta/server` in `server/`. It requires Go 1.27.1. Keep the version in `server/go.mod` and continuous integration aligned.

- Use the standard library unless the reviewed design requires a dependency. Record every dependency in `docs/licensing.md` before adding it to `go.mod`.
- Keep packages focused and dependency direction explicit. Code under `internal/` is private to the server module.
- Return errors to the caller with useful context and preserve causes with `%w` when callers need `errors.Is` or `errors.As`.
- Use `context.Context` only for request lifetime, cancellation and deadlines. Pass it as the first argument and do not store it in a struct.
- Format all Go files with `gofmt`. Do not hand-format generated output.

Follow `instructions/testing.md` for required checks and bounded fuzzing. The first event packages are standard-library-only libraries with no database or operating-system integration.
