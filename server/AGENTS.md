# Go server guide

This directory is the `github.com/ricevanta/ricevanta/server` Go module. The module owns Go packages under `server/`; packages under `internal/` are available only within this module.

Read these files before changing server code:

- `../AGENTS.md` for repository rules and review requirements.
- `../instructions/go.md` and `../instructions/testing.md` for the toolchain and required checks.
- `../docs/design/backend.md`, and the domain design that matches the package, for example `../docs/design/events.md` for `internal/events/` and `../docs/design/policy.md` for `internal/policy/`.
- The `../docs/specs/` file the task names.

The module contains libraries only, under `internal/<domain>/`. It has no executable, server runtime, API, database access, network path or platform integration.
