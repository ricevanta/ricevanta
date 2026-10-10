# Go server guide

This directory is the `github.com/ricevanta/ricevanta/server` Go module. The module owns Go packages under `server/`; packages under `internal/` are available only within this module.

Read these files before changing server code:

- `../AGENTS.md` for repository rules and review requirements.
- `../instructions/go.md` and `../instructions/testing.md` for the toolchain and required checks.
- `../docs/design/backend.md` and `../docs/design/events.md` for server and event-pipeline boundaries.
- `../docs/specs/core-primitives.md` for the implemented event primitives.

The current module contains libraries only: `internal/events/eventid`, `internal/events/batch`, `internal/events/wire` and `internal/events/body` (event upload decoding), `internal/signing/dsse` (DSSE envelopes) and `internal/policy/celdecl` (CEL declarations). Each package's spec is under `../docs/specs/`. The module has no executable, server runtime, API, database access, network path or platform integration.
