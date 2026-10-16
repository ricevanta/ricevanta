# Go server guide

This directory is the `github.com/ricevanta/ricevanta/server` Go module. The module owns Go packages under `server/`; packages under `internal/` are available only within this module.

Read these files before changing server code:

- `../AGENTS.md` for repository rules and review requirements.
- `../instructions/go.md` and `../instructions/testing.md` for the toolchain and required checks.
- `../docs/design/backend.md`, and the domain design that matches the package, for example `../docs/design/events.md` for `internal/events/` and `../docs/design/policy.md` for `internal/policy/`.
- The `../docs/specs/` file the task names.

The module contains libraries under `internal/<domain>/` and independently reviewed `cmd/ricevanta-server` runtime source. The admitted `api` role provides configuration and lifecycle handling, TLS or loopback HTTP, public health/readiness probes and verified static console serving under `../docs/specs/server-runtime.md`. Production console embedding, release integration and required native qualification remain gated. Administrative and agent APIs, identity handlers, database-backed roles and authority consumers remain blocked on their reviewed implementation plans and protocol gates, including BE-12; their reserved paths do not admit operations. Server deployment targets are Linux amd64 and arm64 containers; build/test hosts do not expand that deployment boundary. No releasable server installation is claimed.
