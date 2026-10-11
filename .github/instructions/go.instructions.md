---
applyTo: "server/**"
excludeAgent: "cloud-agent"
---

Review against the [server guide](../../server/AGENTS.md), [Go rules](../../instructions/go.md), [testing rules](../../instructions/testing.md) and the changed package's spec and plan.

- Prefer the standard library; any added dependency needs a reviewed use and a [license row](../../docs/licensing.md). Preserve internal package boundaries and request-context ownership.
- Check exported signatures, exact sentinels with `errors.Is`, required cause wrapping and whole-input error precedence. A generic non-nil error assertion cannot prove the required sentinel.
- Check sizes before decoding, allocation and decompression; test combined defects, boundary values, mutation on failure and independent fixture oracles.
- Verify focused tests use `-count=1` when fixtures live outside `server/`. Keep fuzz targets in both [server.yml](../workflows/server.yml) and the testing instructions; check schema paths in push and pull-request filters.
- Follow the [security checklist](../skills/security-review/SKILL.md) for signing, keys, permission checks and untrusted parsers. DSSE key IDs are hints, not authorization; catalogue parsing does not grant permissions.
