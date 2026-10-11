---
applyTo: "schemas/**"
excludeAgent: "cloud-agent"
---

Review against [documentation rules](../../instructions/documentation.md), [testing rules](../../instructions/testing.md) and the schema's [spec](../../docs/specs/) and [plan](../../docs/plans/).

- Check draft, required fields, closed shapes, numeric/string bounds and examples against the spec. Separate schema validity from semantic, cryptographic and platform acceptance; format annotations alone do not enforce a format.
- Require positive, negative, boundary and combined-defect vectors with exact expected errors and precedence. Check fixture consumers use all cases and independent expected values.
- Register fixtures and their directories in [validate_contracts.py](../../scripts/ci/validate_contracts.py), or the slice's validator, and wire that validator into [design.yml](../workflows/design.yml). Inventory exclusions must not silently hide a new fixture.
- Check [server.yml](../workflows/server.yml) and [agent.yml](../workflows/agent.yml) filters and change detectors cover every schema directory their jobs read, including shared Go/Rust event fixtures. Update required commands in the testing instructions.
- Keep embedded permission catalogue bytes, schema expectations and source coverage aligned with the [permission catalogue spec](../../docs/specs/permission-catalogue.md).
