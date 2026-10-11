---
applyTo: ".github/workflows/**,scripts/ci/**"
excludeAgent: "cloud-agent"
---

Review against [workflow rules](../../instructions/workflow.md), [testing rules](../../instructions/testing.md) and the slice's required checks.

- Require full commit SHA action pins, `contents: read` permissions unless a reviewed need requires more, and checkout with `persist-credentials: false`. Check exact toolchains, lockfile installs and disabled console lifecycle scripts.
- Trace every file a job reads, including schema directories, fixture generators and imported validators. Both push and pull-request path filters, plus internal change detectors, must trigger every consumer.
- Check for accidental duplicate CI commands within a job or overlapping jobs; preserve intentional native, race and interoperability coverage. Check command parity only where [testing rules](../../instructions/testing.md) or the slice plan require it; Go fuzz targets belong in both those instructions and [server.yml](../workflows/server.yml).
- Check new schema/fixture validation is reachable through [validate_contracts.py](../../scripts/ci/validate_contracts.py) or a slice validator and runs in [design.yml](../workflows/design.yml). Failure must fail the required gate, not disappear behind a skip or `continue-on-error`.
- Apply the [security checklist](../skills/security-review/SKILL.md) to event permissions, untrusted interpolation, caches and artifact trust. Review setup must use the single supported `copilot-setup-steps` job and supported job keys in [copilot-code-review.yml](../workflows/copilot-code-review.yml).
