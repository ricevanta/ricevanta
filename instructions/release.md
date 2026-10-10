# Releases

The repository has no releasable binary. Do not publish server artifacts, container images, installers or release tags from the current Go library slices.

A release workflow needs an independently reviewed release design before implementation. The design must define versioning, reproducible inputs, artifact provenance, signing, platform qualification, upgrade and rollback tests, and credential custody. Security-relevant release paths also need adversarial review under `instructions/workflow.md`.

Current continuous integration validates source only. GitHub Actions supplies only the ephemeral `GITHUB_TOKEN` job token with `contents: read`. No repository, organization, environment or deployment secrets are available. Checkout sets `persist-credentials: false`, so it does not retain the token as a checkout credential.
