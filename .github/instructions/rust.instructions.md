---
applyTo: "agent/**"
excludeAgent: "cloud-agent"
---

Review against [Rust rules](../../instructions/rust.md), [testing rules](../../instructions/testing.md#rust-agent) and the changed crate's spec and plan.

- Check workspace metadata and inherited lints, the exact toolchain, exact dependency requirements, committed lockfile and `--locked` checks. Review build scripts, features and the full dependency closure against [licensing](../../docs/licensing.md).
- Check borrowed input, checked arithmetic and bounds before indexing or allocating. Caller-controlled input must not trigger panics, `unwrap`, `expect` or unsafe code in portable libraries.
- Match typed error variants and fields, precedence for combined defects, ownership and mutation on failure. For spool recovery, verify framing, CRC and sequence behavior against the shared vectors and an independent oracle.
- Check fixture regeneration, ordinary seed coverage and CI-only extended property targets in [agent.yml](../workflows/agent.yml). Changes to shared event fixtures must trigger their Go and Rust consumers.
- Keep byte portability claims separate from native permissions, durable writes and platform qualification, as the spec requires.
