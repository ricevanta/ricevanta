# Rust development

The agent uses the virtual Cargo workspace in `agent/`. The first member is `crates/spool`, package `ricevanta-spool`, import `ricevanta_spool`. Follow [the spool spec](../docs/specs/agent-spool-format.md) and its independently approved plan before creating code.

## Toolchain and layout

- Pin `agent/rust-toolchain.toml` to channel `1.99.0`, profile `minimal`, components `rustfmt` and `clippy`. Rust and Cargo 1.99.0 are installed locally. CI uses that exact version, never `stable` or nightly implicitly. [rustup documents the toolchain file](https://rust-lang.github.io/rustup/overrides.html#the-toolchain-file).
- Use a virtual root `agent/Cargo.toml`, explicit members, resolver `3`, edition `2024`, `rust-version = "1.99"`, license `Apache-2.0`, `publish = false`, and shared package version `0.1.0` for this initial workspace. Release work aligns the package version with SH-04; crate versions are not independent product releases.
- Put leaf libraries in `agent/crates/<purpose>/`; package names use `ricevanta-<purpose>`, imports use underscores. Create only the reviewed members. The core's `events` module depends on the spool library, never the reverse. Do not make a root package, binary, runtime or OS crate for this slice.
- Inherit package fields and lints explicitly in each member. Commit `agent/Cargo.lock`. The [Cargo workspace reference](https://doc.rust-lang.org/cargo/reference/workspaces.html) describes shared metadata, lockfiles and lint inheritance. Keep build output under ignored `agent/target/`.

## Code and errors

- Run rustfmt with its defaults. CI checks formatting without rewriting files. Do not add a formatter configuration for personal preferences.
- Set workspace Rust lint `unsafe_code = "forbid"` and `missing_docs = "deny"`; each member uses `[lints] workspace = true`. CI runs Clippy with `-D warnings`. Add narrow lint exceptions only with a reason tied to the reviewed contract; never suppress the workspace's unsafe prohibition in this slice.
- Write no unsafe Rust in portable libraries. Future native bindings need an independently reviewed, isolated OS crate and documented safety invariants; a dependency's internal unsafe code still needs dependency review. The workspace lint does not prove dependencies contain no unsafe code.
- Prefer borrowed slices and fixed-size values for parsers. Check sizes and arithmetic before indexing. Do not panic, unwrap, expect or assert on caller-controlled values in production code. Assertions and unwraps are permitted in tests to report a violated test expectation.
- Expose typed error enums, implement `Display` and `std::error::Error`, and preserve a cause through `source()` when one exists. Match variants in tests. Do not use display strings as a protocol or log event payloads through errors. Do not add `anyhow` or `thiserror` without a reviewed need and license record.
- Document public invariants, accepted inputs, error precedence, mutation on failure and ownership. Avoid generic frameworks when the slice needs one byte format.

## Dependencies and checks

Use the standard library unless the reviewed slice names a dependency. Direct, build and dev dependencies use exact `=x.y.z` requirements; internal workspace paths inherit one shared version. The lockfile pins transitive versions and checksums. No wildcard, branch, unreviewed feature, vendored copy or Git dependency is allowed. [Cargo's dependency rules](https://doc.rust-lang.org/cargo/reference/specifying-dependencies.html) distinguish exact requirements from default compatible-version ranges.

Record all added crates, build tools and licenses in [docs/licensing.md](../docs/licensing.md) before code relies on them. Inspect the full resolved closure and features, including build scripts and transitive licenses. A direct dependency's row does not approve its dependencies. Lockfile changes require review; normal checks use `--locked`. Keep secrets and credential directories out of caches and tracked files.

Follow [instructions/testing.md](testing.md#rust-agent) for exact format, lint, unit, fixture and bounded fuzz-like commands. Start with failing tests, include malformed inputs and combined defects, and use independent fixture oracles. Use the stable std-only mutation target selected by the spool plan; adding coverage-guided fuzzing requires exact tool/runtime pins and license review. Pure codec tests on three hosts establish byte portability only. Native APIs, permissions, durable writes, sensors, installers and whole-product performance require their own qualification checks.
