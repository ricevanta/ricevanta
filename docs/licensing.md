# Licensing

Ricevanta is Apache-2.0. This file records what third-party code and rule sources may be used and under which conditions. Every new dependency or rule pack gets a row before code depends on it.

## Rules

- GPL code is never linked into Ricevanta. A GPL program may run only as a separately distributed optional process after legal review.
- The project's own eBPF programs are dual-licensed MIT and GPL-2.0, because the kernel accepts BPF LSM programs and GPL-only helpers only from GPL-compatible programs. They are separate objects loaded into the kernel, not linked into the agent, and the agent stays Apache-2.0.
- Reference projects are for learning; copying code requires a row in the table and attribution in `NOTICE`.
- Rule packs carry their own license record, author fields and signature from the first pack. Rule licenses are tracked separately from application code.
- Sigma rules under DRL 1.1 require the rule author to be shown wherever a match is displayed, including console alert views and exported events.
- An SBOM is produced for every release.
- Extensions carry an SPDX license expression in their manifest, which the console shows at install; a release SBOM covers first-party extensions. Connector contracts are project OpenAPI 3.1 documents and add no library.

## Code and rule sources

| Source | License | Use |
|---|---|---|
| Sigma rules (SigmaHQ) | DRL 1.1 | Allowed with author attribution in match output and redistributed rules |
| Sigma tooling, pySigma | MIT (verify) | Reference only; Python |
| YARA-X | BSD-3-Clause | Rust library, linkable |
| Community YARA rules | Varies per repository; some non-commercial | Per-pack license record required |
| Magika | Apache-2.0 (verify model weight terms) | Linkable; ONNX runtime adds size |
| Presidio | MIT | Port recognizer patterns, not code; Python |
| Gitleaks | MIT | Patterns reusable with attribution; Go |
| detect-secrets | Apache-2.0 | Patterns reusable |
| Apache Tika | Apache-2.0 | Optional server-side only; Java |
| osquery | Apache-2.0 or GPL-2.0 dual | Reference; not bundled |
| Fleet | MIT, except `ee/` under a source-available license | Only non-`ee/` code; verify each file |
| NanoMDM, MicroMDM | MIT | Design and code reusable |
| Munki | Apache-2.0 | Reference |
| step-ca | Apache-2.0 | Go code reusable |
| `layeh/radius` | MPL-2.0 | Linkable; modified files stay MPL |
| FreeRADIUS | GPL-2.0 | Not used |
| Wazuh | GPL-2.0 with exceptions | Reference only |
| Santa | Apache-2.0 | Design reusable; Objective-C and Swift |
| HarfangLab `endpoint-sec` crate | MIT or Apache-2.0 | Rust Endpoint Security bindings, linkable |
| `micromdm/scep` | MIT | Go SCEP server code reusable |
| `smallstep/crypto` | Apache-2.0 | Go X.509, KMS and PKCS#11 packages |
| `radius-eap` (Ctere1 fork) | MIT | Seed for the in-project EAP-TLS state machine, pinned commit |
| Fleet `server/mdm/microsoft` | MIT (outside `ee/`) | MS-MDE2 and SyncML code reusable; verify each file |
| Falco rules | Apache-2.0 | Reusable through logsource mapping |
| MITRE ATT&CK | MITRE terms, free with attribution notice | Include the notice |
| OCSF schema, `ocsf-schema-compiler`, `ocsf-validator` | Apache-2.0 | Event format and its CI tooling |
| cel-spec and its conformance suite | Apache-2.0 | Language definition and the profile's CI gate |
| DSSE specification | Apache-2.0 | Bundle and command signature envelope |
| CIS Benchmarks | Not freely redistributable | Not bundled; baselines are authored in-project |

## Libraries named in the architecture

| Library | License | Use |
|---|---|---|
| `tokio` | MIT | Agent async runtime |
| `rustls` | Apache-2.0, MIT or ISC | Agent TLS with platform-key signing |
| `rustls-cng` | MIT or Apache-2.0 (verify) | Windows CNG and TPM keys as `rustls` signing keys |
| `security-framework` | MIT or Apache-2.0 | macOS Keychain and Secure Enclave keys; the `rustls` signer is written in-project |
| `rusqlite` with bundled SQLite | MIT; SQLite public domain | Agent local state |
| `aya` | MIT or Apache-2.0 | Linux eBPF loading, BPF LSM, tracing programs |
| `windows-rs` | MIT or Apache-2.0 | Windows API, ETW, CNG and TPM bindings |
| `tss-esapi` | Apache-2.0 or MIT (verify) | Linux TPM 2.0 bindings |
| tpm2-tss | BSD-2-Clause | Linux TPM 2.0 stack, dynamically linked |
| `cel` (cel-rust) | MIT | Agent CEL evaluation |
| `postcard` | MIT or Apache-2.0 | Agent local IPC serialization |
| zstd and the `zstd` Rust crate | BSD-3-Clause; crate MIT | Event spool and upload compression |
| `klauspost/compress` | BSD-3-Clause | Server zstd decompression, pure Go |
| `cel-go` | Apache-2.0 | Server CEL evaluation |
| `pgx` | MIT | Server PostgreSQL driver |
| `go-oidc`, `go-ldap` | Apache-2.0; MIT | Administrator login, directory sync |
| `elimity-com/scim` | MIT | SCIM 2.0 server, pinned commit; early-stage, no bulk |
| SAML library | Verify | Chosen in `design/backend.md` after an activity check; `crewjam/saml` is BSD-2-Clause but stale |
| `minio-go` | Apache-2.0 | S3-compatible blob store client |
| `opensearch-go`, `go-elasticsearch` | Apache-2.0 | Export destination clients; the Elasticsearch client stays Apache-2.0 whatever the server license |
| Vue 3, Vite, Pinia, Vue Router, `vue-i18n`, Element Plus | MIT | Console; PrimeVue 5 is excluded, its license is not MIT |
| Apache ECharts | Apache-2.0 (verify) | Console charts |
| Vitest, Playwright | MIT; Apache-2.0 | Console tests |
| PostgreSQL | PostgreSQL License | System of record |
| CloudNativePG | Apache-2.0 | PostgreSQL operator in the Helm chart |
| Prometheus Go client, OpenTelemetry Go SDK | Apache-2.0 | Server metrics and traces |
| ClickHouse | Apache-2.0 | Optional raw telemetry store, bundled in deploy profiles |
| `clickhouse-go` | Apache-2.0 (verify) | Raw store client |
| OpenSearch | Apache-2.0 | Export destination; not bundled |
| Elasticsearch | AGPL-3.0, SSPL or Elastic License (verify) | Export destination; never bundled |
| `wasmtime`, `wasmtime-wasi`, Cranelift | Apache-2.0 per the repository; LLVM exception, verify | `ricevanta-ext` WebAssembly runtime and compiler (EXT-03) |
| `wit-bindgen` | Apache-2.0 per the repository; LLVM exception, verify | Guest bindings in the extension SDK; host bindings come from `wasmtime::component::bindgen!` |
| `wasm-tools` | Apache-2.0 per the repository; LLVM exception, verify | SDK packaging: component and WIT validation; build tool, not shipped in the agent |
| `@module-federation/vite` | MIT | Console code splitting for first-party code only, if used; never for third-party console modules (EXT-04) |
| `blake3` crate | CC0-1.0, Apache-2.0 or Apache-2.0 with LLVM exception | Content identity |
| TLSH and its Rust crate | Apache-2.0 (verify both) | Content similarity |
| `crc32c` crate | Apache-2.0 or MIT (verify) | Spool record checksums |
| ssdeep | GPL-2.0 | Not used |
| W3C PROV-DM, OpenLineage | W3C document license; Apache-2.0 | Lineage vocabulary only |

## Brand assets and build tools

| Source | License | Use |
|---|---|---|
| Be Vietnam Pro | SIL OFL 1.1 | Outlined into the wordmark and tagline masters; the OFL exempts documents made with the font and no Reserved Font Name is declared; notice in `branding/source/OFL-BeVietnamPro.txt`; font binaries are not committed |
| ImageMagick 7 with librsvg | ImageMagick License; librsvg LGPL-2.1-or-later (verify) | Build-time renderer for `branding/scripts/build.py`; not shipped |
| Pillow | MIT-CMU (verify) | Build-time validation and ICO assembly; not shipped |
| fonttools, uharfbuzz | MIT; Apache-2.0 (verify) | Build-time outlining in `branding/scripts/outline_wordmark.py`; not shipped |
| `branding/reference/approved-concept-board.png` | AI-generated concept art; generating tool and its output terms not recorded (verify) | Visual reference only; not shipped |
