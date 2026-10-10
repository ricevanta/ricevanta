# Licensing

Ricevanta is Apache-2.0. This file records what third-party code and rule sources may be used and under which conditions. Every new dependency or rule pack gets a row before code depends on it.

## Rules

- GPL code is never linked into Ricevanta and no GPL program ships with it; GPL tools appear only as lab test fixtures.
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
| Sigma tooling: pySigma, sigma-cli | LGPL-2.1 | Reference only; neither run nor linked; Python |
| Sigma specification | Public domain per the repository LICENSE (verify full text) | Rule semantics the adapter and evaluator implement in-project |
| YARA-X | BSD-3-Clause | Rust library, linkable |
| Community YARA rules | Varies per repository; some non-commercial | Per-pack license record required |
| Magika repository and `standard_v3_3` model | Repository Apache-2.0; the model directory has no license file of its own (verify the weights) | Model run on `tract-onnx` in `ricevanta-scan`; not shipped until the weight terms are confirmed |
| Presidio (`data-privacy-stack/presidio`, moved from `microsoft/presidio`) | MIT | Port recognizer patterns, not code; Python |
| Gitleaks | MIT | Patterns reusable with attribution; Go |
| detect-secrets | Apache-2.0 | Patterns reusable |
| Apache Tika | Apache-2.0 | Optional server-side only; Java |
| osquery | Apache-2.0 OR GPL-2.0-only | Not bundled; its `specs/*.table` files generate the inventory table map at build time under the Apache-2.0 option |
| Fleet | MIT, except `ee/` under a source-available license | Only non-`ee/` code; verify each file |
| NanoMDM, MicroMDM | MIT | Design and code reusable |
| Munki | Apache-2.0 | Reference |
| step-ca | Apache-2.0 | Go code reusable |
| `layeh/radius` | MPL-2.0 | Packet codec and dictionaries only; untagged and without recent maintenance, pinned commit; modified files stay MPL |
| FreeRADIUS | GPL-2.0 | Not used |
| Wazuh | GPL-2.0 with exceptions | Reference only |
| Santa | Apache-2.0 | Design reusable; Objective-C and Swift |
| HarfangLab `endpoint-sec` crate | MIT or Apache-2.0 | Rust Endpoint Security bindings, linkable |
| `micromdm/scep` | MIT | Go SCEP server code reusable |
| `smallstep/crypto` | Apache-2.0 | Go X.509, KMS and PKCS#11 packages |
| `radius-eap` (Ctere1 fork) | MIT | Seed for the in-project EAP-TLS state machine, pinned commit |
| Fleet `server/mdm/microsoft` | MIT (outside `ee/`) | MS-MDE2 and SyncML code reusable; verify each file |
| Falco rules | Apache-2.0 | Reusable through logsource mapping |
| MITRE ATT&CK and `attack-stix-data` | ATT&CK Terms of Use: non-exclusive, royalty-free license for research, development and commercial purposes; every copy reproduces MITRE's copyright designation and the license | Enterprise STIX data bundled with the server; the notice "© <year of the bundled data> The MITRE Corporation. This work is reproduced and distributed with the permission of The MITRE Corporation." in `NOTICE`, the coverage view and exported layers |
| ATT&CK Navigator | Apache-2.0 | Layer file format for the coverage export; not bundled |
| STIX 2.1, TAXII 2.1 (OASIS Standards) | OASIS IPR policy of the CTI TC (verify mode) | Formats implemented in-project; no library |
| MISP feed format | MISP is AGPL-3.0 | Format parsed in-project; no MISP code used or linked |
| OCSF schema, `ocsf-schema-compiler`, `ocsf-validator` | Apache-2.0 | Event format and its CI tooling |
| cel-spec and its conformance suite | Apache-2.0 | Language definition and the profile's CI gate |
| DSSE specification | Apache-2.0 | Bundle and command signature envelope |
| CIS Benchmarks | Not freely redistributable | Not bundled; baselines are authored in-project |
| CIS Controls | CC BY-NC-ND 4.0 (verify) | Safeguard identifiers in baseline references only |
| macOS Security Compliance Project (mSCP) | CC BY 4.0 (verify the license file) | Baseline item content with attribution in `io.ricevanta.baselines` |
| DISA STIGs | US government work; distribution statement per STIG (verify) | Baseline item content and rule identifiers |
| `apple/device-management` schema repository | MIT (verify) | Source for validation schemas of `apple.declaration` and `apple.profile` items |
| Homebrew | BSD-2-Clause (verify) | Optional macOS package source, invoked as a separate program, not bundled |
| winget-cli | MIT (verify) | Optional Windows package source, invoked, not bundled |
| KMFDDM | MIT | Reference only; not used |
| UnRAR | Freeware license that forbids RAR-compatible archivers; not open source | Not used; RAR archives are `unsupported` |
| MuPDF | AGPL-3.0 | Not used |
| `ocrs` model weights | CC-BY-SA-4.0 | Not used |
| `content_analysis_sdk` | BSD-3-Clause | Protocol of the core's local content-analysis agent |
| hostapd, wpa_supplicant | BSD-3-Clause (verify) | Test fixtures for 802.1X and EAP-TLS interoperability; not shipped |
| strongSwan | GPL-2.0 | Lab-only IKEv2 EAP-TLS test client run as a separate process; never linked or distributed |
| Grafana Loki | AGPL-3.0 (`clients/` carries an Apache-2.0 license file, verify per file) | Export destination only; no Loki package is imported |

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
| `cel` (cel-rust) | MIT | Agent CEL evaluation; second parse in `ricevanta-rulec` |
| `regex` crate | MIT OR Apache-2.0 | Scanner detectors, matcher regular expressions, dictionaries, `ricevanta-rulec` |
| `aho-corasick` crate | Unlicense OR MIT | Matcher prefilter, keyword and deny-list passes |
| `postcard` | MIT or Apache-2.0 | Agent local IPC serialization |
| zstd and the `zstd` Rust crate | BSD-3-Clause; crate MIT | Event spool and upload compression |
| AG-11: [`zstd` 0.13.3](https://raw.githubusercontent.com/gyscos/zstd-rs/v0.13.3/Cargo.toml); zstd-safe 7.2.2; zstd-sys 2.0.16+zstd.1.5.7; cc 1.4.5; pkg-config 0.3.34; find-msvc-tools 0.1.12; shlex 2.0.1; jobserver 0.1.35; libc 0.2.189; getrandom 0.4.3; cfg-if 1.0.4; r-efi 6.0.0 | MIT selected for Rust crates/build helpers; [BSD-3-Clause](https://raw.githubusercontent.com/facebook/zstd/v1.5.7/LICENSE) selected for bundled zstd 1.5.7; complete registry release MIT texts inspected, including r-efi AUTHORS; zstd-sys generated bindings and bundled zstd BSD-3-Clause notices inspected | File-free batch writer and native build closure; exact features in [the spec](specs/agent-batch-writer.md#1-boundary-dependencies-and-alternatives). No GPL/LGPL branch selected. Preserve notices and include the closure in the release SBOM. |
| [`github.com/klauspost/compress` v1.20.1](https://github.com/klauspost/compress/blob/v1.20.1/LICENSE) | BSD-3-Clause for zstd; module also contains Apache-2.0 and MIT paths | Server zstd decompression, pure Go; exact EV-09 pin; retain applicable copyright and license notices in source/binary distribution and include in the release SBOM |
| [`go.yaml.in/yaml/v3` v3.0.4](https://github.com/yaml/go-yaml/blob/v3.0.4/LICENSE) | MIT and Apache-2.0 | Later extension YAML loader only, exact EXT-08 pin; node inspection preserves duplicates and scalar types before conversion. The decoded validator uses only the standard library. Retain both license notices and include the dependency in the release SBOM when shipped. |
| `cel-go` | Apache-2.0 | Server CEL evaluation |
| `pgx` | MIT | Server PostgreSQL driver |
| `go-oidc`, `go-ldap` | Apache-2.0; MIT | Administrator login, directory sync |
| `elimity-com/scim` | MIT | SCIM 2.0 server, pinned commit; early-stage, no bulk |
| SAML library | Verify | Chosen in `design/backend.md` after an activity check; `crewjam/saml` is BSD-2-Clause but stale |
| `minio-go` | Apache-2.0 | S3-compatible blob store client |
| `opensearch-go`, `go-elasticsearch` | Apache-2.0 | Export destination clients; the Elasticsearch client stays Apache-2.0 whatever the server license |
| `franz-go` | BSD-3-Clause | Kafka export destination client, pure Go |
| `go.opentelemetry.io/proto/otlp` | Apache-2.0 | OTLP log export messages |
| `grpc-go` | Apache-2.0 | OTLP/gRPC export transport |
| `protobuf-go` | BSD-3-Clause | OTLP message encoding |
| `azure-sdk-for-go` `azlogs`, `azidentity` | MIT | Microsoft Sentinel Logs Ingestion API client and Entra authentication |
| `aws-sdk-go-v2` | Apache-2.0 (verify) | Signature Version 4 credentials for Amazon OpenSearch Service through the `opensearch-go` signer |
| `maxminddb-golang` | ISC (verify) | Optional geolocation from an operator-supplied MaxMind DB-format file; no database is bundled |
| tpm2-pkcs11 | BSD-2-Clause (verify) | Linux system package providing the TPM network-access key to NetworkManager; not bundled |
| Go `crypto/hpke` | BSD-3-Clause | Sealing gateway secrets to the `radius` role, if the pinned Go release ships it (verify); otherwise RFC 9180 base mode in-project over `crypto/ecdh`, `crypto/hkdf` and `crypto/cipher` |
| libsystemd (sd-journal) | LGPL-2.1-or-later | Loaded at run time on Linux to read the journal; not shipped and not statically linked |
| Vue 3, Vite, Pinia, Vue Router, `vue-i18n`, `@intlify/unplugin-vue-i18n` | MIT | Console framework, build, state, routing, strings; PrimeVue 5 is excluded, its license requires a license key and forbids redistribution without an OEM license |
| Apache ECharts | Apache-2.0 | Console charts, used without `vue-echarts` (BE-08) |
| Vitest, `@vue/test-utils`, Playwright | MIT; MIT; Apache-2.0 | Console tests |
| `openapi-typescript`, `openapi-fetch` | MIT | Console API types and typed client generated from `schemas/openapi/` |
| Reka UI | MIT | Console UI primitives under in-house components |
| TanStack Table, TanStack Virtual (`@tanstack/vue-table`, `@tanstack/vue-virtual`) | MIT | Console data grid |
| Cytoscape.js, `cytoscape-dagre`, `dagre` | MIT | Console lineage graph |
| CodeMirror 6 (`@codemirror/*`, including `lang-yaml`, `lint`, `autocomplete`, `merge`) | MIT | Console policy editor |
| `yaml` (eemeli) | ISC | Console YAML parsing with source ranges |
| Ajv | MIT | Console JSON Schema 2020-12 validators, generated at build time in standalone mode |
| axe-core, `@axe-core/playwright` | MPL-2.0 | Console accessibility tests only; never shipped |
| pnpm | MIT | Console package manager; build tool, not shipped |
| TypeScript, `vue-tsc`, ESLint, `eslint-plugin-vue` | Apache-2.0; MIT; MIT; MIT (verify all) | Console type checking and lint; build tools, not shipped |
| `rsc.io/qr` | BSD-3-Clause | Server-rendered QR codes for break-glass TOTP enrollment |
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
| `blake3` crate | CC0-1.0, Apache-2.0 or Apache-2.0 with LLVM exception | Content identity |
| `infer` | MIT | Scanner magic-number detection |
| `tract-onnx` | MIT OR Apache-2.0 | Magika inference in the scanner |
| `pdfium-render`; PDFium | MIT OR Apache-2.0; BSD-3-Clause | PDF text and page rendering in the scanner |
| `zip`, `quick-xml` | MIT; MIT | OOXML and ODF extraction |
| `calamine` | MIT | Spreadsheet extraction |
| `cfb` | MIT | OLE compound files: legacy Office, Outlook msg |
| `rtf-parser` | MIT | RTF extraction |
| `html5ever` | MIT OR Apache-2.0 | HTML extraction |
| `mail-parser` | Apache-2.0 OR MIT | eml and mbox extraction |
| `msg_parser` | MIT | Outlook msg extraction |
| Tesseract with `tessdata_fast` `vie` and `eng` | Apache-2.0; models Apache-2.0 (verify) | OCR in the scanner |
| Leptonica | BSD-2-Clause (verify) | Tesseract image library |
| `tesseract-rs` | MIT | Builds and binds Tesseract and Leptonica |
| `tar`, `flate2` | MIT OR Apache-2.0 | Archive extraction |
| `bzip2` crate and libbzip2 | MIT OR Apache-2.0; libbzip2 license (verify) | Archive extraction |
| `liblzma` crate and XZ Utils liblzma | MIT OR Apache-2.0; liblzma license (verify) | Archive extraction |
| `sevenz-rust2` | Apache-2.0 | 7z extraction |
| `chardetng`, `encoding_rs` | Apache-2.0 OR MIT; (Apache-2.0 OR MIT) AND BSD-3-Clause | Text encoding detection and decoding |
| TLSH and `tlsh2` | TLSH "Apache OR BSD" per its LICENSE file; `tlsh2` Apache-2.0 OR BSD-3-Clause, pure Rust | Content similarity in `ricevanta-scan` |
| [`crc32c` 0.6.8](https://docs.rs/crate/crc32c/0.6.8/source/Cargo.toml) | MIT OR Apache-2.0 | Spool record checksums; exact registry README grants either license (no standalone LICENSE files); default features; retain upstream license and copyright notices in distributions |
| `rustc_version` 0.4.1 | MIT OR Apache-2.0 | `crc32c` build dependency; registry release LICENSE-MIT and LICENSE-APACHE inspected; retain both notices |
| `semver` 1.0.27 | MIT OR Apache-2.0 | `rustc_version` dependency with default `std` feature; registry release LICENSE-MIT and LICENSE-APACHE inspected; retain both notices |
| ssdeep | GPL-2.0 | Not used |
| W3C PROV-DM, OpenLineage | W3C document license; Apache-2.0 | Lineage vocabulary only |

## Brand assets and build tools

| Source | License | Use |
|---|---|---|
| Python `jsonschema`, `referencing`, PyYAML | MIT; MIT; MIT | Design CI validates JSON Schema and policy examples with local reference resolution; not shipped |
| Python `rfc3339-validator`, `six` | MIT; MIT | Design CI checks exception expiry timestamps; not shipped |
| GitHub Actions `checkout`, `setup-python`, `setup-go` | MIT; MIT; MIT | Design and server CI checkout and language setup; pinned by commit |
| [Rust 1.99.0 toolchain and standard library](https://github.com/rust-lang/rust/tree/1.99.0) | MIT OR Apache-2.0; bundled components carry their own notices | Builds and tests the agent; retain installed toolchain license notices; not redistributed by this slice |
| [Python 3.13.7](https://github.com/python/cpython/blob/v3.13.7/LICENSE) | PSF-2.0 and incorporated-software terms | Fixture generation and CI build tool; not shipped; retain upstream LICENSE and incorporated-software notices if redistributed |
| [GitHub Actions `cache` v6.1.0](https://github.com/actions/cache/tree/55cc8345863c7cc4c66a329aec7e433d2d1c52a9) | MIT; bundled dependencies MIT, ISC, Apache-2.0 and 0BSD | CI registry and Cargo target directory cache, keyed by OS, architecture, toolchain and Cargo.lock; never credentials; exact-commit LICENSE, .licenses/NOTICE and all 44 .licenses/**/*.dep.yml records inspected; retain those notices with any redistribution. Records labeled "other": @actions/http-client 4.0.1 MIT, concat-map 0.0.1 MIT, @protobuf-ts/runtime 2.11.1 Apache-2.0 |
| [GitHub Actions `upload-artifact` v4.6.2](https://github.com/actions/upload-artifact/tree/ea165f8d65b6e75b540449e92b4886f43607fa02) | MIT | CI uploads failing Go fuzz corpus entries; pinned by commit; retain upstream license notices with any redistribution |
| Go 1.27.1 toolchain and standard library | BSD-3-Clause | Builds and tests the server; the standard library supplies its runtime and library code |
| Be Vietnam Pro | SIL OFL 1.1 | Outlined into the wordmark and tagline masters, and bundled as WOFF2 subsets in the console build with the OFL notice beside the files, which OFL 1.1 permits; no Reserved Font Name is declared; notice in `branding/source/OFL-BeVietnamPro.txt`; font binaries are not committed |
| ImageMagick 7 with librsvg | ImageMagick License; librsvg LGPL-2.1-or-later (verify) | Build-time renderer for `branding/scripts/build.py`; not shipped |
| Pillow | MIT-CMU (verify) | Build-time validation and ICO assembly; not shipped |
| fonttools, uharfbuzz | MIT; Apache-2.0 (verify) | Build-time outlining in `branding/scripts/outline_wordmark.py`; not shipped |
| `branding/reference/approved-concept-board.png` | AI-generated concept art; generating tool and its output terms not recorded (verify) | Visual reference only; not shipped |
