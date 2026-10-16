# CI toolchain refresh

[CI hardening Task 11](../plans/ci-hardening.md#task-11-refresh-toolchains-and-retire-the-ubuntu-2404-console-identity) promotes the targets below only after Task 10 has a green full-route `ci-required` result. This specification is staged design. The active manifests, bootstrap rules, requirements and `scripts/ci/toolchains.lock.json` retain their implemented pins until the atomic consumer change passes review and CI. [CI hardening section 8](ci-hardening.md#8-one-validator-environment-and-admitted-tools-ci-04-to-ci-07) owns admission; [licensing staging](../licensing.md#toolchain-refresh-payload-staging) owns downloaded sizes, hashes, URLs and notices.

## 1. Targets and release authority

| Tool | Implemented pin | Task 11 target | Reason and first-party authority |
|---|---|---|---|
| Go | 1.27.1 | 1.27.2 | Latest stable in [Go download metadata](https://go.dev/dl/?mode=json); patch security and correctness fixes |
| Python | 3.14.8 | Retain 3.14.8 | [Runner manifest](https://github.com/actions/python-versions/blob/main/versions-manifest.json) marks 3.15.0 stable, but the required PyYAML wheel closure is absent; section 3 owns the blocker |
| Node | 24.21.0 | 24.22.0 | Latest LTS in [release metadata](https://nodejs.org/dist/index.json), codename Krypton; 26.12.0 is Current, not LTS in that metadata or the [release schedule](https://github.com/nodejs/Release/blob/main/schedule.json) |
| pnpm | 11.18.0 | Retain 11.18.0 | [npm metadata](https://registry.npmjs.org/pnpm/latest) selects 12.11.2, but its compiled dependency closure includes additional restrictive terms; section 4 owns the blocker |
| Playwright | 1.59.1 | 1.64.1 | [npm metadata](https://registry.npmjs.org/playwright/latest) selects 1.64.1; its supported Ubuntu 26.04 mapping permits retirement of the temporary Linux identity |
| Rust | 1.99.0 | 1.99.1 | [Stable channel](https://static.rust-lang.org/dist/channel-rust-stable.toml) and [versioned manifest](https://static.rust-lang.org/dist/channel-rust-1.99.1.toml) agree; compiler and macOS linker fixes matter to the native matrix |

These are exact selected targets, not an instruction to resolve `latest` during installation. A newer upstream release requires another evidence and compatibility review. Dependency libraries outside these toolchains are not upgraded incidentally. No new vendor account, enrollment or terms acceptance is authorized.

## 2. Go, Node and Rust compatibility

Go's [patch notes](https://go.dev/doc/devel/release#go1.27.2) name security fixes in the go command, TLS, templates, HTTP, textproto and OS handling, plus compiler, linker, runtime, vet, coverage, compression and JSON fixes. Set `go 1.27.2` in both `server/go.mod` and `scripts/ci/gotestdecls/go.mod`. Add no `toolchain` directive. Keep `GOTOOLCHAIN=local` in the admitted environment: Go's [toolchain selection contract](https://go.dev/doc/toolchain) otherwise permits automatic downloads. The helper module and server must resolve the identical admitted compiler.

An initial comparison fetched eight Go source files cited by existing contracts at both tags. This is not the complete loader helper closure; section 2.1 defines its separate renewal gate. `cmd/internal/test2json/test2json.go`, `internal/runtime/gc/sizeclasses.go`, `runtime/_mkmalloc/mksizeclasses.go` and `slices/zsortanyfunc.go` are byte-identical. `net/http/server.go`, `transfer.go`, `internal/http2/server.go` and `flow.go` change. The inbound 4 KiB flow-credit threshold remains; outbound flow-control accounting, reset-stream/body-close credit refunds, HTTP/2 TLS state and HPACK updates, CONNECT handling and trailer-count limits change. Recheck event upload framing, rejection, trailers, cancellation, response deadlines and resource budgets under the new compiler. Do not mechanically relabel a source citation as compatibility proof. [Tagged HTTP/2 source](https://github.com/golang/go/tree/go1.27.2/src/net/http/internal/http2), [HTTP transfer source](https://github.com/golang/go/blob/go1.27.2/src/net/http/transfer.go).

Node's [24.22.0 changelog](https://github.com/nodejs/node/blob/v24.22.0/doc/changelogs/CHANGELOG_V24.md) adds crypto, histogram, SQLite and utility APIs and fixes runtime behavior. It lists no major-version migration. The console does not call the added APIs or the newly deprecated private `net.Server._listen2`. It runs TypeScript directly with Node, uses built-in compression for reproducibility and hashes generated assets. The implementer must rerun toolchain guards, generation, typecheck, lint, dependency/license audit, both clean builds and compression budgets. Keep Node's bundled npm unused; no global install or Corepack provisioning replaces the admitted pnpm shim.

Rust's [1.99.1 notes](https://github.com/rust-lang/rust/blob/1.99.1/RELEASES.md#version-1991-2026-10-15) fix FFI `bool` return miscompilation on x86_64, the macOS rust-lld libLLVM rpath and a missing UEFI/embedded `wcslen` symbol. The first two affect relevant native tool paths; the third names targets Ricevanta does not build. Set `agent/rust-toolchain.toml` to `1.99.1`; retain edition 2024, resolver 3 and workspace `rust-version = "1.99"`, since the minimum language version does not need a new minor. Promote all five distribution components together for each admitted platform, including rustfmt 1.10.0 and clippy 0.1.99 from the manifest. The manifest labels Cargo 0.100.0 internally; the downloaded Linux executable reports `cargo 1.99.1`, which native admission must assert separately rather than compare the internal metadata string with the archive version. A source-cache key changes with the compiler; compiled output stays fresh.

The Linux release runner identities are `linux-x64-ubuntu26.04` and release-only `linux-arm64-ubuntu26.04`. No Ubuntu 22.04 runner or lock row is introduced. [Linux build root](linux-build-root.md) independently owns glibc 2.34, CPU and symbol ceilings, image admission and distribution probes. A Rust patch does not qualify its binaries inside that root: release Task 4A must run the exact selected compiler there. The Go release recipe retains `CGO_ENABLED=0`.

### 2.1. Loader source and native proof renewal

A compiler change invalidates the applicability of compiler-bound loader evidence until renewed. [Gate A](../../server/internal/extensions/loader/GATE_A_REVIEW.md), [Gate B](../../server/internal/extensions/loader/GATE_B_REVIEW.md), the [complete allocation audit](../../server/internal/extensions/loader/ALLOCATION_AUDIT.md) and [parser allocation audit](../../server/internal/extensions/loader/internal/yamltokens/ALLOCATION_AUDIT.md) bind source bounds, fixed reserves, compiled layouts, escapes, caches and linked stacks to Go 1.27.1. Their existing reports and binary hashes remain identified with that compiler and source. Do not relabel them as Go 1.27.2 evidence. [The loader gate contract](extension-loader.md) requires independent source and measurement review; passing CI receipts or design approval cannot replace it.

The implementer must build a source inventory from both audits, `tree.go`, `internal/yamltokens/resolve.go`, the actual loader and manifest compiler inputs, and every reached standard-library and compression helper. Compare the exact Go tags across that closure, including helpers without an explicit version string. Trace success and rejecting paths through YAML growth and scalar resolution; allocator, map, slice and interface conversion rules; archive/compression; JSON/DSSE; reflection and descriptor caches; formatter, regexp, URL and pool helpers; and stack/runtime accounting. Review unchanged source under the new compiler too. An unchanged source hash does not establish identical escapes, layouts or linkage.

Two fetched changes demonstrate why the initial eight-file comparison is insufficient:

| Go 1.27.2 source | Verified change | Required implication trace |
|---|---|---|
| [runtime/iface.go](https://github.com/golang/go/blob/go1.27.2/src/runtime/iface.go) | `itab` insertion deduplicates by interface/type pair instead of table-entry pointer identity; SHA-256 `9c8005e792d0363d3b027975af8f07f2ea2f8d591fccfcb1cd117b29d3e2c8b3` | Recheck scalar/slice interface boxing and helper charges against the changed file. Establish whether the insertion branch is reached during startup or the measured candidate, and renew the one-module/no-plugin linkage premise from each new binary. The changed deduplication alone proves neither a larger allocation nor an unchanged bound. |
| [encoding/json/v2/arshal_default.go](https://github.com/golang/go/blob/go1.27.2/src/encoding/json/v2/arshal_default.go) | Nonfinite-float marshal errors gain a legacy-semantics `ValueError` wrapper; failed float parsing no longer sets the destination; SHA-256 `88fafb85abe4475b504e8216d77982289547c7ee941e6a2a8a2f8262a478f0d8` | Re-establish the fields-before-encoding type domain and UseNumber token path, including rejecting prefixes and charged unused unmarshal closures. The current audit admits string, bool, json.Number, map[string]any, []any and any, not floating-point values; prove the changed float branches remain unreachable before retaining their exclusion. Recompute the six-type arshaler, reflection and cold-cache bounds from new source and binaries. |

Before atomic Go promotion, the implementer must produce and hand off all of the following:

1. Renewed Gate A and Gate B source audits with exact tagged helper citations, compiler/source identities and justification for every retained bound or unreachable branch. Preserve the YAML 64 MiB allocation, 1,000,000-object and 8 MiB stack limits, the complete `4*C + 4*T + 128 MiB` envelope, fixed-reserve accounting and all success/rejection corpus coverage. No larger allowance or reduced corpus resolves a compiler migration failure.
2. Fresh native diagnostic evidence on Linux x64, macOS ARM64 and Windows x64 under Task 10's runner identities and exact Go 1.27.2, actual dependency versions, build flags, experiments and linkage. Bind both loader and manifest test binaries per host to repository and selected helper-source hashes. Retain `identity.json`, `manifest-identity.json`, `compiler-summary.json`, `compiler-frames.jsonl`, `escape-decisions.txt` and both binary hashes/artifacts. Renew parser callback/defer/fixed-reserve escape analysis; reached Huffman descriptors, DSSE surrogate conversions, manifest option/literal escapes and charged result copies, and loader zero-copy digest conversion. Re-extract native descriptor counts/layouts, reflection/arshaler/pointer caches, module identities, linked frame/argument/pcsp data, recursive multiplicities, stack guards and span bounds. Derive exclusions from the new linked closure; do not copy an old allowlist or substitute sampled stacks for source/linked bounds.
3. Fresh Gate A qualification before dependent Gate B qualification on all three hosts. Preserve the complete case inventory, fifty fresh-child repetitions for every Gate A repetition family, runtime controls, same-call YAML ledgers and Gate B combined/assembled/direct-full comparisons plus serial/two-call ownership probes. Keep raw counters, helper activity and failed cases; no warmup, subtraction, retries or minimum selection. Preserve separate native race and positive-execution fuzz gates. Source/native diagnostics do not replace final-integration full-route qualification or its receipts.
4. Independent `code_reviewer` confirmation of the exact source and all three native compiler/linkage/escape/cache/stack derivations, plus independent qualification confirmation of both gates against their raw records and tested integration identity. The coordinator records the review artifacts and tested SHA/run URLs and blocks landing until both confirmations and green `ci-required` exist. A failure goes to the troubleshooter; a proposed invariant, bound or mechanism change returns to the designer and independent design reviewer. Design completion requires this explicit handoff, not pre-existing Go 1.27.2 native proof.

The [migration ownership list](ci-toolchain-migration.md#11-loader-renewal-ownership-and-handoff) names the affected audit, source and qualification paths. All resulting audit/document changes land with the Go consumer and lock promotion. This requirement preserves existing loader security bounds rather than adding an endpoint mechanism.

## 3. Python wheel closure and retained pin

Python 3.15.0 has ordinary, GIL-enabled runner payloads for Ubuntu 26.04 x64/Arm64, Windows x64 and macOS ARM64. Payload availability does not make the validator installable. The hash-locked closure in `.github/requirements-design.txt` requires binary wheels only. PyPI's release JSON and downloaded wheel metadata establish this table; [wheel staging](../licensing.md#validator-wheel-staging) records every file, size and digest.

| Locked package | Version | CPython 3.14 on Linux x64, Windows x64, macOS ARM64 | CPython 3.15 on those hosts | Linux ARM64 3.14 / 3.15 |
|---|---|---|---|---|
| [jsonschema](https://pypi.org/pypi/jsonschema/4.25.1/json) | 4.25.1 | Universal wheel | Same wheel | Same / same |
| [PyYAML](https://pypi.org/pypi/PyYAML/6.0.3/json) | 6.0.3 | Three cp314 wheels | No cp315, compatible abi3 or universal wheel | cp314 wheel exists / absent |
| [rfc3339-validator](https://pypi.org/pypi/rfc3339-validator/0.1.4/json) | 0.1.4 | Universal wheel | Same wheel | Same / same |
| [six](https://pypi.org/pypi/six/1.17.0/json) | 1.17.0 | Universal wheel | Same wheel | Same / same |
| [attrs](https://pypi.org/pypi/attrs/26.1.0/json) | 26.1.0 | Universal wheel | Same wheel | Same / same |
| [jsonschema-specifications](https://pypi.org/pypi/jsonschema-specifications/2025.9.1/json) | 2025.9.1 | Universal wheel | Same wheel | Same / same |
| [referencing](https://pypi.org/pypi/referencing/0.37.0/json) | 0.37.0 | Universal wheel | Same wheel | Same / same |
| [rpds-py](https://pypi.org/pypi/rpds-py/2026.6.3/json) | 2026.6.3 | Three cp314 wheels | Three cp315 wheels exist, not hash-admitted | Both exist, not hash-admitted |
| [typing-extensions](https://pypi.org/pypi/typing-extensions/4.16.0/json) | 4.16.0 | Universal wheel | Same wheel | Same / same |

All selected wheels' `Requires-Python` bounds admit 3.14 and 3.15. This is metadata compatibility, not a passing interpreter run. Mandatory `Requires-Dist` edges remain jsonschema to attrs/specifications/referencing/rpds, specifications to referencing, referencing to attrs/rpds, and rfc3339-validator to six. Referencing's typing-extensions edge applies below Python 3.13; the explicit locked typing-extensions package remains installed. No `jsonschema[format]` extra is selected, so its optional GPL-bearing format closure is not admitted.

Retain Python 3.14.8 and the active requirements unchanged. Release Task 2 may add the two staged cp314 Linux ARM64 hashes only together with its host support and native closure proof. The cp315 rpds wheels are research evidence only. Never substitute a cp314 wheel on 3.15, build an sdist, use the runner's package, loosen hashes or drop PyYAML to make the upgrade pass. Move Python only when PyYAML publishes compatible wheels on all consumed hosts and the complete closure, notices, bootstrap and validators pass a reviewed atomic migration.

The [3.15 porting and removal notes](https://docs.python.org/3.15/whatsnew/3.15.html#porting-to-python-3-15) were checked against repository Python use. The migration checklist covers:

- Removed legacy loader `load_module`, `pathlib.is_reserved`, `glob0/glob1`, CGI handler, `sre_*`, `SetPointerType`, `java_ver`, `co_lnotab`, wave markers, obsolete typing constructors/decorator and sysconfig `check_home`; stricter AST constructors and yearless `strptime`. No matching production helper use was found. Check dependency code too once wheels exist.
- SQLite positional arguments, resource-limit sentinels and `mmap.resize` are not used by the current CI helpers. `Path.is_relative_to` and single-path `relative_to` remain valid; do not confuse them with removed `is_reserved`.
- `urlsafe_b64decode` accepts missing padding by default; strict decoding must keep explicit validation. The CI helpers do not call that API. `assertWarns` no longer hides unrelated warnings, and file-backed `iterparse` needs closing; run the complete validator and helper suite with the pinned interpreter.
- Keep ordinary CPython rather than free-threaded payloads. Review 3.15's Windows installer shape, registration purge version, macOS framework version, Linux libpython/RUNPATH relocation, bundled pip, and `compression.zstd` support used by build-root admission. Updating only `.github/python-version` is forbidden.

## 4. pnpm 12 blocker and migration analysis

The [12.11.2 package metadata](https://registry.npmjs.org/pnpm/12.11.2) replaces the JavaScript package with a launcher plus exact optional platform executables such as `@pnpm/exe.linux-x64` and `@pnpm/exe.darwin-arm64`. The current bootstrap copies `bin/pnpm.cjs` and runs it on admitted Node; that is not a pnpm 12 installer. A future move needs separately locked executable payloads, a complete native dependency/license inventory and a new shim/admission contract. The package's top-level MIT label is insufficient.

The pinned source chain is [pnpm-cli](https://github.com/pnpm/pnpm/blob/v12.11.2/pnpm/crates/cli/Cargo.toml) to [pnpm-config](https://github.com/pnpm/pnpm/blob/v12.11.2/pnpm/crates/config/Cargo.toml) to [pnpr-registry](https://github.com/pnpm/pnpm/blob/v12.11.2/pnpr/crates/registry/Cargo.toml), then pnpr-error and pnpr-package-name. These are unconditional dependencies, not merely a disabled remote-cache option. The three pnpr manifests point to [pnpr/LICENSE.md](https://github.com/pnpm/pnpm/blob/v12.11.2/pnpr/LICENSE.md), PolyForm Shield 1.0.0 with acceptance and noncompetition conditions. The [workspace manifest](https://github.com/pnpm/pnpm/blob/v12.11.2/Cargo.toml) and [Cargo lock](https://github.com/pnpm/pnpm/blob/v12.11.2/Cargo.lock) confirm the local package identities. This slice accepts no additional terms and runs no pnpm 12 binary. Retain 11.18.0. Move only when a reviewed upstream payload closure satisfies project policy and its new admission path passes all controls. A newer 11.x release is not silently substituted.

The [12.0 release notes](https://github.com/pnpm/pnpm/releases/tag/v12.0.0) and [12.11.2 notes](https://github.com/pnpm/pnpm/releases/tag/v12.11.2) establish these checks for any future migration:

| Change | Repository consequence |
|---|---|
| Unknown workspace settings can fail under a satisfied package-manager pin | Verify all seven top-level settings/groups in `console/pnpm-workspace.yaml`; preserve strict engines/peers, ignored scripts, exact saves, dependency verification and OS/CPU/libc coverage |
| Canonical peer-cycle resolution can re-key lock entries | Frozen existing lockfiles remain supported upstream; regenerate only with the selected admitted version when changing dependencies, review the full diff, then require a clean frozen reinstall |
| Linux auto import tries hardlinks before clones | No restored compiled output; preserve integrity checks and fresh `node_modules`; do not infer reproducibility from a shared store |
| Strict engines reject incompatible regular descendants inside optional trees | Exercise every supported architecture selected by the workspace, not only the local host |
| `--frozen-lockfile false` is rejected | The workflows use the standalone `--frozen-lockfile` form; keep that spelling |
| Hosted Git dependencies canonicalize to HTTPS | The console lock has registry packages; refuse unexpected Git/URL additions rather than add credentials or global rewrites |
| Managed runtimes/package managers, global shims and remote side-effects cache | Keep every automatic provisioning/cache path disabled or unreachable; prove a mismatched `packageManager` fails before download or execution. Never add a pnpr account or restore build output |

The existing exact `packageManager` and `engines.pnpm` stay at 11.18.0. Playwright's metadata names no newer pnpm requirement; regenerate its entries with the retained admitted pnpm, preserve all resolution integrity values, and require frozen reinstall and dependency audit to prove lockfile compatibility. Do not convert the console to pnpm 12 merely to refresh Playwright.

## 5. Browser target and host closure

Pin `@playwright/test`, `playwright` and `playwright-core` together to 1.64.1. Their downloaded package metadata forms exactly test to playwright to core, with no optional package dependency. Registry SHA-512 integrity and each package's Apache-2.0 LICENSE and NOTICE were checked. Existing Vitest/axe integration versions stay; their peer/API compatibility remains a required implementation test.

| Leaf | Host mapping | Payload and version | Revision |
|---|---|---|---|
| Linux component and CSP Chromium | Ubuntu 26.04 x64 | Chrome for Testing headless shell 156.0.8078.4 | 1248 |
| Linux CSP Firefox | Ubuntu 26.04 x64 | Firefox 157.0, `firefox-ubuntu-24.04.zip` | 1555 |
| macOS CSP WebKit | macOS 26 ARM64 | WebKit 27.2, `webkit-mac-26-arm64.zip` | 2370 |
| Linux video helper | Ubuntu 26.04 x64 | FFmpeg n7.0.1, `ffmpeg-linux.zip` | 1013 |
| macOS video helper | macOS 26 ARM64 | FFmpeg n7.0.1, `ffmpeg-mac-arm64.zip` | 1013 |

The pinned [host mapping](https://github.com/microsoft/playwright/blob/v1.64.1/packages/utils/hostPlatform.ts), [browser manifest](https://github.com/microsoft/playwright/blob/v1.64.1/packages/playwright-core/browsers.json) and [registry](https://github.com/microsoft/playwright/blob/v1.64.1/packages/playwright-core/src/server/registry/index.ts) explicitly support Ubuntu 26.04 and macOS 26. The Firefox filename is the registry's explicit Ubuntu 26.04 mapping, not unsupported-host fallback. No host override is permitted. No Linux WebKit, Windows browser, full Chrome bundle, winldd or Android payload is added.

[Native dependency declarations](https://github.com/microsoft/playwright/blob/v1.64.1/packages/playwright-core/src/server/registry/nativeDeps.ts) include the Ubuntu 26.04 t64 libraries and Firefox's `libavcodec62`. Bootstrap must inspect the actual ELF dependencies and dynamic loads before launching, and cold native CI must prove fonts and codecs needed by the tests. A missing library blocks Task 11; no `apt`, `playwright install --with-deps` or weaker test substitutes. WebKit's inspected Mach-O load commands use only system frameworks, `/usr/lib` and its bundled ANGLE/WebRTC dylibs; the new macOS FFmpeg has only system loads. Native execution and the existing symlink/load-path rejection controls remain mandatory.

The [1.60 through 1.64 release notes](https://github.com/microsoft/playwright/blob/v1.64.1/docs/src/release-notes-js.md) require these repository-specific checks:

- Removed `Locator.ariaRef`, binding `handle`, connection `logger`, and context `videosPath`/`videoSize` options are not used. `exposeBinding` occurrences in negative controls forbid instrumentation, not a dependency on the removed option. No JSX test files or experimental Playwright component-test package are used; Vitest owns components.
- Device descriptors now forward `screen`. Preserve existing viewport semantics by adding `screen: undefined` to each descriptor-based project, and verify component/CSP coverage. Hidden iframe descendants now count as hidden; the CSP iframe negative control must still prove denial. Keep `workers: 1` and retries zero.
- Snapshot-update `missing` can now pass. Authoritative CI must not add update-snapshot options; keep missing evidence fatal. New project defaults must not omit an engine: explicitly select the exact per-leaf project sets and reject missing, extra or skipped projects.
- Video uses VP9 and FFmpeg revision 1013. Preserve same-run reports, trace/screenshot retention and CSP negative controls. Do not loosen a browser assertion just because an engine changed.

The Linux leaf builds once and the macOS leaf verifies and tests the same `dist/` tree digest. After every consumer migrates, remove only the Ubuntu 24.04 lock identity `linux-x64` and its bootstrap leaf. Stable test target suffixes such as `agent:linux-x64`, report names and product support names are not lock identities and remain unchanged. Three ordinary bootstrap platforms remain; release Task 2 adds its separate Arm64 platform.

## 6. Atomic implementation and checks

[Task 11](../plans/ci-hardening.md#task-11-refresh-toolchains-and-retire-the-ubuntu-2404-console-identity) owns one implementation change after independent design approval. Implementing paths are explicit in [the migration file list](ci-toolchain-migration.md). Do not promote a row before its consumer understands it. Re-download staged bytes in an empty directory, compare size/hash and upstream digest/integrity when published, and fail on any difference. The Python runner builds and browser CDN publish no independent digest; review records measured SHA-256, not a fabricated vendor checksum.

Promote Go, Node, Rust, browser rows and package pins with bootstrap version checks, schemas, host maps, fixtures and workflows in the same change. The final production lock has no unused Ubuntu 24.04 rows. If release Arm64 is already admitted, update its Go/Rust rows in that change and run its native proof; otherwise leave them in licensing staging for release Task 2. Release Task 2 must consume the refreshed version family and never install a different Go or Rust patch from x64. Its cp314 ARM64 wheel additions land only with the Arm64 consumer.

Local checks from the repository root: CI schema and examples with `Draft202012Validator`; `python -B scripts/ci/validate_contracts.py`; focused bootstrap, policy, route, inventory, receipt and selected-run unit tests; `python -B scripts/ci/check_policy.py --root .`; `actionlint .github/workflows/*.yml`; design validators; and `git diff --check`. From `console/`, run frozen install, dependency/license audit, typecheck, lint, format check and focused unit tests. Run light Go formatting/vet and Rust formatting/clippy under the admitted versions. These are implementation requirements, not design-stage claims of passing native code.

Go promotion additionally requires every source, native and independent-review prerequisite in section 2.1. CI must prove cold installs and corruption controls on every consumed host; exact versions and component revisions; strict pnpm mismatch refusal; all native server/agent gates, race/fuzz/property budgets, Go test2json proof, interop, loader/OCSF/cost-model gates; all three browser reports, CSP controls, unchanged budgets, two clean builds and equal dist digests; full-route receipt equality and green `ci-required`. Browser, race, extended property and matrix runs stay in CI. Release qualification also runs the Rust toolchain in each pinned build root and preserves ABI/distribution gates.

## 7. Security, benefits and limits

Admission starts at the tested checkout: a reviewed exact lock row chooses an HTTPS URL, byte count and SHA-256; the bootstrap verifies the complete download before bounded extraction, validates host/version/load paths, and exports only the admitted roots. Children run with the existing closed environment and no automatic runtime/tool downloads. Each leaf proves execution in a same-run receipt; the aggregate requires the full expected set for the integration commit. Upstream checksums aid review but never replace repository digest authority. A compromised candidate can execute code in its disposable CI job; these checks are not a sandbox for arbitrary candidate code.

| Attacker | Result in this refresh |
|---|---|
| Stolen enrollment token | No CI admission or publication credential; endpoint enrollment authority remains governed by its separate protocol |
| Compromised agent host | Cannot write reviewed CI pins or mint aggregate receipts; local endpoint compromise gains no signing keys from these test-only payloads |
| Compromised console session | No toolchain or workflow mutation API is introduced; existing server authorization still applies |
| Rogue extension publisher | No extension executes in toolchain admission and publisher signatures cannot authorize a lock change |
| Network position between agent and server | No update authority is added; on the separate CI download path, altered bytes fail size/hash checks and withholding bytes can deny service |
| Database writer without signing keys | Application database state has no role in CI pins, component versions or release signatures |
| Server restored from backup | Cannot roll CI back or admit unsigned CI archives as agent updates; existing recovery fences and signed-release floors remain required |

Benefits: patch fixes reach every compiler consumer, supported browser hosts converge on Ubuntu 26.04, and one exact evidence set prevents partial pin updates. Trade-offs: cold downloads and a full native route cost time; browser assertions and source-specific Go contracts need renewed evidence; Python and pnpm stay pinned while upstream blockers exist. Dependencies: anonymous first-party downloads, existing accepted CI browser terms, Task 10's proven admission, independent review and native runner availability. Limits: package metadata and archive inspection prove neither native execution nor full endpoint/browser qualification. Alternatives rejected: unsupported Python wheels, pnpm 12 under unapproved restrictive terms, silent upgrade to another pnpm branch, Node Current, automatic latest resolution, browser host overrides, lock-only promotion and using the runner image as a Linux ABI floor.

## 8. Open evidence questions

- Do all selected browser payloads and dynamically loaded codecs pass cold admission on Ubuntu 26.04 and macOS 26 without added packages?
- Do the exact Rust 1.99.1 components run inside both pinned Linux build roots and preserve every symbol and distribution probe gate?
- Do renewed Gate A and Gate B source proofs and all three native compiler/linkage/escape/cache/stack derivations retain the existing bounds under Go 1.27.2, with independent source/native and qualification confirmation?
- Do the full native route, Go HTTP/upload regressions, Vitest integration and CSP controls retain their budgets and exact execution evidence under the selected targets?

Task 11 and release Task 4A own these checks. No unresolved result is labeled passed or converted to an unsupported product feature.
