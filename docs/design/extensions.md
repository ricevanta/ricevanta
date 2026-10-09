# Extension design

How third parties extend Ricevanta: the package and its manifest, trust and grants, the five component kinds, console modules, service connectors, browser adapters, and distribution and compatibility. The scope is in `../blueprint.md` section 3.9; decisions EXT-01 to EXT-07 in `../decisions.md`. Process topology is in `../architecture.md`, the agent execution contract in `../specs/extension-agent-runtime.md`, and the compiled bundle in `../specs/policy-envelope.md` section 6. Claims marked "verify" rest on vendor or third-party sources or were not confirmed from a first-party page.

One rule shapes everything below: no third-party code runs inside `ricevanta-agent`, `ricevanta-server`, the sensors, the Windows driver, the macOS system extensions or the browser extension's own code. Code enters through three doors only: the `ricevanta-ext` helper (section 4), a sandboxed console iframe (section 5) and a connector process the operator deploys (section 6). Everything else in a package is data that the server validates against a JSON Schema.

## 1. Package and manifest

An extension is one zstd-compressed tar archive holding `extension.yaml`, its DSSE (Dead Simple Signing Envelope) envelope `envelope.json` and the component files. The manifest schema lives in `schemas/extension/v1alpha1/`.

| Field | Content |
|---|---|
| `apiVersion`, `kind` | `ricevanta.io/v1alpha1`, `Extension` |
| `metadata.id` | Reverse-DNS identifier, unique per publisher; `io.ricevanta.*` is reserved for first-party extensions (`../project.md`) |
| `metadata.version` | SemVer |
| `metadata.publisher` | Display name and key fingerprint (SHA-256 of the Ed25519 public key) |
| `metadata.license` | SPDX (Software Package Data Exchange) license expression, required |
| `metadata.homepage`, `metadata.source` | URLs; the source URL is required |
| `spec.requires` | Interface version per kind the package uses (section 8) |
| `spec.components[]` | Name, kind, interface, files and requested capabilities per component (section 2.3) |
| `files[]` | Path, SHA-256 and size of every archive member except `extension.yaml` and `envelope.json` |

Archive rules match the bundle reader of `../specs/policy-envelope.md` section 6: no links, no duplicate or non-canonical paths, no member outside the listing, declared sizes enforced, and a total decompressed limit of 64 MB by default, configurable per server.

Example:

```yaml
apiVersion: ricevanta.io/v1alpha1
kind: Extension
metadata:
  id: com.example.vn-banking
  version: 1.2.0
  publisher:
    name: Example Security
    key: sha256:9f2c41d0...e1
  license: Apache-2.0
  homepage: https://example.com/ricevanta
  source: https://github.com/example/ricevanta-vn-banking
spec:
  requires:
    content: ext.ricevanta.io/content/v1
    agent-module: ricevanta:agent/classifier@1.0.0
    console-module: ext.ricevanta.io/console-module/v1
  components:
    - name: bank-accounts
      kind: agent-module
      interface: ricevanta:agent/classifier@1.0.0
      file: modules/bank-accounts.wasm
      capabilities:
        memory_pages: 256          # 16 MiB
        fuel_per_call: 50000000
        deadline_ms: 200
    - name: sbv-categories
      kind: content
      format: classification
      file: content/sbv-categories.yaml
    - name: findings-panel
      kind: console-module
      entry: console/index.html
      slots: [alert-panel]
      capabilities:
        scopes: [dlp.matches.read]
files:
  - {path: modules/bank-accounts.wasm, sha256: "3b7a...", size: 412331}
  - {path: content/sbv-categories.yaml, sha256: "c01e...", size: 5120}
  - {path: console/index.html, sha256: "77d4...", size: 2048}
```

## 2. Trust

### 2.1 Keys and the trust list

A publisher signs the exact bytes of `extension.yaml` in a DSSE envelope with payload type `application/vnd.ricevanta.extension-manifest+yaml` and an Ed25519 key; the envelope rules are those of `../specs/policy-envelope.md` section 7, and `keyid` is a hint only. Because the manifest carries the hash of every file, one signature covers the package.

The trust list is server state in the `extensions` module. Each entry holds an Ed25519 public key and its fingerprint, a display name, the id prefixes the key may publish under, and revocations. The server ships one entry, the project's extension publisher key for `io.ricevanta.`, which signs first-party extensions and the index (section 8); the operator can remove it. A package whose key is absent, or whose id falls outside the key's prefixes, is refused, and the console shows the fingerprint and name so the operator can compare them out of band and import the key.

A publisher may add a Sigstore bundle or SLSA (Supply-chain Levels for Software Artifacts) provenance under `attestations/`. The server records and displays them and does not require them.

### 2.2 Install flow

1. The package arrives by console upload, `/api/v1`, GitOps or the index.
2. The bounded reader opens the archive; `extension.yaml` validates against the manifest schema.
3. The signature verifies against the trust list, and the id matches the key's prefixes.
4. Every file hash and size matches `files[]`.
5. Every interface version in `spec.requires` is one the server serves (section 8).
6. Each component validates against its kind: content against its existing schema, an adapter against the adapter schema and selected browser registration (section 7), a console module's entry and slots, a connector's contract names. The server cannot compile WebAssembly, because Go cannot host `wasmtime` without cgo; it checks the component binary's size and declared interface, and the agent's linker enforces imports (`../specs/extension-agent-runtime.md` section 1).
7. An approval request shows the requested capabilities. The approver grants all or a subset; the server stores the granted set.
8. The package goes to the blob store with its SHA-256 in the install record, and enabling assigns targets: device groups for agent-bound components, the console for console modules, `jobs` for connectors.

Install, upgrade, enable, grants, browser-registration creation or change, and trust-list changes other than adding a revocation are protected actions by default (BE-02), like rule-pack publish. Disabling, uninstalling or revoking a component that a compiled `dlp` or `edr` policy or a qualified browser adapter depends on is a weakening change under `../specs/policy-envelope.md` section 2.3 and is protected too; disabling or uninstalling any other component is not. An upgrade that requests capabilities beyond the current grant needs a new approval.

First-party components shipped in the server image (section 8.1) are installed and enabled at first start under the project key, with grants the project fixes per release. A later server release upgrades them without approval unless a grant widens. Disabling them follows the weakening rule above.

### 2.3 Capabilities and grants

| Kind | Requested in the manifest | Enforced by |
|---|---|---|
| `content` | Formats (`RulePack` formats, `classification`, `baseline`, `mdm-template`, `report`) | Server validators of each format |
| `browser-adapter` | One browser registration; OS policy names and native-host use within that registration | Server validation, signed component grant generation, browser registration generation and agent runtime validation (section 7.2) |
| `agent-module` | Interface, memory pages, fuel, deadline; collector broker limits; responder action, entity, step and byte limits. Class concurrency, broker workers and `cleanup_ms` are bundle policy values, not grants | Signed component grant generation, `ricevanta-ext`, the core broker and the durable plan journal (`../specs/extension-agent-runtime.md`) |
| `console-module` | Slots; API scopes as BE-02 permission names | Server-side bridge binding, current grant and current operator permissions on every dispatch |
| `service-connector` | Contract and version; the outbound destinations the connector itself reaches | `jobs` calls only the granted contracts; outbound destinations are displayed and left to the operator's network policy |

The stored grant, never the request, is what reaches bundles, the bridge and `jobs`. Every installed component has its own monotonically increasing `grant_generation`. The `extensions` module increments it on every grant write, including replacement, reduction and a write whose capability values equal an earlier grant. A generation is never reused. Every agent-bound component carries its current generation in the signed bundle; console mount bindings and connector calls bind the same current value. Browser `registration_generation` is a separate counter and cannot substitute for the component grant generation. A later equal grant never revives a stale broker handle, command, pending responder step or console binding.

### 2.4 Delivery to agents

Agents never verify publisher keys. The `policy` module compiles every enabled agent-bound component (content, adapters, WebAssembly modules) into the bundles of its target scopes, listed by hash with its granted capabilities and component `grant_generation` (`../specs/policy-envelope.md` section 6). The blob store is not a trust anchor: `policy` verifies each artifact's SHA-256 against the install record before it places it in a bundle, and `api` does the same before it serves a console module asset. A mismatch refuses the artifact and raises an audit event. The agent verifies the bundle as it does today, against the organization's policy signing key and its per-device assignment (POL-02). The agent trust model stays unchanged, and publisher-key rotation stays a server matter.

### 2.5 Revocation

The trust list revokes a key, an id or one id and version. Removing a revocation is protected, because it re-enables code. Revoking an id or version that an enforcing policy or a qualified adapter depends on is a weakening change and protected (section 2.2). Revoking a publisher key is never held for approval, so a compromised key can be cut off at once; the compiler raises an alert for every enforcing `dlp` or `edr` policy the revocation weakens. A revocation removes agent components from the next bundle compile, stops serving console assets and connector calls at once, and invalidates live console mount bindings in the same server transaction. Queued bridge requests are cancelled; an authenticated notification closes the frame, while the server rejects every later dispatch even if that notification is lost (section 5.2).

The signed index may revoke only packages the project key signed, and the server applies those revocations when the index is enabled. For other listed packages the index may carry a warning, which the console shows; it never revokes them.

### 2.6 Audit and attribution

Every extension action is an audit event. Events that an extension component causes, such as a match by a classifier module, an enrichment, or an API call through a console module, carry `metadata.extension_origin` with descriptive id and version plus immutable package digest, component, component digest and grant generation (`../specs/ocsf-profile.md` section 2), so a SIEM can filter them. The name keeps it apart from OCSF's own `metadata.extensions`, which lists schema extensions.

## 3. Kinds

### 3.1 `content`

Interface `ext.ricevanta.io/content/v1`. Rule packs in the existing `RulePack` formats become `RulePack` resources owned by the extension and follow the rule-pack rules, including license records and publish approval (`../specs/policy-envelope.md` section 5). Classification categories carry regulatory references (DLP-03). Baselines and MDM configuration templates become `Baseline` resources. Report templates are declarative definitions over the report API with no script. Host: the server's existing pipelines, then the agent through bundles. Limit: content can do only what its format can express.

### 3.2 `browser-adapter`

Interface `ext.ricevanta.io/browser-adapter/v1`. Data describing how one browser product is managed on each OS. Host: the agent for install, preflight and gate selection; the server for the console and qualification status. Detail in section 7.

### 3.3 `agent-module`

A WebAssembly component implementing one capability interface. Host: `ricevanta-ext`. Limits: no network, no raw socket and no process spawn.

| Interface | Input | Output | Caller | On a decision path |
|---|---|---|---|---|
| `ricevanta:agent/classifier@1.0.0` | Bytes or text, in chunks | Matches with byte offsets, rule id and confidence | `dlp` | Yes |
| `ricevanta:agent/parser@1.0.0` | Bytes of one document format the built-in scanner does not extract, for the MIME types the policy assigns to it | Text with an offset map | `dlp`, before classification | Yes |
| `ricevanta:agent/collector@1.0.0` | Query parameters; bounded host-broker reads | Rows matching the declared row schema | `mdm` inventory and compliance | No |
| `ricevanta:agent/responder@1.0.0` | Command parameters | A plan: an ordered list of calls to allow-listed actions | `edr` under a signed command | No |

Detail in `../specs/extension-agent-runtime.md`.

### 3.4 `console-module`

Interface `ext.ricevanta.io/console-module/v1` and the bridge schema version. A UI bundle for console slots: a navigation entry with its own page, a device page tab, an alert or finding panel, a dashboard panel and a settings page. Host: the browser, in a sandboxed iframe. Limits: no network, no console DOM, no session. Detail in section 5.

### 3.5 `service-connector`

Interface `ext.ricevanta.io/<contract>/v1` per contract. A process the operator deploys in its own container, Compose service or Helm deployment. The package carries the deployment descriptor (image reference with digest, Compose and Helm examples, configuration schema); the server never runs connector code. Host: the operator's infrastructure. Limits: reachable only through its contract. Detail in section 6.

## 4. Agent runtime: `ricevanta-ext`

`ricevanta-ext` runs `wasm32-wasip2` components in separately replaceable DLP and batch instances of one reduced-privilege Wasmtime binary. Fresh stores, granted WIT worlds, component grant generations, fuel, memory limits and an end-to-end monotonic deadline isolate each call. Separate process, executor, broker-worker and memory capacity keeps batch timeouts from killing or starving DLP calls. The core exposes no raw filesystem preopens. A bounded broker checks every collector operation and opens only singly linked approved regular files under core privilege. Responder modules return a fully validated plan that the core persists before executing existing response actions.

The complete runtime, broker, deadline, watchdog, durable responder plan and recovery contract is in `../specs/extension-agent-runtime.md`. Operator-authored shell and PowerShell scripts remain signed commands and MDM software actions; they are not extensions.

## 5. Console modules

### 5.1 Isolation

The console renders a module as `<iframe sandbox="allow-scripts" src="/ext/<id>/<version>/<entry>">` without `allow-same-origin`, `allow-popups`, `allow-forms` or any top-navigation token. Combining `allow-scripts` with `allow-same-origin` on same-origin content would let the frame remove its own sandbox (MDN), so the module's origin is opaque: no cookies, no storage of the console origin, no console DOM.

The `api` role serves module assets from the blob store under `/ext/<id>/<version>/` with this response header, so the document stays opaque-origin even when someone opens its URL as a top-level page (verify the header's effect on a top-level navigation in Safari):

```
Content-Security-Policy: sandbox allow-scripts; default-src 'none';
  script-src https://<console-host>/ext/<id>/<version>/;
  style-src https://<console-host>/ext/<id>/<version>/;
  img-src https://<console-host>/ext/<id>/<version>/ data:;
  font-src https://<console-host>/ext/<id>/<version>/;
  connect-src 'none'; form-action 'none'; base-uri 'none';
  frame-ancestors https://<console-host>
```

Sources name the console host and path explicitly rather than `'self'`, because `'self'` matching in an opaque-origin document is not settled (verify). `connect-src 'none'` leaves the module no network of its own. The console document's own policy carries `frame-src https://<console-host>/ext/`, so a module frame that navigates itself can load only module paths (verify that `frame-src` governs navigations of an existing frame in every qualified browser). Assets need no credentials and a revoked or disabled module's path returns 404. Asset refusal prevents a new load; it is not the revocation boundary for an existing `MessagePort`.

### 5.2 Bridge

The bridge messages are defined in `schemas/console-bridge/v1/`. The module posts `ready` to the parent with the exact console origin as `targetOrigin`. The host accepts one `ready` per mount, and only when `event.source` is that frame's window and `event.origin` is `"null"`, then replies with one `MessagePort` of a `MessageChannel`. That reply uses `targetOrigin` `"*"`, because a sender cannot name an opaque origin (verify against the HTML specification); every later message runs over the private port. The host closes the port and unmounts the frame on any second `load` event, so a frame that navigates away loses the bridge.

| Message | Direction | Content |
|---|---|---|
| `ready` | Module to host | Bridge schema version |
| `init` | Host to module | Theme tokens, `vue-i18n` locale, slot, slot context (device id, alert id), operator display name, granted scopes |
| `api.request`, `api.response` | Both | OpenAPI operation id and parameters; status and body |
| `approval.pending` | Host to module | A protected action became an approval request (BE-02) |
| `resize`, `navigate`, `notify` | Module to host | Frame height; a console route from the allow list; a toast |

Before it creates the port, the host asks the server for a mount binding under `/api/v1/extension-bridge/bindings`. The server derives the enabled install, immutable package digest, component, grant generation, slot and operator session from authoritative state. It returns an opaque binding id tied to that session and mount. The browser cannot choose or rewrite the extension identity. The host keeps the binding id outside the frame and adds it when forwarding `api.request` to `/api/v1/extension-bridge/bindings/<binding>/dispatch`.

On every dispatch the server checks that the binding is live, the exact package digest and component remain enabled and unrevoked, the current grant generation matches, the operation is in that grant and the current operator still has the permission. Dispatch admission takes the same transactional generation fence that invalidation advances, then enters the named handler only if the fence remains current. A request checked before revocation but still queued cannot enter after invalidation commits. The route applies the same authorization and handlers as the named `/api/v1` operation, so `/api/v1` remains the only write path. Browser state and the scopes in `init` are display hints, not authority. The server rate-limits each binding and caps request and response size. The module never receives the session cookie, an API token or the operator's identity beyond display name and locale.

A disable, revocation, uninstall or any grant write advances the fence and invalidates affected bindings in the same server transaction. The server cancels queued requests that have not entered an API handler and publishes a close notification; the host closes the port and unmounts the frame. Lost notification cannot preserve access because dispatch checks server state. An admitted handler may finish and is audited with its bound extension origin; revocation cannot undo a side effect already admitted. A protected request binds the package digest, component and grant generation with the operator, operation and parameters. Approval does not bypass a later check: immediately before eventual action dispatch, the server refreshes that extension binding and operator authorization through the same fenced admission path.

### 5.3 Slots

A module declares its slots and the scopes each slot needs; the console mounts it only in granted slots. Slots: navigation entry with a page, device page tab, alert or finding panel, dashboard panel, settings page. The host sizes the frame from `resize` messages within slot limits.

`@module-federation/vite` may split first-party console code. It never loads third-party code, because a federated remote runs in the console's realm with its session.

## 6. Service connectors

### 6.1 Contracts

Contracts are OpenAPI 3.1 documents in `schemas/openapi/connectors/<contract>/v1.yaml`. `jobs` is the caller in every contract.

| Contract | Trigger | Request | Response | On failure |
|---|---|---|---|---|
| `export-destination` | Exporter queue (`backend.md` section 4) | NDJSON OCSF batch with batch id, zstd | Acknowledgement; retries are idempotent by batch id | Per-destination queue holds and retries |
| `ca-connector` | Issuance for a profile bound to the PKI module's external CA | Certificate signing request with the subject, SANs, lifetime and usages `jobs` derived | Certificate chain, or pending with a poll location | Request stays pending, then fails with an audit event |
| `notifier` | Alerts, approval requests, device lifecycle events | Event summary and console link | Acknowledgement | Retry, then drop with an audit event |
| `enricher` | Detection and device views, pull | Entity (hash, IP address, domain, device) | Context attributes with a time-to-live | The detection proceeds without enrichment and is marked |

Authority stays in Ricevanta. `jobs` derives every issuance field before it calls a `ca-connector` and checks the returned certificate against them before storing it (`pki.md` section 3). A `notifier` informs; an approval is decided only by an approver under their own identity in the console or the API.

### 6.2 Authentication

Each registered connector holds a TLS server certificate under the `service` certificate profile (`pki.md` section 3). It enrolls for that certificate through ACME with a registration token, as third-party clients do (PKI-01), and `jobs` derives the subject and SAN from the registration row, never from the request. The registration binds the connector to its certificate's SAN, and `jobs` refuses a connection whose certificate does not match it, is revoked under the issuing CA's CRL, or chains elsewhere.

`jobs` has a distinct client identity under the same profile, subject `CN=io.ricevanta.jobs`, which no registration can obtain. Connectors must check for that subject and the Ricevanta issuing CA, so a connector certificate cannot authenticate as `jobs` to another connector. A connector that cannot use the Ricevanta PKI presents a publicly trusted certificate whose fingerprint the registration pins, and authenticates `jobs` by a scoped bearer token the server generates.

Callbacks use `/api/v1` with a scoped API token whose permission is fixed per contract:

| Contract | Callback permission |
|---|---|
| `ca-connector` | Complete only its own pending request ids |
| `export-destination`, `notifier`, `enricher` | None; no callback token is issued |

### 6.3 Health and deployment

`jobs` probes each connector's `GET /contract`, which returns the contracts and versions it serves, and `GET /healthz` on an interval; the console shows status and alerts on failure. The SDK in `extensions/` ships a contract test kit. Deployment examples cover a Compose service on the server's network and a Helm deployment with a `NetworkPolicy` that limits egress to the granted outbound destinations.

## 7. Browser adapters

### 7.1 Schema

The browser extension is one WebExtensions codebase in `browser/`, built per engine family: `chromium` (Manifest V3), `gecko`, and `webkit` (the Safari web extension inside `Ricevanta.app`). A `browser-adapter` is data, validated by `schemas/extension/v1alpha1/browser-adapter.json`:

| Field | Content |
|---|---|
| `browser` | Id, display name, engine family, vendor, upstream and browser-registration id |
| `os.<macos\|windows\|linux>.policy` | Registered policy backend and semantic policy names from the registration's allow list, or `none` |
| `os.<os>.extension_install` | Store family, whether the store family allows a self-hosted update location, the name of the force-install policy key or the MDM payload type |
| `os.<os>.native_host` | Registered system and user manifest targets, the registered policy that disables user-level hosts, or `none` |
| `os.<os>.connector` | `content_analysis` or `none`; policy names and the pinning key come from the engine family and the agent (section 7.2) |
| `os.<os>.web_request_blocking` | `policy-installed`, `all` or `none` |
| `os.<os>.declarative_net_request` | `true` or `false` |
| `limits` | Per OS and channel in the capability-matrix vocabulary, such as "no blocking `webRequest`: content-script gate with `declarativeNetRequest` backstop" |
| `status` | `qualified` (in the project's qualification manifest with evidence) or `community` |

The schema refuses an adapter that leaves a channel undeclared on an OS it lists. An OS entry with no connector and no blocking `webRequest` must declare the content-script gate and its backstop.

### 7.2 Agent use

Before installing an adapter, an operator must select a separately stored browser registration for that one browser product. Creating, widening, replacing or reassigning a registration is a protected action. A registration binds the browser and engine family to exact canonical policy roots or plist domain on each OS, exact native-host targets, and at most 64 exact engine-specific policy names per OS with their value types and semantic purpose. It also records the evidence source and the owner of every normalized write target. The server refuses overlapping ownership. It permits an explicitly shared native-host target only when every owner receives the same agent-generated bytes; it never permits shared policy values.

The server refuses a registration for an OS or Ricevanta reserved namespace, a generic policy ancestor, a non-system native-host target or a policy name outside the engine's supported semantic slots. On Windows it normalizes registry hives, views, case and separators; on Linux it requires an exact absolute directory; on macOS it requires one exact domain or the first-party Safari MDM backend. A registration cannot claim Windows Firewall's `EnableFirewall` value as a browser or native-host policy. First-party registrations for Chrome, Edge, Firefox and Safari ship with the product, are project-owned and are qualification inputs. An operator can register another documented browser as data without a core change.

The adapter may request only names and targets in its registration. The server stores the approved grant as the intersection of the adapter request, current registration and operator selection, then compiles both the component `grant_generation` and the separate registration digest and `registration_generation` into the signed device bundle. The agent independently validates that intersection and the reserved-namespace rules before activation. A registration change invalidates prior grants, increments both affected counters through their own records and requires recompilation.

The agent generates every value it writes, and the MDM server generates a first-party `apple-mdm` payload. The extension id comes from the project's published ids per store family, `update_url` points only to the server's browser-extension update path, connector pins come from the installed agent, and engine policy values come from built-in typed generators. The agent writes its own `ricevanta-nmhost` manifest, never package bytes. At every write and verification it rechecks the current component grant generation and registration generation, resolves the exact target again, rejects symlinks, reparse points, registry-view aliases and case or path aliases that leave the registered target, and opens only the final registered key, file or plist domain. Schema validation alone never authorizes a write.

The agent reads registered user-level locations only to detect a substitute manifest with its host name and reports one as tampering. Preflight verifies force-install, the user-level host policy where one exists, and the connector policy with its pin. The agent selects the gate per DLP-01, runs the bypass probes and reports capability with adapter id, component grant generation, registration generation and status.

The device-side self-test runs the bypass probes for every adapter at preflight and after each adapter or browser change: does the gate hold an upload, paste and print until the decision, and does an alternate request path or a disconnected extension leave the transfer open. The result is reported per capability. A failing self-test shows the capability as failing, never as silently weaker.

### 7.3 Status and qualification

The first-party adapters for Chrome, Edge, Firefox and Safari are required units in `../specs/platform-qualification.md` and are the v1.0.0 browser coverage (`../platform-support.md`). Any other adapter is `community`, and each capability it serves shows as "community adapter, self-tested, not qualified", never "supported". A community adapter becomes qualified only when the project adds it to the qualification manifest with evidence. This is how Brave, Vivaldi, Opera or a Firefox fork joins without a core change.

### 7.4 First-party adapter facts

From Chromium source, vendor documentation and MDN compatibility data:

| Browser | Policy (Windows; macOS; Linux) | Native host, system level | User-level hosts disabled by | Connector | Blocking `webRequest` | Install |
|---|---|---|---|---|---|---|
| Chrome | `HKLM\Software\Policies\Google\Chrome`; `com.google.Chrome`; `/etc/opt/chrome/policies/managed/` | `HKLM\SOFTWARE\Google\Chrome\NativeMessagingHosts\<name>`; `/Library/Google/Chrome/NativeMessagingHosts/`; `/etc/opt/chrome/native-messaging-hosts/` | `NativeMessagingUserLevelHosts` | `content_analysis`, `cloud_only` policies through Chrome Enterprise Core | `policy-installed` | Chrome Web Store, or a self-hosted `update_url` through `ExtensionInstallForcelist` or `ExtensionSettings` |
| Edge | `HKLM\SOFTWARE\Policies\Microsoft\Edge`; `com.microsoft.Edge`; Linux directory not confirmed (verify) | `HKLM\SOFTWARE\Microsoft\Edge\NativeMessagingHosts\<name>`, then the Chrome and Chromium keys; `/Library/Microsoft/Edge/NativeMessagingHosts/`; `/etc/opt/edge/native-messaging-hosts` | `NativeMessagingUserLevelHosts` | `content_analysis` on Windows and macOS; `none` on Linux | `policy-installed`, inherited from Chromium (verify) | Edge Add-ons, or an update URL by policy |
| Firefox | `HKLM\Software\Policies\Mozilla\Firefox`; `org.mozilla.firefox` with `EnterprisePoliciesEnabled`; `/etc/firefox/policies/policies.json` or `distribution/policies.json` in the install directory | `HKLM\SOFTWARE\Mozilla\NativeMessagingHosts\<name>`; `/Library/Application Support/Mozilla/NativeMessagingHosts/`; `/usr/lib/mozilla/native-messaging-hosts/` or the `lib64` path | None: the policy schema has no native messaging key (verify) | `content_analysis` through `ContentAnalysis` | `all` | addons.mozilla.org (AMO), or `ExtensionSettings` `install_url`; release builds require Mozilla signing, also for self-distributed add-ons |
| Safari | `apple-mdm` Safari extension settings, macOS 15 and later | None: the containing app is the host (verify) | Not applicable | `none` | `none` | Inside `Ricevanta.app`, managed `AlwaysOn` (verify distribution outside the App Store) |

### 7.5 Community adapter facts

Not first-party documentation; every entry is verify:

| Browser | What is known |
|---|---|
| Brave | Chromium policy under `HKLM\Software\Policies\BraveSoftware\Brave`, `com.brave.Browser`, `/etc/brave/policies/`; Brave source reuses Chrome's native-host directories; no connector policy found |
| Vivaldi | Chromium-style policy per forum posts; no first-party policy document |
| Opera | No enterprise policy or native-host documentation found |
| Arc | Arc-specific plist per a help article; reported in maintenance mode |
| LibreWolf | Native hosts in `/usr/lib/librewolf/native-messaging-hosts/`; policy not documented |
| Waterfox, Zen | Ship the Firefox policy engine or `policies.json`; Waterfox has no `ContentAnalysis` preference |

## 8. Distribution and compatibility

### 8.1 Channels

There is no marketplace service. The project publishes a static JSON index, DSSE-signed with the project's extension publisher key (payload type `application/vnd.ricevanta.extension-index+json`). Each entry lists id, version, publisher name and fingerprint, download URL (a GitHub release asset or any HTTPS location), SHA-256, size, kinds, interface versions and first-party or community status. It carries revocations only for packages the project key signed, and warnings for other listed packages (section 2.5). The server fetches the index only when the operator enables it; fetching stops if the project key leaves the trust list. A listing is not trust: a community package still needs its publisher key on the trust list.

Air-gapped operators upload packages in the console or apply them through GitOps. The GitOps kind `Extension` (`../specs/policy-envelope.md` section 8) carries `spec.source.url`, `spec.source.sha256`, `spec.grants` and `spec.targets`; applying it creates the install and the approval request of section 2.2.

First-party extensions, including the four browser adapters, are built from `extensions/` and release with the product version (SH-04). The server image also carries their project-owned browser registrations. It installs and enables the adapters at first start under the project key with grants the project fixes (section 2.2), so a new installation has browser coverage before any download.

### 8.2 Interface versions

| Kind | Interface identifier |
|---|---|
| `content` | `ext.ricevanta.io/content/v1`, plus the format's own version (`RulePack` formats) |
| `browser-adapter` | `ext.ricevanta.io/browser-adapter/v1` |
| `agent-module` | WIT package version, such as `ricevanta:agent/classifier@1.0.0` |
| `console-module` | `ext.ricevanta.io/console-module/v1` and the bridge schema version |
| `service-connector` | `ext.ricevanta.io/<contract>/v1` and its OpenAPI document version |

Interfaces change additively within a major. A new major ships beside the previous one, and the server and agent serve both for at least the agent compatibility window, the current minor release and the two before it (AG-04). The server refuses a package that needs a version it does not serve and names the version. An agent in a mixed fleet refuses to instantiate a module whose WIT version it does not serve and reports the component as unsupported on that device. The product version is not the compatibility key.

## 9. Benefits, trade-offs, dependencies, limits, alternatives

Benefits: any browser a vendor documents for enterprise management can be added as data, without a core change, and its weaker gates show up in the self-test instead of being assumed. Third parties add detectors, parsers, collectors, UI and integrations without forking. The agent and the server keep their trust models: agents still verify one signing key and one assignment, and no foreign code shares a process with signing keys or enforcement. One package format, one signature scheme and one approval flow cover five kinds. Grants make the operator's consent explicit and enforced.

Trade-offs: `ricevanta-ext` with Cranelift adds disk size to the agent package (wasmtime documents about 19 MB for a C API release build and about 2.1 MB without a compiler; the embedding size is not documented, verify), and it is a second content helper on the decision path, sharing the content deadline. A fresh store per call costs instantiation time on every decision. Console modules pay a message round trip for every API call and cannot use the console's components directly. Connectors are one more process for the operator to run and monitor. The server cannot inspect WebAssembly modules beyond their headers, so import enforcement happens on each agent.

Dependencies: `wasmtime` with Cranelift and `wasmtime-wasi` in the agent; `wit-bindgen` and `wasm-tools` in the SDK; DSSE, Ed25519 and JSON Schema 2020-12 already used by the policy envelope; the Ricevanta PKI for `service` certificates. All have rows in `../licensing.md`. The agent depends on wasmtime Tier 1 support on the three v1.0.0 host targets: macOS ARM64, Windows x64 and Linux x64 (verify). wasmtime ships a semver-major release monthly and every twelfth release is LTS with 24 months of support; the agent tracks LTS releases, and each change of version invalidates the compile cache (`agent.md` section 8).

Limits: modules have no network and no process spawn at v1.0.0, so an enricher that needs the network is a connector. The server does not enforce a connector's outbound destinations; the operator's network policy does. Firefox has no policy that disables user-level native hosts (verify), so a user-level substitute host on Firefox is an OS limit (`../platform-support.md`). Community adapters are self-tested, not qualified. Facts for Vivaldi, Opera, Arc and the Firefox forks have no first-party source. Console modules render only in the declared slots, and the CSP header's behaviour on a top-level navigation is unconfirmed in Safari (verify). A sandboxed frame can still navigate itself; the console's `frame-src` limits it to module paths (verify), so carrying granted data out in a URL rests on that header, and the grant bounds the data a module can read in any case.

Alternatives considered:

- In-process server plugins on `wazero`, `wasmtime-go`, Go's `plugin` package or go-plugin: rejected by EXT-05; revisit when `wazero` implements WASIp2 with fuel.
- Extism, interpreters and native libraries on the agent: rejected by EXT-03.
- Same-page console plugins, Module Federation for third-party code, Shadow DOM and ShadowRealm: rejected by EXT-04.
- Serving `/ext/` from a separate host name, as MDN advises for sandboxed content: not chosen. It costs every self-hoster a second host name and certificate, and the opaque origin from the sandbox already gives the frame no access to the console origin.
- Sigstore keyless signing and agent-side publisher verification: rejected by EXT-02.
- An OCI registry or a hosted marketplace: rejected by EXT-07.
- A fixed browser list: rejected by EXT-06.
